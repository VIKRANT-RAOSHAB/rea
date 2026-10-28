import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  ESP8266_REFUSAL,
  createEspImageDecoder,
  recognizeEspImage,
} from "./espImage.js";
import { classifyEspSegment, espChipForId } from "./espChips.js";
import {
  ESP32C3_APP_SEGMENTS,
  ESP32C3_BOOTLOADER_SEGMENTS,
  appDescriptor,
  bootloaderDescriptor,
  erasedTo4KiB,
  esp8266Image,
  espChecksum,
  espImage,
  pattern,
  signatureBlock,
  signedEspImage,
} from "./espImage.fixture.js";

const decode = (bytes: Uint8Array, chunkBytes = 7) => {
  const decoder = createEspImageDecoder(bytes.length);
  for (
    let offset = 0;
    offset < bytes.length && !decoder.satisfied;
    offset += chunkBytes
  )
    decoder.write(bytes.subarray(offset, offset + chunkBytes));
  return decoder.finish();
};

const image = (bytes: Uint8Array, chunkBytes?: number) => {
  const decoded = decode(bytes, chunkBytes);
  if (!decoded.ok) throw new Error(decoded.error.message);
  return decoded.value;
};

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const classifications = (bytes: Uint8Array) =>
  image(bytes).segments.map(({ metadata }) => metadata.classification);

const APP = espImage({ segments: ESP32C3_APP_SEGMENTS });
const PADDED = erasedTo4KiB(APP);

/** A sector holding `slots` at their indices, the rest erased. */
const sector = (slots: readonly (Buffer | null)[]): Buffer => {
  const bytes = Buffer.alloc(4096, 0xff);
  slots.forEach((slot, index) => slot?.copy(bytes, index * 1216));
  return bytes;
};

describe("ESP image recognition", () => {
  it.each([
    ["an ESP32-C3 app", APP, "esp-image"],
    ["an image cut after its first header", APP.subarray(0, 40), "esp-image"],
    ["a header alone", APP.subarray(0, 24), "esp-image"],
    ["an ESP8266 v1 image", esp8266Image(), "esp8266"],
    ["an ESP8266 image led by eboot", esp8266Image(0x4010_f000), "esp8266"],
    ["an ESP8266 v3 image led by IROM", esp8266Image(0x4020_1010), "esp8266"],
  ] as const)("recognizes %s", (_name, bytes, expected) => {
    expect(recognizeEspImage(bytes, bytes.length)).toBe(expected);
  });

  const changed = (offset: number, value: number): Buffer => {
    const bytes = Buffer.from(APP);
    bytes[offset] = value;
    return bytes;
  };

  it.each([
    ["another magic", changed(0, 0xea)],
    // Valid, but loads nothing; the decoder still reads one.
    ["an image with no segments", espImage({ segments: [] })],
    ["17 segments", changed(1, 17)],
    ["a flash mode outside the enum", changed(2, 6)],
    ["a flash speed outside the enum", changed(3, 0x23)],
    ["a hash_appended byte of 2", changed(23, 2)],
    ["an unaligned first segment length", changed(28, 0x21)],
    ["fewer than 24 bytes", APP.subarray(0, 23)],
    // DOS .COM near jumps, over code or over a zeroed data area.
    [
      "an x86 jump stub",
      Buffer.from([0xe9, 0x0d, 0x01, 0xb4, 0x09, ...Buffer.alloc(59)]),
    ],
    [
      "an x86 jump over zeros",
      Buffer.from([0xe9, 0x00, 0x01, ...Buffer.alloc(61)]),
    ],
    ["encrypted flash", pattern(4096, 0x5a)],
    ["nothing", Buffer.alloc(0)],
  ] as const)("does not recognize %s", (_name, bytes) => {
    expect(recognizeEspImage(bytes, bytes.length)).toBeUndefined();
  });
});

describe("ESP image decoding", () => {
  it("reports header, chip, segment, integrity and descriptor facts", () => {
    const decoded = image(APP);
    expect(decoded.metadata).toEqual({
      kind: "esp-image",
      header: {
        segment_count: 4,
        spi_mode: 2,
        spi_speed: 0,
        spi_size: 2,
        entry_addr: 0x4038_0000,
        wp_pin: 0xee,
        spi_pin_drv: "000000",
        chip_id: 5,
        min_chip_rev: 0,
        min_chip_rev_full: 0,
        max_chip_rev_full: 199,
        reserved: "00000000",
        hash_appended: true,
      },
      chip: { target: "esp32c3", isa: "riscv", source: "ESP-IDF v6.1" },
      // Segments end at 456; the checksum ends the next 16-byte block.
      checksum: {
        offset: 463,
        stored: espChecksum(ESP32C3_APP_SEGMENTS),
        computed: espChecksum(ESP32C3_APP_SEGMENTS),
        status: "valid",
      },
      appended_sha256: {
        offset: 464,
        stored: sha256(APP.subarray(0, 464)),
        computed: sha256(APP.subarray(0, 464)),
        status: "valid",
      },
      image_end: 496,
      signature_sector_offset: null,
      undescribed_trailing: [],
      descriptor: {
        kind: "app",
        offset: 32,
        secure_version: 0,
        version: "1.2.3",
        project_name: "rea_esp_fixture",
        time: "12:34:56",
        date: "Oct 27 2026",
        idf_ver: "v6.1",
        app_elf_sha256: "ab".repeat(32),
        min_efuse_blk_rev_full: 0,
        max_efuse_blk_rev_full: 199,
        mmu_page_size: 16,
      },
    });
    expect(
      decoded.segments.map(({ dataOffset, availableLength, metadata }) => [
        metadata.index,
        metadata.load_addr,
        metadata.data_len,
        metadata.header_offset,
        dataOffset,
        availableLength,
        metadata.classification,
      ]),
    ).toEqual([
      [0, 0x3c00_0020, 288, 24, 32, 288, "mapped"],
      [1, 0x3fc8_8000, 16, 320, 328, 16, "loaded"],
      [2, 0x4038_0000, 32, 344, 352, 32, "loaded"],
      [3, 0x4200_0020, 64, 384, 392, 64, "mapped"],
    ]);
    expect(decoded.coverage).toBe("complete");
    expect(decoded.limitations).toEqual([]);
    expect(decoded.signatureBlocks).toEqual([]);
  });

  it("decodes identically from any chunking", () => {
    const signed = signedEspImage(APP, ["rsa", null, "ecdsa-p384"]);
    const expected = image(signed, signed.length);
    for (const chunkBytes of [1, 3, 16, 4096])
      expect(image(signed, chunkBytes)).toEqual(expected);
  });

  it("reads an image with no segments", () => {
    const decoded = image(espImage({ segments: [] }));
    expect(decoded.metadata).toMatchObject({
      checksum: { offset: 31, stored: 0xef, computed: 0xef, status: "valid" },
      appended_sha256: { offset: 32, status: "valid" },
      image_end: 64,
      descriptor: null,
    });
    expect(decoded.segments).toEqual([]);
    expect(decoded.coverage).toBe("complete");
  });

  it("reads a bootloader descriptor only with zero reserved bytes", () => {
    expect(
      image(espImage({ segments: ESP32C3_BOOTLOADER_SEGMENTS })).metadata
        .descriptor,
    ).toEqual({
      kind: "bootloader",
      offset: 32,
      secure_version: 1,
      version: 1,
      idf_ver: "v6.1",
      date_time: "Oct 27 2026 12:34:56",
    });
    const code = bootloaderDescriptor();
    code[1] = 0x41;
    const decoded = image(
      espImage({ segments: [{ address: 0x4038_0000, data: code }] }),
    );
    expect(decoded.metadata.descriptor).toBeNull();
    expect(decoded.limitations).toEqual([
      "ESP image segment 0 begins with the bootloader descriptor magic 0x50, but its reserved bytes are not zero; it is not read as an esp_bootloader_desc_t.",
    ]);
  });

  it("omits a descriptor string that is not UTF-8", () => {
    const descriptor = appDescriptor();
    descriptor[16] = 0xff;
    const decoded = image(
      espImage({ segments: [{ address: 0x3c00_0020, data: descriptor }] }),
    );
    expect(decoded.metadata.descriptor).toMatchObject({
      version: null,
      project_name: "rea_esp_fixture",
    });
    expect(decoded.limitations).toEqual([
      "ESP image descriptor field version is not valid UTF-8; its value is omitted.",
    ]);
  });
});

describe("ESP image segment classification", () => {
  it("classifies by the ESP32 memory map and keeps padding unloaded", () => {
    const bytes = espImage({
      chipId: 0,
      segments: [
        { address: 0x3f40_0020, data: appDescriptor() },
        { address: 0, data: pattern(16, 1) },
        { address: 0x3ffb_0000, data: pattern(16, 2) },
        { address: 0x4008_0000, data: pattern(16, 3) },
        { address: 0x400d_0020, data: pattern(16, 4) },
        { address: 0x5000_0000, data: pattern(16, 5) },
      ],
    });
    expect(image(bytes).metadata.chip).toEqual({
      target: "esp32",
      isa: "xtensa",
      source: "ESP-IDF v6.1",
    });
    expect(classifications(bytes)).toEqual([
      "mapped",
      "not-loaded",
      "loaded",
      "loaded",
      "mapped",
      "loaded",
    ]);
  });

  it("reports unknown chips without guessing a memory map", () => {
    const decoded = image(
      espImage({ chipId: 0x1f, segments: ESP32C3_APP_SEGMENTS }),
    );
    expect(decoded.metadata.chip).toBeNull();
    expect(
      new Set(decoded.segments.map(({ metadata }) => metadata.classification)),
    ).toEqual(new Set(["unknown"]));
    expect(decoded.limitations).toEqual([
      "ESP image chip_id 0x001f is not in the ESP-IDF v6.1 chip table; chip, ISA and segment classification are unknown.",
    ]);
  });

  it("leaves ESP32-C6 mapping unknown where the bootloader page size decides it", () => {
    // The app's page size does not establish the bootloader's.
    const bytes = espImage({
      chipId: 0x0d,
      segments: [
        { address: 0x4200_0020, data: appDescriptor({ mmuPageSizeLog2: 16 }) },
        { address: 0x4210_0000, data: pattern(16, 1) },
        { address: 0x4230_0000, data: pattern(16, 2) },
        { address: 0x4300_0000, data: pattern(16, 3) },
      ],
    });
    expect(classifications(bytes)).toEqual([
      "mapped",
      "mapped",
      "unknown",
      "loaded",
    ]);
    expect(image(bytes).limitations).toEqual([
      "esp32c6 maps flash through 256 MMU pages of the bootloader's configured size, which the image does not record; segments from 0x42200000 to 0x43000000 are unclassified.",
    ]);
  });

  it("derives the ISA from chip_id, not from the series letter", () => {
    expect(espChipForId(0x20)).toMatchObject({
      target: "esp32s31",
      isa: "riscv",
    });
    expect(espChipForId(0x09)).toMatchObject({
      target: "esp32s3",
      isa: "xtensa",
    });
    // ESP32-P4 maps PSRAM through its own MMU.
    expect(classifyEspSegment(espChipForId(0x12), 0x4800_0000)).toBe("mapped");
  });
});

describe("ESP image integrity", () => {
  it("reports a checksum mismatch as an integrity fact", () => {
    const computed = espChecksum(ESP32C3_APP_SEGMENTS);
    const stored = computed ^ 0x5a;
    const decoded = image(
      espImage({ segments: ESP32C3_APP_SEGMENTS, checksum: stored }),
    );
    expect(decoded.metadata.checksum).toMatchObject({
      stored,
      computed,
      status: "invalid",
    });
    expect(decoded.metadata.appended_sha256.status).toBe("valid");
    expect(decoded.coverage).toBe("complete");
    const byte = (value: number) => value.toString(16).padStart(2, "0");
    expect(decoded.limitations).toEqual([
      `ESP image checksum 0x${byte(stored)} at offset 0x1cf does not match the computed 0x${byte(computed)}.`,
    ]);
  });

  it("reports an appended SHA-256 mismatch", () => {
    const bytes = Buffer.from(APP);
    bytes.writeUInt8(bytes.readUInt8(bytes.length - 1) ^ 1, bytes.length - 1);
    const decoded = image(bytes);
    expect(decoded.metadata.checksum.status).toBe("valid");
    expect(decoded.metadata.appended_sha256.status).toBe("invalid");
    expect(decoded.limitations).toEqual([
      "ESP image appended SHA-256 at offset 0x1d0 does not match the SHA-256 of the bytes before it.",
    ]);
  });

  it("marks an image without a digest", () => {
    expect(
      image(espImage({ segments: ESP32C3_APP_SEGMENTS, hashAppended: false }))
        .metadata.appended_sha256,
    ).toEqual({
      offset: null,
      stored: null,
      computed: null,
      status: "not-appended",
    });
  });

  it("keeps a truncated segment as an image with unavailable integrity", () => {
    const decoded = image(APP.subarray(0, 360));
    expect(decoded.metadata).toMatchObject({
      checksum: { offset: null, computed: null, status: "unavailable" },
      appended_sha256: { offset: null, computed: null, status: "unavailable" },
      image_end: null,
    });
    expect(
      decoded.segments.map(({ availableLength }) => availableLength),
    ).toEqual([288, 16, 8]);
    expect(decoded.coverage).toBe("unknown");
    expect(decoded.limitations).toEqual([
      "ESP image is truncated: segment 2 declares 32 bytes at offset 0x160, but the file holds 8.",
    ]);
  });

  it("reports a file that ends before a declared segment header", () => {
    const decoded = image(APP.subarray(0, 344));
    expect(decoded.segments).toHaveLength(2);
    expect(decoded.limitations).toEqual([
      "ESP image is truncated: the header declares 4 segments, but the file ends before the header of segment 2.",
    ]);
  });

  it.each([
    [
      "checksum",
      460,
      "ESP image is truncated before its checksum at offset 0x1cf.",
    ],
    [
      "appended SHA-256",
      470,
      "ESP image is truncated before its appended SHA-256 at offset 0x1d0.",
    ],
  ] as const)(
    "keeps coverage unknown when the file ends before its %s",
    (_name, end, message) => {
      // Signature blocks would follow the image end, so their absence is unknown.
      const decoded = image(APP.subarray(0, end));
      expect(decoded.limitations).toEqual([message]);
      expect(decoded.coverage).toBe("unknown");
    },
  );

  it("reports an unaligned segment length that ESP-IDF rejects", () => {
    const decoded = image(
      espImage({
        segments: [
          { address: 0x3c00_0020, data: appDescriptor() },
          { address: 0x4038_0000, data: pattern(6, 1) },
          { address: 0x3fc8_8000, data: Buffer.alloc(0) },
        ],
      }),
    );
    expect(decoded.metadata.checksum.status).toBe("valid");
    expect(decoded.limitations).toEqual([
      "ESP image segment 1 length 0x6 is not a multiple of 4; ESP-IDF rejects such an image.",
    ]);
  });

  it.each([
    ["esp32c3", 0x0005, true],
    ["esp32s3", 0x0009, false],
  ] as const)(
    "applies ESP-IDF's 16 MiB segment limit to %s by its cache address width",
    (target, chipId, limited) => {
      const bytes = Buffer.from(
        espImage({
          chipId,
          segments: [{ address: 0x3fc8_8000, data: pattern(16, 1) }],
        }),
      );
      // Segment 0 declares 16 MiB; the file holds only its first bytes.
      bytes.writeUInt32LE(0x100_0000, 28);
      const decoded = image(bytes);
      expect(decoded.limitations).toEqual([
        ...(limited
          ? [
              `ESP image segment 0 length 0x1000000 is 16 MiB or more; ESP-IDF rejects such an image for ${target}.`,
            ]
          : []),
        `ESP image is truncated: segment 0 declares 16777216 bytes at offset 0x20, but the file holds ${String(bytes.length - 0x20)}.`,
      ]);
    },
  );
});

describe("ESP image trailing bytes", () => {
  it("describes erased flash that runs past the signature slots", () => {
    const decoded = image(
      Buffer.concat([APP, Buffer.alloc(0x1_0000 - APP.length, 0xff)]),
    );
    expect(decoded.metadata.undescribed_trailing).toEqual([]);
    expect(decoded.coverage).toBe("complete");
  });

  it.each([
    [
      "inside the padding",
      Buffer.concat([APP, Buffer.alloc(1000, 0xff)]),
      "0x5d8",
    ],
    ["at the sector boundary", PADDED, "0x1000"],
  ] as const)(
    "keeps coverage unknown when erased flash ends %s",
    (_name, bytes, end) => {
      // A signed download cut here would have lost its signature sector.
      const decoded = image(bytes);
      expect(decoded.metadata.undescribed_trailing).toEqual([]);
      expect(decoded.coverage).toBe("unknown");
      expect(decoded.limitations).toEqual([
        `The file ends at ${end} in erased flash, before the Secure Boot v2 signature slots at 0x1000 are complete; signature blocks may be missing.`,
      ]);
    },
  );

  it("reports flash segments that a RAM-only header leaves uncounted", () => {
    const headerOnly = espImage({
      segments: ESP32C3_APP_SEGMENTS.slice(1, 3),
      hashAppended: false,
    });
    const flash = Buffer.concat([
      Buffer.from([0, 0, 0, 0, 16, 0, 0, 0]),
      Buffer.alloc(16),
    ]);
    const decoded = image(Buffer.concat([headerOnly, flash]));
    expect(decoded.metadata).toMatchObject({
      checksum: { status: "valid" },
      appended_sha256: { status: "not-appended" },
      image_end: 96,
      undescribed_trailing: [{ offset: 96, length: 24 }],
    });
    expect(decoded.coverage).toBe("unknown");
    expect(decoded.limitations).toEqual([
      "24 bytes after the ESP image, in 1 range(s) from offset 0x60, are not described by its header, erased flash or a signature sector. They may be other flash contents, a Secure Boot v1 signature, or flash segments that esptool --ram-only-header leaves out of the segment count.",
    ]);
  });

  it("starts an undescribed range at the first byte that is not erased", () => {
    const bytes = Buffer.concat([
      PADDED,
      Buffer.alloc(4096, 0xff),
      pattern(64, 1),
    ]);
    expect(image(bytes).metadata.undescribed_trailing).toEqual([
      { offset: 8192, length: 64 },
    ]);
  });

  it("reports disjoint undescribed ranges around a signature sector", () => {
    const padded = Buffer.concat([APP, Buffer.alloc(4096 - APP.length)]);
    const bytes = Buffer.concat([
      padded,
      sector([signatureBlock("rsa", padded)]),
      Buffer.alloc(64, 0x11),
    ]);
    const decoded = image(bytes);
    expect(decoded.signatureBlocks).toHaveLength(1);
    expect(decoded.metadata.undescribed_trailing).toEqual([
      { offset: 496, length: 3600 },
      { offset: 8192, length: 64 },
    ]);
    expect(decoded.coverage).toBe("unknown");
  });
});

describe("Secure Boot v2 signature blocks", () => {
  it("observes blocks without verifying them", () => {
    const signed = signedEspImage(APP, ["rsa", "ecdsa-p256", "ecdsa-p384"]);
    const decoded = image(signed);
    const content = signed.subarray(0, 4096);
    expect(decoded.metadata).toMatchObject({
      signature_sector_offset: 4096,
      undescribed_trailing: [],
    });
    expect(decoded.coverage).toBe("complete");
    expect(decoded.limitations).toEqual([]);
    const block = (
      offset: number,
      facts: Record<string, unknown>,
      keyStart: number,
      keyEnd: number,
    ) => [
      offset,
      {
        kind: "esp-image-signature-block",
        ...facts,
        public_key_sha256: sha256(
          signed.subarray(offset + keyStart, offset + keyEnd),
        ),
        signature_status: "unverified",
      },
    ];
    const sha256Fields = {
      digest_algorithm: "sha256",
      image_digest: sha256(content),
      image_digest_matches: true,
    };
    expect(
      decoded.signatureBlocks.map(({ offset, metadata }) => [offset, metadata]),
    ).toEqual([
      block(
        4096,
        {
          index: 0,
          version: 2,
          scheme: "rsa",
          sha_version: null,
          curve_id: null,
          ...sha256Fields,
        },
        36,
        812,
      ),
      block(
        5312,
        {
          index: 1,
          version: 3,
          scheme: "ecdsa",
          sha_version: 0,
          curve_id: 2,
          ...sha256Fields,
        },
        36,
        101,
      ),
      block(
        6528,
        {
          index: 2,
          version: 3,
          scheme: "ecdsa",
          sha_version: 1,
          curve_id: 3,
          digest_algorithm: "sha384",
          image_digest: createHash("sha384").update(content).digest("hex"),
          image_digest_matches: true,
        },
        52,
        149,
      ),
    ]);
  });

  it("examines every slot, so an erased slot does not hide a later block", () => {
    const decoded = image(signedEspImage(APP, ["rsa", null, "ecdsa-p256"]));
    expect(
      decoded.signatureBlocks.map(({ offset, metadata }) => [
        offset,
        metadata.index,
      ]),
    ).toEqual([
      [4096, 0],
      [6528, 2],
    ]);
    expect(decoded.coverage).toBe("complete");
  });

  it("does not admit a slot whose CRC32 does not match", () => {
    const decoded = image(
      Buffer.concat([
        PADDED,
        sector([
          signatureBlock("rsa", PADDED),
          signatureBlock("rsa", PADDED, { crc: 0 }),
        ]),
      ]),
    );
    expect(
      decoded.signatureBlocks.map(({ metadata }) => metadata.index),
    ).toEqual([0]);
    expect(decoded.metadata.undescribed_trailing).toEqual([
      { offset: 5312, length: 1216 },
    ]);
    expect(decoded.limitations).toContain(
      "Secure Boot v2 slot 1 at offset 0x14c0 has the 0xE7 magic but not a matching CRC32 or a complete block; it is not a valid signature block.",
    );
    // A stray 0xE7 in trailing data, without a valid block, is not a sector.
    const stray = image(
      Buffer.concat([PADDED, Buffer.from([0xe7]), pattern(100, 3)]),
    );
    expect(stray.metadata.signature_sector_offset).toBeNull();
    expect(stray.metadata.undescribed_trailing).toEqual([
      { offset: 4096, length: 101 },
    ]);
    expect(stray.limitations).toContain(
      "Secure Boot v2 slot 0 at offset 0x1000 has the 0xE7 magic but not a matching CRC32 or a complete block; it is not a valid signature block.",
    );
  });

  it("reports a damaged slot when no slot holds a valid block", () => {
    const decoded = image(
      Buffer.concat([
        PADDED,
        sector([signatureBlock("rsa", PADDED, { crc: 0 })]),
      ]),
    );
    expect(decoded.signatureBlocks).toEqual([]);
    expect(decoded.metadata.undescribed_trailing).toEqual([
      { offset: 4096, length: 4096 },
    ]);
    expect(decoded.limitations).toContain(
      "Secure Boot v2 slot 0 at offset 0x1000 has the 0xE7 magic but not a matching CRC32 or a complete block; it is not a valid signature block.",
    );
    expect(decoded.coverage).toBe("unknown");
  });
});

describe("Secure Boot v2 block layouts and sector bounds", () => {
  it.each([
    [
      "an unknown ECDSA sha_version",
      { shaVersion: 2 },
      { version: 3, scheme: "ecdsa", sha_version: 2 },
    ],
    [
      "an unknown version",
      { version: 4 },
      { version: 4, scheme: null, sha_version: null },
    ],
  ] as const)("leaves layout facts unknown for %s", (_name, options, known) => {
    const decoded = image(
      Buffer.concat([
        PADDED,
        sector([signatureBlock("ecdsa-p256", PADDED, options)]),
      ]),
    );
    expect(decoded.signatureBlocks[0]?.metadata).toEqual({
      kind: "esp-image-signature-block",
      index: 0,
      ...known,
      curve_id: null,
      digest_algorithm: null,
      image_digest: null,
      image_digest_matches: null,
      public_key_sha256: null,
      signature_status: "unverified",
    });
  });

  it("reports a digest that does not match and bytes in the sector slack", () => {
    const slack = sector([
      signatureBlock("rsa", PADDED, { imageDigest: Buffer.alloc(32) }),
    ]);
    slack[3700] = 0;
    const decoded = image(Buffer.concat([PADDED, slack]));
    expect(decoded.signatureBlocks[0]?.metadata.image_digest_matches).toBe(
      false,
    );
    expect(decoded.metadata.undescribed_trailing).toEqual([
      { offset: 4096 + 3700, length: 396 },
    ]);
  });

  it("reports a truncated sector and describes an erased tail after it", () => {
    const signed = signedEspImage(APP, ["rsa"]);
    const cut = image(signed.subarray(0, 4096 + 1300));
    expect(cut.coverage).toBe("unknown");
    expect(cut.signatureBlocks).toHaveLength(1);
    expect(cut.limitations).toEqual([
      "Secure Boot v2 signature sector at offset 0x1000 is truncated: the file ends at 0x1514, before 0x2000.",
    ]);
    expect(
      image(Buffer.concat([signed, Buffer.alloc(32, 0xff)])).coverage,
    ).toBe("complete");
    expect(
      image(Buffer.concat([signed, Buffer.alloc(32)])).metadata
        .undescribed_trailing,
    ).toEqual([{ offset: 8192, length: 32 }]);
  });
});

describe("ESP image refusals", () => {
  it.each([0x4010_0000, 0x4010_f000, 0x4020_1010])(
    "refuses an ESP8266 image whose first segment loads at %i",
    (address) => {
      expect(decode(esp8266Image(address))).toEqual({
        ok: false,
        error: { kind: "unsupported", message: ESP8266_REFUSAL },
      });
    },
  );

  it("refuses bytes that are not an ESP image header", () => {
    expect(decode(pattern(64, 0x5a))).toMatchObject({
      ok: false,
      error: { kind: "format" },
    });
  });

  it("refuses input that stops before the admitted size", () => {
    const decoder = createEspImageDecoder(APP.length);
    decoder.write(APP.subarray(0, 100));
    expect(decoder.finish()).toEqual({
      ok: false,
      error: {
        kind: "format",
        message:
          "ESP image input ended at offset 0x64, before the admitted size 0x1f0",
      },
    });
  });
});
