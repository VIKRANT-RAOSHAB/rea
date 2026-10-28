import { createHash } from "node:crypto";
import { crc32 as nativeCrc32 } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  cells,
  devicetreeFixture,
  dtString,
} from "../devicetree/Devicetree.fixture.js";
import { parseDeviceLoader } from "./loaders.js";
import { crc32 } from "./loaders-common.js";

const parse = (format: string, bytes: Buffer | string, maxItems = 1000) =>
  parseDeviceLoader(typeof bytes === "string" ? Buffer.from(bytes) : bytes, {
    format,
    maxItems,
  });
const uf2 = (address: number, number = 0, total = 1, family = 0x1234) => {
  const b = Buffer.alloc(512);
  [0x0a324655, 0x9e5d5157, 0x2000, address, 4, number, total, family].forEach(
    (v, i) => b.writeUInt32LE(v, i * 4),
  );
  b.set([1, 2, 3, 4], 32);
  b.writeUInt32LE(0x0ab16f30, 508);
  return b;
};
const esp = (extended: boolean, hash = false) => {
  const b = Buffer.alloc(extended ? 48 : 32);
  b[0] = 0xe9;
  b[1] = 1;
  b.writeUInt32LE(0x40001000, 4);
  const start = extended ? 24 : 8;
  if (extended) b[23] = hash ? 1 : 0;
  b.writeUInt32LE(0x40001000, start);
  b.writeUInt32LE(4, start + 4);
  b.set([1, 2, 3, 4], start + 8);
  b[b.length - 1] = 0xeb;
  return hash ? Buffer.concat([b, createHash("sha256").update(b).digest()]) : b;
};
const uimage = (
  payload = Buffer.from([1, 2, 3]),
  compression = 0,
  type = 2,
) => {
  const h = Buffer.alloc(64);
  h.writeUInt32BE(0x27051956);
  h.writeUInt32BE(payload.length, 12);
  h.writeUInt32BE(0x80000000, 16);
  h.writeUInt32BE(0x80000004, 20);
  h.writeUInt32BE(nativeCrc32(payload), 24);
  h[29] = 2;
  h[30] = type;
  h[31] = compression;
  h.writeUInt32BE(nativeCrc32(h), 4);
  return Buffer.concat([h, payload]);
};
const fit = (data: Buffer, external = false) => {
  const dt = devicetreeFixture({
    name: "",
    properties: {
      description: dtString("Fixture"),
      "#address-cells": cells(1),
    },
    children: [
      {
        name: "images",
        children: [
          {
            name: "kernel",
            properties: {
              type: dtString("kernel"),
              arch: dtString("arm"),
              compression: dtString("none"),
              load: cells(0x80000000),
              entry: cells(0x80000004),
              ...(external
                ? { "data-offset": cells(0), "data-size": cells(data.length) }
                : { data }),
            },
            children: [
              {
                name: "hash-1",
                properties: {
                  algo: dtString("sha256"),
                  value: createHash("sha256").update(data).digest(),
                },
              },
            ],
          },
        ],
      },
      {
        name: "configurations",
        properties: { default: dtString("conf-1") },
        children: [
          { name: "conf-1", properties: { kernel: dtString("kernel") } },
        ],
      },
    ],
  });
  return external
    ? Buffer.concat([dt, Buffer.alloc((4 - (dt.length % 4)) % 4), data])
    : dt;
};

describe("text firmware record loaders", () => {
  it("reconstructs sparse HEX payloads and a distinct entry without filling gaps", () => {
    const r = parse(
      "intel-hex",
      ":020000040800F2\n:03001000010203E7\n:0100200004DB\n:0400000508000010DF\n:00000001FF\n",
    );
    expect(r.entryPoint).toBe("0x8000010");
    expect(r.regions.map((x) => x.loadAddress)).toEqual([
      "0x8000010",
      "0x8000020",
    ]);
    expect(r.regions[0]?.bytes.equals(Buffer.from([1, 2, 3]))).toBe(true);
    expect(r.regions[0]?.fileOffset).toBeNull();
    expect(r.architecture).toBeNull();
  });
  it.each([
    ":03001000010203E6\n:00000001FF", // checksum
    ":03001000010203E7", // EOF
    ":00000001FF\n:00000001FF", // after EOF
    ":03001000010203E7\n:03001000010203E7\n:00000001FF", // overlap
    ":02000004FFFFFC\n:02FFFF000001FF\n:00000001FF", // overflow
  ])("rejects ambiguous or corrupt HEX %s", (source) =>
    expect(() => parse("intel-hex", source)).toThrow(),
  );
  it("bounds records before reconstructing payloads", () =>
    expect(() =>
      parse("intel-hex", ":03001000010203E7\n:00000001FF", 1),
    ).toThrow(/max_items/));
  it("verifies S-record checksum and declared record count", () => {
    const r = parse("srec", "S1061000010203E3\nS5030001FB\nS9031000EC\n");
    expect(r.entryPoint).toBe("0x1000");
    expect(r.regions[0]?.bytes.toString("hex")).toBe("010203");
    expect(() =>
      parse("srec", "S1061000010203E3\nS5030002FA\nS9031000EC"),
    ).toThrow(/count mismatch/);
    expect(() => parse("srec", "S1061000010203E2\nS9031000EC")).toThrow(
      /checksum/,
    );
  });
});

describe("UF2 blocks", () => {
  it("sorts numbered out-of-order blocks into addressed contiguous payloads", () => {
    const r = parse(
      "uf2",
      Buffer.concat([uf2(0x1004, 1, 2), uf2(0x1000, 0, 2)]),
    );
    expect(r.complete).toBe(true);
    expect(r.regions[0]?.loadAddress).toBe("0x1000");
    expect(r.regions[0]?.bytes.length).toBe(8);
  });
  it("preserves families separately and accepts exact retransmitted blocks", () => {
    expect(
      parse("uf2", Buffer.concat([uf2(0x1000), uf2(0x1000)])).regions,
    ).toHaveLength(1);
    expect(
      parse("uf2", Buffer.concat([uf2(0x1000), uf2(0x1000, 0, 1, 0x4567)]))
        .regions,
    ).toHaveLength(2);
  });
  it("reports incomplete block sets and refuses conflicting duplicates/truncation", () => {
    expect(parse("uf2", uf2(0x1000, 0, 2)).complete).toBe(false);
    const changed = uf2(0x1000);
    changed[32] = 9;
    expect(() => parse("uf2", Buffer.concat([uf2(0x1000), changed]))).toThrow(
      /Conflicting/,
    );
    expect(() => parse("uf2", uf2(0x1000).subarray(0, -1))).toThrow(/512/);
  });
  it("inventories file-container blocks without mistaking them for flash", () => {
    const b = uf2(0);
    b.writeUInt32LE(0x1000, 8);
    const r = parse("uf2", b);
    expect(r.complete).toBe(false);
    expect(r.regions).toEqual([]);
  });
});

describe("Espressif images and partition tables", () => {
  it.each([false, true])(
    "loads explicit E9 profile extended=%s with checksum",
    (extended) => {
      const r = parse(extended ? "esp32" : "esp8266", esp(extended));
      expect(r.entryPoint).toBe("0x40001000");
      expect(r.architecture).toBe("xtensa");
      expect(r.regions[0]?.fileOffset).toBe(extended ? 32 : 16);
    },
  );
  it("verifies appended image hashes and rejects modified segments", () => {
    const good = esp(true, true);
    expect(parse("esp32", good).complete).toBe(true);
    const badHash = Buffer.from(good);
    badHash[good.length - 1] = badHash[good.length - 1]! ^ 1;
    expect(() => parse("esp32", badHash)).toThrow(/SHA-256/);
    const badData = esp(false);
    badData[16] = badData[16]! ^ 1;
    expect(() => parse("esp8266", badData)).toThrow(/checksum/);
    expect(() => parse("esp32", good.subarray(0, 30))).toThrow(/outside/);
  });
  it("checks standalone partition entry ownership and MD5", () => {
    const b = Buffer.alloc(96, 255);
    b.writeUInt16LE(0x50aa);
    b[2] = 0;
    b[3] = 0;
    b.writeUInt32LE(0x10000, 4);
    b.writeUInt32LE(0x100000, 8);
    b.fill(0, 12, 32);
    b.write("factory", 12);
    b.writeUInt16LE(0xebeb, 32);
    createHash("md5").update(b.subarray(0, 32)).digest().copy(b, 48);
    const r = parse("esp-partitions", b);
    expect(r.regions).toEqual([]);
    expect(r.items[0]?.flash_offset).toBe("0x10000");
    expect(r.items[1]?.valid).toBe(true);
    b[48] = b[48]! ^ 1;
    expect(() => parse("esp-partitions", b)).toThrow(/MD5/);
  });
});

describe("console cartridge containers", () => {
  it("maps 16-KiB NROM once and records the mirrored bank plus reset vector", () => {
    const b = Buffer.alloc(16 + 16384);
    b.set([0x4e, 0x45, 0x53, 0x1a, 1]);
    b.writeUInt16LE(0xc010, b.length - 4);
    const r = parse("ines", b);
    expect(r.entryPoint).toBe("0xc010");
    expect(r.regions[0]?.loadAddress).toBe("0xc000");
    expect(r.items.some((i) => i.kind === "mirror")).toBe(true);
    b[6] = 0x10;
    const banked = parse("ines", b);
    expect(banked.complete).toBe(false);
    expect(banked.entryPoint).toBeNull();
    expect(banked.regions[0]?.loadAddress).toBeNull();
    expect(() => parse("ines", b.subarray(0, -1))).toThrow(/outside/);
  });
  it("identifies GB's real processor and reports banked cartridge limits", () => {
    const b = Buffer.alloc(32768);
    b.write("TEST", 0x134);
    b[0x147] = 1;
    const r = parse("gameboy", b);
    expect(r.architecture).toBe("lr35902");
    expect(r.complete).toBe(false);
    expect(r.regions[1]?.loadAddress).toBeNull();
  });
  it("retains GBA header integrity and the ARM7 cartridge address", () => {
    const b = Buffer.alloc(0xc0);
    b[0xb2] = 0x96;
    let sum = 0x19;
    for (let i = 0xa0; i <= 0xbc; i++) sum += b[i]!;
    b[0xbd] = -sum & 255;
    const r = parse("gba", b);
    expect(r.entryPoint).toBe("0x8000000");
    expect(r.architecture).toBe("armv4t");
    expect(r.items[0]?.header_checksum_valid).toBe(true);
  });
});

describe("U-Boot images", () => {
  it("uses independently checked CRC vectors and validates both legacy checksums", () => {
    expect(crc32(Buffer.from("123456789"))).toBe(0xcbf43926);
    const good = uimage();
    expect(
      parse("uimage", good).regions[0]?.bytes.equals(Buffer.from([1, 2, 3])),
    ).toBe(true);
    good[64] = good[64]! ^ 1;
    expect(() => parse("uimage", good)).toThrow(/payload CRC/);
    const badHeader = uimage();
    badHeader[32] = badHeader[32]! ^ 1;
    expect(() => parse("uimage", badHeader)).toThrow(/header CRC/);
  });
  it("does not map compressed payload bytes as executable memory", () => {
    const r = parse("uimage", uimage(Buffer.from([1, 2, 3]), 1));
    expect(r.complete).toBe(false);
    expect(r.regions[0]?.loadAddress).toBeNull();
  });
  it("splits an uncompressed multi-image using aligned component sizes", () => {
    const r = parse(
      "uimage",
      uimage(
        Buffer.concat([cells(3, 2, 0), Buffer.from([1, 2, 3, 0, 4, 5])]),
        0,
        4,
      ),
    );
    expect(r.regions.map((x) => x.bytes.toString("hex"))).toEqual([
      "010203",
      "0405",
    ]);
  });
  it.each([false, true])(
    "decodes FIT payload/hash/configuration external=%s",
    (external) => {
      const data = Buffer.alloc(300, 7),
        r = parse("fit", fit(data, external));
      expect(r.regions[0]?.bytes.equals(data)).toBe(true);
      expect(r.regions[0]?.loadAddress).toBe("0x80000000");
      expect(r.entryPoint).toBeNull();
      expect(r.items.some((i) => i.kind === "fit-hash" && i.verified)).toBe(
        true,
      );
      expect(r.items.some((i) => i.kind === "fit-configuration")).toBe(true);
    },
  );
  it("refuses a FIT external payload outside the supplied file", () =>
    expect(() =>
      parse("fit", fit(Buffer.alloc(300), true).subarray(0, -1)),
    ).toThrow(/outside/));
});

describe("CMSIS-SVD hardware metadata", () => {
  const source = `<device schemaVersion="1.3"><name>Fixture</name><addressUnitBits>8</addressUnitBits><width>32</width><size>32</size><access>read-write</access><cpu><name>CM4</name></cpu><peripherals><peripheral><name>GPIO</name><baseAddress>0x40000000</baseAddress><registers><cluster><name>PORT</name><addressOffset>0x20</addressOffset><register><name>DATA%s</name><dim>2</dim><dimIncrement>4</dimIncrement><addressOffset>0x8</addressOffset><fields><field><name>ENABLE</name><bitRange>[3:2]</bitRange></field></fields></register></cluster></registers></peripheral></peripherals></device>`;
  it("expands register arrays under clusters with inherited widths and field bits", () => {
    const r = parse("svd", source),
      registers = r.items.filter((i) => i.kind === "svd-register");
    expect(r.architecture).toBe("cortex-m");
    expect(registers.map((i) => i.address)).toEqual([
      "0x40000028",
      "0x4000002c",
    ]);
    expect(registers[0]?.size_bits).toBe("32");
    expect(registers[0]?.fields).toEqual([
      {
        name: "ENABLE",
        bit_offset: "2",
        bit_width: "2",
        access: "read-write",
        description: null,
      },
    ]);
  });
  it("does not invent derived registers and rejects DTDs/oversized arrays", () => {
    expect(
      parse(
        "svd",
        source.replace("<register>", '<register derivedFrom="OTHER">'),
      ).complete,
    ).toBe(false);
    expect(() =>
      parse("svd", '<!DOCTYPE device [<!ENTITY x "payload">]>' + source),
    ).toThrow(/types are unsupported/);
    expect(() =>
      parse("svd", source.replace("<dim>2</dim>", "<dim>99999</dim>")),
    ).toThrow(/max_items/);
  });
});
