import { describe, expect, it } from "vitest";
import { parseDeviceStorage } from "./storage.js";

// Source-owned fixture construction follows PI 1.8 FV/FFS and littlefs SPEC.md.
const fvGuid = Buffer.from("78e58c8c3d8a1c4f9935896185c32dd3", "hex");
const guid = Buffer.from("443322116655887799aabbccddeeff00", "hex");
const section = (type: number, payload: Buffer): Buffer => {
  const b = Buffer.alloc(4 + payload.length);
  b.writeUIntLE(b.length, 0, 3);
  b[3] = type;
  payload.copy(b, 4);
  return b;
};
const fv = (
  payload = section(0x10, Buffer.from("MZfixture")),
  type = 7,
): Buffer => {
  const b = Buffer.alloc(512, 255);
  b.fill(0, 0, 72);
  fvGuid.copy(b, 16);
  b.writeBigUInt64LE(512n, 32);
  b.write("_FVH", 40, "ascii");
  b.writeUInt32LE(0x800, 44);
  b.writeUInt16LE(72, 48);
  b[55] = 2;
  b.writeUInt32LE(1, 56);
  b.writeUInt32LE(512, 60);
  let checksum = 0;
  for (let o = 0; o < 72; o += 2)
    checksum = (checksum + b.readUInt16LE(o)) & 65535;
  b.writeUInt16LE(-checksum & 65535, 50);
  const f = 72;
  b.fill(0, f, f + 24);
  guid.copy(b, f);
  b[f + 17] = 0xaa;
  b[f + 18] = type;
  b[f + 23] = 0xf8;
  b.writeUIntLE(24 + payload.length, f + 20, 3);
  payload.copy(b, f + 24);
  let headerSum = 0;
  for (let i = 0; i < 24; i++)
    if (i !== 17 && i !== 23) headerSum += b[f + i] ?? 0;
  b[f + 16] = -headerSum & 255;
  return b;
};
const crc = (b: Buffer, initial = 0xffffffff): number => {
  let c = initial;
  for (const v of b) {
    c ^= v;
    for (let i = 0; i < 8; i++)
      c = (c >>> 1) ^ ((c & 1) !== 0 ? 0xedb88320 : 0);
  }
  return c >>> 0;
};
interface Tag {
  type: number;
  id: number;
  data: Buffer;
  deleted?: boolean;
}
const metadata = (
  revision: number,
  commits: Tag[][],
  blockSize = 256,
): Buffer => {
  const b = Buffer.alloc(blockSize, 255);
  b.writeUInt32LE(revision, 0);
  let off = 4;
  let previous = 0xffffffff;
  let checksum = crc(b.subarray(0, 4));
  for (const entries of commits) {
    for (const entry of entries) {
      const tag =
        ((entry.type << 20) |
          (entry.id << 10) |
          (entry.deleted === true ? 0x3ff : entry.data.length)) >>>
        0;
      b.writeUInt32BE((tag ^ previous) >>> 0, off);
      entry.data.copy(b, off + 4);
      checksum = crc(b.subarray(off, off + 4 + entry.data.length), checksum);
      previous = tag;
      off += 4 + entry.data.length;
    }
    const ctag = ((0x500 << 20) | (0x3ff << 10) | 4) >>> 0;
    b.writeUInt32BE((ctag ^ previous) >>> 0, off);
    checksum = crc(b.subarray(off, off + 4), checksum);
    b.writeUInt32LE(checksum, off + 4);
    off += 8;
    checksum = 0xffffffff;
    previous = ctag;
  }
  return b;
};
const wordPair = (a: number, b: number): Buffer => {
  const out = Buffer.alloc(8);
  out.writeUInt32LE(a, 0);
  out.writeUInt32LE(b, 4);
  return out;
};
const superTags = (count = 8): Tag[] => {
  const b = Buffer.alloc(24);
  b.writeUInt32LE(0x20001, 0);
  b.writeUInt32LE(256, 4);
  b.writeUInt32LE(count, 8);
  b.writeUInt32LE(255, 12);
  b.writeUInt32LE(0x7fffffff, 16);
  b.writeUInt32LE(1022, 20);
  return [
    { type: 0xff, id: 0, data: Buffer.from("littlefs") },
    { type: 0x201, id: 0, data: b },
  ];
};
const fileTags = (id: number, name: string, contents: string): Tag[] => [
  { type: 1, id, data: Buffer.from(name) },
  { type: 0x201, id, data: Buffer.from(contents) },
];
const image = (): Buffer => {
  const b = Buffer.alloc(8 * 256, 255);
  metadata(5, [
    [...superTags(), ...fileTags(1, "hello.txt", "old")],
    [{ type: 0x201, id: 1, data: Buffer.from("hello") }],
  ]).copy(b, 0);
  metadata(4, [[...superTags(), ...fileTags(1, "hello.txt", "stale")]]).copy(
    b,
    256,
  );
  return b;
};
const parseLfs = (b: Buffer, extra = {}) =>
  parseDeviceStorage(b, {
    format: "littlefs",
    maxItems: 1000,
    blockSize: 256,
    ...extra,
  });

describe("UEFI PI storage", () => {
  it("inventories verified FV and FFS headers and extracts original PE section bytes", () => {
    const r = parseDeviceStorage(fv(), { format: "uefi", maxItems: 100 });
    expect(r.complete).toBe(true);
    expect(r.items.map((i) => i.kind)).toEqual([
      "firmware-volume",
      "ffs-file",
      "section",
    ]);
    expect(r.items[0]).toMatchObject({ checksum_valid: true, file_bytes: 512 });
    expect(r.items[1]).toMatchObject({
      header_checksum_valid: true,
      data_checksum_valid: true,
      effective_state: 4,
    });
    expect(r.regions[0]?.fileOffset).toBe(100);
    expect(r.regions[0]?.bytes.toString()).toBe("MZfixture");
  });
  it("preserves capsule-relative payload offsets", () => {
    const capsule = Buffer.alloc(540);
    guid.copy(capsule);
    capsule.writeUInt32LE(28, 16);
    capsule.writeUInt32LE(540, 24);
    fv().copy(capsule, 28);
    const r = parseDeviceStorage(capsule, { format: "uefi", maxItems: 100 });
    expect(r.items[0]).toMatchObject({
      kind: "capsule",
      header_bytes: 28,
      signature_verified: false,
    });
    expect(r.regions[0]?.fileOffset).toBe(128);
  });
  it("withholds contents after checksum failures", () => {
    const b = fv();
    b[72] = (b[72] ?? 0) ^ 1;
    const r = parseDeviceStorage(b, { format: "uefi", maxItems: 100 });
    expect(r.complete).toBe(false);
    expect(r.regions).toEqual([]);
    expect(r.warnings.join()).toContain("checksum mismatch");
  });
  it("marks compressed sections opaque, and decodes explicit uncompressed sections", () => {
    const nested = section(0x10, Buffer.from("MZnested"));
    const header = Buffer.alloc(5);
    header.writeUInt32LE(nested.length);
    const clear = parseDeviceStorage(
      fv(section(1, Buffer.concat([header, nested]))),
      { format: "uefi", maxItems: 100 },
    );
    expect(clear.complete).toBe(true);
    expect(clear.regions[0]?.bytes.toString()).toBe("MZnested");
    header[4] = 1;
    const opaque = parseDeviceStorage(
      fv(section(1, Buffer.concat([header, nested]))),
      { format: "uefi", maxItems: 100 },
    );
    expect(opaque.complete).toBe(false);
    expect(opaque.items.find((i) => i.compression_type === 1)).toBeDefined();
  });
  it("rejects truncated FV, malformed section extents, unknown inputs, and exhausted budgets", () => {
    expect(() =>
      parseDeviceStorage(fv().subarray(0, 500), {
        format: "uefi",
        maxItems: 100,
      }),
    ).toThrow("range outside");
    const bad = fv();
    bad.writeUIntLE(500, 96, 3);
    expect(() =>
      parseDeviceStorage(bad, { format: "uefi", maxItems: 100 }),
    ).toThrow("range outside");
    expect(() =>
      parseDeviceStorage(Buffer.alloc(64), { format: "uefi", maxItems: 100 }),
    ).toThrow("No structurally valid");
    expect(() =>
      parseDeviceStorage(fv(), { format: "uefi", maxItems: 1 }),
    ).toThrow("maxItems");
  });
});

describe("littlefs committed metadata", () => {
  it("chooses newest revision and only latest committed file data", () => {
    const r = parseLfs(image());
    expect(r.version).toBe("2.1");
    expect(r.complete).toBe(true);
    expect(r.items[0]).toMatchObject({
      selected_block: 0,
      revision: 5,
      valid_commits: 2,
    });
    expect(r.regions.map((i) => [i.name, i.bytes.toString()])).toEqual([
      ["hello.txt", "hello"],
    ]);
    expect(r.regions[0]?.fileOffset).not.toBeNull();
  });
  it("falls back to alternate valid revision and ignores uncommitted tails", () => {
    const b = image();
    b[10] = (b[10] ?? 0) ^ 1;
    const r = parseLfs(b);
    expect(r.items[0]).toMatchObject({ selected_block: 1, revision: 4 });
    expect(r.regions[0]?.bytes.toString()).toBe("stale");
    const appended = image();
    const selected = parseLfs(appended).items[0];
    const end = selected?.committed_end;
    if (typeof end !== "number") throw new Error("fixture missing commit end");
    appended.fill(0, end, end + 10);
    expect(parseLfs(appended).regions[0]?.bytes.toString()).toBe("hello");
  });
  it("handles revision wraparound and rejects both corrupt copies", () => {
    const b = image();
    metadata(0xffffffff, [[...superTags(), ...fileTags(1, "a", "old")]]).copy(
      b,
      0,
    );
    metadata(0, [[...superTags(), ...fileTags(1, "a", "new")]]).copy(b, 256);
    expect(parseLfs(b).regions[0]?.bytes.toString()).toBe("new");
    b.fill(255, 0, 512);
    expect(() => parseLfs(b)).toThrow("No CRC-valid");
  });
  it("applies create/delete ID shifts and traverses child directory pairs", () => {
    const b = image();
    const tags: Tag[] = [
      ...superTags(),
      ...fileTags(1, "remove", "gone"),
      ...fileTags(2, "keep", "retained"),
      { type: 0x4ff, id: 1, data: Buffer.alloc(0) },
      { type: 0x401, id: 1, data: Buffer.alloc(0) },
      { type: 2, id: 1, data: Buffer.from("dir") },
      { type: 0x200, id: 1, data: wordPair(2, 3) },
      { type: 0x600, id: 0x3ff, data: wordPair(2, 3) },
    ];
    metadata(8, [tags]).copy(b, 0);
    metadata(1, [[...fileTags(0, "child", "content")]]).copy(b, 512);
    const r = parseLfs(b);
    expect(r.regions.map((i) => [i.name, i.bytes.toString()])).toEqual([
      ["dir/child", "content"],
      ["keep", "retained"],
    ]);
  });
  it("reconstructs multi-block CTZ content and records discontiguous source extents", () => {
    const b = image();
    const content = Buffer.from(Array.from({ length: 600 }, (_, i) => i & 255));
    metadata(7, [
      [
        ...superTags(),
        { type: 1, id: 1, data: Buffer.from("large.bin") },
        { type: 0x202, id: 1, data: wordPair(6, 600) },
      ],
    ]).copy(b, 0);
    content.copy(b, 4 * 256, 0, 256);
    b.writeUInt32LE(4, 5 * 256);
    content.copy(b, 5 * 256 + 4, 256, 508);
    b.writeUInt32LE(5, 6 * 256);
    b.writeUInt32LE(4, 6 * 256 + 4);
    content.copy(b, 6 * 256 + 8, 508);
    const r = parseLfs(b);
    expect(r.regions[0]?.bytes.equals(content)).toBe(true);
    expect(r.regions[0]?.fileOffset).toBeNull();
    expect(r.items.find((i) => i.path === "large.bin")?.extents).toHaveLength(
      3,
    );
    b.writeUInt32LE(6, 6 * 256);
    expect(() => parseLfs(b)).toThrow("Cycle in littlefs CTZ");
  });
  it("does not extract a namespace with pending global move/orphan state", () => {
    const b = image();
    const pending = Buffer.alloc(12);
    pending[0] = 1;
    metadata(9, [
      [
        ...superTags(),
        ...fileTags(1, "a", "candidate"),
        { type: 0x7ff, id: 0x3ff, data: pending },
      ],
    ]).copy(b, 0);
    const r = parseLfs(b);
    expect(r.complete).toBe(false);
    expect(r.regions).toEqual([]);
    expect(r.warnings.join()).toContain("global move/orphan");
  });
  it("requires matching geometry and supported version instead of magic-string detection", () => {
    expect(() =>
      parseDeviceStorage(image(), { format: "littlefs", maxItems: 100 }),
    ).toThrow("explicit blockSize");
    expect(() => parseLfs(image().subarray(0, 2047))).toThrow("complete");
    expect(() => parseLfs(image(), { blockCount: 7 })).toThrow("disagrees");
    const b = image();
    const tags = superTags();
    tags[1]?.data.writeUInt32LE(0x30000);
    metadata(10, [tags]).copy(b, 0);
    expect(() => parseLfs(b)).toThrow("Unsupported littlefs");
    expect(() => parseLfs(image(), { maxItems: 1 })).toThrow("maxItems");
  });
});
