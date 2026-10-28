import { createHash } from "node:crypto";
import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { ascii, count, fail, hex, result, span } from "./loaders-common.js";

/** esptool E9 image profile; the caller explicitly selects ESP32 or ESP8266. */
export const parseEspImage = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format),
    extended = o.format === "esp32";
  span(bytes, 0, extended ? 24 : 8);
  if (bytes[0] !== 0xe9) fail("Espressif E9 image magic mismatch");
  const segments = bytes[1]!;
  if (!segments || segments > 16)
    fail("Espressif image segment count is invalid");
  count(segments + 1, o);
  r.entryPoint = hex(bytes.readUInt32LE(4));
  r.version = extended ? "ESP32 E9 extended header" : "ESP8266 E9";
  const chip = extended ? bytes.readUInt16LE(12) : null;
  const architectures: Record<number, string> = {
    0: "xtensa",
    2: "xtensa",
    5: "riscv32",
    9: "xtensa",
    12: "riscv32",
    13: "riscv32",
    16: "riscv32",
    18: "riscv32",
  };
  r.architecture = extended ? (architectures[chip!] ?? null) : "xtensa";
  const hasHash = extended ? bytes[23]! : 0;
  if (hasHash !== 0 && hasHash !== 1)
    fail("Invalid Espressif hash-appended flag");
  r.items.push({
    kind: "image-header",
    chip_id: chip,
    spi_mode: bytes[2]!,
    spi_config: bytes[3]!,
    segment_count: segments,
    entry_point: r.entryPoint,
    hash_appended: hasHash === 1,
  });
  let cursor = extended ? 24 : 8,
    checksum = 0xef;
  for (let i = 0; i < segments; i++) {
    span(bytes, cursor, 8);
    const address = bytes.readUInt32LE(cursor),
      size = bytes.readUInt32LE(cursor + 4),
      start = cursor + 8;
    const data = span(bytes, start, size);
    if (address + size > 0x100000000)
      fail("Espressif segment address overflows");
    for (const b of data) checksum ^= b;
    r.regions.push({
      name: `segment-${i}`,
      fileOffset: start,
      loadAddress: hex(address),
      bytes: data,
    });
    r.items.push({
      kind: "segment",
      index: i,
      file_offset: start,
      load_address: hex(address),
      bytes: size,
    });
    cursor = start + size;
  }
  const checksumAt = Math.ceil((cursor + 1) / 16) * 16 - 1;
  span(bytes, cursor, checksumAt + 1 - cursor);
  if (bytes.subarray(cursor, checksumAt).some((b) => b !== 0))
    fail("Espressif checksum padding is not zero");
  if (bytes[checksumAt] !== checksum)
    fail("Espressif image XOR checksum mismatch");
  cursor = checksumAt + 1;
  r.items.push({
    kind: "image-integrity",
    checksum_offset: checksumAt,
    xor_checksum_valid: true,
  });
  if (hasHash) {
    const digest = span(bytes, cursor, 32),
      actual = createHash("sha256").update(bytes.subarray(0, cursor)).digest();
    if (!digest.equals(actual)) fail("Espressif appended SHA-256 mismatch");
    r.items.push({
      kind: "image-sha256",
      file_offset: cursor,
      sha256: digest.toString("hex"),
      valid: true,
    });
    cursor += 32;
  }
  if (cursor !== bytes.length) {
    r.complete = false;
    r.warnings.push(
      "Trailing bytes may be secure-boot signatures, padding or another image; they are not interpreted",
    );
    r.items.push({
      kind: "trailing-data",
      file_offset: cursor,
      bytes: bytes.length - cursor,
    });
  }
  r.limitations.push(
    "Image integrity checks do not authenticate its publisher. Secure-boot signatures, encryption, merged flash dumps and ROM bootloader behavior are not reconstructed. Segment byte order is not evidence of a particular device board.",
  );
  return r;
};

/** A standalone binary partition-table sector, not an implicitly located flash dump. */
export const parseEspPartitions = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format);
  r.version = "ESP-IDF binary partition table";
  if (bytes.length < 32 || bytes.length % 32)
    fail("Espressif partition table requires complete 32-byte records");
  let entries = 0,
    ended = false,
    hashSeen = false;
  const ranges: { start: number; end: number }[] = [];
  for (let cursor = 0; cursor < bytes.length; cursor += 32) {
    const b = bytes.subarray(cursor, cursor + 32);
    if (b.every((x) => x === 255)) {
      ended = true;
      continue;
    }
    if (ended) fail("Non-erased data follows partition table terminator");
    const magic = b.readUInt16LE(0);
    if (magic === 0xebeb) {
      if (hashSeen || b.subarray(2, 16).some((x) => x !== 255))
        fail("Invalid partition MD5 marker");
      const actual = createHash("md5")
        .update(bytes.subarray(0, cursor))
        .digest();
      if (!b.subarray(16).equals(actual))
        fail("Espressif partition-table MD5 mismatch");
      count(r.items.length + 1, o);
      r.items.push({
        kind: "table-md5",
        file_offset: cursor,
        md5: actual.toString("hex"),
        valid: true,
      });
      hashSeen = true;
      ended = true;
      continue;
    }
    if (magic !== 0x50aa || hashSeen)
      fail("Invalid Espressif partition entry magic/order");
    if (++entries > 95) fail("Espressif partition table exceeds 95 entries");
    count(r.items.length + 1, o);
    const start = b.readUInt32LE(4),
      size = b.readUInt32LE(8);
    if (!size || start + size > 0x100000000 || start % 4096)
      fail("Invalid Espressif partition address, alignment or size");
    if (ranges.some((x) => start < x.end && x.start < start + size))
      fail("Overlapping Espressif partitions");
    ranges.push({ start, end: start + size });
    r.items.push({
      kind: "partition",
      file_offset: cursor,
      type: b[2]!,
      subtype: b[3]!,
      flash_offset: hex(start),
      bytes: size,
      label: ascii(b.subarray(12, 28)),
      flags: b.readUInt32LE(28),
    });
  }
  if (!entries) fail("Espressif table has no partition entries");
  if (!hashSeen) r.warnings.push("Partition table has no MD5 record");
  r.limitations.push(
    "Partition offsets are declarations in a separately supplied flash address space. A standalone table does not contain its partitions, select an OTA image, establish encryption keys, or identify processor ISA.",
  );
  return r;
};
