import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import {
  ascii,
  count,
  crc32,
  fail,
  hex,
  result,
  span,
} from "./loaders-common.js";

const multiPayload = (
  data: Buffer,
  r: ReturnType<typeof result>,
  o: DeviceParseOptions,
): void => {
  const sizes: number[] = [];
  let cursor = 0;
  for (;;) {
    span(data, cursor, 4);
    const n = data.readUInt32BE(cursor);
    cursor += 4;
    if (!n) break;
    count(sizes.length + 2, o);
    sizes.push(n);
  }
  for (let i = 0; i < sizes.length; i++) {
    const n = sizes[i]!,
      payload = span(data, cursor, n);
    r.regions.push({
      name: `component-${i}`,
      fileOffset: 64 + cursor,
      loadAddress: null,
      bytes: payload,
    });
    r.items.push({
      kind: "multi-component",
      index: i,
      file_offset: 64 + cursor,
      bytes: n,
    });
    cursor += i === sizes.length - 1 ? n : Math.ceil(n / 4) * 4;
  }
  if (cursor !== data.length) {
    r.complete = false;
    r.warnings.push(
      "Trailing bytes inside legacy multi-image payload are not interpreted",
    );
  }
};

export const parseUimage = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format);
  span(bytes, 0, 64);
  if (bytes.readUInt32BE(0) !== 0x27051956)
    fail("U-Boot legacy image magic mismatch");
  const header = Buffer.from(bytes.subarray(0, 64)),
    expectedHeaderCrc = header.readUInt32BE(4);
  header.writeUInt32BE(0, 4);
  if (crc32(header) !== expectedHeaderCrc)
    fail("U-Boot image header CRC mismatch");
  const size = bytes.readUInt32BE(12),
    data = span(bytes, 64, size),
    compression = bytes[31]!,
    type = bytes[30]!;
  if (crc32(data) !== bytes.readUInt32BE(24))
    fail("U-Boot image payload CRC mismatch");
  const arch: Record<number, string> = {
    2: "arm",
    3: "x86",
    5: "mips",
    6: "mips64",
    7: "powerpc",
    12: "m68k",
    22: "arm64",
    24: "x86_64",
    25: "xtensa",
    26: "riscv",
  };
  r.version = "U-Boot legacy uImage";
  r.architecture = arch[bytes[29]!] ?? null;
  r.entryPoint = hex(bytes.readUInt32BE(20));
  count(1, o);
  r.items.push({
    kind: "legacy-header",
    name: ascii(bytes.subarray(32, 64)),
    timestamp: bytes.readUInt32BE(8),
    os: bytes[28]!,
    architecture_id: bytes[29]!,
    type,
    compression,
    load_address: hex(bytes.readUInt32BE(16)),
    entry_point: r.entryPoint,
    header_crc_valid: true,
    data_crc_valid: true,
  });
  if (type === 4 && compression === 0) {
    multiPayload(data, r, o);
  } else {
    r.regions.push({
      name: compression === 0 ? "payload" : "compressed-payload",
      fileOffset: 64,
      loadAddress: compression === 0 ? hex(bytes.readUInt32BE(16)) : null,
      bytes: data,
    });
    if (compression !== 0) {
      r.complete = false;
      r.limitations.push(
        "Compressed legacy payload is preserved without decompression; its stored bytes must not be mapped as executable code.",
      );
    }
  }
  if (64 + size !== bytes.length) {
    r.complete = false;
    r.warnings.push(
      "Trailing bytes after the declared legacy image are not interpreted",
    );
  }
  r.limitations.push(
    "CRC checks detect corruption, not publisher authenticity. Header architecture declarations do not select endian, ABI, or every processor variant.",
  );
  return r;
};
