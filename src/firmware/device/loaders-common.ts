import type {
  DeviceParseOptions,
  DeviceParseResult,
  DeviceRegion,
} from "./types.js";
import { DeviceParseFailure } from "./types.js";

export function fail(message: string): never {
  throw new DeviceParseFailure("format", message);
}
export function unsupported(message: string): never {
  throw new DeviceParseFailure("unsupported", message);
}
export const count = (n: number, o: DeviceParseOptions): void => {
  if (n > o.maxItems)
    throw new DeviceParseFailure("limit", "Device structure exceeds max_items");
};
export const span = (b: Buffer, offset: number, size: number): Buffer => {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(size) ||
    offset < 0 ||
    size < 0 ||
    offset > b.length - size
  )
    fail("Device structure extends outside the supplied file");
  return b.subarray(offset, offset + size);
};
export const hex = (n: number | bigint): string => `0x${n.toString(16)}`;
type MutableResult = {
  -readonly [K in keyof DeviceParseResult]: DeviceParseResult[K];
};
export const result = (format: string): MutableResult => ({
  format,
  version: null,
  architecture: null,
  entryPoint: null,
  regions: [],
  items: [],
  limitations: [
    "Static file interpretation does not establish device behavior or execute target code.",
  ],
  warnings: [],
  complete: true,
});
export const ascii = (b: Buffer): string =>
  b.toString("ascii").replace(/\0.*$/s, "");
export const crc32 = (b: Buffer): number => {
  let value = 0xffffffff;
  for (const byte of b) {
    value ^= byte;
    for (let i = 0; i < 8; i++)
      value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
};

/** Merge adjacent records, retaining sparse gaps and rejecting ambiguous overlap. */
export const addressedRegions = (
  records: { address: number; bytes: Buffer }[],
  prefix: string,
): DeviceRegion[] => {
  records.sort((a, b) => a.address - b.address);
  const groups: { start: number; end: number; parts: Buffer[] }[] = [];
  for (const r of records) {
    if (r.address + r.bytes.length > 0x100000000)
      fail("Addressed record exceeds the 32-bit address space");
    if (!r.bytes.length) continue;
    const last = groups.at(-1);
    if (last && r.address < last.end)
      fail("Overlapping addressed records have ambiguous ownership");
    if (last && r.address === last.end) {
      last.parts.push(r.bytes);
      last.end += r.bytes.length;
    } else
      groups.push({
        start: r.address,
        end: r.address + r.bytes.length,
        parts: [r.bytes],
      });
  }
  return groups.map((g, i) => ({
    name: `${prefix}-${i}`,
    fileOffset: null,
    loadAddress: hex(g.start),
    bytes: Buffer.concat(g.parts),
  }));
};

export function* textLines(
  bytes: Buffer,
): Generator<{ text: string; offset: number }> {
  if (bytes.some((b) => b > 127))
    fail("Text firmware contains non-ASCII bytes");
  const source = bytes.toString("ascii");
  let offset = 0;
  for (const match of source.matchAll(/[^\r\n]*(?:\r\n|\r|\n|$)/g)) {
    const raw = match[0];
    if (!raw.length) break;
    const text = raw.replace(/[\r\n]+$/, "");
    if (text.trim().length) yield { text: text.trim(), offset };
    offset += raw.length;
  }
}
