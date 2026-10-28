import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import {
  addressedRegions,
  count,
  fail,
  hex,
  result,
  textLines,
} from "./loaders-common.js";

export const parseIntelHex = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format),
    records: { address: number; bytes: Buffer }[] = [];
  let base = 0,
    ended = false;
  for (const line of textLines(bytes)) {
    count(r.items.length + 1, o);
    if (ended) fail("Intel HEX record follows EOF");
    if (!/^:[0-9a-f]+$/i.test(line.text) || line.text.length % 2 !== 1)
      fail("Invalid Intel HEX record syntax");
    const b = Buffer.from(line.text.slice(1), "hex");
    if (b.length < 5) fail("Intel HEX record is too short");
    const n = b[0]!;
    if (b.length !== n + 5)
      fail("Intel HEX byte count does not match record length");
    if (b.reduce((sum, x) => sum + x, 0) % 256 !== 0)
      fail("Intel HEX checksum mismatch");
    const address = b.readUInt16BE(1),
      type = b[3]!,
      data = b.subarray(4, 4 + n);
    r.items.push({
      kind: "record",
      file_offset: line.offset,
      record_type: type,
      address: hex(base + address),
      data_bytes: n,
      checksum_valid: true,
    });
    if (type === 0) records.push({ address: base + address, bytes: data });
    else if (type === 1) {
      if (n || address) fail("Invalid Intel HEX EOF");
      ended = true;
    } else if (type === 2 || type === 4) {
      if (n !== 2 || address) fail("Invalid Intel HEX extended address record");
      base = data.readUInt16BE(0) * (type === 2 ? 16 : 65536);
    } else if (type === 3 || type === 5) {
      if (n !== 4 || address) fail("Invalid Intel HEX start address record");
      const entry = hex(
        type === 3
          ? data.readUInt16BE(0) * 16 + data.readUInt16BE(2)
          : data.readUInt32BE(0),
      );
      if (r.entryPoint !== null && r.entryPoint !== entry)
        fail("Conflicting Intel HEX start address declarations");
      r.entryPoint = entry;
    } else fail(`Unsupported Intel HEX record type ${type}`);
  }
  if (!ended) fail("Intel HEX EOF record is missing");
  r.regions = addressedRegions(records, "hex");
  r.version = "Intel HEX";
  r.limitations.push(
    "Record addresses do not identify a CPU; gaps are not filled. Region bytes are derived from text records and have no contiguous source byte mapping.",
  );
  return r;
};

export const parseSRecord = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format),
    records: { address: number; bytes: Buffer }[] = [];
  let ended = false,
    dataCount = 0,
    declaredCount: number | null = null;
  const widths: Record<string, number> = {
    "0": 2,
    "1": 2,
    "2": 3,
    "3": 4,
    "5": 2,
    "6": 3,
    "7": 4,
    "8": 3,
    "9": 2,
  };
  for (const line of textLines(bytes)) {
    count(r.items.length + 1, o);
    if (ended) fail("S-record follows termination record");
    if (
      !/^S[012356789][0-9a-f]+$/i.test(line.text) ||
      line.text.length % 2 !== 0
    )
      fail("Invalid Motorola S-record syntax");
    const kind = line.text[1]!,
      width = widths[kind]!,
      b = Buffer.from(line.text.slice(2), "hex");
    if (b.length < width + 2 || b[0] !== b.length - 1)
      fail("S-record byte count mismatch");
    if (b.reduce((sum, x) => sum + x, 0) % 256 !== 255)
      fail("S-record checksum mismatch");
    const address = b.readUIntBE(1, width),
      data = b.subarray(width + 1, -1);
    r.items.push({
      kind: `S${kind}`,
      file_offset: line.offset,
      address: hex(address),
      data_bytes: data.length,
      checksum_valid: true,
    });
    if (["1", "2", "3"].includes(kind)) {
      records.push({ address, bytes: data });
      dataCount++;
    } else if (kind === "5" || kind === "6") {
      if (data.length || declaredCount !== null)
        fail("Invalid or repeated S-record count declaration");
      declaredCount = address;
    } else if (["7", "8", "9"].includes(kind)) {
      if (data.length) fail("Termination S-record contains data");
      r.entryPoint = hex(address);
      ended = true;
    }
  }
  if (!ended) fail("S-record termination record is missing");
  if (declaredCount !== null && declaredCount !== dataCount)
    fail("S-record declared data-record count mismatch");
  r.regions = addressedRegions(records, "srec");
  r.version = "Motorola S-record";
  r.limitations.push(
    "Addresses do not identify a CPU. Sparse gaps are preserved; reconstructed bytes have no contiguous source byte mapping.",
  );
  return r;
};

export const parseUf2 = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format);
  r.version = "UF2";
  if (!bytes.length || bytes.length % 512)
    fail("UF2 requires complete 512-byte blocks");
  count(bytes.length / 512, o);
  const families = new Map<
    string,
    {
      total: number;
      seen: Map<number, Buffer>;
      records: { address: number; bytes: Buffer }[];
    }
  >();
  for (let offset = 0; offset < bytes.length; offset += 512) {
    const b = bytes.subarray(offset, offset + 512);
    if (
      b.readUInt32LE(0) !== 0x0a324655 ||
      b.readUInt32LE(4) !== 0x9e5d5157 ||
      b.readUInt32LE(508) !== 0x0ab16f30
    )
      fail("UF2 magic mismatch");
    const flags = b.readUInt32LE(8),
      address = b.readUInt32LE(12),
      size = b.readUInt32LE(16),
      number = b.readUInt32LE(20),
      total = b.readUInt32LE(24),
      family = flags & 0x2000 ? hex(b.readUInt32LE(28)) : "unspecified";
    if (size > (flags & 0x4000 ? 452 : 476) || !total || number >= total)
      fail("UF2 block size or numbering is invalid");
    r.items.push({
      kind: "block",
      file_offset: offset,
      flags,
      target_address: hex(address),
      payload_bytes: size,
      block_number: number,
      block_count: total,
      family_id: family,
    });
    if ((flags & ~0xf001) !== 0) {
      r.complete = false;
      r.warnings.push(`UF2 block ${number} has unsupported flags`);
      continue;
    }
    if (flags & 0x1000) {
      r.complete = false;
      r.warnings.push(
        "UF2 file-container blocks are inventoried without reconstruction",
      );
      continue;
    }
    const group = families.get(family) ?? {
      total,
      seen: new Map<number, Buffer>(),
      records: [],
    };
    if (group.total !== total)
      fail("UF2 block count changes within one family");
    const old = group.seen.get(number);
    if (old) {
      if (!old.equals(b)) fail("Conflicting UF2 duplicate block");
      continue;
    }
    group.seen.set(number, b);
    families.set(family, group);
    if (flags & 1) continue;
    if (address % 4 || size % 4)
      fail("UF2 flash address and payload must be 4-byte aligned");
    group.records.push({ address, bytes: b.subarray(32, 32 + size) });
    if (flags & 0xc000) {
      r.complete = false;
      r.warnings.push(
        "UF2 optional MD5/extension tags are retained in source but not decoded or verified",
      );
    }
  }
  for (const [family, group] of families) {
    if (group.seen.size !== group.total) {
      r.complete = false;
      r.warnings.push(`UF2 family ${family} has missing numbered blocks`);
    }
    r.regions.push(...addressedRegions(group.records, `uf2-${family}`));
  }
  r.limitations.push(
    "Family IDs are declarations, not proof of a physical board. Different families remain separate; source block locations are recorded before address reconstruction.",
  );
  return r;
};
