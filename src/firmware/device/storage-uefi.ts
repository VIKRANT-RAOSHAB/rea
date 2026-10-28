import type { JsonValue } from "../../domain/jsonValue.js";
import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { DeviceParseFailure } from "./types.js";

type MutableResult = {
  -readonly [K in keyof DeviceParseResult]: DeviceParseResult[K];
};

const FFS_GUIDS = new Set([
  "7a9354d9-0468-444a-81ce-0bf617d890df",
  "8c8ce578-8a3d-4f1c-9935-896185c32dd3",
  "5473c07a-3dcb-4dca-bd6f-1e9689e7349a",
]);
const align = (value: number, boundary: number): number =>
  Math.ceil(value / boundary) * boundary;
const u24 = (b: Buffer, o: number): number => b.readUIntLE(o, 3);
const sum8 = (b: Buffer): number => {
  let sum = 0;
  for (const byte of b) sum = (sum + byte) & 255;
  return sum;
};
const sum16 = (b: Buffer): number => {
  let sum = 0;
  for (let i = 0; i < b.length; i += 2) sum = (sum + b.readUInt16LE(i)) & 65535;
  return sum;
};
const guid = (b: Buffer, o: number): string =>
  `${b.readUInt32LE(o).toString(16).padStart(8, "0")}-${b
    .readUInt16LE(o + 4)
    .toString(16)
    .padStart(4, "0")}-${b
    .readUInt16LE(o + 6)
    .toString(16)
    .padStart(
      4,
      "0",
    )}-${b.subarray(o + 8, o + 10).toString("hex")}-${b.subarray(o + 10, o + 16).toString("hex")}`;

/** PI FV/FFS/section structure over original image offsets. */
export const parseUefi = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  const result: MutableResult = {
    format: "uefi",
    version: null,
    architecture: null,
    entryPoint: null,
    regions: [],
    items: [],
    warnings: [],
    complete: true,
    limitations: [
      "Static PI firmware-volume, FFS and section inspection; no device update or firmware execution.",
      "GUID-defined processing, Tiano/LZMA compression, authenticated capsule signatures and vendor-specific wrappers are not decoded or authenticated.",
      "Extracted PE/TE sections retain file provenance; their runtime load addresses and platform applicability remain unknown.",
    ],
  };
  const add = (item: Record<string, JsonValue>): void => {
    if (result.items.length + result.regions.length >= options.maxItems)
      throw new DeviceParseFailure(
        "limit",
        "UEFI item/region count exceeds maxItems",
      );
    result.items.push(item);
  };
  const warn = (message: string): void => {
    result.warnings.push(message);
    result.complete = false;
  };
  const requireRange = (
    start: number,
    size: number,
    end = bytes.length,
  ): void => {
    if (
      !Number.isSafeInteger(size) ||
      size < 0 ||
      start < 0 ||
      start > end - size
    )
      throw new DeviceParseFailure(
        "format",
        `UEFI range outside its container at file offset ${start}`,
      );
  };
  const region = (name: string, start: number, end: number): void => {
    if (result.items.length + result.regions.length >= options.maxItems)
      throw new DeviceParseFailure(
        "limit",
        "UEFI item/region count exceeds maxItems",
      );
    result.regions.push({
      name,
      fileOffset: start,
      loadAddress: null,
      bytes: bytes.subarray(start, end),
    });
  };
  const volumes = new Set<number>();

  const sections = (
    start: number,
    end: number,
    parent: string,
    depth: number,
  ): void => {
    if (depth > 32)
      throw new DeviceParseFailure(
        "limit",
        "UEFI nested section depth exceeds 32",
      );
    let off = start;
    while (off < end) {
      if (end - off < 4) {
        if (bytes.subarray(off, end).some((b) => b !== 0 && b !== 255))
          warn(`Unparsed section tail at ${off}`);
        return;
      }
      if (bytes.subarray(off, end).every((b) => b === 255)) return;
      let size = u24(bytes, off);
      const type = bytes[off + 3] ?? 0;
      let header = 4;
      if (size === 0xffffff) {
        requireRange(off, 8, end);
        size = bytes.readUInt32LE(off + 4);
        header = 8;
      }
      if (size < header)
        throw new DeviceParseFailure(
          "format",
          `Invalid UEFI section size at ${off}`,
        );
      requireRange(off, size, end);
      const body = off + header;
      const stop = off + size;
      const item: Record<string, JsonValue> = {
        kind: "section",
        file_offset: off,
        file_bytes: size,
        header_bytes: header,
        section_type: type,
        parent,
      };
      if (type === 0x15)
        item.text = bytes
          .subarray(body, stop)
          .toString("utf16le")
          .replace(/\0+$/u, "");
      if (type === 0x14 && stop - body >= 2) {
        item.build_number = bytes.readUInt16LE(body);
        item.text = bytes
          .subarray(body + 2, stop)
          .toString("utf16le")
          .replace(/\0+$/u, "");
      }
      add(item);
      const identity = `${parent}/section-${off.toString(16)}`;
      if (type === 0x10 || type === 0x12 || type === 0x19 || type === 0x18) {
        const skip = type === 0x18 ? 16 : 0;
        requireRange(body, skip, stop);
        if (skip !== 0) item.subtype_guid = guid(bytes, body);
        region(
          `${identity}.${type === 0x10 ? "pe" : type === 0x12 ? "te" : "bin"}`,
          body + skip,
          stop,
        );
      } else if (type === 0x01) {
        requireRange(body, 5, stop);
        const decodedBytes = bytes.readUInt32LE(body);
        const compression = bytes[body + 4] ?? 0;
        item.uncompressed_bytes = decodedBytes;
        item.compression_type = compression;
        if (compression === 0) {
          if (stop - body - 5 !== decodedBytes)
            throw new DeviceParseFailure(
              "format",
              `UEFI uncompressed section length mismatch at ${off}`,
            );
          sections(body + 5, stop, identity, depth + 1);
        } else {
          warn(
            `Compressed section at ${off} requires an external decoder (type ${compression})`,
          );
          region(`${identity}.compressed`, body + 5, stop);
        }
      } else if (type === 0x02) {
        requireRange(body, 20, stop);
        const dataOffset = bytes.readUInt16LE(body + 16);
        const attributes = bytes.readUInt16LE(body + 18);
        item.definition_guid = guid(bytes, body);
        item.attributes = attributes;
        item.data_offset = dataOffset;
        if (dataOffset < header + 20 || dataOffset > size)
          throw new DeviceParseFailure(
            "format",
            `Invalid GUID-defined UEFI data offset at ${off}`,
          );
        if ((attributes & 1) !== 0) {
          warn(
            `GUID-defined processing required at ${off}: ${String(item.definition_guid)}`,
          );
          region(`${identity}.guid-data`, off + dataOffset, stop);
        } else sections(off + dataOffset, stop, identity, depth + 1);
      } else if (type === 0x03) sections(body, stop, identity, depth + 1);
      else if (type === 0x17) volume(body, stop, depth + 1);
      // Dependency expressions and version/UI fields are inventory data, not native code.
      else if (![0x11, 0x13, 0x14, 0x15, 0x16, 0x1b, 0x1c].includes(type))
        warn(`Unknown UEFI section type ${type} at ${off}`);
      off = start + align(stop - start, 4);
    }
  };

  const volume = (start: number, containerEnd: number, depth: number): void => {
    if (volumes.has(start)) return;
    if (depth > 32)
      throw new DeviceParseFailure("limit", "UEFI nested FV depth exceeds 32");
    requireRange(start, 56, containerEnd);
    if (bytes.toString("ascii", start + 40, start + 44) !== "_FVH")
      throw new DeviceParseFailure(
        "format",
        `Missing UEFI FV signature at ${start}`,
      );
    const lengthBig = bytes.readBigUInt64LE(start + 32);
    if (lengthBig > BigInt(Number.MAX_SAFE_INTEGER))
      throw new DeviceParseFailure(
        "format",
        "UEFI FV length exceeds safe integer range",
      );
    const length = Number(lengthBig);
    const headerBytes = bytes.readUInt16LE(start + 48);
    if (
      length < 56 ||
      headerBytes < 64 ||
      headerBytes % 2 !== 0 ||
      headerBytes > length
    )
      throw new DeviceParseFailure(
        "format",
        `Invalid UEFI FV/header length at ${start}`,
      );
    requireRange(start, length, containerEnd);
    const stop = start + length;
    const checksumOk = sum16(bytes.subarray(start, start + headerBytes)) === 0;
    const fsGuid = guid(bytes, start + 16);
    const attributes = bytes.readUInt32LE(start + 44);
    const revision = bytes[start + 55] ?? 0;
    const extOffset = bytes.readUInt16LE(start + 52);
    const map: JsonValue[] = [];
    let mappedBytes = 0;
    let terminated = false;
    for (let o = start + 56; o + 8 <= start + headerBytes; o += 8) {
      const count = bytes.readUInt32LE(o);
      const blockBytes = bytes.readUInt32LE(o + 4);
      if (count === 0 && blockBytes === 0) {
        terminated = true;
        break;
      }
      if (count === 0 || blockBytes === 0)
        throw new DeviceParseFailure(
          "format",
          `Invalid UEFI FV block map at ${o}`,
        );
      mappedBytes += count * blockBytes;
      if (!Number.isSafeInteger(mappedBytes))
        throw new DeviceParseFailure(
          "format",
          "UEFI FV block map size overflow",
        );
      map.push({ blocks: count, block_bytes: blockBytes });
    }
    if (!terminated || mappedBytes !== length)
      throw new DeviceParseFailure(
        "format",
        `UEFI FV block map does not match its declared length at ${start}`,
      );
    const item: Record<string, JsonValue> = {
      kind: "firmware-volume",
      file_offset: start,
      file_bytes: length,
      header_bytes: headerBytes,
      filesystem_guid: fsGuid,
      attributes,
      revision,
      checksum_valid: checksumOk,
      block_map: map,
    };
    let filesStart = headerBytes;
    if (extOffset !== 0) {
      requireRange(start + extOffset, 20, stop);
      const extSize = bytes.readUInt32LE(start + extOffset + 16);
      if (extSize < 20)
        throw new DeviceParseFailure(
          "format",
          `Invalid UEFI FV extension length at ${start + extOffset}`,
        );
      requireRange(start + extOffset, extSize, stop);
      item.volume_guid = guid(bytes, start + extOffset);
      filesStart = Math.max(filesStart, extOffset + extSize);
    }
    add(item);
    volumes.add(start);
    if (!checksumOk) {
      warn(
        `UEFI FV header checksum mismatch at ${start}; files were not interpreted`,
      );
      return;
    }
    if (revision !== 2 || !FFS_GUIDS.has(fsGuid)) {
      warn(`Unsupported UEFI FV revision/filesystem at ${start}`);
      return;
    }
    result.version = "PI FV revision 2 / FFS";
    let off = start + align(filesStart, 8);
    const erased = (attributes & 0x800) !== 0 ? 255 : 0;
    while (off + 24 <= stop) {
      if (bytes.subarray(off, off + 24).every((b) => b === erased)) break;
      const name = guid(bytes, off);
      const type = bytes[off + 18] ?? 0;
      const attrs = bytes[off + 19] ?? 0;
      let size = u24(bytes, off + 20);
      let fileHeader = 24;
      if ((attrs & 1) !== 0) {
        requireRange(off, 32, stop);
        if (size !== 0)
          throw new DeviceParseFailure(
            "format",
            `FFS large-file header requires Size=0 at ${off}`,
          );
        const large = bytes.readBigUInt64LE(off + 24);
        if (large > BigInt(Number.MAX_SAFE_INTEGER))
          throw new DeviceParseFailure(
            "format",
            "FFS large-file size exceeds safe integer range",
          );
        size = Number(large);
        fileHeader = 32;
      }
      if (size < fileHeader)
        throw new DeviceParseFailure(
          "format",
          `Invalid UEFI FFS file length at ${off}`,
        );
      requireRange(off, size, stop);
      const stateByte = bytes[off + 23] ?? 0;
      const logicalState = erased === 255 ? ~stateByte & 255 : stateByte;
      const state =
        logicalState === 0 ? 0 : 2 ** Math.floor(Math.log2(logicalState));
      const headerSum =
        (sum8(bytes.subarray(off, off + fileHeader)) -
          (bytes[off + 17] ?? 0) -
          stateByte) &
        255;
      const headerValid = headerSum === 0;
      const dataValid =
        (attrs & 0x40) !== 0
          ? ((sum8(bytes.subarray(off + fileHeader, off + size)) +
              (bytes[off + 17] ?? 0)) &
              255) ===
            0
          : bytes[off + 17] === 0xaa;
      add({
        kind: "ffs-file",
        file_offset: off,
        file_bytes: size,
        header_bytes: fileHeader,
        guid: name,
        file_type: type,
        attributes: attrs,
        raw_state: stateByte,
        effective_state: state,
        header_checksum_valid: headerValid,
        data_checksum_valid: dataValid,
      });
      if (state === 4 && headerValid && dataValid) {
        if (type === 1)
          region(
            `${name}-${off.toString(16)}.raw`,
            off + fileHeader,
            off + size,
          );
        else if (type !== 0xf0)
          sections(
            off + fileHeader,
            off + size,
            `${name}-${off.toString(16)}`,
            depth + 1,
          );
      } else if (state === 4)
        warn(`FFS checksum mismatch at ${off}; payload was not interpreted`);
      else if (![0, 8, 16, 32].includes(state))
        warn(`Non-data-valid FFS state ${state} at ${off}`);
      off = start + align(off + size - start, 8);
    }
  };

  if (bytes.length >= 28) {
    const headerSize = bytes.readUInt32LE(16);
    const flags = bytes.readUInt32LE(20);
    const imageSize = bytes.readUInt32LE(24);
    if (
      headerSize >= 28 &&
      headerSize <= imageSize &&
      imageSize === bytes.length &&
      (flags & ~0x70000) === 0 &&
      bytes.subarray(0, 16).some((b) => b !== 0 && b !== 255)
    ) {
      add({
        kind: "capsule",
        guid: guid(bytes, 0),
        header_bytes: headerSize,
        file_bytes: imageSize,
        flags,
        signature_verified: false,
      });
    }
  }
  // Scan candidate FV boundaries in a caller-selected image; only structurally valid FVs become containers.
  let search = 0;
  while (search < bytes.length) {
    const signature = bytes.indexOf("_FVH", search, "ascii");
    if (signature < 0) break;
    search = signature + 4;
    const start = signature - 40;
    if (start < 0 || volumes.has(start)) continue;
    volume(start, bytes.length, 0);
  }
  if (volumes.size === 0) {
    if (result.items.some((item) => item.kind === "capsule")) {
      const start = bytes.readUInt32LE(16);
      region("capsule-payload.bin", start, bytes.length);
      warn(
        "Capsule payload contains no supported FV; vendor/FMP payload structure remains opaque",
      );
    } else
      throw new DeviceParseFailure(
        "format",
        "No structurally valid UEFI firmware volume or capsule found",
      );
  }
  return result;
};
