import type { JsonValue } from "../../domain/jsonValue.js";
import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { DeviceParseFailure } from "./types.js";

type MutableResult = {
  -readonly [K in keyof DeviceParseResult]: DeviceParseResult[K];
};

interface Entry {
  type: number;
  id: number;
  size: number;
  offset: number;
  data: Buffer;
}
interface Metadata {
  block: number;
  revision: number;
  commits: number;
  entries: Entry[];
  end: number;
  discardedTail: boolean;
}
interface FileEntry {
  name?: Entry;
  struct?: Entry;
  attributes: Map<number, Entry>;
}
interface Directory {
  metadata: Metadata;
  files: Map<number, FileEntry>;
  tail: readonly [number, number] | null;
  split: boolean;
  state: Buffer | null;
}

/** littlefs CRC uses reflected CRC-32 without a final complement. */
const crc32 = (data: Buffer, initial = 0xffffffff): number => {
  let crc = initial;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc >>> 1) ^ ((crc & 1) === 0 ? 0 : 0xedb88320);
  }
  return crc >>> 0;
};
const trailingZeroes = (value: number): number =>
  31 - Math.clz32(value & -value);
const pairKey = (pair: readonly [number, number]): string =>
  [...pair].sort((a, b) => a - b).join(":");

/** Read-only littlefs v2 committed metadata and namespace reconstruction. */
export const parseLittlefs = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  const blockSize = options.blockSize;
  if (
    blockSize === undefined ||
    !Number.isSafeInteger(blockSize) ||
    blockSize < 128
  )
    throw new DeviceParseFailure(
      "format",
      "littlefs requires an explicit blockSize of at least 128 bytes",
    );
  if (bytes.length % blockSize !== 0 || bytes.length < blockSize * 2)
    throw new DeviceParseFailure(
      "format",
      "littlefs image must contain at least two complete selected-size blocks",
    );
  const availableBlocks = bytes.length / blockSize;
  const blockCount = options.blockCount ?? availableBlocks;
  if (
    !Number.isSafeInteger(blockCount) ||
    blockCount < 2 ||
    blockCount > availableBlocks
  )
    throw new DeviceParseFailure(
      "format",
      "littlefs blockCount must fit the supplied image",
    );
  const result: MutableResult = {
    format: "littlefs",
    version: null,
    architecture: null,
    entryPoint: null,
    regions: [],
    items: [],
    warnings: [],
    complete: true,
    limitations: [
      "Read-only littlefs v2.0/v2.1 inspection with caller-selected logical geometry; no mount, repair, write or target execution.",
      "Only CRC-committed metadata from the newest valid revision in each pair is used; uncommitted suffixes and alternate copies remain observations.",
      "Pending global move/orphan state is inventoried but not repaired; in that case extracted regions are withheld.",
      "Inline files retain an original file offset. CTZ reconstruction reports each physical extent; a multi-block derived payload has no single source offset.",
      "File-content integrity is not guaranteed by metadata CRCs; littlefs does not provide a checksum for ordinary file contents.",
    ],
  };
  let totalTags = 0;
  let decodedBytes = 0;
  const add = (item: Record<string, JsonValue>): void => {
    if (result.items.length + result.regions.length >= options.maxItems)
      throw new DeviceParseFailure(
        "limit",
        "littlefs item/region count exceeds maxItems",
      );
    result.items.push(item);
  };
  const warningSet = new Set<string>();
  const warn = (message: string): void => {
    if (!warningSet.has(message)) result.warnings.push(message);
    warningSet.add(message);
    result.complete = false;
  };
  const block = (id: number): Buffer => {
    if (!Number.isSafeInteger(id) || id < 0 || id >= blockCount)
      throw new DeviceParseFailure(
        "format",
        `littlefs block pointer ${id} is outside selected geometry`,
      );
    return bytes.subarray(id * blockSize, (id + 1) * blockSize);
  };
  const readMetadata = (id: number): Metadata | null => {
    const b = block(id);
    const revision = b.readUInt32LE(0);
    let crc = crc32(b.subarray(0, 4));
    let previous = 0xffffffff;
    let off = 4;
    let commits = 0;
    let committedEnd = 0;
    const entries: Entry[] = [];
    let committedCount = 0;
    let discardedTail = false;
    while (off + 4 <= blockSize) {
      const stored = b.readUInt32BE(off);
      const tag = (stored ^ previous) >>> 0;
      if ((tag & 0x80000000) !== 0 || tag === 0) {
        discardedTail = !b.subarray(off).every((v) => v === 255);
        break;
      }
      const type = (tag >>> 20) & 0x7ff;
      const entryId = (tag >>> 10) & 0x3ff;
      const size = tag & 0x3ff;
      const payloadSize = size === 0x3ff ? 0 : size;
      if (off + 4 + payloadSize > blockSize) {
        discardedTail = true;
        break;
      }
      crc = crc32(b.subarray(off, off + 4), crc);
      previous = tag;
      if ((type & 0x780) === 0x500) {
        if (payloadSize < 4 || b.readUInt32LE(off + 4) !== crc) {
          discardedTail = true;
          break;
        }
        commits++;
        committedCount = entries.length;
        committedEnd = off + 4 + payloadSize;
        previous = (previous ^ ((type & 1) * 0x80000000)) >>> 0;
        crc = 0xffffffff;
      } else {
        crc = crc32(b.subarray(off + 4, off + 4 + payloadSize), crc);
        if (++totalTags > options.maxItems * 8)
          throw new DeviceParseFailure(
            "limit",
            "littlefs decoded metadata tags exceed maxItems work allowance",
          );
        entries.push({
          type,
          id: entryId,
          size,
          offset: id * blockSize + off + 4,
          data: b.subarray(off + 4, off + 4 + payloadSize),
        });
      }
      off += 4 + payloadSize;
    }
    if (commits === 0) return null;
    return {
      block: id,
      revision,
      commits,
      entries: entries.slice(0, committedCount),
      end: committedEnd,
      discardedTail,
    };
  };
  const cache = new Map<string, Directory>();
  const fetch = (pair: readonly [number, number]): Directory => {
    const key = pairKey(pair);
    const cached = cache.get(key);
    if (cached !== undefined) return cached;
    if (pair[0] === pair[1])
      throw new DeviceParseFailure(
        "format",
        "littlefs metadata pair must contain distinct blocks",
      );
    const a = readMetadata(pair[0]);
    const b = readMetadata(pair[1]);
    if (a === null && b === null)
      throw new DeviceParseFailure(
        "format",
        `No CRC-valid littlefs metadata commit in pair ${key}`,
      );
    const selected =
      a === null
        ? b
        : b === null
          ? a
          : ((b.revision - a.revision) | 0) > 0
            ? b
            : a;
    if (selected === null)
      throw new DeviceParseFailure(
        "format",
        "No valid littlefs metadata selected",
      );
    add({
      kind: "metadata-pair",
      blocks: [...pair],
      selected_block: selected.block,
      revision: selected.revision,
      valid_commits: selected.commits,
      committed_end: selected.end,
      discarded_tail: selected.discardedTail,
      alternate_revision:
        selected === a ? (b?.revision ?? null) : (a?.revision ?? null),
    });
    const directory: Directory = {
      metadata: selected,
      files: new Map(),
      tail: null,
      split: false,
      state: null,
    };
    const get = (id: number): FileEntry => {
      let file = directory.files.get(id);
      if (file === undefined) {
        file = { attributes: new Map() };
        directory.files.set(id, file);
      }
      return file;
    };
    for (const entry of selected.entries) {
      const { type, id, size } = entry;
      if (type === 0x401 || type === 0x4ff) {
        const shift = type === 0x401 ? 1 : -1;
        const shifted = new Map<number, FileEntry>();
        for (const [fileId, file] of directory.files) {
          if (shift === -1 && fileId === id) continue;
          shifted.set(fileId >= id ? fileId + shift : fileId, file);
        }
        directory.files = shifted;
      } else if ((type & 0x700) === 0) {
        const file = get(id);
        if (size === 0x3ff) delete file.name;
        else file.name = entry;
      } else if ((type & 0x700) === 0x200) {
        const file = get(id);
        if (size === 0x3ff) delete file.struct;
        else file.struct = entry;
      } else if ((type & 0x700) === 0x300) {
        if (size === 0x3ff) get(id).attributes.delete(type);
        else get(id).attributes.set(type, entry);
      } else if ((type & 0x700) === 0x600) {
        if (size !== 8)
          throw new DeviceParseFailure(
            "format",
            "littlefs tail tag requires an 8-byte pair",
          );
        const next = [
          entry.data.readUInt32LE(0),
          entry.data.readUInt32LE(4),
        ] as const;
        directory.tail =
          next[0] === 0xffffffff || next[1] === 0xffffffff ? null : next;
        directory.split = (type & 1) !== 0;
      } else if (type === 0x7ff) {
        if (size !== 12)
          throw new DeviceParseFailure(
            "format",
            "littlefs global state requires 12 bytes",
          );
        directory.state = entry.data;
      } else if (type !== 0x5ff)
        warn(
          `Unsupported littlefs metadata type 0x${type.toString(16)} in block ${selected.block}`,
        );
    }
    cache.set(key, directory);
    return directory;
  };

  // The metadata thread starts at 0/1; the last superblock entry identifies the root pair.
  let pair: readonly [number, number] | null = [0, 1];
  let root: readonly [number, number] | null = null;
  let superblock: Entry | null = null;
  const threaded = new Set<string>();
  const globalState = Buffer.alloc(12);
  while (pair !== null) {
    const key = pairKey(pair);
    if (threaded.has(key))
      throw new DeviceParseFailure(
        "format",
        "Cycle in littlefs metadata thread",
      );
    threaded.add(key);
    const directory = fetch(pair);
    const zero = directory.files.get(0);
    if (
      zero?.name?.type === 0xff &&
      zero.name.data.equals(Buffer.from("littlefs", "ascii"))
    ) {
      if (zero.struct?.type !== 0x201 || zero.struct.size !== 24)
        throw new DeviceParseFailure(
          "format",
          "littlefs superblock requires a 24-byte inline structure",
        );
      root = pair;
      superblock = zero.struct;
    }
    if (directory.state !== null)
      for (let i = 0; i < 12; i++)
        globalState[i] = (globalState[i] ?? 0) ^ (directory.state[i] ?? 0);
    pair = directory.tail;
  }
  if (root === null || superblock === null)
    throw new DeviceParseFailure(
      "format",
      "No CRC-committed littlefs superblock in metadata thread",
    );
  const version = superblock.data.readUInt32LE(0);
  const major = version >>> 16;
  const minor = version & 65535;
  if (major !== 2 || minor > 1)
    throw new DeviceParseFailure(
      "unsupported",
      `Unsupported littlefs on-disk version ${major}.${minor}`,
    );
  if (
    superblock.data.readUInt32LE(4) !== blockSize ||
    superblock.data.readUInt32LE(8) !== blockCount
  )
    throw new DeviceParseFailure(
      "format",
      "Selected littlefs geometry disagrees with committed superblock",
    );
  result.version = `${major}.${minor}`;
  add({
    kind: "superblock",
    file_offset: superblock.offset,
    version: result.version,
    block_size: blockSize,
    block_count: blockCount,
    root_pair: [...root],
    name_max: superblock.data.readUInt32LE(12),
    file_max: superblock.data.readUInt32LE(16),
    attr_max: superblock.data.readUInt32LE(20),
    global_state_hex: globalState.toString("hex"),
  });
  if (globalState.some((v) => v !== 0))
    warn(
      "Pending littlefs global move/orphan state; candidate namespace inventory is partial and payload extraction is withheld",
    );
  const allowExtract = globalState.every((v) => v === 0);
  const directoryPaths = new Map<string, string>();
  const activePath = new Set<string>();
  const readCtz = (
    head: number,
    size: number,
  ): { data: Buffer; extents: JsonValue[]; singleOffset: number | null } => {
    if (size > bytes.length || decodedBytes + size > bytes.length)
      throw new DeviceParseFailure(
        "limit",
        "littlefs extracted data exceeds supplied image extent",
      );
    if (size === 0)
      return { data: Buffer.alloc(0), extents: [], singleOffset: null };
    const starts = [0];
    let capacity = blockSize;
    let count = 1;
    while (capacity < size) {
      starts.push(capacity);
      capacity += blockSize - 4 * (trailingZeroes(count) + 1);
      count++;
      if (count > blockCount)
        throw new DeviceParseFailure(
          "format",
          "littlefs CTZ file requires more blocks than filesystem",
        );
    }
    const out = Buffer.alloc(size);
    let physical = head;
    const used = new Set<number>();
    const extents: JsonValue[] = [];
    for (let index = count - 1; index >= 0; index--) {
      if (used.has(physical))
        throw new DeviceParseFailure("format", "Cycle in littlefs CTZ chain");
      used.add(physical);
      const b = block(physical);
      const header = index === 0 ? 0 : 4 * (trailingZeroes(index) + 1);
      const start = starts[index] ?? 0;
      const length = Math.min(size - start, blockSize - header);
      b.copy(out, start, header, header + length);
      extents.push({
        file_offset: physical * blockSize + header,
        file_bytes: length,
        logical_offset: start,
        block: physical,
      });
      if (index > 0) physical = b.readUInt32LE(0);
    }
    return {
      data: out,
      extents: extents.reverse(),
      singleOffset: count === 1 ? head * blockSize : null,
    };
  };
  const walk = (
    first: readonly [number, number],
    path: string,
    depth: number,
  ): void => {
    if (depth > 128)
      throw new DeviceParseFailure(
        "limit",
        "littlefs directory depth exceeds 128",
      );
    let current: readonly [number, number] | null = first;
    const chain = new Set<string>();
    while (current !== null) {
      const key = pairKey(current);
      if (chain.has(key) || activePath.has(key))
        throw new DeviceParseFailure(
          "format",
          "Cycle in littlefs directory namespace",
        );
      const oldPath = directoryPaths.get(key);
      if (oldPath !== undefined && oldPath !== path)
        throw new DeviceParseFailure(
          "format",
          "littlefs directory pair has conflicting namespace parents",
        );
      directoryPaths.set(key, path);
      chain.add(key);
      activePath.add(key);
      const directory = fetch(current);
      for (const [id, file] of [...directory.files].sort(
        (a, b) => a[0] - b[0],
      )) {
        const name = file.name;
        const structure = file.struct;
        if (name === undefined || name.type === 0xff) continue;
        const display = name.data.toString("utf8");
        if (
          display.length === 0 ||
          display === "." ||
          display === ".." ||
          /[\0/]/u.test(display)
        )
          throw new DeviceParseFailure(
            "format",
            "Invalid littlefs filename in committed metadata",
          );
        const fullName = path === "" ? display : `${path}/${display}`;
        const item: Record<string, JsonValue> = {
          kind: name.type === 2 ? "directory" : "file",
          path: fullName,
          name_hex: name.data.toString("hex"),
          metadata_pair: [...current],
          id,
          name_file_offset: name.offset,
          attributes: [...file.attributes.values()].map((entry) => ({
            type: entry.type & 255,
            file_offset: entry.offset,
            data_hex: entry.data.toString("hex"),
          })),
        };
        add(item);
        if (structure === undefined) {
          warn(`Missing littlefs structure for ${fullName}`);
          continue;
        }
        item.structure_type = structure.type;
        item.structure_file_offset = structure.offset;
        if (
          name.type === 2 &&
          structure.type === 0x200 &&
          structure.size === 8
        ) {
          const child = [
            structure.data.readUInt32LE(0),
            structure.data.readUInt32LE(4),
          ] as const;
          walk(child, fullName, depth + 1);
        } else if (name.type === 1 && structure.type === 0x201) {
          item.file_bytes = structure.size;
          item.storage = "inline";
          if (allowExtract) {
            decodedBytes += structure.size;
            if (decodedBytes > bytes.length)
              throw new DeviceParseFailure(
                "limit",
                "littlefs extracted data exceeds supplied image extent",
              );
            result.regions.push({
              name: fullName,
              fileOffset: structure.offset,
              loadAddress: null,
              bytes: structure.data,
            });
          }
        } else if (
          name.type === 1 &&
          structure.type === 0x202 &&
          structure.size === 8
        ) {
          const head = structure.data.readUInt32LE(0);
          const size = structure.data.readUInt32LE(4);
          item.file_bytes = size;
          item.storage = "ctz";
          item.head_block = head;
          if (allowExtract) {
            const decoded = readCtz(head, size);
            decodedBytes += size;
            item.extents = decoded.extents;
            result.regions.push({
              name: fullName,
              fileOffset: decoded.singleOffset,
              loadAddress: null,
              bytes: decoded.data,
            });
          }
        } else
          warn(
            `Unsupported littlefs name/structure combination for ${fullName}`,
          );
        if (result.items.length + result.regions.length > options.maxItems)
          throw new DeviceParseFailure(
            "limit",
            "littlefs item/region count exceeds maxItems",
          );
      }
      activePath.delete(key);
      current = directory.split ? directory.tail : null;
    }
  };
  walk(root, "", 0);
  return result;
};
