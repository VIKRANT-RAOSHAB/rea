import {
  DeviceParseFailure,
  type DeviceParseOptions,
  type DeviceParseResult,
} from "./types.js";

/** Decode a caller-located Cortex-M vector table; this does not emulate reset. */
export const parseCortexVectors = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  const layout = options.layout;
  if (
    typeof layout?.base_address !== "string" ||
    !/^0x[0-9a-fA-F]{1,8}$/u.test(layout.base_address)
  )
    throw new DeviceParseFailure(
      "format",
      "Cortex-M vector inspection requires layout_path with a base_address in byte coordinates.",
    );
  const base = Number(BigInt(layout.base_address));
  const offset = layout.vector_offset ?? 0;
  const vectorCount = layout.vector_count ?? 16;
  if (
    typeof offset !== "number" ||
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset % 4 !== 0 ||
    typeof vectorCount !== "number" ||
    !Number.isSafeInteger(vectorCount) ||
    vectorCount < 2 ||
    vectorCount > options.maxItems
  )
    throw new DeviceParseFailure(
      "format",
      "Select an aligned vector_offset and vector_count >= 2 within max_items.",
    );
  if (
    offset > bytes.length - vectorCount * 4 ||
    base + bytes.length > 0x100000000
  )
    throw new DeviceParseFailure(
      "format",
      "Cortex-M vector range or memory map exceeds the supplied image.",
    );
  const names = [
    "initial-stack",
    "reset",
    "nmi",
    "hard-fault",
    "memory-management",
    "bus-fault",
    "usage-fault",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "svc",
    "debug-monitor",
    "reserved",
    "pend-sv",
    "sys-tick",
  ];
  const warnings: string[] = [];
  const items: DeviceParseResult["items"] = [];
  let complete = true;
  for (let index = 0; index < vectorCount; index++) {
    const at = offset + index * 4,
      value = bytes.readUInt32LE(at),
      handler = (value & 0xfffffffe) >>> 0;
    const unused = index !== 0 && (value === 0 || value === 0xffffffff);
    const mapped =
      index !== 0 &&
      !unused &&
      handler >= base &&
      handler < base + bytes.length;
    items.push({
      kind: index === 0 ? "initial-stack" : "vector",
      index,
      name: names[index] ?? `irq-${index - 16}`,
      file_offset: at,
      raw_value: `0x${value.toString(16)}`,
      handler_address:
        index === 0 || unused ? null : `0x${handler.toString(16)}`,
      thumb: index === 0 || unused ? null : (value & 1) === 1,
      mapped_to_supplied_image: index === 0 || unused ? null : mapped,
      handler_file_offset: mapped ? handler - base : null,
    });
    if (index !== 0 && !unused && (value & 1) === 0) {
      warnings.push(`Vector ${index} has no Thumb-state bit.`);
      complete = false;
    }
  }
  const stack = bytes.readUInt32LE(offset),
    reset = bytes.readUInt32LE(offset + 4),
    resetAddress = (reset & 0xfffffffe) >>> 0;
  if (stack % 4 !== 0) {
    warnings.push("Initial stack pointer is not word-aligned.");
    complete = false;
  }
  const validReset = reset !== 0 && reset !== 0xffffffff && (reset & 1) === 1;
  if (!validReset) {
    warnings.push("The reset vector is not a valid selected Thumb handler.");
    complete = false;
  }
  return {
    format: options.format,
    version: "Cortex-M little-endian vectors",
    architecture: "cortex-m",
    entryPoint: validReset ? `0x${resetAddress.toString(16)}` : null,
    regions: [
      {
        name: "firmware",
        fileOffset: 0,
        loadAddress: `0x${base.toString(16)}`,
        bytes,
      },
    ],
    items,
    complete,
    warnings,
    limitations: [
      "The processor profile and vector-table placement are caller-selected. Values do not establish exact MCU identity, SRAM validity, interrupt execution or live state. Reserved entries and handlers outside the supplied image are preserved without inventing code.",
    ],
  };
};
