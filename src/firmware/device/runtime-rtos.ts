import type { JsonValue } from "../../domain/jsonValue.js";
import {
  DeviceParseFailure,
  type DeviceParseOptions,
  type DeviceParseResult,
} from "./types.js";
import {
  RuntimeBudget,
  runtimeHex,
  runtimeReport,
  runtimeText,
} from "./runtime-reader.js";

// RTOS memory layouts vary with release, ABI and build options. Offset descriptions
// are caller-selected evidence, never silently guessed from a family name.
const OS_NAMES = new Set(["freertos", "zephyr", "threadx"]);
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const requiredInteger = (value: unknown, name: string, minimum = 0): number => {
  if (
    !Number.isSafeInteger(value) ||
    typeof value !== "number" ||
    value < minimum
  )
    throw new DeviceParseFailure(
      "format",
      `RTOS layout ${name} must be an integer >= ${minimum}`,
    );
  return value;
};
const address = (value: unknown, name: string): bigint => {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,16}$/u.test(value))
    throw new DeviceParseFailure(
      "format",
      `RTOS layout ${name} must be an explicit 0x hexadecimal address`,
    );
  return BigInt(value);
};

/**
 * Decode caller-described task/queue/timer structures from one saved RAM image.
 *
 * Layout: { os, version, evidence_kind:"ram-snapshot", base_address,
 * pointer_bytes:4|8, byte_order:"little"|"big", architecture?:string,
 * objects:[{kind:"task"|"queue"|"timer", addresses?:["0x..."],
 *   head?:"0x...", head_is_pointer?:boolean, end?:"0x...",
 *   next_offset?:number, link_offset?:number,
 *   fields:{ name:{offset, type:"cstring", length, indirect?:boolean},
 *            priority:{offset,type:"u32"}, stack:{offset,type:"pointer"} }}] }
 *
 * Linked traversal follows node+next_offset, then subtracts link_offset to find
 * the containing object. Explicit addresses always name containing objects.
 * A configured end sentinel or a return to the first node ends a circular list.
 */
export const parseRtosSnapshot = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  const layout = options.layout;
  if (!isRecord(layout))
    throw new DeviceParseFailure(
      "unsupported",
      "RTOS snapshot inspection requires a caller-selected layout; offsets and OS versions are never guessed",
    );
  if (typeof layout.os !== "string" || !OS_NAMES.has(layout.os))
    throw new DeviceParseFailure(
      "unsupported",
      "RTOS layout os must be freertos, zephyr or threadx",
    );
  if (typeof layout.version !== "string" || layout.version.trim().length === 0)
    throw new DeviceParseFailure(
      "format",
      "RTOS layout requires the selected OS version/build identifier",
    );
  if (layout.evidence_kind !== "ram-snapshot")
    throw new DeviceParseFailure(
      "unsupported",
      "RTOS structure inspection requires evidence_kind=ram-snapshot; flash images are not running task memory",
    );
  const pointerBytes = requiredInteger(
    layout.pointer_bytes,
    "pointer_bytes",
    1,
  );
  if (pointerBytes !== 4 && pointerBytes !== 8)
    throw new DeviceParseFailure(
      "unsupported",
      "RTOS pointer_bytes must be four or eight",
    );
  if (layout.byte_order !== "little" && layout.byte_order !== "big")
    throw new DeviceParseFailure(
      "format",
      "RTOS byte_order must be little or big",
    );
  const little = layout.byte_order === "little",
    base = address(layout.base_address, "base_address");
  const maxPointer = (1n << BigInt(pointerBytes * 8)) - 1n;
  if (base + BigInt(bytes.length) > maxPointer + 1n)
    throw new DeviceParseFailure(
      "format",
      "RTOS RAM snapshot exceeds the selected pointer address width",
    );
  const budget = new RuntimeBudget(options.maxItems),
    result = runtimeReport("rtos");
  const offsetAt = (at: bigint, size: number, label: string): number => {
    const offset = at - base;
    if (
      offset < 0n ||
      offset > BigInt(bytes.length) ||
      BigInt(size) > BigInt(bytes.length) - offset
    )
      throw new DeviceParseFailure(
        "format",
        `${label} at ${runtimeHex(at)} is not covered by the selected RAM snapshot`,
      );
    return Number(offset);
  };
  const readInteger = (at: bigint, size: number, signed = false): bigint => {
    const offset = offsetAt(at, size, "RTOS integer");
    let value = 0n;
    for (let i = 0; i < size; i++)
      value =
        (value << 8n) | BigInt(bytes[offset + (little ? size - i - 1 : i)]!);
    return signed && value >= 1n << BigInt(size * 8 - 1)
      ? value - (1n << BigInt(size * 8))
      : value;
  };
  const objects = layout.objects;
  if (!Array.isArray(objects) || objects.length === 0)
    throw new DeviceParseFailure(
      "format",
      "RTOS layout objects must contain at least one task, queue or timer description",
    );
  for (let group = 0; group < objects.length; group++) {
    budget.consume();
    const definition: unknown = objects[group];
    if (
      !isRecord(definition) ||
      !["task", "queue", "timer"].includes(String(definition.kind))
    )
      throw new DeviceParseFailure(
        "format",
        "RTOS object kind must be task, queue or timer",
      );
    if (
      !isRecord(definition.fields) ||
      Object.keys(definition.fields).length === 0
    )
      throw new DeviceParseFailure(
        "format",
        "RTOS object fields must be an explicit nonempty field map",
      );
    const fieldDefinitions = Object.entries(definition.fields);
    // Parse once before acquiring pointers or interpreting objects.
    const fields = fieldDefinitions.map(([name, value]) => {
      if (!isRecord(value))
        throw new DeviceParseFailure(
          "format",
          `RTOS field ${name} must contain offset/type`,
        );
      const offset = requiredInteger(value.offset, `${name}.offset`);
      const type = value.type;
      if (
        typeof type !== "string" ||
        !/^(?:[ui](?:8|16|32|64)|pointer|cstring|bytes)$/u.test(type)
      )
        throw new DeviceParseFailure(
          "unsupported",
          `Unsupported RTOS field type for ${name}: ${String(type)}`,
        );
      const length =
        type === "cstring" || type === "bytes"
          ? requiredInteger(value.length, `${name}.length`, 1)
          : 0;
      if (value.indirect !== undefined && typeof value.indirect !== "boolean")
        throw new DeviceParseFailure(
          "format",
          `RTOS ${name}.indirect must be boolean`,
        );
      if (value.indirect === true && type !== "cstring" && type !== "bytes")
        throw new DeviceParseFailure(
          "format",
          "RTOS indirect fields must be cstring or bytes",
        );
      return { name, offset, type, length, indirect: value.indirect === true };
    });
    const readObject = (at: bigint, node: bigint | null): void => {
      budget.consume();
      const fileOffset = offsetAt(at, 1, "RTOS object");
      const values: Record<string, JsonValue> = {};
      const sources: Record<string, JsonValue>[] = [];
      for (const field of fields) {
        budget.consume();
        let location = at + BigInt(field.offset);
        const pointerLocation = location;
        if (field.indirect) location = readInteger(location, pointerBytes);
        let value: JsonValue;
        let size: number;
        if (field.type === "cstring" || field.type === "bytes") {
          size = field.length;
          if (field.indirect && location === 0n) {
            values[field.name] = null;
            sources.push({
              name: field.name,
              pointer_file_offset: offsetAt(
                pointerLocation,
                pointerBytes,
                "RTOS string pointer",
              ),
              address: "0x0",
              file_offset: null,
              bytes: 0,
            });
            continue;
          }
          const fieldOffset = offsetAt(location, size, `RTOS ${field.name}`);
          const data = bytes.subarray(fieldOffset, fieldOffset + size);
          if (field.type === "cstring") {
            const end = data.indexOf(0);
            value = runtimeText(end < 0 ? data : data.subarray(0, end));
            if (end < 0)
              result.warnings.push(
                `RTOS field ${field.name} at ${runtimeHex(location)} has no NUL within the selected ${size}-byte range`,
              );
          } else value = { encoding: "hex", value: data.toString("hex") };
        } else {
          size =
            field.type === "pointer"
              ? pointerBytes
              : Number(field.type.slice(1)) / 8;
          const raw = readInteger(location, size, field.type.startsWith("i"));
          value =
            field.type === "pointer"
              ? runtimeHex(raw)
              : raw <= BigInt(Number.MAX_SAFE_INTEGER) &&
                  raw >= BigInt(Number.MIN_SAFE_INTEGER)
                ? Number(raw)
                : raw.toString();
        }
        values[field.name] = value;
        sources.push({
          name: field.name,
          address: runtimeHex(location),
          file_offset: offsetAt(location, size, `RTOS ${field.name}`),
          bytes: size,
          pointer_file_offset: field.indirect
            ? offsetAt(pointerLocation, pointerBytes, "RTOS indirect field")
            : null,
        });
      }
      result.items.push({
        kind: String(definition.kind),
        group,
        address: runtimeHex(at),
        node_address: node === null ? null : runtimeHex(node),
        file_offset: fileOffset,
        values,
        fields: sources,
        interpretation_basis: "caller-selected-layout",
        evidence_kind: "saved-ram-snapshot",
      });
    };
    const explicit = definition.addresses;
    if (explicit !== undefined) {
      if (!Array.isArray(explicit))
        throw new DeviceParseFailure(
          "format",
          "RTOS addresses must be an array of explicit hexadecimal addresses",
        );
      for (let i = 0; i < explicit.length; i++)
        readObject(
          address(explicit[i], `objects[${group}].addresses[${i}]`),
          null,
        );
    }
    if (definition.head !== undefined) {
      const nextOffset = requiredInteger(definition.next_offset, "next_offset"),
        linkOffset =
          definition.link_offset === undefined
            ? 0
            : requiredInteger(definition.link_offset, "link_offset");
      if (
        definition.head_is_pointer !== undefined &&
        typeof definition.head_is_pointer !== "boolean"
      )
        throw new DeviceParseFailure(
          "format",
          "RTOS head_is_pointer must be boolean",
        );
      let first = address(definition.head, "head");
      if (definition.head_is_pointer === true)
        first = readInteger(first, pointerBytes);
      const sentinel =
        definition.end === undefined ? 0n : address(definition.end, "end");
      const visited = new Set<bigint>();
      let node = first;
      while (node !== 0n && node !== sentinel) {
        if (visited.has(node)) {
          if (node !== first) {
            result.complete = false;
            result.warnings.push(
              `RTOS linked structure enters a cycle at ${runtimeHex(node)} before returning to its first node`,
            );
          }
          break;
        }
        visited.add(node);
        if (node < BigInt(linkOffset))
          throw new DeviceParseFailure(
            "format",
            "RTOS link_offset underflows the node address",
          );
        readObject(node - BigInt(linkOffset), node);
        node = readInteger(node + BigInt(nextOffset), pointerBytes);
      }
      result.items.push({
        kind: "list",
        object_kind: String(definition.kind),
        group,
        first_node: runtimeHex(first),
        sentinel: runtimeHex(sentinel),
        observed_nodes: visited.size,
        termination_address: runtimeHex(node),
      });
    }
    if (explicit === undefined && definition.head === undefined)
      throw new DeviceParseFailure(
        "format",
        "RTOS object descriptions require addresses or a linked-list head",
      );
  }
  result.items.unshift({
    kind: "layout",
    os: layout.os,
    os_version: layout.version,
    pointer_bytes: pointerBytes,
    byte_order: layout.byte_order,
    base_address: runtimeHex(base),
    snapshot_bytes: bytes.length,
    applicability: "caller-declared",
    evidence_kind: "saved-ram-snapshot",
  });
  result.limitations.push(
    "RTOS names and field meanings come from the explicit caller-selected layout. This parser does not identify the OS, ABI, build options or structure offsets from bytes alone.",
    "These are observations of supplied saved RAM bytes, not a live running device. The parser cannot establish snapshot atomicity, current task state, CPU register state or whether pointers remain valid at another time.",
    "Only the selected task/queue/timer fields and linked structures are inspected. Static flash task-creation reconstruction and automatic FreeRTOS/Zephyr/ThreadX symbol-based layout recovery remain outside this profile.",
  );
  return {
    ...result,
    version: `${layout.os}:${layout.version}`,
    architecture:
      typeof layout.architecture === "string" ? layout.architecture : null,
  };
};
