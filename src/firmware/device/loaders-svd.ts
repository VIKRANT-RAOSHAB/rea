import type { Element } from "@xmldom/xmldom";
import type { JsonValue } from "../../domain/jsonValue.js";
import { parseXmlDocument } from "../../domain/xmlDocument.js";
import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { DeviceParseFailure } from "./types.js";
import { count, fail, hex, result } from "./loaders-common.js";

const children = (e: Element, tag?: string): Element[] => {
  const found: Element[] = [];
  for (let n = e.firstChild; n; n = n.nextSibling)
    if (n.nodeType === 1) {
      const element = n as Element;
      if (tag === undefined || element.localName === tag) found.push(element);
    }
  return found;
};
const child = (e: Element, tag: string): Element | undefined =>
  children(e, tag)[0];
const text = (e: Element, tag: string): string | null =>
  child(e, tag)?.textContent?.trim() ?? null;
const integer = (value: string | null): bigint | null => {
  if (value === null) return null;
  const s = value.replaceAll("_", "");
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(s))
    fail(`Unsupported SVD numeric representation: ${value}`);
  return BigInt(s);
};
type Properties = {
  size: bigint | null;
  access: string | null;
  reset: bigint | null;
  resetMask: bigint | null;
};
const props = (e: Element, inherited: Properties): Properties => ({
  size: integer(text(e, "size")) ?? inherited.size,
  access: text(e, "access") ?? inherited.access,
  reset: integer(text(e, "resetValue")) ?? inherited.reset,
  resetMask: integer(text(e, "resetMask")) ?? inherited.resetMask,
});

/** Concrete peripheral/register metadata; unresolved inheritance remains explicit. */
export const parseSvd = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  if (bytes.length > 8388608)
    throw new DeviceParseFailure(
      "limit",
      "SVD XML exceeds the 8-MiB parsed-document allowance",
    );
  const r = result(o.format);
  let structures = 0;
  const structure = () => count(++structures, o);
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return fail("SVD is not valid UTF-8");
  }
  const parsed = parseXmlDocument(source, {
    doctype: "reject",
    lineEndings: "preserve",
  });
  if (!parsed.ok) fail(parsed.error.message);
  const device = parsed.value.documentElement;
  if (!device || device.localName !== "device")
    fail("CMSIS-SVD requires a device root");
  if (integer(text(device, "addressUnitBits")) !== 8n)
    throw new DeviceParseFailure(
      "unsupported",
      "SVD profile requires 8-bit address units",
    );
  r.version = device.getAttribute("schemaVersion") || null;
  const cpu = child(device, "cpu"),
    cpuName = cpu ? text(cpu, "name") : null;
  r.architecture = cpuName?.startsWith("CM") ? "cortex-m" : null;
  r.items.push({
    kind: "svd-device",
    name: text(device, "name"),
    vendor: text(device, "vendor"),
    description: text(device, "description"),
    cpu: cpuName,
    schema_version: r.version,
  });
  const defaults = props(device, {
    size: null,
    access: null,
    reset: null,
    resetMask: null,
  });
  const unresolved = (e: Element, path: string): boolean => {
    const derivation = e.getAttribute("derivedFrom");
    if (!derivation) return false;
    count(r.items.length + 1, o);
    r.items.push({
      kind: "svd-unresolved-derivation",
      path,
      derived_from: derivation,
    });
    r.complete = false;
    return true;
  };
  const instances = (e: Element): { suffix: string; offset: bigint }[] => {
    const dim = integer(text(e, "dim"));
    if (dim === null) return [{ suffix: "", offset: 0n }];
    if (dim < 1n || dim > BigInt(o.maxItems))
      throw new DeviceParseFailure(
        "limit",
        "SVD array dimension exceeds max_items",
      );
    const increment = integer(text(e, "dimIncrement"));
    if (increment === null) fail("SVD array has no dimIncrement");
    const n = Number(dim),
      indexes = text(e, "dimIndex");
    let names: string[];
    if (indexes === null)
      names = Array.from({ length: n }, (_, i) => String(i));
    else if (indexes.includes(","))
      names = indexes.split(",").map((s) => s.trim());
    else {
      const numeric = /^(\d+)-(\d+)$/.exec(indexes),
        alpha = /^([A-Za-z])-([A-Za-z])$/.exec(indexes);
      if (numeric) {
        const from = Number(numeric[1]),
          to = Number(numeric[2]);
        if (
          !Number.isSafeInteger(from) ||
          !Number.isSafeInteger(to) ||
          to - from + 1 !== n
        )
          fail("SVD dimIndex range disagrees with dim");
        names = Array.from({ length: n }, (_, i) => String(from + i));
      } else if (alpha) {
        const from = alpha[1]!.charCodeAt(0),
          to = alpha[2]!.charCodeAt(0);
        if (to - from + 1 !== n)
          fail("SVD alphabetic dimIndex disagrees with dim");
        names = Array.from({ length: n }, (_, i) =>
          String.fromCharCode(from + i),
        );
      } else names = [indexes];
    }
    if (names.length !== n) fail("SVD dimIndex count disagrees with dim");
    return names.map((suffix, i) => ({
      suffix,
      offset: BigInt(i) * increment,
    }));
  };
  const visit = (
    container: Element,
    path: string,
    base: bigint,
    inherited: Properties,
    depth: number,
  ): void => {
    if (depth > 32)
      throw new DeviceParseFailure(
        "limit",
        "SVD cluster nesting exceeds 32 levels",
      );
    for (const e of children(container)) {
      if (e.localName !== "register" && e.localName !== "cluster") continue;
      structure();
      const templateName = text(e, "name");
      if (!templateName) fail("SVD register/cluster has no name");
      if (unresolved(e, `${path}.${templateName}`)) continue;
      const offset = integer(text(e, "addressOffset"));
      if (offset === null) fail("SVD register/cluster has no addressOffset");
      const properties = props(e, inherited);
      for (const instance of instances(e)) {
        structure();
        const name = templateName.replace(/\[?%s\]?/g, instance.suffix),
          fullName = `${path}.${name}`,
          address = base + offset + instance.offset;
        if (e.localName === "cluster") {
          visit(e, fullName, address, properties, depth + 1);
          continue;
        }
        count(r.items.length + 1, o);
        const fields: JsonValue[] = [];
        const fieldRoot = child(e, "fields");
        for (const f of fieldRoot ? children(fieldRoot, "field") : []) {
          structure();
          count(r.items.length + fields.length + 2, o);
          const derivation = f.getAttribute("derivedFrom"),
            dimension = text(f, "dim");
          if (derivation || dimension !== null) {
            r.complete = false;
            fields.push({
              name: text(f, "name"),
              derived_from: derivation || null,
              dimension,
              unresolved: true,
            });
            continue;
          }
          let low = integer(text(f, "bitOffset")),
            width = integer(text(f, "bitWidth"));
          if (low === null) {
            low = integer(text(f, "lsb"));
            const high = integer(text(f, "msb"));
            if (low !== null && high !== null) width = high - low + 1n;
            else {
              const range = /^\[(\d+):(\d+)\]$/.exec(text(f, "bitRange") ?? "");
              if (range) {
                low = BigInt(range[2]!);
                width = BigInt(range[1]!) - low + 1n;
              }
            }
          }
          if (
            low === null ||
            width === null ||
            low < 0n ||
            width < 1n ||
            (properties.size !== null && low + width > properties.size)
          )
            fail("Invalid or missing SVD field bit range");
          fields.push({
            name: text(f, "name"),
            bit_offset: low.toString(),
            bit_width: width.toString(),
            access: text(f, "access") ?? properties.access,
            description: text(f, "description"),
          });
        }
        r.items.push({
          kind: "svd-register",
          path: fullName,
          address: hex(address),
          size_bits: properties.size?.toString() ?? null,
          access: properties.access,
          reset_value: properties.reset === null ? null : hex(properties.reset),
          reset_mask:
            properties.resetMask === null ? null : hex(properties.resetMask),
          description: text(e, "description"),
          fields,
        });
      }
    }
  };
  const peripherals = child(device, "peripherals");
  if (!peripherals) fail("SVD has no peripherals element");
  for (const p of children(peripherals, "peripheral")) {
    structure();
    const name = text(p, "name");
    if (!name) fail("SVD peripheral has no name");
    if (unresolved(p, name)) continue;
    const base = integer(text(p, "baseAddress"));
    if (base === null) fail("SVD peripheral has no baseAddress");
    for (const instance of instances(p)) {
      structure();
      const path = name.replace(/\[?%s\]?/g, instance.suffix),
        address = base + instance.offset;
      count(r.items.length + 1, o);
      r.items.push({
        kind: "svd-peripheral",
        name: path,
        base_address: hex(address),
        description: text(p, "description"),
      });
      const registers = child(p, "registers");
      if (registers) visit(registers, path, address, props(p, defaults), 0);
    }
  }
  r.limitations.push(
    "SVD is caller-supplied hardware metadata, not evidence that a firmware matches that chip or that registers have these values at runtime. Concrete registers, clusters and register/peripheral arrays are expanded; derivedFrom and field arrays are reported unresolved. Enumerated field values, write constraints and read side effects are not reconstructed; no analysis database annotations are applied.",
  );
  return r;
};
