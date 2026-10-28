import { createHash } from "node:crypto";
import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { DeviceParseFailure } from "./types.js";
import {
  DevicetreeLimitFailure,
  parseDevicetree,
} from "../devicetree/DevicetreeParser.js";
import { count, crc32, fail, hex, result, span } from "./loaders-common.js";

type Tree = ReturnType<typeof parseDevicetree>;
type Node = Tree["nodes"][number];

/** Own the validated tree and original bytes together; never decode a truncated property preview. */
class FitReader {
  readonly report: ReturnType<typeof result>;
  readonly tree: Tree;
  readonly nodes: Map<string, Node>;
  readonly descendants = new Map<string, Node[]>();

  constructor(
    readonly bytes: Buffer,
    readonly options: DeviceParseOptions,
  ) {
    this.report = result(options.format);
    try {
      this.tree = parseDevicetree(
        bytes,
        {
          path: "<supplied-fit>",
          sha256: createHash("sha256").update(bytes).digest("hex"),
          bytes: bytes.length,
        },
        {
          path: "<supplied-fit>",
          max_file_bytes: bytes.length,
          max_nodes: options.maxItems,
          max_properties: options.maxItems,
          max_depth: 64,
        },
      );
    } catch (cause) {
      throw new DeviceParseFailure(
        cause instanceof DevicetreeLimitFailure ? "limit" : "format",
        cause instanceof Error ? cause.message : "Malformed FIT devicetree",
      );
    }
    this.nodes = new Map(this.tree.nodes.map((n) => [n.path, n]));
    for (const n of this.tree.nodes)
      if (n.parent !== null) {
        const group = this.descendants.get(n.parent) ?? [];
        group.push(n);
        this.descendants.set(n.parent, group);
      }
  }

  property(path: string, name: string) {
    return this.nodes.get(path)?.properties.find((p) => p.name === name);
  }
  raw(path: string, name: string): Buffer | null {
    const p = this.property(path, name);
    return p ? span(this.bytes, p.offset, p.bytes) : null;
  }
  string(path: string, name: string): string | null {
    const b = this.raw(path, name);
    if (b === null) return null;
    if (!b.length || b.at(-1) !== 0 || b.subarray(0, -1).includes(0))
      fail(`FIT ${name} is not a single terminated string`);
    return b.subarray(0, -1).toString("utf8");
  }
  strings(path: string, name: string): string[] | null {
    const b = this.raw(path, name);
    if (b === null) return null;
    if (!b.length || b.at(-1) !== 0) fail(`FIT ${name} is not a string list`);
    return b.subarray(0, -1).toString("utf8").split("\0");
  }
  cell(path: string, name: string): bigint | null {
    const b = this.raw(path, name);
    if (b === null) return null;
    if (b.length !== 4 && b.length !== 8)
      fail(`FIT ${name} must be one or two cells`);
    return b.length === 4 ? BigInt(b.readUInt32BE(0)) : b.readBigUInt64BE(0);
  }

  payload(n: Node): { fileOffset: number | null; data: Buffer | null } {
    const inline = this.property(n.path, "data"),
      position = this.cell(n.path, "data-position"),
      relative = this.cell(n.path, "data-offset"),
      size = this.cell(n.path, "data-size");
    if (inline) {
      if (position !== null || relative !== null || size !== null)
        fail("FIT image mixes inline and external payload declarations");
      return {
        fileOffset: inline.offset,
        data: span(this.bytes, inline.offset, inline.bytes),
      };
    }
    if (size !== null && (position !== null || relative !== null)) {
      if (position !== null && relative !== null)
        fail("FIT image declares both external address forms");
      const offset =
        position ??
        BigInt(Math.ceil(this.tree.header.totalsize / 4) * 4) + relative!;
      if (
        offset > BigInt(Number.MAX_SAFE_INTEGER) ||
        size > BigInt(Number.MAX_SAFE_INTEGER)
      )
        fail("FIT external data range exceeds safe file coordinates");
      return {
        fileOffset: Number(offset),
        data: span(this.bytes, Number(offset), Number(size)),
      };
    }
    this.report.complete = false;
    this.report.warnings.push(
      `FIT image ${n.path} has no supported payload declaration`,
    );
    return { fileOffset: null, data: null };
  }

  hash(child: Node, data: Buffer | null): void {
    const r = this.report;
    count(r.items.length + 1, this.options);
    const algorithm = this.string(child.path, "algo"),
      value = this.raw(child.path, "value");
    if (
      !child.path.split("/").at(-1)?.startsWith("hash") ||
      !data ||
      !algorithm ||
      !value
    ) {
      r.complete = false;
      r.items.push({
        kind: "fit-uninterpreted-image-child",
        path: child.path,
        algorithm,
      });
      return;
    }
    let digest: Buffer | null = null;
    if (["sha1", "sha256", "sha384", "sha512", "md5"].includes(algorithm))
      digest = createHash(algorithm).update(data).digest();
    else if (algorithm === "crc32") {
      digest = Buffer.alloc(4);
      digest.writeUInt32BE(crc32(data));
    }
    if (digest && !digest.equals(value))
      fail(`FIT hash mismatch at ${child.path}`);
    r.items.push({
      kind: "fit-hash",
      path: child.path,
      algorithm,
      verified: digest !== null,
      value_hex: value.toString("hex"),
    });
    if (!digest) {
      r.complete = false;
      r.warnings.push(`FIT hash algorithm ${algorithm} is not verified`);
    }
  }

  image(n: Node): void {
    const r = this.report;
    count(r.items.length + 1, this.options);
    const { fileOffset, data } = this.payload(n),
      compression = this.string(n.path, "compression"),
      load = this.cell(n.path, "load"),
      entry = this.cell(n.path, "entry");
    r.items.push({
      kind: "fit-image",
      path: n.path,
      type: this.string(n.path, "type"),
      arch: this.string(n.path, "arch"),
      os: this.string(n.path, "os"),
      compression,
      load_address: load === null ? null : hex(load),
      entry_point: entry === null ? null : hex(entry),
      data_file_offset: fileOffset,
      data_bytes: data?.length ?? null,
    });
    if (data)
      r.regions.push({
        name: n.path.slice(8),
        fileOffset,
        loadAddress: compression === "none" && load !== null ? hex(load) : null,
        bytes: data,
      });
    if (compression !== "none") {
      r.complete = false;
      r.limitations.push(
        `FIT image ${n.path} payload compression is ${compression ?? "undeclared"}; stored bytes are preserved without executable mapping or decompression.`,
      );
    }
    for (const child of this.descendants.get(n.path) ?? [])
      this.hash(child, data);
  }

  configuration(n: Node, imageNames: Set<string>): void {
    const r = this.report;
    count(r.items.length + 1, this.options);
    const refs: Record<string, string[] | null> = {};
    for (const name of [
      "kernel",
      "firmware",
      "ramdisk",
      "fdt",
      "loadables",
      "setup",
    ]) {
      refs[name] = this.strings(n.path, name);
      for (const ref of refs[name] ?? [])
        if (!imageNames.has(ref)) {
          r.complete = false;
          r.warnings.push(
            `FIT configuration ${n.path} references missing image ${ref}`,
          );
        }
    }
    r.items.push({
      kind: "fit-configuration",
      path: n.path,
      image_references: refs,
    });
    if (this.descendants.has(n.path)) {
      r.complete = false;
      r.limitations.push(
        `Configuration children including signatures at ${n.path} are not verified.`,
      );
    }
  }

  parse(): DeviceParseResult {
    const r = this.report,
      images = this.descendants.get("/images") ?? [];
    if (!images.length) fail("FIT requires a nonempty /images node");
    for (const n of images) this.image(n);
    const names = new Set(images.map((n) => n.path.slice(8)));
    for (const n of this.descendants.get("/configurations") ?? [])
      this.configuration(n, names);
    r.items.push({
      kind: "fit-root",
      default_configuration: this.string("/configurations", "default"),
      description: this.string("/", "description"),
    });
    count(r.items.length, this.options);
    r.version = `FIT/FDT v${this.tree.header.version}`;
    r.limitations.push(
      "Hash verification is not signature authentication. No configuration is silently selected, no payload is executed, and external data is read only from the supplied file. Shared image-data properties and encrypted payloads are not reconstructed.",
    );
    return r;
  }
}

export const parseFit = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => new FitReader(bytes, options).parse();
