import { isUtf8 } from "node:buffer";
import type { JsonValue } from "../../domain/jsonValue.js";
import { DeviceParseFailure, type DeviceParseResult } from "./types.js";

/** One checked byte cursor shared by the runtime container parsers. */
export class RuntimeReader {
  offset = 0;
  littleEndian = true;
  constructor(readonly bytes: Buffer) {}
  take(length: number, label: string): Buffer {
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > this.bytes.length - this.offset
    )
      throw new DeviceParseFailure(
        "format",
        `Truncated or invalid ${label} at file offset ${this.offset}`,
      );
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
  byte(label = "byte"): number {
    return this.take(1, label)[0]!;
  }
  integer(width: number, label: string, signed = false): bigint {
    if (width !== 1 && width !== 2 && width !== 4 && width !== 8)
      throw new DeviceParseFailure(
        "unsupported",
        `Unsupported ${label} width: ${width}`,
      );
    const b = this.take(width, label);
    let value = 0n;
    for (let i = 0; i < width; i++)
      value = (value << 8n) | BigInt(b[this.littleEndian ? width - i - 1 : i]!);
    return signed && value >= 1n << BigInt(width * 8 - 1)
      ? value - (1n << BigInt(width * 8))
      : value;
  }
  number(width: number, label: string): number {
    const value = this.integer(width, label);
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new DeviceParseFailure(
        "limit",
        `${label} exceeds safe numeric bounds`,
      );
    return Number(value);
  }
  /** MSB-first seven-bit groups; Lua 5.4 terminates with a set high bit. */
  variable(label: string, terminalHighBit = false): number {
    let value = 0;
    for (let i = 0; i < 8; i++) {
      const b = this.byte(label);
      value = value * 128 + (b & 0x7f);
      if (!Number.isSafeInteger(value))
        throw new DeviceParseFailure(
          "limit",
          `${label} exceeds safe numeric bounds`,
        );
      if (((b & 0x80) !== 0) === terminalHighBit) return value;
    }
    throw new DeviceParseFailure(
      "limit",
      `${label} has an overlong variable integer`,
    );
  }
  float(width: number, label: string): JsonValue {
    const bytes = this.take(width, label);
    const value =
      width === 8
        ? this.littleEndian
          ? bytes.readDoubleLE()
          : bytes.readDoubleBE()
        : width === 4
          ? this.littleEndian
            ? bytes.readFloatLE()
            : bytes.readFloatBE()
          : NaN;
    if (width !== 4 && width !== 8)
      throw new DeviceParseFailure(
        "unsupported",
        `Unsupported ${label} representation`,
      );
    return Number.isFinite(value)
      ? value
      : { representation: bytes.toString("hex"), nonfinite: String(value) };
  }
}

export const runtimeText = (bytes: Buffer): JsonValue =>
  isUtf8(bytes)
    ? bytes.toString("utf8")
    : { encoding: "hex", value: bytes.toString("hex") };
export const runtimeHex = (value: bigint): string => `0x${value.toString(16)}`;

/** Counts every decoded structure/instruction, including entries nested in constants. */
export class RuntimeBudget {
  used = 0;
  constructor(readonly maxItems: number) {
    if (!Number.isSafeInteger(maxItems) || maxItems < 1)
      throw new DeviceParseFailure(
        "limit",
        "maxItems must be a positive safe integer",
      );
  }
  consume(count = 1): void {
    if (
      !Number.isSafeInteger(count) ||
      count < 0 ||
      count > this.maxItems - this.used
    )
      throw new DeviceParseFailure(
        "limit",
        `Decoded runtime structures exceed maxItems=${this.maxItems}`,
      );
    this.used += count;
  }
}

type MutableRuntimeReport = {
  -readonly [K in keyof DeviceParseResult]: DeviceParseResult[K];
};
export const runtimeReport = (format: string): MutableRuntimeReport => ({
  format,
  version: null,
  architecture: null,
  entryPoint: null,
  regions: [],
  items: [],
  limitations: [],
  warnings: [],
  complete: true,
});

export const assertRuntimeDepth = (depth: number): void => {
  if (depth > 64)
    throw new DeviceParseFailure("limit", "Runtime nesting exceeds 64 levels");
};
