import type { JsonValue } from "../../domain/jsonValue.js";

/** Explicit caller choices for portable, execution-free device artifact inspection. */
export interface DeviceParseOptions {
  readonly format: string;
  readonly maxItems: number;
  readonly blockSize?: number;
  readonly blockCount?: number;
  readonly layout?: Record<string, unknown>;
}

/** A recoverable payload; its bytes are not included in the public JSON report. */
export interface DeviceRegion {
  readonly name: string;
  readonly fileOffset: number | null;
  readonly loadAddress: string | null;
  readonly bytes: Buffer;
}

/** Parsed facts, with the supported coverage recorded independently of success. */
export interface DeviceParseResult {
  readonly format: string;
  readonly version: string | null;
  readonly architecture: string | null;
  readonly entryPoint: string | null;
  readonly regions: DeviceRegion[];
  readonly items: Record<string, JsonValue>[];
  readonly limitations: string[];
  readonly warnings: string[];
  readonly complete: boolean;
}

/** Expected malformed-input, unsupported-profile and selected-budget refusals. */
export class DeviceParseFailure extends Error {
  constructor(
    readonly kind: "format" | "unsupported" | "limit",
    message: string,
  ) {
    super(message);
    this.name = "DeviceParseFailure";
  }
}
