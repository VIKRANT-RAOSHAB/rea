import {
  DeviceParseFailure,
  type DeviceParseOptions,
  type DeviceParseResult,
} from "./types.js";
import { parseLuaChunk } from "./runtime-lua.js";
import { parseMicroPython } from "./runtime-mpy.js";
import { parseRtosSnapshot } from "./runtime-rtos.js";

/** Inspect version-selected embedded runtimes without loading or executing code. */
export const parseDeviceRuntime = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  switch (options.format) {
    case "lua":
      return parseLuaChunk(bytes, options);
    case "mpy":
      return parseMicroPython(bytes, options);
    case "rtos":
      return parseRtosSnapshot(bytes, options);
    default:
      throw new DeviceParseFailure(
        "unsupported",
        `Unknown runtime format: ${options.format}`,
      );
  }
};
