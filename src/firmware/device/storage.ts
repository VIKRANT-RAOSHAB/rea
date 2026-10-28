import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { DeviceParseFailure } from "./types.js";
import { parseUefi } from "./storage-uefi.js";
import { parseLittlefs } from "./storage-littlefs.js";

/** Read-only storage-container dispatch; no mounts or target execution. */
export const parseDeviceStorage = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  if (options.format === "uefi") return parseUefi(bytes, options);
  if (options.format === "littlefs") return parseLittlefs(bytes, options);
  throw new DeviceParseFailure(
    "unsupported",
    `Unsupported storage format: ${options.format}`,
  );
};
