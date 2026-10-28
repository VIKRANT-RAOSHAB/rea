import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { unsupported } from "./loaders-common.js";
import { parseIntelHex, parseSRecord, parseUf2 } from "./loaders-records.js";
import { parseEspImage, parseEspPartitions } from "./loaders-esp.js";
import { parseInes, parseGameboy, parseGba } from "./loaders-console.js";
import { parseUimage } from "./loaders-boot.js";
import { parseFit } from "./loaders-fit.js";
import { parseSvd } from "./loaders-svd.js";

/** One explicit format selects one parser; suffixes and unrecognized bytes never select a CPU. */
export const parseDeviceLoader = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  switch (options.format) {
    case "intel-hex":
      return parseIntelHex(bytes, options);
    case "srec":
      return parseSRecord(bytes, options);
    case "uf2":
      return parseUf2(bytes, options);
    case "esp32":
    case "esp8266":
      return parseEspImage(bytes, options);
    case "esp-partitions":
      return parseEspPartitions(bytes, options);
    case "ines":
      return parseInes(bytes, options);
    case "gameboy":
      return parseGameboy(bytes, options);
    case "gba":
      return parseGba(bytes, options);
    case "uimage":
      return parseUimage(bytes, options);
    case "fit":
      return parseFit(bytes, options);
    case "svd":
      return parseSvd(bytes, options);
    default:
      return unsupported(
        `No device loader for explicitly selected format ${options.format}`,
      );
  }
};
