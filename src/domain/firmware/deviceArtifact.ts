import { z } from "zod";
import { absoluteLocalPathStringSchema } from "../localPath.js";
import { digestSchema } from "../digests.js";
import { jsonObjectSchema } from "../jsonValue.js";

export const DEVICE_ARTIFACT_FORMATS = [
  "intel-hex",
  "srec",
  "uf2",
  "esp32",
  "esp8266",
  "esp-partitions",
  "ines",
  "gameboy",
  "gba",
  "uimage",
  "fit",
  "svd",
  "uefi",
  "littlefs",
  "mpy",
  "lua",
  "rtos",
  "cortex-m-vectors",
] as const;

export const deviceArtifactInputSchema = z.strictObject({
  path: absoluteLocalPathStringSchema,
  format: z.enum(DEVICE_ARTIFACT_FORMATS),
  max_file_bytes: z.int().min(1).max(134217728).default(33554432),
  max_items: z.int().min(1).max(100000).default(20000),
  item_offset: z.int().min(0).default(0),
  item_limit: z.int().min(1).max(1000).default(200),
  block_size: z
    .int()
    .min(128)
    .max(1048576)
    .exactOptional()
    .describe("littlefs block size in bytes; required for littlefs"),
  block_count: z.int().min(2).max(1048576).exactOptional(),
  layout_path: absoluteLocalPathStringSchema
    .exactOptional()
    .describe(
      "Explicit RTOS saved-memory or Cortex-M vector layout JSON; required for rtos and cortex-m-vectors",
    ),
});

export const extractDeviceArtifactInputSchema =
  deviceArtifactInputSchema.extend({
    output_directory: absoluteLocalPathStringSchema.describe(
      "New output directory with an existing parent; never overwrites a directory",
    ),
  });

const artifactIdentity = z.strictObject({
  path: z.string(),
  sha256: digestSchema,
  bytes: z.int().nonnegative(),
});
export const deviceArtifactReportSchema = z.strictObject({
  artifact: artifactIdentity,
  layout_artifact: artifactIdentity.nullable(),
  format: z.enum(DEVICE_ARTIFACT_FORMATS),
  version: z.string().nullable(),
  architecture: z.string().nullable(),
  entry_point: z.string().nullable(),
  regions: z.array(
    z.strictObject({
      name: z.string(),
      file_offset: z.int().nonnegative().nullable(),
      load_address: z.string().nullable(),
      bytes: z.int().nonnegative(),
      sha256: digestSchema,
      extracted_path: z.string().nullable(),
    }),
  ),
  items: z.array(jsonObjectSchema),
  coverage: z.strictObject({
    parser_complete: z.boolean(),
    total_items: z.int().nonnegative(),
    item_offset: z.int().nonnegative(),
    returned_items: z.int().nonnegative(),
    next_offset: z.int().nonnegative().nullable(),
  }),
  output_directory: z.string().nullable(),
  manifest_path: z.string().nullable(),
  warnings: z.array(z.string()),
  limitations: z.array(z.string()),
});

export type DeviceArtifactInput = z.output<typeof deviceArtifactInputSchema>;
export type ExtractDeviceArtifactInput = z.output<
  typeof extractDeviceArtifactInputSchema
>;
export type DeviceArtifactReport = z.output<typeof deviceArtifactReportSchema>;
