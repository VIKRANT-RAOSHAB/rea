import {
  deviceArtifactInputSchema,
  extractDeviceArtifactInputSchema,
  deviceArtifactReportSchema,
} from "../../domain/firmware/deviceArtifact.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";
import { toolContractMetadata } from "../toolEffects.js";
import type { ToolContract } from "../toolContractTypes.js";

export const DEVICE_ARTIFACT_TOOL_CONTRACTS = [
  {
    name: "inspect_device_artifact",
    ...toolContractMetadata("inspect_device_artifact"),
    kind: "firmware-provider",
    description:
      "Inspect a caller-selected firmware carrier, cartridge, hardware description, embedded bytecode or RTOS saved-memory snapshot using portable built-in parsers. Select format explicitly. Report addressed payloads, source hashes/ranges, version-bounded decoded facts, unsupported features and item-page coverage. littlefs requires block_size; rtos requires a build-specific layout_path. No target execution or device access. Use extract_device_artifact to materialize supported regions, then open a returned raw image with its explicit processor/load/entry selections.",
    inputSchema: deviceArtifactInputSchema,
    outputSchema: evidenceResultOf(deviceArtifactReportSchema),
    examples: [
      {
        title: "Inspect a UF2 image",
        input: { path: "/tmp/firmware.uf2", format: "uf2" },
      },
      {
        title: "Inspect a saved RTOS memory image",
        input: {
          path: "/tmp/ram.bin",
          format: "rtos",
          layout_path: "/tmp/rtos-layout.json",
        },
      },
    ],
  },
  {
    name: "extract_device_artifact",
    ...toolContractMetadata("extract_device_artifact"),
    kind: "firmware-provider",
    description:
      "Parse an explicit local device artifact and publish its recoverable regions plus a provenance manifest into a new output directory. Parent must exist; existing destinations are never overwritten. Preserves container and derived payload hashes and original-file offsets where meaningful. Unsupported compression, cartridge banks and bytecode variants remain explicit limitations. No target code execution, mounts, firmware flashing or live hardware acquisition.",
    inputSchema: extractDeviceArtifactInputSchema,
    outputSchema: evidenceResultOf(deviceArtifactReportSchema),
    examples: [
      {
        title: "Extract an addressed Intel HEX payload",
        input: {
          path: "/tmp/firmware.hex",
          format: "intel-hex",
          output_directory: "/tmp/firmware-regions",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
