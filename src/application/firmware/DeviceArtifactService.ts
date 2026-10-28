import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { DeviceArtifactPort } from "./DeviceArtifactPort.js";
import {
  deviceArtifactInputSchema,
  extractDeviceArtifactInputSchema,
  deviceArtifactReportSchema,
} from "../../domain/firmware/deviceArtifact.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { parseAnalysisInput } from "../AnalysisInput.js";
import { createEvidence } from "../../domain/evidence.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { err } from "../../domain/result.js";

export type DeviceArtifactOperation =
  | "inspect_device_artifact"
  | "extract_device_artifact";

/** Both adapters use the same validation, source identity and Evidence envelope. */
export class DeviceArtifactService {
  constructor(readonly provider: DeviceArtifactPort) {}
  close() {
    return this.provider.close();
  }
  async execute(
    operation: DeviceArtifactOperation,
    rawInput: unknown,
    options?: ExecutionOptions,
  ) {
    const schema =
      operation === "extract_device_artifact"
        ? extractDeviceArtifactInputSchema
        : deviceArtifactInputSchema;
    const parsed = parseAnalysisInput(
      operation,
      rawInput,
      schema,
      options?.signal,
    );
    if (!parsed.ok) return parsed;
    const input = parsed.value;
    if (
      !isAbsolute(input.path) ||
      (input.layout_path !== undefined && !isAbsolute(input.layout_path)) ||
      ("output_directory" in input &&
        (typeof input.output_directory !== "string" ||
          !isAbsolute(input.output_directory)))
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: "All selected paths must be absolute paths on this host.",
          },
        ]),
      );
    if (
      (input.format === "littlefs" && input.block_size === undefined) ||
      (["rtos", "cortex-m-vectors"].includes(input.format) &&
        input.layout_path === undefined)
    )
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: [input.format === "littlefs" ? "block_size" : "layout_path"],
            reason: "invalid_value",
            message:
              "The selected format requires explicit geometry or a saved-memory layout.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input, options);
    if (!inspected.ok) return inspected;
    const output = deviceArtifactReportSchema.safeParse(inspected.value);
    if (
      !output.success ||
      output.data.artifact.path !== input.path ||
      output.data.artifact.bytes > input.max_file_bytes ||
      output.data.items.length > input.item_limit ||
      output.data.coverage.total_items > input.max_items
    )
      return err(
        new AnalysisOutputError(
          operation,
          "Device artifact provider returned invalid output or changed the selected identity.",
        ),
      );
    const report = output.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: report.artifact.path,
          format: "file",
          sha256: report.artifact.sha256,
        },
        this.provider.identity,
        {
          operation,
          parameters: input,
          result: report,
          confidence: "observed",
          limitations: report.limitations,
          locations: [
            { kind: "artifact-path", path: report.artifact.path },
            ...(report.layout_artifact === null
              ? []
              : [
                  {
                    kind: "artifact-path" as const,
                    path: report.layout_artifact.path,
                  },
                ]),
          ],
        },
      ),
      options?.signal,
    );
  }
}
