import { publishDeviceArtifact } from "./DeviceArtifactPublication.js";
import { createHash } from "node:crypto";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import {
  artifactFilePrimaryFacts,
  artifactFileCancellationCause,
} from "../../artifacts/ArtifactFileOperation.js";
import {
  projectStableArtifactFailure,
  projectArtifactCloseFailure,
} from "../../artifacts/StableArtifactFailure.js";
import type { DeviceArtifactPort } from "../../application/firmware/DeviceArtifactPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import type {
  DeviceArtifactInput,
  ExtractDeviceArtifactInput,
  DeviceArtifactReport,
} from "../../domain/firmware/deviceArtifact.js";
import {
  AnalysisInputError,
  AnalysisUnsupportedTargetError,
  AnalysisResourceConstraintError,
  AnalysisCancelledError,
  AnalysisArtifactChangedError,
  AnalysisAccessDeniedError,
} from "../../domain/analysisErrorCore.js";
import { ArtifactOperationError } from "../../domain/artifactOperationError.js";
import { jsonObjectSchema } from "../../domain/jsonValue.js";
import { err, ok } from "../../domain/result.js";
import { DeviceParseFailure } from "./types.js";
import { parseDeviceLoader } from "./loaders.js";
import { parseDeviceStorage } from "./storage.js";
import { parseDeviceRuntime } from "./runtime.js";
import { parseCortexVectors } from "./vectors.js";
import { DEVICE_ARTIFACT_PROVIDER as IDENTITY } from "../../domain/investigationProviders.js";

const digest = (bytes: Buffer) =>
  createHash("sha256").update(bytes).digest("hex");
type Input = DeviceArtifactInput | ExtractDeviceArtifactInput;

/** Portable, bounded file parsing and explicitly requested additive extraction. */
export class DeviceArtifactProvider implements DeviceArtifactPort {
  readonly identity = IDENTITY;
  readonly #resources = new ArtifactResourceScope();
  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause) {
      throw projectArtifactCloseFailure(
        cause,
        IDENTITY.id,
        "inspect_device_artifact",
      );
    }
  }
  async inspect(input: Input, options?: ExecutionOptions) {
    const operation =
      "output_directory" in input
        ? "extract_device_artifact"
        : "inspect_device_artifact";
    const cancelled = () => {
      if (options?.signal?.aborted)
        throw new AnalysisCancelledError(operation, {
          cause: options.signal.reason,
        });
    };
    try {
      return await this.#resources.run(async () => {
        cancelled();
        const source = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        let layout: Record<string, unknown> | undefined;
        let layoutArtifact: DeviceArtifactReport["layout_artifact"] = null;
        if (input.layout_path !== undefined) {
          const selected = await readStableArtifact(
            input.layout_path,
            1048576,
            options?.signal,
            undefined,
            this.#resources,
          );
          layout = jsonObjectSchema.parse(
            JSON.parse(selected.bytes.toString("utf8")),
          );
          layoutArtifact = {
            path: input.layout_path,
            sha256: selected.sha256,
            bytes: selected.bytes.length,
          };
        }
        const parserOptions = {
          format: input.format,
          maxItems: input.max_items,
          ...(input.block_size === undefined
            ? {}
            : { blockSize: input.block_size }),
          ...(input.block_count === undefined
            ? {}
            : { blockCount: input.block_count }),
          ...(layout === undefined ? {} : { layout }),
        };
        const result =
          input.format === "cortex-m-vectors"
            ? parseCortexVectors(source.bytes, parserOptions)
            : ["uefi", "littlefs"].includes(input.format)
              ? parseDeviceStorage(source.bytes, parserOptions)
              : ["mpy", "lua", "rtos"].includes(input.format)
                ? parseDeviceRuntime(source.bytes, parserOptions)
                : parseDeviceLoader(source.bytes, parserOptions);
        cancelled();
        if (result.format !== input.format)
          throw new DeviceParseFailure(
            "format",
            "Parser changed the selected format.",
          );
        if (
          result.items.length > input.max_items ||
          result.regions.length > input.max_items
        )
          throw new DeviceParseFailure(
            "limit",
            "Decoded item/region count exceeds max_items.",
          );
        let decodedBytes = 0;
        const regions = result.regions.map((region) => {
          decodedBytes += region.bytes.length;
          if (decodedBytes > 134217728)
            throw new DeviceParseFailure(
              "limit",
              "Recoverable region bytes exceed the fixed 128 MiB decoded-byte ceiling.",
            );
          if (
            region.fileOffset !== null &&
            (!Number.isSafeInteger(region.fileOffset) ||
              region.fileOffset < 0 ||
              region.fileOffset > source.bytes.length - region.bytes.length ||
              !region.bytes.equals(
                source.bytes.subarray(
                  region.fileOffset,
                  region.fileOffset + region.bytes.length,
                ),
              ))
          )
            throw new DeviceParseFailure(
              "format",
              "Parser returned a payload with an invalid original-file mapping.",
            );
          return {
            name: region.name,
            file_offset: region.fileOffset,
            load_address: region.loadAddress,
            bytes: region.bytes.length,
            sha256: digest(region.bytes),
            extracted_path: null as string | null,
          };
        });
        const end = Math.min(
          input.item_offset + input.item_limit,
          result.items.length,
        );
        const report: DeviceArtifactReport = {
          artifact: {
            path: input.path,
            sha256: source.sha256,
            bytes: source.bytes.length,
          },
          layout_artifact: layoutArtifact,
          format: input.format,
          version: result.version,
          architecture: result.architecture,
          entry_point: result.entryPoint,
          regions,
          items: result.items.slice(input.item_offset, end),
          coverage: {
            parser_complete: result.complete,
            total_items: result.items.length,
            item_offset: input.item_offset,
            returned_items: Math.max(0, end - input.item_offset),
            next_offset: end < result.items.length ? end : null,
          },
          output_directory: null,
          manifest_path: null,
          warnings: result.warnings,
          limitations: [
            ...result.limitations,
            "Static inspection does not execute target code, flash devices, observe live tasks, or establish original source recovery. Payload hashes identify extracted bytes; decoded regions may have no direct original-file offset.",
          ],
        };
        if ("output_directory" in input)
          await publishDeviceArtifact({
            directory: input.output_directory,
            report,
            regions: result.regions,
            resources: this.#resources,
            ...(options?.signal === undefined
              ? {}
              : { signal: options.signal }),
          });
        return ok(report);
      });
    } catch (cause) {
      const facts = artifactFilePrimaryFacts(cause);
      const value = facts.cause;
      const classified =
        value instanceof DeviceParseFailure
          ? value.kind === "unsupported"
            ? new AnalysisUnsupportedTargetError(
                operation,
                input.path,
                value.message,
                { cause: value },
              )
            : value.kind === "limit"
              ? new AnalysisResourceConstraintError(
                  operation,
                  "capacity",
                  value.message,
                  { max_items: input.max_items },
                  {
                    cause: value,
                    retryable: false,
                    remediationAction:
                      "Select a smaller artifact or raise max_items within the supported ceiling.",
                  },
                )
              : new AnalysisInputError(operation, { cause: value }, [
                  {
                    path: ["path"],
                    reason: "invalid_format",
                    message: value.message,
                  },
                ])
          : value instanceof AnalysisCancelledError
            ? value
            : value instanceof ArtifactReaderFailure &&
                value.reason === "cancelled"
              ? new AnalysisCancelledError(operation, {
                  cause: artifactFileCancellationCause(value),
                })
              : value instanceof ArtifactReaderFailure &&
                  value.reason === "integrity"
                ? new AnalysisArtifactChangedError(
                    operation,
                    input.path,
                    value.message,
                    { cause: value },
                  )
                : value instanceof ArtifactReaderFailure &&
                    value.reason === "limit"
                  ? new AnalysisResourceConstraintError(
                      operation,
                      "memory",
                      value.message,
                      { max_file_bytes: input.max_file_bytes },
                      {
                        cause: value,
                        retryable: false,
                        remediationAction:
                          "Select a smaller file or raise max_file_bytes within the supported ceiling.",
                      },
                    )
                  : value instanceof Error &&
                      "code" in value &&
                      (value.code === "EPERM" || value.code === "EACCES")
                    ? new AnalysisAccessDeniedError(
                        operation,
                        input.path,
                        value.code,
                        { cause: value },
                      )
                    : new ArtifactOperationError(
                        operation,
                        "io",
                        undefined,
                        value instanceof Error ? value.message : String(value),
                        { cause: value },
                      );
      return err(
        projectStableArtifactFailure(
          cause,
          classified,
          input.path,
          IDENTITY.id,
          operation,
        ),
      );
    }
  }
}
