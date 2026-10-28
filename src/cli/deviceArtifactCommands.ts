import { z } from "incur";
import { createDeviceArtifactService } from "../composition/deviceArtifacts.js";
import { deviceArtifactInputSchema } from "../domain/firmware/deviceArtifact.js";
import { localPathStringSchema } from "../domain/localPath.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { projectCliAnalysisResult } from "./projectCliAnalysisResult.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { logCliCommand } from "../cliLogging.js";
import type { CliInstance } from "./types.js";
import type { Logger } from "pino";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { cliIntegerArgument } from "./options.js";

export const registerDeviceArtifactCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const schema = deviceArtifactInputSchema.shape;
  const fields = {
    "artifact-format": schema.format,
    maxFileBytes: cliIntegerArgument(1).default(
      schema.max_file_bytes.parse(undefined),
    ),
    maxItems: cliIntegerArgument(1).default(schema.max_items.parse(undefined)),
    itemOffset: cliIntegerArgument(0).default(
      schema.item_offset.parse(undefined),
    ),
    itemLimit: cliIntegerArgument(1).default(
      schema.item_limit.parse(undefined),
    ),
    blockSize: cliIntegerArgument(128).optional(),
    blockCount: cliIntegerArgument(2).optional(),
    layoutPath: localPathStringSchema.optional(),
  };
  for (const extract of [false, true]) {
    const command = extract
      ? CLI_COMMANDS.extractDeviceArtifact
      : CLI_COMMANDS.inspectDeviceArtifact;
    const operation = extract
      ? "extract_device_artifact"
      : "inspect_device_artifact";
    cli.command(command, {
      description: extract
        ? "Extract device artifact regions with verified hashes into a new directory"
        : "Inspect firmware, cartridge, bytecode and saved RTOS structures without execution",
      args: z.object({
        path: localPathStringSchema,
        ...(extract ? { outputDirectory: localPathStringSchema } : {}),
      }),
      options: z.object(fields),
      run: ({ args, options }) =>
        withCommandCancellation((signal) =>
          logCliCommand(logger, command, () => {
            const service = createDeviceArtifactService();
            return finishAnalysisCommand(
              () =>
                service.execute(
                  operation,
                  {
                    path: absoluteCallerPath(args.path),
                    format: options["artifact-format"],
                    max_file_bytes: options.maxFileBytes,
                    max_items: options.maxItems,
                    item_offset: options.itemOffset,
                    item_limit: options.itemLimit,
                    ...(options.blockSize === undefined
                      ? {}
                      : { block_size: options.blockSize }),
                    ...(options.blockCount === undefined
                      ? {}
                      : { block_count: options.blockCount }),
                    ...(options.layoutPath === undefined
                      ? {}
                      : {
                          layout_path: absoluteCallerPath(options.layoutPath),
                        }),
                    ...(extract &&
                    "outputDirectory" in args &&
                    typeof args.outputDirectory === "string"
                      ? {
                          output_directory: absoluteCallerPath(
                            args.outputDirectory,
                          ),
                        }
                      : {}),
                  },
                  { signal },
                ),
              service,
              "rea-device-artifact",
              operation,
              signal,
            ).then(projectCliAnalysisResult);
          }),
        ),
    });
  }
};
