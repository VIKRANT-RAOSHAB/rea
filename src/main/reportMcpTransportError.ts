import type { Logger } from "pino";
import { z } from "zod";

import {
  MCP_CONNECTION_LOST,
  MCP_TRANSPORT_ERROR,
  MCP_VALIDATION_FAILED,
} from "./messages.js";

/** SDK error callbacks also report recoverable validation and protocol errors. */
export const reportMcpTransportError = (
  error: unknown,
  logger: Logger,
  writeStderr: (text: string) => void,
): void => {
  const diagnostic =
    error instanceof z.ZodError
      ? { kind: "validation_error", message: MCP_VALIDATION_FAILED }
      : error instanceof Error &&
          "code" in error &&
          (error.code === "EPIPE" || error.code === "ECONNRESET")
        ? { kind: "connection_lost", message: MCP_CONNECTION_LOST }
        : { kind: "unknown", message: MCP_TRANSPORT_ERROR };
  // Do not echo raw frames or exception text, which can contain caller data.
  logger.error({ kind: diagnostic.kind }, diagnostic.message);
  writeStderr(`${diagnostic.message}\n`);
};
