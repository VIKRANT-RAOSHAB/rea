import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { DeviceArtifactService } from "../application/firmware/DeviceArtifactService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { DEVICE_ARTIFACT_TOOL_CONTRACTS } from "../contracts/firmware/deviceArtifactToolContracts.js";
import { createContractToolHandler } from "./contractToolHandler.js";
import { applicationToolRegistrationOptions } from "./toolRegistrationOptions.js";

export const registerDeviceArtifactTools = (
  server: EvidenceMcpServer,
  service: DeviceArtifactService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  for (const contract of DEVICE_ARTIFACT_TOOL_CONTRACTS)
    server.registerTool(
      contract.name,
      applicationToolRegistrationOptions(contract),
      handler(contract),
    );
};
