import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  DeviceArtifactInput,
  ExtractDeviceArtifactInput,
  DeviceArtifactReport,
} from "../../domain/firmware/deviceArtifact.js";
import type { Result } from "../../domain/result.js";

export interface DeviceArtifactPort {
  readonly identity: ProviderIdentity;
  inspect(
    input: DeviceArtifactInput | ExtractDeviceArtifactInput,
    options?: ExecutionOptions,
  ): Promise<Result<DeviceArtifactReport, AnalysisError>>;
  close(): Promise<void>;
}
