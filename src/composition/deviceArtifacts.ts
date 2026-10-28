import { DeviceArtifactService } from "../application/firmware/DeviceArtifactService.js";
import { DeviceArtifactProvider } from "../firmware/device/DeviceArtifactProvider.js";

export const createDeviceArtifactService = () =>
  new DeviceArtifactService(new DeviceArtifactProvider());
