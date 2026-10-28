import { Readable } from "node:stream";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { SafeOutputTree } from "../../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../artifacts/SafeOutputTreeCreationFailure.js";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { DeviceArtifactReport } from "../../domain/firmware/deviceArtifact.js";
import type { DeviceRegion } from "./types.js";

/** Publish using the existing exclusive-output owner, readback and cleanup leases. */
export const publishDeviceArtifact = async (context: {
  directory: string;
  report: DeviceArtifactReport;
  regions: readonly DeviceRegion[];
  resources: ArtifactResourceScope;
  signal?: AbortSignal;
}): Promise<void> => {
  let tree: SafeOutputTree | undefined;
  let releaseAttempted = false;
  try {
    tree = await SafeOutputTree.create(context.directory);
    for (let index = 0; index < context.regions.length; index++) {
      const payload = context.regions[index]!,
        region = context.report.regions[index]!;
      const name = `region-${String(index).padStart(5, "0")}.bin`;
      const written = await tree.write(
        name,
        Readable.from([payload.bytes]),
        { bytes: payload.bytes.length, sha256: region.sha256 },
        context.signal,
      );
      region.extracted_path = join(tree.outputRoot, written.relativePath);
    }
    context.report.output_directory = tree.outputRoot;
    context.report.manifest_path = join(tree.outputRoot, "manifest.json");
    const manifest = Buffer.from(
      JSON.stringify(context.report, null, 2) + "\n",
    );
    await tree.write(
      "manifest.json",
      Readable.from([manifest]),
      {
        bytes: manifest.length,
        sha256: createHash("sha256").update(manifest).digest("hex"),
      },
      context.signal,
    );
    await tree.commit(context.signal);
    releaseAttempted = true;
    const released = await context.resources.release({
      kind: "output-tree",
      resource: tree.outputRoot,
      tree,
    });
    if (released.kind === "failed")
      throw context.resources.cleanupFailure({ kind: "completed" }, [released]);
  } catch (cause) {
    if (releaseAttempted) throw cause;
    if (cause instanceof SafeOutputTreeCreationFailure) tree = cause.tree;
    if (tree !== undefined) {
      const released = await context.resources.release({
        kind: "output-tree",
        resource: tree.outputRoot,
        tree,
      });
      if (released.kind === "failed")
        throw context.resources.cleanupFailure({ kind: "failed", cause }, [
          released,
        ]);
    }
    throw cause;
  }
};
