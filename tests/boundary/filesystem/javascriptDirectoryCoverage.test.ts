import { execFile } from "node:child_process";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, it } from "vitest";

import { scanArtifactInventory } from "../../fixtures/artifactInventory.js";
import { analyzeJavaScriptApplication } from "../../support/javascriptApplicationScope.js";
import { javascriptApplicationAnalysisResultSchema } from "../../../src/domain/javascript/javascriptApplicationAnalysis.js";
import { DirectoryArtifactReader } from "../../../src/artifacts/DirectoryArtifactReader.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

it
  .skipIf(process.platform === "win32" || process.getuid?.() === 0)
  .for(["private/**", "private", "private/hidden?.js"])(
  "keeps selector %s unresolved under unreadable directory traversal",
  async (selector) => {
    const root = await createTestTempDirectory("rea-js-selection-permissions-");
    const denied = join(root, "private");
    await mkdir(denied);
    await writeFile(join(root, "good.js"), "export const observed = true;");
    await writeFile(join(denied, "hidden1.js"), "export const unseen = true;");
    await chmod(denied, 0);
    try {
      const result = await analyzeJavaScriptApplication({
        input_path: root,
        source_paths: [selector],
      });
      expect(result).toMatchObject({
        ok: false,
        error: {
          reason: "unavailable",
          partialObservation: {
            kind: "artifact-inventory",
            inventory: { coverage: { status: "unknown" } },
          },
        },
      });
    } finally {
      await chmod(denied, 0o700);
    }
  },
);

it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "keeps observed folder matches useful with explicit incomplete inventory coverage",
  async () => {
    const root = await createTestTempDirectory("rea-js-selection-readable-");
    const denied = join(root, "private");
    await mkdir(denied);
    await mkdir(join(root, "src"));
    await writeFile(
      join(root, "src", "good.js"),
      "export const observed = true;",
    );
    await writeFile(join(denied, "hidden.js"), "export const unseen = true;");
    await chmod(denied, 0);
    try {
      const response = await analyzeJavaScriptApplication({
        input_path: root,
        source_paths: ["src"],
      });
      if (!response.ok) throw response.error;
      const result = javascriptApplicationAnalysisResultSchema.parse(
        response.value.normalized_result,
      );
      expect(result.source_selection).toMatchObject({
        requested_paths: ["src"],
        selected_paths: ["src/good.js"],
      });
      expect(result.graph.coverage.status).toBe("partial");
      expect(result.graph.limitations).toContainEqual(
        expect.stringContaining('directory-descendants at "private"'),
      );
    } finally {
      await chmod(denied, 0o700);
    }
  },
);

it.skipIf(process.platform === "win32")(
  "projects inventoried special-entry omissions into partial application coverage",
  async () => {
    const root = await createTestTempDirectory("rea-js-directory-fifo-");
    await writeFile(join(root, "good.js"), "export const answer = 42;");
    await promisify(execFile)("mkfifo", [join(root, "events.pipe")], {
      timeout: 2_000,
    });
    const analyzed = await analyzeJavaScriptApplication({ input_path: root });
    if (!analyzed.ok) throw analyzed.error;
    const result = javascriptApplicationAnalysisResultSchema.parse(
      analyzed.value.normalized_result,
    );
    expect(result.graph.coverage).toMatchObject({
      status: "partial",
      truncated: false,
    });
    expect(result.graph.limitations).toContain(
      'Artifact traversal omitted fifo at "events.pipe".',
    );
    expect(
      result.semantic_graph.nodes.some(
        ({ identity }) => identity.module_path === "good.js",
      ),
    ).toBe(true);
  },
);

it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "retains readable source facts and permission omissions while refusing an unreadable root",
  async () => {
    const root = await createTestTempDirectory("rea-js-directory-permissions-");
    const deniedFile = join(root, "closed.js");
    const deniedDirectory = join(root, "private");
    await mkdir(deniedDirectory);
    await writeFile(
      join(root, "good.js"),
      'require("./private/hidden.js"); const { BrowserWindow } = require("electron"); new BrowserWindow().loadFile("page.html"); module.exports = 42;',
    );
    await writeFile(
      join(root, "page.html"),
      "<!doctype html><title>Fixture</title>",
    );
    await writeFile(deniedFile, "export const unseen = true;");
    await writeFile(
      join(deniedDirectory, "hidden.js"),
      "export const hidden = true;",
    );
    await chmod(deniedFile, 0);
    await chmod(deniedDirectory, 0);
    try {
      const inventory = await scanArtifactInventory(root);
      expect(inventory.coverage.status).toBe("unknown");
      expect(
        inventory.occurrences.find(
          ({ logical_path }) => logical_path === "closed.js",
        ),
      ).toMatchObject({ hash_status: "unavailable", artifact_id: null });
      expect(
        inventory.occurrences.some(
          ({ logical_path }) => logical_path === "private/hidden.js",
        ),
      ).toBe(false);
      expect(inventory.limitations).toContainEqual(
        expect.stringContaining('directory-descendants at "private"'),
      );
      const selectedReader = new DirectoryArtifactReader(root);
      try {
        await expect(
          (async () => {
            for await (const entry of selectedReader.entries())
              expect(entry.path).not.toBe("private/hidden.js");
          })(),
        ).rejects.toMatchObject({
          reason: "io",
          entryPath: "private",
        });
      } finally {
        await selectedReader.close();
      }
      const analyzed = await analyzeJavaScriptApplication({ input_path: root });
      if (!analyzed.ok) throw analyzed.error;
      const result = javascriptApplicationAnalysisResultSchema.parse(
        analyzed.value.normalized_result,
      );
      expect(result.graph.coverage).toMatchObject({
        status: "partial",
        truncated: false,
      });
      expect(result.graph.limitations).toEqual(
        expect.arrayContaining([...inventory.limitations]),
      );
      const unavailableScopes = result.graph.nodes
        .filter(({ kind }) => kind === "unknown")
        .flatMap(({ observations }) => observations)
        .filter(
          ({ properties }) =>
            properties.path === "closed.js" &&
            properties.operation === "analyze-javascript-source",
        );
      expect(unavailableScopes).toHaveLength(1);
      expect(unavailableScopes[0]).toMatchObject({
        properties: {
          source_bytes_available: false,
          inventory_occurrence_id: inventory.occurrences.find(
            ({ logical_path }) => logical_path === "closed.js",
          )?.occurrence_id,
        },
        evidence: {
          authority: "ast-static-analysis",
          state: "unavailable",
          artifact: { available: true, sha256: result.root_artifact_sha256 },
        },
      });
      const unavailableEntry = result.graph.nodes.find(
        ({ identity }) =>
          identity.strategy === "canonical-path" &&
          identity.path === "closed.js",
      );
      expect(unavailableEntry).toMatchObject({
        kind: "artifact",
        observations: [
          expect.objectContaining({
            properties: expect.objectContaining({ content_available: false }),
            evidence: expect.objectContaining({
              extractor: expect.objectContaining({
                operation: "inventory-unavailable-entry",
              }),
            }),
          }),
        ],
      });
      expect(
        result.semantic_graph.nodes.some(
          ({ identity }) => identity.module_path === "good.js",
        ),
      ).toBe(true);
      const moduleLinks = result.graph.edges.filter(
        ({ relation, properties }) =>
          relation === "imports" &&
          properties.specifier === "./private/hidden.js" &&
          properties.module_link_kind !== undefined,
      );
      expect(moduleLinks).toHaveLength(1);
      expect(moduleLinks[0]?.properties).toMatchObject({
        resolution_status: "unavailable",
        resolved_path: null,
      });
      const renderer = result.graph.nodes
        .flatMap(({ observations }) => observations)
        .find(({ properties }) => properties.declared_path === "page.html");
      expect(renderer?.properties).toMatchObject({
        resolution_status: "unavailable",
        resolved_path: null,
      });
      expect(
        await analyzeJavaScriptApplication({
          input_path: root,
          source_paths: ["private/hidden.js"],
        }),
      ).toMatchObject({
        ok: false,
        error: {
          reason: "unavailable",
          partialObservation: {
            kind: "artifact-inventory",
            inventory: { coverage: { status: "unknown" } },
          },
        },
      });
      await chmod(root, 0);
      await expect(scanArtifactInventory(root)).rejects.toMatchObject({
        reason: "io",
      });
    } finally {
      await chmod(root, 0o700);
      await chmod(deniedDirectory, 0o700);
      await chmod(deniedFile, 0o600);
    }
  },
);
