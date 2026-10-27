import { join } from "node:path";

import { expect, it } from "vitest";

import { estimateJavaScriptStaticApplicationProjection } from "../../../src/domain/javascript/javascriptApplicationProjectionResources.js";
import { analyzeJavaScriptStaticSource } from "../../../src/domain/javascript/javascriptStaticAnalysis.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  reconstructJavaScriptFixture,
  writeFixtureFiles,
} from "../../support/javascriptApplicationFixture.js";

// A bundle chunk made of many small functions, each with storage and request
// findings, as minified application chunks commonly are.
const chunk = (functions: number): string =>
  Array.from(
    { length: functions },
    (_, index) =>
      `export function f${String(index)}(a){` +
      `localStorage.setItem("pref.${String(index % 5)}",String(a));` +
      `const d=localStorage.getItem("pref.${String(index % 5)}");` +
      `return fetch("/rpc/p${String(index % 7)}",{method:"POST",body:d});}`,
  ).join("\n");

it("charges a bounded multiple of the application relationships it admits", async () => {
  const text = chunk(400);
  const root = await createTestTempDirectory("rea-projection-estimate-");
  await writeFixtureFiles(root, { "assets/chunk.js": text });
  const result = await reconstructJavaScriptFixture(join(root, "assets"));
  const facts = analyzeJavaScriptStaticSource(text);
  const checkpointBytes = Buffer.byteLength(JSON.stringify(facts));
  const estimate = estimateJavaScriptStaticApplicationProjection(
    facts,
    checkpointBytes,
    "chunk.js",
  );
  const serialized = Buffer.byteLength(JSON.stringify(result.graph));

  expect(facts.storage.length).toBeGreaterThanOrEqual(800);
  // Parsed JSON retains a few times its bytes. A charge far above that makes
  // the shared parent budget refuse later sources that would fit.
  expect(estimate).toBeGreaterThanOrEqual(3 * serialized);
  expect(estimate).toBeLessThanOrEqual(8 * serialized);
});
