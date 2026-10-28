import { writeFile, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { Ajv2020 } from "ajv/dist/2020.js";
import { expect, it, onTestFinished } from "vitest";
import { z } from "zod";
import { createServer } from "../../../src/server/createServer.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import {
  createTestBinarySession,
  createCacheProvider,
} from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { silentLogger } from "../../../src/logger.js";

const connect = async () => {
  const session = createTestBinarySession(createCacheProvider([]));
  const server = createServer(
    { kind: "session", session },
    { logger: silentLogger },
  );
  const client = new Client({ name: "device-artifact-test", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);
  return { client, session };
};
const value = (result: unknown) =>
  z
    .object({ normalized_result: z.record(z.string(), z.unknown()) })
    .parse(result).normalized_result;

it("advertises both exact device artifact contracts after JSON Schema conversion", () => {
  const ajv = new Ajv2020({ strict: false });
  for (const name of [
    "inspect_device_artifact",
    "extract_device_artifact",
  ] as const) {
    const contract = toolContract(name);
    const validate = ajv.compile(
      z.toJSONSchema(contract.inputSchema, { io: "input" }),
    );
    for (const example of contract.examples)
      expect(validate(example.input), JSON.stringify(validate.errors)).toBe(
        true,
      );
    expect(validate({ path: "/tmp/a", format: "invented" })).toBe(false);
  }
});

it("inspects addressed firmware, pages items, records provenance and exclusively extracts verified bytes", async () => {
  const root = await createTestTempDirectory("rea-device-mcp-");
  const path = join(root, "firmware.hex");
  const source = Buffer.from(":02000000704747\n:00000001FF\n");
  await writeFile(path, source);
  const { client } = await connect();
  const inspected = await client.callTool({
    name: "inspect_device_artifact",
    arguments: { path, format: "intel-hex", item_limit: 1 },
  });
  expect(inspected.isError, JSON.stringify(inspected.content)).not.toBe(true);
  const report = value(inspected.structuredContent);
  expect(report.artifact).toMatchObject({
    path,
    sha256: createHash("sha256").update(source).digest("hex"),
  });
  expect(report.coverage).toMatchObject({
    returned_items: 1,
    item_offset: 0,
    next_offset: 1,
  });
  const regions = z
    .array(
      z.object({
        sha256: z.string(),
        load_address: z.string(),
        bytes: z.number(),
        file_offset: z.number().nullable(),
      }),
    )
    .parse(report.regions);
  expect(regions[0]).toMatchObject({
    load_address: "0x0",
    bytes: 2,
    file_offset: null,
  });
  const directory = join(root, "regions");
  const extracted = await client.callTool({
    name: "extract_device_artifact",
    arguments: { path, format: "intel-hex", output_directory: directory },
  });
  expect(extracted.isError, JSON.stringify(extracted.content)).not.toBe(true);
  expect(
    (await readFile(join(directory, "region-00000.bin"))).equals(
      Buffer.from("7047", "hex"),
    ),
  ).toBe(true);
  expect(
    JSON.parse(await readFile(join(directory, "manifest.json"), "utf8"))
      .artifact.sha256,
  ).toBe(createHash("sha256").update(source).digest("hex"));
  const before = await readdir(directory);
  const collision = await client.callTool({
    name: "extract_device_artifact",
    arguments: { path, format: "intel-hex", output_directory: directory },
  });
  expect(collision.isError).toBe(true);
  expect(await readdir(directory)).toEqual(before);
  expect((await readFile(path)).equals(source)).toBe(true);
});

it("rejects malformed checksums, missing littlefs geometry and RTOS layout before publication", async () => {
  const root = await createTestTempDirectory("rea-device-mcp-errors-");
  const path = join(root, "bad.hex");
  await writeFile(path, ":02000000704748\n:00000001FF\n");
  const { client } = await connect();
  for (const input of [
    { path, format: "intel-hex" },
    { path, format: "littlefs" },
    { path, format: "rtos" },
  ]) {
    const response = await client.callTool({
      name: "inspect_device_artifact",
      arguments: input,
    });
    expect(response.isError).toBe(true);
  }
});
