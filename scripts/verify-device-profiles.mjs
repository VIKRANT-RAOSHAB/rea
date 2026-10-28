import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

// Tiny analyst-authored instruction sequences; only the analysis engine runs.
const fixtures = [
  ["x86", "b807000000c3"],
  ["x86_64", "b807000000c3"],
  ["arm64", "e00080d2c0035fd6"],
  ["6502", "a90760"],
  ["m68k", "70074e75"],
  ["armv4t", "0700a0e31eff2fe1"],
  ["arm", "0700a0e31eff2fe1"],
  ["thumb", "07207047"],
  ["cortex-m", "07207047"],
  ["avr8", "87e00895"],
  ["pic12", "0708"],
  ["pic16", "0734"],
  ["pic18", "070c"],
  ["8051", "740722"],
  ["xtensa", "0df0"],
  ["mips32le", "0800e00300000000"],
  ["mips32be", "03e0000800000000"],
  ["riscv32", "1305700067800000"],
  ["riscv64", "1305700067800000"],
  ["z80", "3e07c9"],
  ["msp430", "3041"],
];
const selected = process.argv.slice(2);
const workspace = resolve(".cache/device-verification");
await mkdir(workspace, { recursive: true });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [resolve("scripts/rea.mjs"), "mcp"],
  env: {
    ...process.env,
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_LOG_LEVEL: "silent",
  },
  stderr: "pipe",
});
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-16000);
});
const client = new Client({
  name: "rea-device-profile-verifier",
  version: "1",
});
let reports = [];
try {
  reports = JSON.parse(
    await readFile(join(workspace, "profiles.json"), "utf8"),
  ).reports;
} catch (cause) {
  if (cause.code !== "ENOENT") throw cause;
}
const invoke = async (name, args = {}) => {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  if (result.isError)
    throw Error(
      `${name}: ${JSON.stringify(result.structuredContent ?? result.content).slice(0, 10000)}`,
    );
  return result.structuredContent;
};
try {
  await client.connect(transport);
  for (const [architecture, hex] of fixtures) {
    if (selected.length && !selected.includes(architecture)) continue;
    const bytes = Buffer.from(hex, "hex"),
      path = join(workspace, `${architecture}.bin`);
    await writeFile(path, bytes);
    const started = Date.now();
    try {
      const opened = await invoke("open_binary", {
        path,
        format: "raw-binary",
        architecture,
        entry_point: "0x100",
        provider_id: "ghidra",
      });
      const image = await invoke("inspect_native_load_image");
      assert.equal(
        image.normalized_result.status,
        "verified",
        JSON.stringify(image.normalized_result),
      );
      const memory = await invoke("read_bytes", {
        address: "0x100",
        length: bytes.length,
      });
      assert.equal(memory.normalized_result.bytes_hex, hex);
      const pseudo = await invoke("procedure_pseudo_code", {
        procedure: "entry",
      });
      assert.equal(typeof pseudo.normalized_result, "string");
      assert.ok(pseudo.normalized_result.length > 0);
      assert.deepEqual(await readFile(path), bytes);
      const proof = {
        architecture,
        ok: true,
        elapsed_ms: Date.now() - started,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        language: image.normalized_result.language_id,
        load_image: image.normalized_result.status,
        pseudocode: pseudo.normalized_result,
        evidence_ids: [
          image.evidence_id,
          memory.evidence_id,
          pseudo.evidence_id,
        ],
        opened,
      };
      reports = reports.filter((item) => item.architecture !== architecture);
      reports.push(proof);
      await writeFile(
        join(workspace, `${architecture}-evidence.json`),
        JSON.stringify({ image, memory, pseudo }, null, 2),
      );
      process.stdout.write(
        `${architecture}: verified mapping, memory and pseudocode\n`,
      );
    } catch (error) {
      reports = reports.filter((item) => item.architecture !== architecture);
      reports.push({
        architecture,
        ok: false,
        elapsed_ms: Date.now() - started,
        error: String(error),
      });
      process.stdout.write(
        `${architecture}: FAILED ${String(error).slice(0, 900)}\n`,
      );
    } finally {
      try {
        await invoke("close_binary");
      } catch (error) {
        process.stdout.write(`close: ${String(error).slice(0, 300)}\n`);
      }
    }
    await writeFile(
      join(workspace, "profiles.json"),
      JSON.stringify(
        { host: process.platform, target_execution: false, reports },
        null,
        2,
      ),
    );
  }
  if (selected.includes("--swinxs")) {
    const suppliedPath = selected[selected.indexOf("--swinxs") + 1];
    if (suppliedPath === undefined)
      throw new Error("Usage: --swinxs /absolute/path/to/firmware_520.bin");
    const path = resolve(suppliedPath);
    const original = await readFile(path);
    try {
      await invoke("open_binary", {
        path,
        format: "raw-binary",
        architecture: "armv4t",
        load_address: "0x2000",
        entry_point: "0x2054",
        provider_id: "ghidra",
      });
      const image = await invoke("inspect_native_load_image");
      assert.equal(
        image.normalized_result.status,
        "verified",
        JSON.stringify(image.normalized_result),
      );
      assert.equal(image.normalized_result.base_address, "0x2000");
      assert.equal(image.normalized_result.entry.address, "0x2054");
      assert.equal(image.normalized_result.entry.file_offset, 84);
      const memory = await invoke("read_bytes", {
        address: "0x2000",
        length: 16,
      });
      assert.equal(
        memory.normalized_result.bytes_hex,
        original.subarray(0, 16).toString("hex"),
      );
      const pseudo = await invoke("procedure_pseudo_code", {
        procedure: "entry",
      });
      assert.equal(typeof pseudo.normalized_result, "string");
      assert.deepEqual(await readFile(path), original);
      await writeFile(
        join(workspace, "swinxs-evidence.json"),
        JSON.stringify({ image, memory, pseudo }, null, 2),
      );
      process.stdout.write(
        "Swinxs: original ARM7 firmware verified and reset entry decompiled through REA\n",
      );
    } finally {
      await invoke("close_binary");
    }
  }
} finally {
  await client.close();
  await transport.close();
  await writeFile(join(workspace, "provider-stderr.txt"), stderr);
}
if (reports.some((x) => !x.ok)) process.exitCode = 1;
