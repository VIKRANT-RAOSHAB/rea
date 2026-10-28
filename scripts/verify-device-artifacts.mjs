import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile, readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
const exec = promisify(execFile),
  base = resolve(".cache/device-verification");
await mkdir(base, { recursive: true });
const work = await mkdtemp(join(base, "artifacts-"));
const cli = async (args) =>
  JSON.parse(
    (
      await exec(
        process.execPath,
        [resolve("scripts/rea.mjs"), ...args, "--json"],
        { timeout: 60000, maxBuffer: 16777216 },
      )
    ).stdout,
  );
const proofs = [];
const hexPath = join(work, "image.hex");
await writeFile(hexPath, ":02000000704747\n:00000001FF\n");
const hex = await cli([
  "inspect-device-artifact",
  hexPath,
  "--artifact-format",
  "intel-hex",
  "--item-limit",
  "1",
]);
assert.equal(
  hex.normalized_result.regions[0].sha256,
  createHash("sha256").update(Buffer.from("7047", "hex")).digest("hex"),
);
assert.equal(hex.normalized_result.coverage.returned_items, 1);
proofs.push({
  case: "compiled CLI Intel HEX and numeric paging",
  evidence_id: hex.evidence_id,
});
const output = join(work, "hex-output");
const extracted = await cli([
  "extract-device-artifact",
  hexPath,
  output,
  "--artifact-format",
  "intel-hex",
]);
assert.ok(
  (await readFile(join(output, "region-00000.bin"))).equals(
    Buffer.from("7047", "hex"),
  ),
);
proofs.push({
  case: "compiled CLI extraction and readback",
  evidence_id: extracted.evidence_id,
});
const vectorPath = join(work, "vectors.bin"),
  layoutPath = join(work, "vectors.json"),
  vectors = Buffer.alloc(64);
vectors.writeUInt32LE(0x20001000);
vectors.writeUInt32LE(0x08000021, 4);
await writeFile(vectorPath, vectors);
await writeFile(
  layoutPath,
  JSON.stringify({ base_address: "0x08000000", vector_count: 16 }),
);
const vector = await cli([
  "inspect-device-artifact",
  vectorPath,
  "--artifact-format",
  "cortex-m-vectors",
  "--layout-path",
  layoutPath,
]);
assert.equal(vector.normalized_result.entry_point, "0x8000020");
assert.equal(vector.normalized_result.layout_artifact.path, layoutPath);
proofs.push({
  case: "compiled CLI Cortex-M vector layout",
  evidence_id: vector.evidence_id,
});
let littlefsProof = null;
if (process.argv[2] !== undefined) {
  const littlefsPath = resolve(process.argv[2]);
  const littlefs = await cli([
    "extract-device-artifact",
    littlefsPath,
    join(work, "littlefs-output"),
    "--artifact-format",
    "littlefs",
    "--block-size",
    "256",
  ]);
  assert.equal(littlefs.normalized_result.coverage.parser_complete, true);
  littlefsProof = littlefs;
  const payloads = await Promise.all(
    littlefs.normalized_result.regions.map((r) => readFile(r.extracted_path)),
  );
  assert.ok(payloads.some((b) => b.toString() === "hello-upstream"));
  const expected = Buffer.alloc(1000);
  for (let i = 0; i < expected.length; i++) expected[i] = i & 255;
  assert.ok(payloads.some((b) => b.equals(expected)));
  proofs.push({
    case: "compiled CLI upstream-produced littlefs inline and CTZ files",
    evidence_id: littlefs.evidence_id,
    source_sha256: littlefs.subject.digest.sha256,
  });
} else
  process.stdout.write(
    "Optional upstream-produced littlefs check skipped; pass its image path as the first argument.\n",
  );
const mpyPath = join(work, "tiny.mpy");
const qstr = (text) =>
  Buffer.concat([
    Buffer.from([Buffer.byteLength(text) * 2]),
    Buffer.from(text),
    Buffer.from([0]),
  ]);
await writeFile(
  mpyPath,
  Buffer.concat([
    Buffer.from([0x4d, 6, 0, 31, 2, 0]),
    qstr("x.py"),
    qstr("<module>"),
    Buffer.from([40, 0, 2, 1, 0x51, 0x63]),
  ]),
);
const mpy = await cli([
  "inspect-device-artifact",
  mpyPath,
  "--artifact-format",
  "mpy",
]);
assert.equal(mpy.normalized_result.coverage.parser_complete, true);
assert.ok(
  mpy.normalized_result.items.some((item) => item.kind === "instruction"),
);
proofs.push({
  case: "compiled CLI MicroPython fixture also accepted by upstream mpy-tool",
  evidence_id: mpy.evidence_id,
});
await writeFile(
  join(base, "artifact-cli-evidence.json"),
  JSON.stringify(
    { hex, extracted, vector, littlefs: littlefsProof, mpy },
    null,
    2,
  ),
);
await writeFile(
  join(base, "artifact-cli-verification.json"),
  JSON.stringify({ target_execution: false, work, proofs }, null, 2),
);
for (const proof of proofs) process.stdout.write(`${proof.case}: passed\n`);
assert.ok((await readdir(output)).includes("manifest.json"));
