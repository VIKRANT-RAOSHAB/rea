import { expect, it } from "vitest";
import { parseCortexVectors } from "./vectors.js";
it("separates tagged Thumb vectors from executable byte addresses", () => {
  const bytes = Buffer.alloc(64);
  bytes.writeUInt32LE(0x20001000);
  bytes.writeUInt32LE(0x08000021, 4);
  bytes.writeUInt32LE(0x08001001, 8);
  const report = parseCortexVectors(bytes, {
    format: "cortex-m-vectors",
    maxItems: 32,
    layout: { base_address: "0x08000000", vector_count: 16 },
  });
  expect(report.entryPoint).toBe("0x8000020");
  expect(report.items[1]).toMatchObject({
    thumb: true,
    handler_file_offset: 32,
  });
  expect(report.items[2]).toMatchObject({
    mapped_to_supplied_image: false,
    handler_file_offset: null,
  });
  expect(report.complete).toBe(true);
});
it("retains invalid state and rejects unsupported table bounds", () => {
  const bytes = Buffer.alloc(64);
  bytes.writeUInt32LE(0x20000003);
  bytes.writeUInt32LE(0x8000020, 4);
  const choices = {
    format: "cortex-m-vectors",
    maxItems: 32,
    layout: { base_address: "0x8000000" },
  };
  const result = parseCortexVectors(bytes, choices);
  expect(result.complete).toBe(false);
  expect(result.entryPoint).toBeNull();
  expect(() =>
    parseCortexVectors(bytes, {
      ...choices,
      layout: { base_address: "0x8000000", vector_offset: 2 },
    }),
  ).toThrow("aligned");
  expect(() =>
    parseCortexVectors(bytes, {
      ...choices,
      layout: { base_address: "0x8000000", vector_count: 30 },
    }),
  ).toThrow("range");
});
