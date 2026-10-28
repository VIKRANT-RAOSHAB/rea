import { describe, expect, it } from "vitest";
import {
  admitRawBinary,
  binaryArchitectureSchema,
  rawBinarySelectionError,
} from "./rawBinary.js";
import { RAW_BINARY_PROFILES } from "./rawBinaryProfiles.js";
import { snapshotMatchesTarget, snapshotTarget } from "./analysisSnapshot.js";
import type { BinaryTarget } from "./binaryTargetTypes.js";
import { openBinaryInputSchema } from "../contracts/sessionLifecycleInputs.js";

describe("device raw processor admission", () => {
  it.each(Object.keys(RAW_BINARY_PROFILES))(
    "admits a bounded explicit %s profile",
    (architecture) => {
      expect(binaryArchitectureSchema.safeParse(architecture).success).toBe(
        true,
      );
      expect(
        admitRawBinary({
          architecture,
          entryPoint: "0x100",
          loadAddress: "0x80",
          fileBytes: 256,
        }).ok,
      ).toBe(true);
    },
  );
  it("separates ARM execution entry from the vector-table load address", () => {
    expect(
      admitRawBinary({
        architecture: "cortex-m",
        entryPoint: "0x8000080",
        loadAddress: "0x08000000",
        fileBytes: 256,
      }),
    ).toEqual({
      ok: true,
      value: {
        architecture: "cortex-m",
        entryPoint: "0x8000080",
        entryPointSource: "0x8000080",
        loadAddress: "0x8000000",
        loadAddressSource: "0x08000000",
      },
    });
    expect(
      admitRawBinary({
        architecture: "cortex-m",
        entryPoint: "0x8000081",
        loadAddress: "0x8000000",
        fileBytes: 256,
      }).ok,
    ).toBe(false);
    expect(
      admitRawBinary({
        architecture: "armv4t",
        entryPoint: "0x1ffc",
        loadAddress: "0x2000",
        fileBytes: 8,
      }).ok,
    ).toBe(false);
  });
  it.each(["avr8", "pic12", "pic16"])(
    "uses byte coordinates over word-addressed %s code memory",
    (architecture) => {
      expect(
        admitRawBinary({ architecture, entryPoint: "0x1fffe", fileBytes: 2 })
          .ok,
      ).toBe(true);
      expect(
        admitRawBinary({ architecture, entryPoint: "0x1fffe", fileBytes: 4 })
          .ok,
      ).toBe(false);
      expect(
        admitRawBinary({ architecture, entryPoint: "0x101", fileBytes: 2 }).ok,
      ).toBe(false);
      expect(
        admitRawBinary({ architecture, entryPoint: "0x100", fileBytes: 3 }).ok,
      ).toBe(false);
    },
  );
  it("retains base selection in snapshots and rejects a mismatched mapping", () => {
    const target: BinaryTarget = {
      path: "/tmp/firmware.bin",
      sha256: "a".repeat(64),
      kind: "executable",
      format: "raw-binary",
      architecture: "armv4t",
      availableArchitectures: ["armv4t"],
      entryPoint: "0x2054",
      entryPointSource: "0x2054",
      loadAddress: "0x2000",
    };
    const snapshot = snapshotTarget(target);
    expect(snapshotMatchesTarget(snapshot, target)).toBe(true);
    expect(
      snapshotMatchesTarget(snapshot, { ...target, loadAddress: "0x1000" }),
    ).toBe(false);
  });
  it("exposes load_address through MCP only with an explicit raw interpretation", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "C:/firmware.bin",
        format: "raw-binary",
        architecture: "armv4t",
        entry_point: "0x2054",
        load_address: "0x2000",
      }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "C:/firmware.exe",
        load_address: "0x2000",
      }).success,
    ).toBe(false);
    expect(
      rawBinarySelectionError({ format: "dos-com", loadAddress: "0x1000" }),
    ).toContain("raw-binary");
  });
});
