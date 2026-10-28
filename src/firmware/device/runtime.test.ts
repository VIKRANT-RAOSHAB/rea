import { describe, expect, it } from "vitest";
import { parseDeviceRuntime } from "./runtime.js";
import type { DeviceParseOptions } from "./types.js";

const options = (
  format: string,
  extra: Partial<DeviceParseOptions> = {},
): DeviceParseOptions => ({ format, maxItems: 1000, ...extra });
const u32 = (value: number, little = true): Buffer => {
  const b = Buffer.alloc(4);
  if (little) b.writeUInt32LE(value >>> 0);
  else b.writeUInt32BE(value >>> 0);
  return b;
};
const i64 = (value: bigint, little = true): Buffer => {
  const b = Buffer.alloc(8);
  if (little) b.writeBigInt64LE(value);
  else b.writeBigInt64BE(value);
  return b;
};
const f64 = (value: number, little = true): Buffer => {
  const b = Buffer.alloc(8);
  if (little) b.writeDoubleLE(value);
  else b.writeDoubleBE(value);
  return b;
};
const lua53String = (value: string | null): Buffer =>
  value === null
    ? Buffer.from([0])
    : Buffer.concat([
        Buffer.from([Buffer.byteLength(value) + 1]),
        Buffer.from(value),
      ]);
const lua54Unsigned = (n: number): Buffer => {
  const groups = [0x80 | (n & 127)];
  for (
    let value = Math.floor(n / 128);
    value > 0;
    value = Math.floor(value / 128)
  )
    groups.unshift(value & 127);
  return Buffer.from(groups);
};

/** Independently authored chunks equivalent to a two-instruction return-7 function. */
const lua53 = (
  little = true,
  constant: Buffer = Buffer.concat([Buffer.from([19]), i64(7n, little)]),
): Buffer =>
  Buffer.concat([
    Buffer.from([
      0x1b, 0x4c, 0x75, 0x61, 0x53, 0, 0x19, 0x93, 13, 10, 0x1a, 10, 4, 8, 4, 8,
      8,
    ]),
    i64(0x5678n, little),
    f64(370.5, little),
    Buffer.from([0]),
    lua53String("@example.lua"),
    u32(0, little),
    u32(0, little),
    Buffer.from([0, 0, 2]),
    u32(2, little),
    u32(1, little),
    u32(38 | (2 << 23), little),
    u32(1, little),
    constant,
    u32(0, little),
    u32(0, little),
    u32(0, little),
    u32(0, little),
    u32(0, little),
  ]);
const lua54 = (): Buffer =>
  Buffer.concat([
    Buffer.from([
      0x1b, 0x4c, 0x75, 0x61, 0x54, 0, 0x19, 0x93, 13, 10, 0x1a, 10, 4, 8, 8,
    ]),
    i64(0x5678n),
    f64(370.5),
    Buffer.from([0]),
    Buffer.from([0x80, 0x80, 0x80, 0, 0, 2, 0x82]),
    u32((((7 + 65535) << 15) | 1) >>> 0),
    u32(72),
    Buffer.from([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80]),
  ]);
const microQstr = (value: string): Buffer =>
  Buffer.concat([
    Buffer.from([Buffer.byteLength(value) * 2]),
    Buffer.from(value),
    Buffer.from([0]),
  ]);
const micro = (
  code = Buffer.from([0, 2, 1, 0x51, 0x63]),
  objects = Buffer.alloc(0),
  objectCount = 0,
): Buffer =>
  Buffer.concat([
    Buffer.from([0x4d, 6, 0, 31, 2, objectCount]),
    microQstr("x.py"),
    microQstr("<module>"),
    objects,
    Buffer.from([code.length * 8]),
    code,
  ]);

describe("Lua embedded runtime chunks", () => {
  it.each([true, false])(
    "decodes Lua 5.3 prototype/constants/opcodes in little-endian=%s",
    (little) => {
      const report = parseDeviceRuntime(lua53(little), options("lua"));
      expect(report.complete).toBe(true);
      expect(report.version).toBe("5.3");
      expect(
        report.items.find((item) => item.kind === "constant"),
      ).toMatchObject({ tag: 19, value: "7" });
      expect(
        report.items
          .filter((item) => item.kind === "instruction")
          .map((item) => item.mnemonic),
      ).toEqual(["LOADK", "RETURN"]);
      expect(
        report.items.find((item) => item.kind === "prototype"),
      ).toMatchObject({
        source: "@example.lua",
        instruction_count: 2,
        constant_count: 1,
      });
      expect(report.regions).toHaveLength(1);
      expect(report.regions[0]!.bytes.length).toBe(8);
      expect(
        report.regions[0]!.bytes.equals(
          lua53(little).subarray(
            report.regions[0]!.fileOffset!,
            report.regions[0]!.fileOffset! + 8,
          ),
        ),
      ).toBe(true);
    },
  );
  it("decodes Lua 5.4 terminal-high-bit integers and different opcodes", () => {
    const report = parseDeviceRuntime(lua54(), options("lua"));
    expect(report.version).toBe("5.4");
    expect(report.complete).toBe(true);
    expect(
      report.items
        .filter((item) => item.kind === "instruction")
        .map((item) => item.mnemonic),
    ).toEqual(["LOADI", "RETURN1"]);
    expect(
      report.items.find((item) => item.kind === "instruction"),
    ).toMatchObject({ sBx: 7 });
  });
  it("preserves Lua large integers without lossy numeric coercion", () => {
    const report = parseDeviceRuntime(
      lua53(true, Buffer.concat([Buffer.from([19]), i64(9007199254740993n)])),
      options("lua"),
    );
    expect(report.items.find((item) => item.kind === "constant")!.value).toBe(
      "9007199254740993",
    );
  });
  it("preserves binary Lua strings", () => {
    const report = parseDeviceRuntime(
      lua53(true, Buffer.from([4, 3, 0xff, 0x00])),
      options("lua"),
    );
    expect(
      report.items.find((item) => item.kind === "constant")!.value,
    ).toEqual({ encoding: "hex", value: "ff00" });
  });
  it("retains nonfinite Lua constants as explicit representations", () => {
    const report = parseDeviceRuntime(
      lua53(true, Buffer.concat([Buffer.from([3]), f64(Infinity)])),
      options("lua"),
    );
    expect(
      report.items.find((item) => item.kind === "constant")!.value,
    ).toMatchObject({ nonfinite: "Infinity" });
  });
  it("marks trailing bytes as outside parsed coverage", () => {
    const report = parseDeviceRuntime(
      Buffer.concat([lua53(), Buffer.from([1])]),
      options("lua"),
    );
    expect(report.complete).toBe(false);
    expect(report.warnings[0]).toContain("Trailing 1 bytes");
  });
  it.each([0, 4, 12, 33, 50, 70])(
    "rejects truncation at %i bytes",
    (length) => {
      expect(() =>
        parseDeviceRuntime(lua53().subarray(0, length), options("lua")),
      ).toThrow();
    },
  );
  it("rejects unsupported versions, LuaJIT, unknown opcodes and small item budgets", () => {
    const old = lua53();
    old[4] = 0x51;
    expect(() => parseDeviceRuntime(old, options("lua"))).toThrow("5.1");
    expect(() =>
      parseDeviceRuntime(Buffer.from([0x1b, 0x4c, 0x4a, 2]), options("lua")),
    ).toThrow("LuaJIT");
    const invalid = lua53();
    const codeOffset = parseDeviceRuntime(invalid, options("lua")).regions[0]!
      .fileOffset!;
    invalid.writeUInt32LE(63, codeOffset);
    expect(() => parseDeviceRuntime(invalid, options("lua"))).toThrow(
      "Unknown Lua opcode",
    );
    expect(() =>
      parseDeviceRuntime(lua53(), options("lua", { maxItems: 1 })),
    ).toThrow("maxItems");
  });
  it("does not allocate for a declared unbounded instruction count", () => {
    const invalid = lua53();
    const codeOffset = parseDeviceRuntime(invalid, options("lua")).regions[0]!
      .fileOffset!;
    invalid.writeUInt32LE(0xffffffff, codeOffset - 4);
    expect(() => parseDeviceRuntime(invalid, options("lua"))).toThrow(
      "maxItems",
    );
  });
});

describe("MicroPython embedded runtime chunks", () => {
  it("decodes .mpy v6 qstrs, prelude and instruction source offsets", () => {
    const report = parseDeviceRuntime(micro(), options("mpy"));
    expect(report.complete).toBe(true);
    expect(report.version).toBe("6-bytecode");
    expect(report.items.find((item) => item.kind === "function")).toMatchObject(
      { name: "<module>", code_kind: 2, state_slots: 1 },
    );
    expect(
      report.items
        .filter((item) => item.kind === "instruction")
        .map((item) => item.mnemonic),
    ).toEqual(["LOAD_CONST_NONE", "RETURN_VALUE"]);
    const instruction = report.items.find(
      (item) => item.kind === "instruction",
    )!;
    expect(micro()[instruction.file_offset as number]).toBe(0x51);
  });
  it("lists imported qstrs, object constants and signed compact integers", () => {
    const code = Buffer.from([0, 2, 1, 0x1b, 0, 0x23, 0, 0x22, 0x7f, 0x63]);
    const report = parseDeviceRuntime(
      micro(code, Buffer.from([5, 2, 0x68, 0x69, 0]), 1),
      options("mpy"),
    );
    expect(
      report.items.find((item) => item.mnemonic === "IMPORT_NAME"),
    ).toMatchObject({ qstr: "x.py" });
    expect(
      report.items.find((item) => item.kind === "constant")!.value,
    ).toMatchObject({ type: "str", value: "hi" });
    expect(
      report.items.find((item) => item.mnemonic === "LOAD_CONST_SMALL_INT"),
    ).toMatchObject({ argument: -1 });
  });
  it("retains static qstr identities without guessing a firmware table", () => {
    const bytes = Buffer.concat([
      Buffer.from([0x4d, 6, 0, 31, 1, 0, 3, 40]),
      Buffer.from([0, 2, 0, 0x51, 0x63]),
    ]);
    const report = parseDeviceRuntime(bytes, options("mpy"));
    expect(report.items.find((item) => item.kind === "qstr")!.value).toEqual({
      static_qstr_index: 1,
    });
    expect(
      report.limitations.some((item) => item.includes("Static qstr")),
    ).toBe(true);
  });
  it("extracts native v6.3 assembly payload without applying relocations", () => {
    const code = Buffer.from([0x0d, 0xf0]);
    const bytes = Buffer.concat([
      Buffer.from([0x4d, 6, 9 * 4 + 3, 31, 1, 0]),
      microQstr("x.py"),
      Buffer.from([code.length * 8 + 3]),
      code,
      Buffer.from([0, 0, 0]),
    ]);
    const report = parseDeviceRuntime(bytes, options("mpy"));
    expect(report.version).toBe("6.3-native");
    expect(report.architecture).toBe("xtensa");
    expect(report.regions[0]!.bytes.equals(code)).toBe(true);
    expect(report.items.find((item) => item.kind === "function")).toMatchObject(
      { code_kind: 5, positional_arguments: 0, native_type_signature: 0 },
    );
    expect(
      report.limitations.some((item) =>
        item.includes("relocations are not applied"),
      ),
    ).toBe(true);
  });
  it("rejects wrong versions, missing terminators, invalid qstr/constant references and truncated arguments", () => {
    const old = micro();
    old[1] = 5;
    expect(() => parseDeviceRuntime(old, options("mpy"))).toThrow("version 5");
    const terminator = micro();
    terminator[11] = 1;
    expect(() => parseDeviceRuntime(terminator, options("mpy"))).toThrow(
      "zero terminator",
    );
    expect(() =>
      parseDeviceRuntime(
        micro(Buffer.from([0, 2, 1, 0x1b, 2])),
        options("mpy"),
      ),
    ).toThrow("qstr index");
    expect(() =>
      parseDeviceRuntime(
        micro(Buffer.from([0, 2, 1, 0x23, 0])),
        options("mpy"),
      ),
    ).toThrow("constant index");
    expect(() =>
      parseDeviceRuntime(
        micro(Buffer.from([0, 2, 1, 0x22, 0x80])),
        options("mpy"),
      ),
    ).toThrow("Truncated");
    expect(() =>
      parseDeviceRuntime(micro(), options("mpy", { maxItems: 1 })),
    ).toThrow("maxItems");
  });
  it("bounds nested containers and malformed size preludes", () => {
    expect(() =>
      parseDeviceRuntime(
        micro(Buffer.from([0, 0x7e, 1, 0x51, 0x63])),
        options("mpy"),
      ),
    ).toThrow("prelude extends");
    const nativeOld = Buffer.from([0x4d, 6, 9 * 4 + 2, 31]);
    expect(() => parseDeviceRuntime(nativeOld, options("mpy"))).toThrow(
      "sub-version 2",
    );
  });
});

describe("Explicit RTOS saved RAM structures", () => {
  const memory = (): Buffer => {
    const bytes = Buffer.alloc(128);
    bytes.writeUInt32LE(0x1020, 0); // global list head pointer
    bytes.writeUInt32LE(0x1040, 32);
    bytes.writeUInt32LE(7, 36);
    bytes.write("worker\0", 40);
    bytes.writeUInt32LE(0x1020, 64);
    bytes.writeUInt32LE(3, 68);
    bytes.write("idle\0", 72);
    return bytes;
  };
  const layout = (os = "freertos"): Record<string, unknown> => ({
    os,
    version: "test-layout-v1",
    evidence_kind: "ram-snapshot",
    base_address: "0x1000",
    pointer_bytes: 4,
    byte_order: "little",
    objects: [
      {
        kind: "task",
        head: "0x1000",
        head_is_pointer: true,
        next_offset: 0,
        fields: {
          next: { offset: 0, type: "pointer" },
          priority: { offset: 4, type: "u32" },
          name: { offset: 8, type: "cstring", length: 16 },
        },
      },
    ],
  });
  it.each(["freertos", "zephyr", "threadx"])(
    "walks caller-described %s circular task structures",
    (os) => {
      const report = parseDeviceRuntime(
        memory(),
        options("rtos", { layout: layout(os) }),
      );
      expect(report.complete).toBe(true);
      expect(
        report.items
          .filter((item) => item.kind === "task")
          .map((item) => item.values),
      ).toEqual([
        { next: "0x1040", priority: 7, name: "worker" },
        { next: "0x1020", priority: 3, name: "idle" },
      ]);
      expect(report.items[0]).toMatchObject({
        os,
        applicability: "caller-declared",
        evidence_kind: "saved-ram-snapshot",
      });
    },
  );
  it("subtracts an intrusive link offset and preserves real source offsets", () => {
    const selected = layout();
    selected.objects = [
      {
        kind: "task",
        head: "0x1020",
        next_offset: 0,
        link_offset: 8,
        fields: { priority: { offset: 12, type: "u32" } },
      },
    ];
    const report = parseDeviceRuntime(
      memory(),
      options("rtos", { layout: selected }),
    );
    expect(report.items.find((item) => item.kind === "task")).toMatchObject({
      address: "0x1018",
      node_address: "0x1020",
      file_offset: 24,
      values: { priority: 7 },
    });
  });
  it("supports big-endian 64-bit pointers without truncation", () => {
    const base = 0x1000000000000n,
      bytes = Buffer.alloc(32);
    bytes.writeBigUInt64BE(base + 16n, 0);
    bytes.writeBigUInt64BE(0n, 16);
    bytes.writeUInt32BE(5, 24);
    const selected = {
      ...layout("threadx"),
      base_address: "0x1000000000000",
      pointer_bytes: 8,
      byte_order: "big",
      objects: [
        {
          kind: "queue",
          head: "0x1000000000000",
          head_is_pointer: true,
          next_offset: 0,
          fields: { count: { offset: 8, type: "u32" } },
        },
      ],
    };
    const report = parseDeviceRuntime(
      bytes,
      options("rtos", { layout: selected }),
    );
    expect(report.items.find((item) => item.kind === "queue")).toMatchObject({
      address: "0x1000000000010",
      values: { count: 5 },
    });
  });
  it("marks an unexpected internal cycle partial and never loops forever", () => {
    const bytes = memory();
    bytes.writeUInt32LE(0x1040, 64);
    const report = parseDeviceRuntime(
      bytes,
      options("rtos", { layout: layout() }),
    );
    expect(report.complete).toBe(false);
    expect(report.items.filter((item) => item.kind === "task")).toHaveLength(2);
    expect(report.warnings[0]).toContain("cycle");
  });
  it("requires explicit profile data and rejects pointers outside the saved image", () => {
    expect(() => parseDeviceRuntime(memory(), options("rtos"))).toThrow(
      "requires a caller-selected layout",
    );
    expect(() =>
      parseDeviceRuntime(
        memory(),
        options("rtos", {
          layout: { ...layout(), evidence_kind: "static-firmware" },
        }),
      ),
    ).toThrow("ram-snapshot");
    const bytes = memory();
    bytes.writeUInt32LE(0x9000, 32);
    expect(() =>
      parseDeviceRuntime(bytes, options("rtos", { layout: layout() })),
    ).toThrow("not covered");
    expect(() =>
      parseDeviceRuntime(
        memory(),
        options("rtos", { layout: layout(), maxItems: 2 }),
      ),
    ).toThrow("maxItems");
  });
});

it("rejects an unrecognized runtime format without fallback", () => {
  expect(() => parseDeviceRuntime(Buffer.alloc(0), options("unknown"))).toThrow(
    "Unknown runtime format",
  );
});

// Fixture encoder itself exercises the 5.4 continuation convention independently.
it("uses continuation bytes before terminal high-bit bytes in Lua 5.4 fixtures", () => {
  expect(lua54Unsigned(16384).equals(Buffer.from([1, 0, 0x80]))).toBe(true);
});
