import type { JsonValue } from "../../domain/jsonValue.js";
import { DeviceParseFailure } from "./types.js";
import { RuntimeReader, RuntimeBudget } from "./runtime-reader.js";

// MicroPython v1.24.1 opcode/prelude definitions; see runtime-mpy.ts for MIT notice.
const MNEMONICS: Readonly<Record<number, string>> = {
  0x10: "LOAD_CONST_STRING",
  0x11: "LOAD_NAME",
  0x12: "LOAD_GLOBAL",
  0x13: "LOAD_ATTR",
  0x14: "LOAD_METHOD",
  0x15: "LOAD_SUPER_METHOD",
  0x16: "STORE_NAME",
  0x17: "STORE_GLOBAL",
  0x18: "STORE_ATTR",
  0x19: "DELETE_NAME",
  0x1a: "DELETE_GLOBAL",
  0x1b: "IMPORT_NAME",
  0x1c: "IMPORT_FROM",
  0x20: "MAKE_CLOSURE",
  0x21: "MAKE_CLOSURE_DEFARGS",
  0x22: "LOAD_CONST_SMALL_INT",
  0x23: "LOAD_CONST_OBJ",
  0x24: "LOAD_FAST_N",
  0x25: "LOAD_DEREF",
  0x26: "STORE_FAST_N",
  0x27: "STORE_DEREF",
  0x28: "DELETE_FAST",
  0x29: "DELETE_DEREF",
  0x2a: "BUILD_TUPLE",
  0x2b: "BUILD_LIST",
  0x2c: "BUILD_MAP",
  0x2d: "BUILD_SET",
  0x2e: "BUILD_SLICE",
  0x2f: "STORE_COMP",
  0x30: "UNPACK_SEQUENCE",
  0x31: "UNPACK_EX",
  0x32: "MAKE_FUNCTION",
  0x33: "MAKE_FUNCTION_DEFARGS",
  0x34: "CALL_FUNCTION",
  0x35: "CALL_FUNCTION_VAR_KW",
  0x36: "CALL_METHOD",
  0x37: "CALL_METHOD_VAR_KW",
  0x40: "UNWIND_JUMP",
  0x42: "JUMP",
  0x43: "POP_JUMP_IF_TRUE",
  0x44: "POP_JUMP_IF_FALSE",
  0x45: "JUMP_IF_TRUE_OR_POP",
  0x46: "JUMP_IF_FALSE_OR_POP",
  0x47: "SETUP_WITH",
  0x48: "SETUP_EXCEPT",
  0x49: "SETUP_FINALLY",
  0x4a: "POP_EXCEPT_JUMP",
  0x4b: "FOR_ITER",
  0x50: "LOAD_CONST_FALSE",
  0x51: "LOAD_CONST_NONE",
  0x52: "LOAD_CONST_TRUE",
  0x53: "LOAD_NULL",
  0x54: "LOAD_BUILD_CLASS",
  0x55: "LOAD_SUBSCR",
  0x56: "STORE_SUBSCR",
  0x57: "DUP_TOP",
  0x58: "DUP_TOP_TWO",
  0x59: "POP_TOP",
  0x5a: "ROT_TWO",
  0x5b: "ROT_THREE",
  0x5c: "WITH_CLEANUP",
  0x5d: "END_FINALLY",
  0x5e: "GET_ITER",
  0x5f: "GET_ITER_STACK",
  0x62: "STORE_MAP",
  0x63: "RETURN_VALUE",
  0x64: "RAISE_LAST",
  0x65: "RAISE_OBJ",
  0x66: "RAISE_FROM",
  0x67: "YIELD_VALUE",
  0x68: "YIELD_FROM",
  0x69: "IMPORT_STAR",
};
const opcodeName = (op: number): string | undefined =>
  op >= 0x70 && op < 0xb0
    ? "LOAD_CONST_SMALL_INT_MULTI"
    : op >= 0xb0 && op < 0xc0
      ? "LOAD_FAST_MULTI"
      : op >= 0xc0 && op < 0xd0
        ? "STORE_FAST_MULTI"
        : op >= 0xd0 && op < 0xd4
          ? "UNARY_OP_MULTI"
          : op >= 0xd7 && op < 0xfa
            ? "BINARY_OP_MULTI"
            : MNEMONICS[op];

export interface MicroPrelude {
  readonly nameIndex: number;
  readonly opcodeOffset: number;
  readonly args: number[];
  readonly stateSlots: number;
  readonly exceptionSlots: number;
  readonly scopeFlags: number;
  readonly positionalArgs: number;
  readonly keywordArgs: number;
  readonly defaultArgs: number;
}

/** Read the .mpy v6 bit-packed prelude, bounded by one function's bytes. */
export const microPrelude = (
  bytes: Buffer,
  start: number,
  qstrCount: number,
): MicroPrelude => {
  const r = new RuntimeReader(bytes);
  r.offset = start;
  let z = r.byte("MicroPython function prelude");
  let state = (z >>> 3) & 15,
    exception = (z >>> 2) & 1,
    flags = 0,
    positional = z & 3,
    keyword = 0,
    defaults = 0;
  for (let n = 0; (z & 0x80) !== 0; n++) {
    if (n > 7)
      throw new DeviceParseFailure(
        "limit",
        "MicroPython signature prelude exceeds supported width",
      );
    z = r.byte("MicroPython signature continuation");
    state += (z & 0x30) * 2 ** (2 * n);
    exception += (z & 2) * 2 ** n;
    flags += ((z & 0x40) >>> 6) * 2 ** n;
    positional += (z & 4) * 2 ** n;
    keyword += ((z & 8) >>> 3) * 2 ** n;
    defaults += (z & 1) * 2 ** n;
  }
  let info = 0,
    cells = 0;
  for (let n = 0; ; n++) {
    if (n > 7)
      throw new DeviceParseFailure(
        "limit",
        "MicroPython size prelude exceeds supported width",
      );
    const b = r.byte("MicroPython size prelude");
    info += ((b & 0x7e) >>> 1) * 2 ** (6 * n);
    cells += (b & 1) * 2 ** n;
    if ((b & 0x80) === 0) break;
  }
  const infoStart = r.offset;
  const opcodes = infoStart + info + cells;
  if (!Number.isSafeInteger(opcodes) || opcodes > bytes.length)
    throw new DeviceParseFailure(
      "format",
      "MicroPython function prelude extends beyond its code data",
    );
  if (positional + keyword + 1 > bytes.length - r.offset)
    throw new DeviceParseFailure(
      "format",
      "MicroPython argument names cannot fit in the function prelude",
    );
  const args: number[] = [];
  for (let i = 0; i < positional + keyword + 1; i++) {
    const index = r.variable("MicroPython argument qstr index");
    if (index >= qstrCount)
      throw new DeviceParseFailure(
        "format",
        "MicroPython prelude qstr index is outside its table",
      );
    args.push(index);
  }
  if (r.offset > infoStart + info)
    throw new DeviceParseFailure(
      "format",
      "MicroPython argument names exceed the source-info extent",
    );
  return {
    nameIndex: args[0]!,
    opcodeOffset: opcodes,
    args: args.slice(1),
    stateSlots: state + 1,
    exceptionSlots: exception,
    scopeFlags: flags,
    positionalArgs: positional,
    keywordArgs: keyword,
    defaultArgs: defaults,
  };
};

export const decodeMicroInstructions = (
  code: Buffer,
  prelude: MicroPrelude,
  id: number,
  offset: number,
  qstrs: JsonValue[],
  objectCount: number,
  budget: RuntimeBudget,
): Record<string, JsonValue>[] => {
  const items: Record<string, JsonValue>[] = [];
  const instructions = new RuntimeReader(code);
  instructions.offset = prelude.opcodeOffset;
  while (instructions.offset < code.length) {
    budget.consume();
    const at = instructions.offset,
      op = instructions.byte("MicroPython opcode"),
      name = opcodeName(op);
    if (name === undefined)
      throw new DeviceParseFailure(
        "format",
        `Unknown MicroPython opcode 0x${op.toString(16)} at file offset ${offset + at}`,
      );
    const format = (0x3a4 >>> (2 * (op >>> 4))) & 3;
    let argument: JsonValue = null,
      extra: number | null = null;
    if (format === 1 || format === 2) {
      let b = instructions.byte("MicroPython instruction argument"),
        arg = BigInt(b & 0x7f);
      if (op === 0x22 && (b & 0x40) !== 0) arg -= 128n;
      let groups = 1;
      while ((b & 0x80) !== 0) {
        if (groups++ > 16)
          throw new DeviceParseFailure(
            "limit",
            "MicroPython instruction argument exceeds 16 variable groups",
          );
        b = instructions.byte("MicroPython instruction argument continuation");
        arg = arg * 128n + BigInt(b & 0x7f);
      }
      argument =
        arg <= BigInt(Number.MAX_SAFE_INTEGER) &&
        arg >= BigInt(Number.MIN_SAFE_INTEGER)
          ? Number(arg)
          : arg.toString();
      if (format === 1 && (arg < 0n || arg >= BigInt(qstrs.length)))
        throw new DeviceParseFailure(
          "format",
          "MicroPython instruction qstr index is outside its table",
        );
      if (op === 0x23 && arg >= BigInt(objectCount))
        throw new DeviceParseFailure(
          "format",
          "MicroPython constant index is outside its object table",
        );
    } else if (format === 3) {
      const first = instructions.byte("MicroPython jump offset");
      const signed = op === 0x40 || op === 0x42 || op === 0x43 || op === 0x44;
      argument =
        (first & 0x80) === 0
          ? first - (signed ? 0x40 : 0)
          : ((first & 0x7f) |
              (instructions.byte("MicroPython jump offset continuation") <<
                7)) -
            (signed ? 0x4000 : 0);
    } else if (op >= 0x70 && op < 0xb0) argument = op - 0x80;
    else if (op >= 0xb0 && op < 0xd0) argument = op & 15;
    else if (op >= 0xd0 && op < 0xd4) argument = op - 0xd0;
    else if (op >= 0xd7) argument = op - 0xd7;
    if ((op & 0x9e) === 0)
      extra = instructions.byte("MicroPython extra argument");
    items.push({
      kind: "instruction",
      function: id,
      file_offset: offset + at,
      bytecode_offset: at,
      opcode: op,
      mnemonic: name,
      argument,
      extra_argument: extra,
      bytes: code.subarray(at, instructions.offset).toString("hex"),
      qstr:
        format === 1 && typeof argument === "number" ? qstrs[argument]! : null,
    });
  }

  return items;
};
