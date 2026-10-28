import type { JsonValue } from "../../domain/jsonValue.js";
import {
  DeviceParseFailure,
  type DeviceParseOptions,
  type DeviceParseResult,
} from "./types.js";
import {
  RuntimeReader,
  RuntimeBudget,
  assertRuntimeDepth,
  runtimeText,
  runtimeReport,
} from "./runtime-reader.js";

// Layouts: Lua upstream v5.3.6/v5.4.7 lundump.c, lopcodes.h (https://www.lua.org/source/).
// These are decoded VM fields, not reconstruction of original Lua source.
const OPCODES53 =
  "MOVE LOADK LOADKX LOADBOOL LOADNIL GETUPVAL GETTABUP GETTABLE SETTABUP SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR UNM BNOT NOT LEN CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP FORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG EXTRAARG".split(
    " ",
  );
const OPCODES54 =
  "MOVE LOADI LOADF LOADK LOADKX LOADFALSE LFALSESKIP LOADTRUE LOADNIL GETUPVAL SETUPVAL GETTABUP GETTABLE GETI GETFIELD SETTABUP SETTABLE SETI SETFIELD NEWTABLE SELF ADDI ADDK SUBK MULK MODK POWK DIVK IDIVK BANDK BORK BXORK SHRI SHLI ADD SUB MUL MOD POW DIV IDIV BAND BOR BXOR SHL SHR MMBIN MMBINI MMBINK UNM BNOT NOT LEN CONCAT CLOSE TBC JMP EQ LT LE EQK EQI LTI LEI GTI GEI TEST TESTSET CALL TAILCALL RETURN RETURN0 RETURN1 FORLOOP FORPREP TFORPREP TFORCALL TFORLOOP SETLIST CLOSURE VARARG VARARGPREP EXTRAARG".split(
    " ",
  );

interface LuaLayout {
  readonly version: number;
  readonly sizeT: number;
  readonly integer: number;
  readonly number: number;
}

const readLuaHeader = (
  r: RuntimeReader,
): LuaLayout & { mainUpvalues: number } => {
  if (r.bytes.subarray(0, 3).equals(Buffer.from([0x1b, 0x4c, 0x4a])))
    throw new DeviceParseFailure(
      "unsupported",
      "LuaJIT bytecode uses a separate format; this parser supports standard Lua 5.3 and 5.4",
    );
  if (!r.take(4, "Lua signature").equals(Buffer.from([0x1b, 0x4c, 0x75, 0x61])))
    throw new DeviceParseFailure(
      "format",
      "Missing Lua binary chunk signature",
    );
  const version = r.byte("Lua version");
  const format = r.byte("Lua format");
  if (format !== 0)
    throw new DeviceParseFailure(
      "unsupported",
      `Lua chunk format ${format} is not the standard format`,
    );
  if (version !== 0x53 && version !== 0x54)
    throw new DeviceParseFailure(
      "unsupported",
      `Lua ${version >> 4}.${version & 15} chunks are not supported; select Lua 5.3 or 5.4`,
    );
  if (
    !r
      .take(6, "Lua data marker")
      .equals(Buffer.from([0x19, 0x93, 13, 10, 0x1a, 10]))
  )
    throw new DeviceParseFailure("format", "Invalid Lua data marker");
  let sizeT = 8;
  if (version === 0x53) {
    if (r.byte("Lua int width") !== 4)
      throw new DeviceParseFailure(
        "unsupported",
        "Lua 5.3 C int width must be four bytes",
      );
    sizeT = r.byte("Lua size_t width");
    if (sizeT !== 4 && sizeT !== 8)
      throw new DeviceParseFailure(
        "unsupported",
        "Lua size_t width must be four or eight bytes",
      );
  }
  const instructionWidth = r.byte("Lua instruction width");
  const integerWidth = r.byte("Lua integer width");
  const numberWidth = r.byte("Lua number width");
  if (
    instructionWidth !== 4 ||
    (integerWidth !== 4 && integerWidth !== 8) ||
    (numberWidth !== 4 && numberWidth !== 8)
  )
    throw new DeviceParseFailure(
      "unsupported",
      "Unsupported Lua instruction, integer or floating-point representation",
    );
  const marker = r.offset;
  const integerMarker = r.integer(integerWidth, "Lua integer marker");
  if (integerMarker !== 0x5678n) {
    r.offset = marker;
    r.littleEndian = false;
    if (r.integer(integerWidth, "Lua integer marker") !== 0x5678n)
      throw new DeviceParseFailure(
        "format",
        "Lua integer marker does not identify either supported byte order",
      );
  }
  if (r.float(numberWidth, "Lua floating-point marker") !== 370.5)
    throw new DeviceParseFailure(
      "unsupported",
      "Lua floating-point marker does not match IEEE float/double 370.5",
    );
  return {
    version,
    sizeT,
    integer: integerWidth,
    number: numberWidth,
    mainUpvalues: r.byte("Lua main closure upvalue count"),
  };
};
class LuaChunkReader {
  readonly result = runtimeReport("lua");
  nextProto = 0;
  constructor(
    readonly r: RuntimeReader,
    readonly layout: LuaLayout,
    readonly budget: RuntimeBudget,
  ) {}
  count(label: string, minBytes = 0): number {
    const value =
      this.layout.version === 0x54
        ? this.r.variable(label, true)
        : this.r.number(4, label);
    this.budget.consume(value);
    if (
      minBytes > 0 &&
      value > Math.floor((this.r.bytes.length - this.r.offset) / minBytes)
    )
      throw new DeviceParseFailure(
        "format",
        `${label} cannot fit in the remaining chunk`,
      );
    return value;
  }
  readString(label: string): JsonValue {
    let length =
      this.layout.version === 0x54
        ? this.r.variable(`${label} length`, true)
        : this.r.byte(`${label} length`);
    if (this.layout.version === 0x53 && length === 255)
      length = this.r.number(this.layout.sizeT, `${label} extended length`);
    if (length === 0) return null;
    return runtimeText(this.r.take(length - 1, label));
  }
  instruction(
    word: number,
    proto: number,
    pc: number,
    offset: number,
  ): Record<string, JsonValue> {
    const op = word & (this.layout.version === 0x53 ? 63 : 127);
    const name = (this.layout.version === 0x53 ? OPCODES53 : OPCODES54)[op];
    if (name === undefined)
      throw new DeviceParseFailure(
        "format",
        `Unknown Lua opcode ${op} at file offset ${offset}`,
      );
    return this.layout.version === 0x53
      ? {
          kind: "instruction",
          prototype: proto,
          pc,
          file_offset: offset,
          word: `0x${word.toString(16).padStart(8, "0")}`,
          opcode: op,
          mnemonic: name,
          A: (word >>> 6) & 255,
          B: word >>> 23,
          C: (word >>> 14) & 511,
          Bx: word >>> 14,
          sBx: (word >>> 14) - 131071,
          Ax: word >>> 6,
        }
      : {
          kind: "instruction",
          prototype: proto,
          pc,
          file_offset: offset,
          word: `0x${word.toString(16).padStart(8, "0")}`,
          opcode: op,
          mnemonic: name,
          A: (word >>> 7) & 255,
          k: (word >>> 15) & 1,
          B: (word >>> 16) & 255,
          C: word >>> 24,
          Bx: word >>> 15,
          sBx: (word >>> 15) - 65535,
          Ax: word >>> 7,
          sJ: (word >>> 7) - 16777215,
        };
  }
  readCode(id: number): number {
    const codeCount = this.count("instruction count", 4);
    const codeOffset = this.r.offset;
    for (let pc = 0; pc < codeCount; pc++) {
      const at = this.r.offset;
      this.result.items.push(
        this.instruction(this.r.number(4, "instruction word"), id, pc, at),
      );
    }
    this.result.regions.push({
      name: `lua-prototype-${id}-code`,
      fileOffset: codeOffset,
      loadAddress: null,
      bytes: this.r.bytes.subarray(codeOffset, this.r.offset),
    });
    return codeCount;
  }
  readConstants(id: number): number {
    const constantCount = this.count("constant count", 1);
    for (let i = 0; i < constantCount; i++) {
      const at = this.r.offset,
        tag = this.r.byte("constant tag");
      let value: JsonValue;
      const floatTag = this.layout.version === 0x53 ? 3 : 19;
      const intTag = this.layout.version === 0x53 ? 19 : 3;
      if (tag === 0) value = null;
      else if (this.layout.version === 0x53 && tag === 1) {
        const flag = this.r.byte("boolean constant");
        if (flag > 1)
          throw new DeviceParseFailure(
            "format",
            "Lua boolean constant must be zero or one",
          );
        value = flag === 1;
      } else if (this.layout.version === 0x54 && (tag === 1 || tag === 17))
        value = tag === 17;
      else if (tag === floatTag)
        value = this.r.float(this.layout.number, "number constant");
      else if (tag === intTag)
        value = this.r
          .integer(this.layout.integer, "integer constant", true)
          .toString();
      else if (tag === 4 || tag === 20) {
        value = this.readString("string constant");
        if (value === null)
          throw new DeviceParseFailure(
            "format",
            "Lua string constants cannot be null",
          );
      } else
        throw new DeviceParseFailure(
          "format",
          `Unknown Lua constant tag ${tag} at file offset ${at}`,
        );
      this.result.items.push({
        kind: "constant",
        prototype: id,
        index: i,
        file_offset: at,
        tag,
        value,
      });
    }
    return constantCount;
  }
  readUpvalues(id: number): number {
    const upvalues = this.count(
      "upvalue count",
      this.layout.version === 0x53 ? 2 : 3,
    );
    for (let i = 0; i < upvalues; i++)
      this.result.items.push({
        kind: "upvalue",
        prototype: id,
        index: i,
        in_stack: this.r.byte("upvalue in-stack flag"),
        index_in_parent: this.r.byte("upvalue index"),
        upvalue_kind:
          this.layout.version === 0x54 ? this.r.byte("upvalue kind") : null,
      });
    return upvalues;
  }
  readDebug(id: number, codeCount: number, upvalues: number) {
    const lineCount = this.count(
      "line info count",
      this.layout.version === 0x53 ? 4 : 1,
    );
    if (lineCount !== 0 && lineCount !== codeCount)
      throw new DeviceParseFailure(
        "format",
        "Lua line-info length must be zero or match instruction count",
      );
    const lineOffset = this.r.offset;
    this.r.take(
      lineCount * (this.layout.version === 0x53 ? 4 : 1),
      "source line information",
    );
    let absoluteLineCount = 0;
    if (this.layout.version === 0x54) {
      absoluteLineCount = this.count("absolute line info count", 2);
      for (let i = 0; i < absoluteLineCount; i++) {
        const pc = this.r.variable("absolute line pc", true),
          sourceLine = this.r.variable("absolute source line", true);
        if (pc >= codeCount)
          throw new DeviceParseFailure(
            "format",
            "Lua absolute source-line pc is outside its prototype",
          );
        this.result.items.push({
          kind: "source_line",
          prototype: id,
          pc,
          source_line: sourceLine,
        });
      }
    }
    const localCount = this.count("local variable count", 1);
    for (let i = 0; i < localCount; i++) {
      const name = this.readString("local variable name");
      const start =
        this.layout.version === 0x54
          ? this.r.variable("local start pc", true)
          : this.r.number(4, "local start pc");
      const end =
        this.layout.version === 0x54
          ? this.r.variable("local end pc", true)
          : this.r.number(4, "local end pc");
      if (start > end || end > codeCount)
        throw new DeviceParseFailure(
          "format",
          "Lua local variable range is outside its prototype",
        );
      this.result.items.push({
        kind: "local_variable",
        prototype: id,
        name,
        start_pc: start,
        end_pc: end,
      });
    }
    const upvalueNames = this.count("upvalue name count", 1);
    if (upvalueNames !== 0 && upvalueNames !== upvalues)
      throw new DeviceParseFailure(
        "format",
        "Lua upvalue-name this.count must be zero or match the upvalue count",
      );
    for (let i = 0; i < upvalueNames; i++)
      this.result.items.push({
        kind: "upvalue_name",
        prototype: id,
        index: i,
        name: this.readString("upvalue name"),
      });
    return { lineOffset, lineCount, absoluteLineCount, localCount };
  }
  readPrototype(
    parent: number | null,
    parentSource: JsonValue,
    depth: number,
  ): { id: number; upvalues: number } {
    assertRuntimeDepth(depth);
    this.budget.consume();
    const id = this.nextProto++;
    const offset = this.r.offset;
    const ownSource = this.readString("Lua source name");
    const source = ownSource === null ? parentSource : ownSource;
    const line =
      this.layout.version === 0x54
        ? this.r.variable("first source line", true)
        : this.r.number(4, "first source line");
    const lastLine =
      this.layout.version === 0x54
        ? this.r.variable("last source line", true)
        : this.r.number(4, "last source line");
    const parameters = this.r.byte("parameter count");
    const vararg = this.r.byte("vararg flags");
    const stack = this.r.byte("stack slots");
    const codeCount = this.readCode(id);
    const constantCount = this.readConstants(id);
    const upvalues = this.readUpvalues(id);
    const children = this.count("child prototype count", 1);
    for (let i = 0; i < children; i++)
      this.readPrototype(id, source, depth + 1);
    const { lineOffset, lineCount, absoluteLineCount, localCount } =
      this.readDebug(id, codeCount, upvalues);
    this.result.items.push({
      kind: "prototype",
      id,
      parent,
      source,
      file_offset: offset,
      file_bytes: this.r.offset - offset,
      first_source_line: line,
      last_source_line: lastLine,
      parameters,
      vararg_flags: vararg,
      stack_slots: stack,
      instruction_count: codeCount,
      constant_count: constantCount,
      upvalue_count: upvalues,
      child_count: children,
      line_info_offset: lineOffset,
      line_info_count: lineCount,
      absolute_line_info_count: absoluteLineCount,
      local_count: localCount,
    });
    return { id, upvalues };
  }
}
/** Inspect standard Lua 5.3/5.4 binary chunks in either byte order. */
export const parseLuaChunk = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  const reader = new RuntimeReader(bytes);
  const header = readLuaHeader(reader);
  const parser = new LuaChunkReader(
    reader,
    header,
    new RuntimeBudget(options.maxItems),
  );
  parser.result.items.push({
    kind: "header",
    version: header.version === 0x53 ? "5.3" : "5.4",
    byte_order: reader.littleEndian ? "little" : "big",
    instruction_bytes: 4,
    integer_bytes: header.integer,
    number_bytes: header.number,
    size_t_bytes: header.version === 0x53 ? header.sizeT : null,
    main_upvalues: header.mainUpvalues,
  });
  const main = parser.readPrototype(null, null, 0);
  if (main.upvalues !== header.mainUpvalues)
    throw new DeviceParseFailure(
      "format",
      "Lua closure upvalue count does not match the main prototype",
    );
  if (reader.offset !== bytes.length) {
    parser.result.complete = false;
    parser.result.warnings.push(
      `Trailing ${bytes.length - reader.offset} bytes after the Lua chunk were not interpreted`,
    );
  }
  parser.result.limitations.push(
    "Only standard Lua 5.3 and 5.4 chunks using 32-bit instructions, four/eight-byte integers and IEEE float/double are decoded; LuaJIT and other versions are separate unsupported formats.",
    "Instruction fields, constants and prototype relationships are static observations. This parser does not execute, verify control-flow safety, emulate, or reconstruct original source.",
    "Lua integers are emitted as decimal strings to preserve values outside JavaScript's exact numeric range. Stripped debug names cannot be recovered.",
  );
  return { ...parser.result, version: header.version === 0x53 ? "5.3" : "5.4" };
};
