import {
  microPrelude,
  decodeMicroInstructions,
  type MicroPrelude,
} from "./runtime-mpy-bytecode.js";
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

// Format references: MicroPython v1.24.1 tools/mpy-tool.py, py/bc0.h and py/persistentcode.c.
// https://github.com/micropython/micropython/tree/v1.24.1
// Decoder formulas and opcode definitions derived from those MIT-licensed files:
// Copyright (c) 2013-2020 Damien P. George.
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

const NATIVE_ARCHITECTURES = [
  null,
  "x86",
  "x86_64",
  "armv6",
  "armv6m",
  "armv7m",
  "armv7em",
  "armv7em-sp",
  "armv7em-dp",
  "xtensa",
  "xtensa-windowed",
  "rv32imc",
] as const;
/** Inspect MicroPython .mpy v6; native v6.3 code remains unrelocated payload. */
export const parseMicroPython = (
  bytes: Buffer,
  options: DeviceParseOptions,
): DeviceParseResult => {
  const r = new RuntimeReader(bytes),
    budget = new RuntimeBudget(options.maxItems);
  if (r.byte("MicroPython magic") !== 0x4d)
    throw new DeviceParseFailure("format", "Missing MicroPython .mpy magic");
  const version = r.byte("MicroPython version"),
    feature = r.byte("MicroPython feature byte"),
    smallInt = r.byte("MicroPython small-int width");
  if (version !== 6)
    throw new DeviceParseFailure(
      "unsupported",
      `MicroPython .mpy version ${version} is not supported; this parser supports version 6`,
    );
  const archId = feature >>> 2,
    subVersion = feature & 3;
  if (archId !== 0 && subVersion !== 3)
    throw new DeviceParseFailure(
      "unsupported",
      `Native .mpy sub-version ${subVersion} is not supported; native v6.3 is required`,
    );
  if (archId >= NATIVE_ARCHITECTURES.length)
    throw new DeviceParseFailure(
      "unsupported",
      `Unknown MicroPython native architecture ${archId}`,
    );
  if (smallInt === 0 || smallInt > 64)
    throw new DeviceParseFailure(
      "format",
      "MicroPython small-int width must be in 1..64",
    );
  const result = runtimeReport("mpy");
  result.items.push({
    kind: "header",
    version,
    sub_version: subVersion,
    native_architecture_id: archId,
    native_architecture: NATIVE_ARCHITECTURES[archId] ?? null,
    small_int_bits: smallInt,
  });
  const qstrCount = r.variable("MicroPython qstr count"),
    objectCount = r.variable("MicroPython object count");
  budget.consume(qstrCount + objectCount);
  if (qstrCount === 0 || qstrCount + objectCount > bytes.length - r.offset)
    throw new DeviceParseFailure(
      "format",
      "MicroPython qstr/object tables cannot fit in this file",
    );
  const qstrs: JsonValue[] = [];
  let staticQstrs = false;
  for (let i = 0; i < qstrCount; i++) {
    const offset = r.offset,
      size = r.variable("MicroPython qstr size");
    let value: JsonValue;
    if ((size & 1) !== 0) {
      value = { static_qstr_index: Math.floor(size / 2) };
      staticQstrs = true;
    } else {
      value = runtimeText(r.take(size / 2, "MicroPython qstr contents"));
      if (r.byte("MicroPython qstr terminator") !== 0)
        throw new DeviceParseFailure(
          "format",
          "MicroPython qstr must have a zero terminator",
        );
    }
    qstrs.push(value);
    result.items.push({ kind: "qstr", index: i, file_offset: offset, value });
  }
  const object = (depth: number): JsonValue => {
    assertRuntimeDepth(depth);
    budget.consume();
    const tag = r.byte("MicroPython object tag");
    if (tag === 0) return { type: "native_function_table" };
    if (tag === 1) return null;
    if (tag === 2 || tag === 3) return tag === 3;
    if (tag === 4) return { type: "ellipsis" };
    if (tag === 10) {
      const count = r.variable("MicroPython tuple count");
      if (count > bytes.length - r.offset)
        throw new DeviceParseFailure(
          "format",
          "MicroPython tuple cannot fit in remaining bytes",
        );
      const items: JsonValue[] = [];
      for (let i = 0; i < count; i++) items.push(object(depth + 1));
      return { type: "tuple", values: items };
    }
    if (tag < 5 || tag > 9)
      throw new DeviceParseFailure(
        "format",
        `Unknown MicroPython object tag ${tag}`,
      );
    const size = r.variable("MicroPython object length"),
      data = r.take(size, "MicroPython object data");
    if (
      (tag === 5 || tag === 6) &&
      r.byte("MicroPython object terminator") !== 0
    )
      throw new DeviceParseFailure(
        "format",
        "MicroPython string/bytes object must have a zero terminator",
      );
    const types = ["str", "bytes", "int", "float", "complex"];
    return {
      type: types[tag - 5]!,
      value: tag === 6 ? data.toString("hex") : runtimeText(data),
      encoding: tag === 6 ? "hex" : "serialized-text",
    };
  };
  for (let i = 0; i < objectCount; i++) {
    const at = r.offset;
    result.items.push({
      kind: "constant",
      index: i,
      file_offset: at,
      value: object(0),
    });
  }
  let codeId = 0,
    hasNative = false;
  const rawCode = (parent: number | null, depth: number): void => {
    assertRuntimeDepth(depth);
    budget.consume();
    const headerOffset = r.offset,
      packed = r.variable("MicroPython code kind/length");
    const kind = (packed & 3) + 2,
      children = (packed & 4) !== 0,
      size = Math.floor(packed / 8);
    const offset = r.offset,
      code = r.take(size, "MicroPython function data"),
      id = codeId++;
    result.regions.push({
      name: `mpy-function-${id}-${kind === 2 ? "bytecode" : "native"}`,
      fileOffset: offset,
      loadAddress: null,
      bytes: code,
    });
    let prelude: MicroPrelude | undefined,
      nativeFlags = 0,
      nativeArguments = 0,
      nativeTypeSignature = 0;
    if (kind === 2) prelude = microPrelude(code, 0, qstrCount);
    else {
      if (archId === 0)
        throw new DeviceParseFailure(
          "format",
          "Native MicroPython code has no native architecture declaration",
        );
      hasNative = true;
      if (kind === 3)
        prelude = microPrelude(
          code,
          r.variable("MicroPython native prelude offset"),
          qstrCount,
        );
      else {
        nativeFlags = r.variable("MicroPython native scope flags");
        if (kind === 4) {
          const rodataSize =
            (nativeFlags & 0x20) !== 0
              ? r.variable("MicroPython rodata length")
              : 0;
          const bssSize =
            (nativeFlags & 0x40) !== 0
              ? r.variable("MicroPython bss length")
              : 0;
          if (rodataSize > 0) {
            const at = r.offset;
            result.regions.push({
              name: `mpy-function-${id}-rodata`,
              fileOffset: at,
              loadAddress: null,
              bytes: r.take(rodataSize, "MicroPython native rodata"),
            });
          }
          result.items.push({
            kind: "native_data",
            function: id,
            rodata_bytes: rodataSize,
            bss_bytes: bssSize,
          });
          if ((nativeFlags & 0x10) !== 0) {
            for (;;) {
              budget.consume();
              const at = r.offset,
                op = r.byte("MicroPython relocation");
              if (op === 0xff) break;
              const address =
                (op & 1) !== 0
                  ? r.variable("MicroPython relocation address")
                  : null;
              const operation = op >>> 1;
              const repetitions =
                operation <= 5 && (operation & 1) !== 0
                  ? r.variable("MicroPython relocation repetition")
                  : 1;
              result.items.push({
                kind: "native_relocation",
                function: id,
                file_offset: at,
                operation,
                address,
                repetitions,
              });
            }
          }
        } else {
          nativeArguments = r.variable("MicroPython native argument count");
          nativeTypeSignature = r.variable("MicroPython native type signature");
        }
      }
    }
    result.items.push({
      kind: "function",
      id,
      parent,
      file_offset: headerOffset,
      data_offset: offset,
      data_bytes: size,
      code_kind: kind,
      name: prelude === undefined ? null : qstrs[prelude.nameIndex]!,
      argument_qstr_indices: prelude?.args ?? [],
      opcode_offset:
        prelude === undefined || kind !== 2
          ? null
          : offset + prelude.opcodeOffset,
      state_slots: prelude?.stateSlots ?? null,
      exception_slots: prelude?.exceptionSlots ?? null,
      scope_flags: prelude?.scopeFlags ?? nativeFlags,
      positional_arguments: prelude?.positionalArgs ?? nativeArguments,
      keyword_arguments: prelude?.keywordArgs ?? null,
      default_arguments: prelude?.defaultArgs ?? null,
      native_type_signature: kind === 5 ? nativeTypeSignature : null,
    });
    if (kind === 2 && prelude !== undefined)
      result.items.push(
        ...decodeMicroInstructions(
          code,
          prelude,
          id,
          offset,
          qstrs,
          objectCount,
          budget,
        ),
      );
    if (children) {
      const count = r.variable("MicroPython child count");
      if (count > bytes.length - r.offset)
        throw new DeviceParseFailure(
          "format",
          "MicroPython child count cannot fit in the remaining file",
        );
      for (let i = 0; i < count; i++) rawCode(id, depth + 1);
    }
  };
  rawCode(null, 0);
  if (r.offset !== bytes.length) {
    result.complete = false;
    result.warnings.push(
      `Trailing ${bytes.length - r.offset} bytes were not interpreted`,
    );
  }
  if (staticQstrs)
    result.limitations.push(
      "Static qstr references retain their declared indices; this parser does not substitute a build-specific firmware qstr table.",
    );
  if (hasNative)
    result.limitations.push(
      "Native .mpy v6.3 text/rodata/relocation extents are decoded but native instructions are not disassembled and relocations are not applied. Extracted code has no established runtime load address.",
    );
  result.limitations.push(
    "Format scope is MicroPython .mpy v6 with native sub-version 3 when native code is present, based on MicroPython v1.24.1. Other file versions and future opcode changes are unsupported.",
    "Qstr references, object constants, preludes and opcode listings are static file observations. This parser does not execute the module or reconstruct original Python source.",
  );
  return {
    ...result,
    version: archId === 0 ? "6-bytecode" : "6.3-native",
    architecture: NATIVE_ARCHITECTURES[archId] ?? null,
  };
};
