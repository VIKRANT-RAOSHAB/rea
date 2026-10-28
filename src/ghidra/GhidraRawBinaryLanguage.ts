import type { RawBinaryAdmission } from "../domain/rawBinary.js";

/** Bound Ghidra language for a caller-supplied raw-binary architecture. */
export interface GhidraRawBinaryLanguage {
  readonly languageId: string;
  readonly compilerSpecId: "default" | "gcc";
  readonly defaultAddressSpace: "ram" | "RAM" | "code" | "CODE";
}

/**
 * Map caller-visible CPU families to generic Ghidra languages with a
 * supported generic compiler specification. These are analysis conventions,
 * not evidence of the target's original compiler or physical board. Each
 * profile binds a specific instruction set, byte order and program space.
 */
export const ghidraRawBinaryLanguage = (
  architecture: RawBinaryAdmission["architecture"],
): GhidraRawBinaryLanguage => {
  switch (architecture) {
    case "armv4t":
      return {
        languageId: "ARM:LE:32:v4t",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "thumb":
      return {
        languageId: "ARM:LE:32:v8T",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "cortex-m":
      return {
        languageId: "ARM:LE:32:Cortex",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "avr8":
      return {
        languageId: "avr8:LE:16:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "code",
      };
    case "pic12":
      return {
        languageId: "PIC-12:LE:16:PIC-12C5xx",
        compilerSpecId: "default",
        defaultAddressSpace: "CODE",
      };
    case "pic16":
      return {
        languageId: "PIC-16:LE:16:PIC-16",
        compilerSpecId: "default",
        defaultAddressSpace: "CODE",
      };
    case "pic18":
      return {
        languageId: "PIC-18:LE:24:PIC-18",
        compilerSpecId: "default",
        defaultAddressSpace: "CODE",
      };
    case "8051":
      return {
        languageId: "8051:BE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "CODE",
      };
    case "xtensa":
      return {
        languageId: "Xtensa:LE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "mips32le":
      return {
        languageId: "MIPS:LE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "mips32be":
      return {
        languageId: "MIPS:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "riscv32":
      return {
        languageId: "RISCV:LE:32:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "riscv64":
      return {
        languageId: "RISCV:LE:64:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "z80":
      return {
        languageId: "z80:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "msp430":
      return {
        languageId: "TI_MSP430:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "RAM",
      };
    case "6502":
      return {
        languageId: "6502:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "RAM",
      };
    case "m68k":
      // Ghidra's default 68000 language decodes the 68040 superset; no
      // MC68000-only variant is declared in the 68000 processor module.
      return {
        languageId: "68000:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "x86":
      return {
        languageId: "x86:LE:32:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "x86_64":
      return {
        languageId: "x86:LE:64:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "arm":
      return {
        languageId: "ARM:LE:32:v7",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "arm64":
      return {
        languageId: "AARCH64:LE:64:v8A",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
  }
};
