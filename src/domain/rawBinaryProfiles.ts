/** Processor address conventions, independent of any disassembler engine. */
export const RAW_BINARY_PROFILES = {
  x86: { bits: 32, unitBytes: 1, alignment: 1 },
  x86_64: { bits: 64, unitBytes: 1, alignment: 1 },
  arm: { bits: 32, unitBytes: 1, alignment: 4 },
  arm64: { bits: 64, unitBytes: 1, alignment: 4 },
  "6502": { bits: 16, unitBytes: 1, alignment: 1 },
  m68k: { bits: 32, unitBytes: 1, alignment: 2 },
  armv4t: { bits: 32, unitBytes: 1, alignment: 4 },
  thumb: { bits: 32, unitBytes: 1, alignment: 2 },
  "cortex-m": { bits: 32, unitBytes: 1, alignment: 2 },
  avr8: { bits: 16, unitBytes: 2, alignment: 1 },
  pic12: { bits: 16, unitBytes: 2, alignment: 1 },
  pic16: { bits: 16, unitBytes: 2, alignment: 1 },
  pic18: { bits: 24, unitBytes: 1, alignment: 2 },
  "8051": { bits: 16, unitBytes: 1, alignment: 1 },
  xtensa: { bits: 32, unitBytes: 1, alignment: 1 },
  mips32le: { bits: 32, unitBytes: 1, alignment: 4 },
  mips32be: { bits: 32, unitBytes: 1, alignment: 4 },
  riscv32: { bits: 32, unitBytes: 1, alignment: 2 },
  riscv64: { bits: 64, unitBytes: 1, alignment: 2 },
  z80: { bits: 16, unitBytes: 1, alignment: 1 },
  msp430: { bits: 16, unitBytes: 1, alignment: 2 },
} as const;

export type RawBinaryArchitecture = keyof typeof RAW_BINARY_PROFILES;

/** Preserve the legacy combined load/entry interpretation when no base is selected. */
export const rawBinaryLoadAddress = (target: {
  readonly entryPoint: string;
  readonly loadAddress?: string;
}): string => target.loadAddress ?? target.entryPoint;
