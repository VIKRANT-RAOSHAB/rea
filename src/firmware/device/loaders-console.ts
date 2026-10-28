import type { DeviceParseOptions, DeviceParseResult } from "./types.js";
import { ascii, count, fail, hex, result, span } from "./loaders-common.js";

export const parseInes = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format);
  span(bytes, 0, 16);
  if (!bytes.subarray(0, 4).equals(Buffer.from([0x4e, 0x45, 0x53, 0x1a])))
    fail("iNES magic mismatch");
  const f6 = bytes[6]!,
    f7 = bytes[7]!,
    nes2 = (f7 & 12) === 8;
  r.version = nes2 ? "NES 2.0" : "iNES 1.0";
  r.architecture = "6502";
  const mapper = (f6 >>> 4) | (f7 & 0xf0) | (nes2 ? (bytes[8]! & 15) << 8 : 0),
    submapper = nes2 ? bytes[8]! >>> 4 : 0;
  const pHigh = nes2 ? bytes[9]! & 15 : 0,
    cHigh = nes2 ? bytes[9]! >>> 4 : 0;
  r.items.push({
    kind: "cartridge-header",
    mapper,
    submapper,
    trainer: !!(f6 & 4),
    battery: !!(f6 & 2),
    mirroring: f6 & 8 ? "four-screen" : f6 & 1 ? "vertical" : "horizontal",
    console_type: f7 & 3,
  });
  if (pHigh === 15 || cHigh === 15) {
    r.complete = false;
    r.limitations.push(
      "NES 2.0 exponent/multiplier ROM sizing is not supported; no guessed payload map is produced.",
    );
    return r;
  }
  const prgSize = (bytes[4]! + pHigh * 256) * 16384,
    chrSize = (bytes[5]! + cHigh * 256) * 8192;
  if (!prgSize) fail("iNES has no PRG ROM");
  const trainer = f6 & 4 ? 512 : 0,
    start = 16 + trainer;
  span(bytes, start, prgSize + chrSize);
  count(2 + (trainer ? 1 : 0), o);
  if (trainer)
    r.regions.push({
      name: "trainer",
      fileOffset: 16,
      loadAddress: "0x7000",
      bytes: span(bytes, 16, 512),
    });
  const mapper0 =
    mapper === 0 && (prgSize === 16384 || prgSize === 32768) && submapper === 0;
  r.regions.push({
    name: "prg-rom",
    fileOffset: start,
    loadAddress: mapper0 ? (prgSize === 16384 ? "0xc000" : "0x8000") : null,
    bytes: span(bytes, start, prgSize),
  });
  if (chrSize)
    r.regions.push({
      name: "chr-rom",
      fileOffset: start + prgSize,
      loadAddress: null,
      bytes: span(bytes, start + prgSize, chrSize),
    });
  if (mapper0) {
    r.entryPoint = hex(bytes.readUInt16LE(start + prgSize - 4));
    r.items.push({
      kind: "vectors",
      file_offset: start + prgSize - 6,
      nmi: hex(bytes.readUInt16LE(start + prgSize - 6)),
      reset: r.entryPoint,
      irq: hex(bytes.readUInt16LE(start + prgSize - 2)),
    });
    if (prgSize === 16384)
      r.items.push({
        kind: "mirror",
        source_region: "prg-rom",
        addresses: ["0x8000", "0xc000"],
        bytes: 16384,
      });
  } else {
    r.complete = false;
    r.limitations.push(
      `Mapper ${mapper}, submapper ${submapper} payloads are inventoried without bank-switching reconstruction.`,
    );
  }
  if (start + prgSize + chrSize !== bytes.length) {
    r.complete = false;
    r.warnings.push("Trailing cartridge data is not interpreted");
  }
  r.limitations.push(
    "CHR is PPU data, not CPU executable memory. Static cartridge mapping does not emulate console hardware or VT32-specific extensions. A 16-KiB NROM bank is represented once with its alias reported separately.",
  );
  return r;
};

export const parseGameboy = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format);
  span(bytes, 0, 0x150);
  r.version = "Game Boy cartridge";
  r.architecture = "lr35902";
  r.entryPoint = "0x100";
  let h = 0;
  for (let i = 0x134; i <= 0x14c; i++) h = (h - bytes[i]! - 1) & 255;
  let global = 0;
  for (let i = 0; i < bytes.length; i++)
    if (i !== 0x14e && i !== 0x14f) global = (global + bytes[i]!) & 65535;
  const code = bytes[0x148]!,
    expected =
      code <= 8
        ? 32768 * 2 ** code
        : code === 0x52
          ? 72 * 16384
          : code === 0x53
            ? 80 * 16384
            : code === 0x54
              ? 96 * 16384
              : null;
  r.items.push({
    kind: "cartridge-header",
    title: ascii(
      bytes.subarray(
        0x134,
        bytes[0x143] === 0x80 || bytes[0x143] === 0xc0 ? 0x143 : 0x144,
      ),
    ),
    cartridge_type: bytes[0x147]!,
    color_flag: bytes[0x143]!,
    rom_size_code: code,
    ram_size_code: bytes[0x149]!,
    declared_rom_bytes: expected,
    header_checksum_valid: h === bytes[0x14d],
    global_checksum_valid: global === bytes.readUInt16BE(0x14e),
  });
  if (h !== bytes[0x14d]) r.warnings.push("Game Boy header checksum mismatch");
  if (global !== bytes.readUInt16BE(0x14e))
    r.warnings.push("Game Boy global checksum mismatch");
  if (expected === null || expected !== bytes.length) {
    r.complete = false;
    r.warnings.push(
      "ROM size is unknown or differs from the header declaration",
    );
  }
  const banks = Math.ceil(bytes.length / 16384);
  count(banks + 1, o);
  for (let bank = 0; bank < banks; bank++)
    r.regions.push({
      name: `rom-bank-${bank}`,
      fileOffset: bank * 16384,
      loadAddress:
        bank === 0 ? "0x0" : bytes[0x147] === 0 && bank === 1 ? "0x4000" : null,
      bytes: bytes.subarray(
        bank * 16384,
        Math.min((bank + 1) * 16384, bytes.length),
      ),
    });
  if (bytes[0x147] !== 0) {
    r.complete = false;
    r.limitations.push(
      "MBC bank switching and cartridge RAM/RTC state are not reconstructed; banks retain separate identities.",
    );
  }
  r.limitations.push(
    "LR35902 is not generic Z80; the processor identity must not be substituted with a Z80 decoder. Header checksums do not establish authenticity.",
  );
  return r;
};

export const parseGba = (
  bytes: Buffer,
  o: DeviceParseOptions,
): DeviceParseResult => {
  const r = result(o.format);
  span(bytes, 0, 0xc0);
  count(1, o);
  r.version = "Game Boy Advance cartridge";
  r.architecture = "armv4t";
  r.entryPoint = "0x8000000";
  if (bytes.length > 33554432)
    fail("GBA ROM exceeds the standard 32-MiB cartridge window");
  let sum = 0x19;
  for (let i = 0xa0; i <= 0xbc; i++) sum += bytes[i]!;
  const valid = ((sum + bytes[0xbd]!) & 255) === 0;
  r.items.push({
    kind: "cartridge-header",
    title: ascii(bytes.subarray(0xa0, 0xac)),
    game_code: ascii(bytes.subarray(0xac, 0xb0)),
    maker_code: ascii(bytes.subarray(0xb0, 0xb2)),
    fixed_byte_valid: bytes[0xb2] === 0x96,
    header_checksum_valid: valid,
    software_version: bytes[0xbc]!,
  });
  if (!valid || bytes[0xb2] !== 0x96)
    r.warnings.push("GBA fixed header byte or complement checksum mismatch");
  r.regions.push({
    name: "cartridge-rom",
    fileOffset: 0,
    loadAddress: "0x8000000",
    bytes,
  });
  r.limitations.push(
    "Cartridge EEPROM, SRAM/flash saves, GPIO devices and runtime ARM/Thumb transitions are not emulated. The entry address identifies the cartridge entry instruction, not the program's main function.",
  );
  return r;
};
