# Device and firmware extension

This local experimental extension is based on REA 6.8.0, commit
`b9d1a61dd5829e3f2f16be6e1ee32d9c1f57c103`. It adds portable device-artifact
inspection/extraction and expands raw Ghidra imports, including Windows.
It is a local branch, not an upstream release or a claim of universal device support.

## Public operations

- CLI: `inspect-device-artifact`, `extract-device-artifact`.
- MCP: `inspect_device_artifact`, `extract_device_artifact`.
- Native CLI/MCP: existing analysis operations accept expanded raw processor
  selections and an optional separate `load_address` / `--load-address`.

Select an artifact format explicitly. CLI uses `--artifact-format` to avoid
conflicting with Incur's global output-format option. MCP uses `format`.
The inspection command only reads selected files; extraction publishes a new
directory with payload files and a provenance manifest. Neither operation runs
the target, flashes hardware, mounts a filesystem, or acquires live memory.

```powershell
node scripts/rea.mjs inspect-device-artifact firmware.hex --artifact-format intel-hex --json
node scripts/rea.mjs extract-device-artifact firmware.uf2 new-regions --artifact-format uf2 --json
node scripts/rea.mjs inspect-device-artifact filesystem.bin --artifact-format littlefs --block-size 256 --json
node scripts/rea.mjs inspect-device-artifact application.mpy --artifact-format mpy --json
node scripts/rea.mjs inspect-device-artifact application.luac --artifact-format lua --json
```

Run these commands from this checkout, after building it. The output directory's
parent must exist and the directory itself must be absent. Paths in MCP requests
must be absolute. The existing REA installation and its client registration are
not replaced by this local build.

## Format support

| Explicit format    | Implemented interpretation                                                                                           | Important boundary                                                                                                                             |
| ------------------ | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `intel-hex`        | Record checksums, extended addresses, start addresses and sparse addressed payloads                                  | Ambiguous overlaps and malformed records are rejected; sparse holes are not zero-filled                                                        |
| `srec`             | Motorola S-record data, count/termination records, checksums and sparse payloads                                     | Explicit record widths; reconstructed payloads have no invented original-file offset                                                           |
| `uf2`              | 512-byte blocks, family IDs, duplicates, numbering, addressed flash reconstruction                                   | Families stay separate; optional MD5/tags and file-container blocks are explicit partial coverage                                              |
| `esp32`            | E9 header/extended header, chip declarations, loadable segments, XOR checksum and appended SHA-256                   | A selected standalone image, not automatic combined-flash discovery; secure-boot signatures are not authenticated                              |
| `esp8266`          | Selected E9 image layout, segments and checksum                                                                      | Other wrappers and combined dumps need separate handling                                                                                       |
| `esp-partitions`   | Espressif partition rows, labels, ranges, flags and optional MD5                                                     | Describes the selected table; does not automatically locate or extract every partition of another file                                         |
| `ines`             | iNES/NES 2.0 header, PRG/CHR/trainer payloads, mapper-0 addressing and vectors                                       | Other mappers are inventoried without banking reconstruction; exponent-size encoding is partial; no VT32 emulation                             |
| `gameboy`          | Cartridge metadata/checksums and separate ROM banks                                                                  | CPU is identified as LR35902, not generic Z80; MBC switching and native LR35902 decompilation are not added                                    |
| `gba`              | Header/checksum, entry declaration and ROM payload                                                                   | ARM7 code remains a separate explicit raw analysis; no console emulation                                                                       |
| `uimage`           | Legacy U-Boot header/data CRCs, component metadata and multi-image members                                           | Compressed payloads remain encoded; checksums do not establish authenticity                                                                    |
| `fit`              | Existing DTB structural parser plus image/configuration relationships, inline/external payloads and supported hashes | Signatures and compressed data remain explicit limitations; selected FIT structure is not a boot execution trace                               |
| `svd`              | CMSIS-SVD peripheral/register/field metadata, concrete clusters and arrays                                           | Unresolved inheritance is partial; no automatic device matching or Windows Ghidra metadata mutation                                            |
| `uefi`             | Capsule envelopes, PI volumes, FFS files, sections/checksums and direct PE/TE/raw payloads                           | Compressed/GUID-specific processing and vendor/authentication formats remain opaque; no signature-trust claim                                  |
| `littlefs`         | v2 committed metadata, CRCs, newest revision selection, directories, inline and CTZ files                            | Caller supplies block geometry; pending global move/orphan state withholds namespace extraction; unsupported versions remain explicit          |
| `mpy`              | MicroPython v6 qstrs, constants, preludes, bytecode listings and native v6.3 payload/relocation metadata             | Native payloads are not relocated or executed; firmware-specific static qstr names may be unknown                                              |
| `lua`              | Standard Lua 5.3/5.4 headers, prototypes, constants, instructions and available debug metadata in either byte order  | LuaJIT/other versions are unsupported; listings are not original source                                                                        |
| `rtos`             | Caller-described FreeRTOS, Zephyr or ThreadX task/queue/timer records in saved RAM, including linked lists           | Explicit version/build layout is required; no guessed offsets, live-state observation or automatic task-creation recovery from arbitrary flash |
| `cortex-m-vectors` | Caller-located little-endian vector table, initial stack value, Thumb-tagged handlers and source offsets             | Explicit base/table layout; stack/handler values do not establish board identity or live execution                                             |

`coverage.parser_complete` refers to the parser's supported interpretation, not
all hardware behavior or every byte of free space. Unsupported constructs produce
limitations/partial coverage. Malformed input and selected resource ceilings
produce typed failures. A successful container inventory is not complete native
decompilation of all its payloads.

## Raw processor profiles

Ghidra uses the selected installed language and compiler conventions. Those
choices do not identify the original compiler, ABI, exact chip, or custom ISA.

| Selection  | Ghidra language           | Program space / address unit        |
| ---------- | ------------------------- | ----------------------------------- |
| `x86`      | `x86:LE:32:default`       | ram / byte                          |
| `x86_64`   | `x86:LE:64:default`       | ram / byte                          |
| `arm`      | `ARM:LE:32:v7`            | ram / byte                          |
| `armv4t`   | `ARM:LE:32:v4t`           | ram / byte; ARM mode                |
| `thumb`    | `ARM:LE:32:v8T`           | ram / byte; Thumb mode              |
| `cortex-m` | `ARM:LE:32:Cortex`        | ram / byte; Thumb mode              |
| `arm64`    | `AARCH64:LE:64:v8A`       | ram / byte                          |
| `avr8`     | `avr8:LE:16:default`      | code / two-byte word                |
| `pic12`    | `PIC-12:LE:16:PIC-12C5xx` | CODE / two-byte word                |
| `pic16`    | `PIC-16:LE:16:PIC-16`     | CODE / two-byte word                |
| `pic18`    | `PIC-18:LE:24:PIC-18`     | CODE / byte                         |
| `8051`     | `8051:BE:16:default`      | CODE / byte                         |
| `xtensa`   | `Xtensa:LE:32:default`    | ram / byte                          |
| `mips32le` | `MIPS:LE:32:default`      | ram / byte                          |
| `mips32be` | `MIPS:BE:32:default`      | ram / byte                          |
| `riscv32`  | `RISCV:LE:32:default`     | ram / byte                          |
| `riscv64`  | `RISCV:LE:64:default`     | ram / byte                          |
| `z80`      | `z80:LE:16:default`       | ram / byte                          |
| `msp430`   | `TI_MSP430:LE:16:default` | RAM / byte                          |
| `6502`     | `6502:LE:16:default`      | RAM / byte; NMOS 6502               |
| `m68k`     | `68000:BE:32:default`     | ram / byte; stock superset language |

**Every public REA address remains a byte coordinate.** AVR/PIC word addresses
are converted only at the Ghidra loader boundary. Consequently a native code
word at processor word address `0x80` has REA byte address `0x100`.
Input files for word-addressed profiles contain complete little-endian code
words. Do not pass textual HEX records as raw instructions.

`entry_point` is the execution seed. `load_address` is where raw file offset zero
is mapped; it defaults to `entry_point` for existing callers. Both enter target
and cache identity. Thumb execution addresses are even byte addresses; strip the
state bit from a vector value before selecting the execution seed.

```powershell
node scripts/rea.mjs decompile firmware.bin entry --target-format raw-binary --architecture armv4t --load-address 0x2000 --entry-point 0x2054 --provider ghidra --json
```

This verifies the file-backed flash interpretation. It does not reconstruct
runtime RAM initialization, hardware registers or bootloader state automatically.
Intel HEX, UF2 and other carriers first need their supported payloads extracted.
Some devices have custom Xtensa instructions, enhanced PIC variants, alternate
ARM byte order, or RISC-V ABI/extensions outside these bounded profiles.

## Geometry and layout files

littlefs requires the actual device's block size; `block_count` is optional and
defaults to the supplied image's complete blocks. These values are choices to
verify against the device, not autodetection results.

Cortex-M vector inspection uses a JSON layout supplied with `--layout-path`:

```json
{ "base_address": "0x08000000", "vector_offset": 0, "vector_count": 16 }
```

RTOS snapshot layouts explicitly identify the OS/build, pointer representation,
snapshot base and selected structure fields. This illustrative layout does not
describe a universal FreeRTOS TCB:

```json
{
  "os": "freertos",
  "version": "my-firmware-build-with-known-offsets",
  "evidence_kind": "ram-snapshot",
  "architecture": "cortex-m",
  "base_address": "0x20000000",
  "pointer_bytes": 4,
  "byte_order": "little",
  "objects": [
    {
      "kind": "task",
      "addresses": ["0x20000040"],
      "fields": {
        "priority": { "offset": 4, "type": "u32" },
        "name": { "offset": 8, "type": "cstring", "length": 16 },
        "stack": { "offset": 24, "type": "pointer" }
      }
    }
  ]
}
```

Use `os: "zephyr"` or `"threadx"` only with the corresponding build's known layout.
Object groups also accept `kind: "queue"` or `"timer"`, and linked traversal with
`head`, `head_is_pointer`, `next_offset`, optional `link_offset`, and an `end`
sentinel. Cycles, out-of-image pointers and unknown fields are not silently
converted to valid task state. Field types include signed/unsigned 8/16/32/64-bit
integers, pointers, bounded cstrings and bytes; strings/bytes can be indirect.

## Provenance, budgets and verification

Reports retain input path/hash/size, separately hashed layout files, supported
version, declared or selected architecture, source locations, payload hashes,
warnings, limitations, and explicit item paging. Regions with reconstructed
bytes have `file_offset: null`. There is no invented mapping across reconstruction.

Default file admission is 32 MiB, selectable up to 128 MiB. The default parser
item budget is 20,000, selectable up to 100,000. Reports page 200 items by default
(up to 1,000 per request); all region identities are returned. The fixed decoded
payload ceiling is 128 MiB. Geometry and version checks add format constraints.
Extraction reuses REA's `SafeOutputTree`: exclusive creation, original/generated
file identities, independent byte/hash readback, commit and retained cleanup.
The manifest records the selected metadata page and all published regions.

Tests include malformed/truncated input, checksums, sparse addressing, duplicate
blocks, cartridge variants, XML structures, nested firmware sections, littlefs
CRC/revision/CTZ handling, Lua/MPY representations, RTOS pointer bounds, and public
MCP extraction/refusal paths. Real Ghidra verification uses small analyst-authored
instruction sequences and checks mappings, byte reads and nonempty pseudocode.
The real Swinxs image also verifies separate flash base/reset entry inside REA.
These are static analysis checks, not physical-device compatibility tests.

The local verification run passed 422 tests across 18 test files. All 21 raw
profiles passed real Ghidra 12.1.4 mapping, memory-read and pseudocode checks on
Windows x64. The original Swinxs firmware passed a separate load-base/reset-entry
check. Five compiled-CLI checks passed, including extraction and a littlefs 2.1
image generated with upstream littlefs 2.11. MicroPython's upstream v1.24.1
`mpy-tool.py` also accepted the deterministic tiny MPY fixture. These checks do
not constitute the full repository CI suite. Targeted lint has no errors and
retains complexity/size warnings in the larger parsers.

Reproduce native checks with `node scripts/verify-device-profiles.mjs` and an
existing configured Ghidra/Java installation. To check Swinxs separately, pass
`--swinxs /absolute/path/to/firmware_520.bin`. The firmware is caller-supplied.
`node scripts/verify-device-artifacts.mjs` creates its own small HEX/vector/MPY
fixtures. Optionally pass an upstream-generated littlefs image as its first
argument to run the additional producer-compatibility check. The owned generator
source is `scripts/device-fixtures/littlefs-generator.c`; compile it against
upstream `lfs.c`/`lfs_util.c` and run it in a scratch directory to create that
image. Generated images and binaries belong outside version control.

The native TypeScript 7 emitter exhausted host memory during a normal build.
The checked-in JavaScript TypeScript 6 compiler can emit the same source after a
separate TypeScript 7 no-emit check:

```powershell
node node_modules/typescript/lib/tsc.js --noEmit -p tsconfig.json
node --max-old-space-size=1536 node_modules/typescript6/lib/tsc.js -p tsconfig.build.json --noCheck
node scripts/record-catalog-digests.mjs
node scripts/record-mcp-catalog.mjs
node scripts/bundle-runtime.mjs
node scripts/generate-skill-metadata.mjs
```

The existing Ghidra/Java installation and matching Windows native addon are still
required for native analysis. Portable device-artifact inspection needs neither.

## Primary format references

- [Intel HEX](https://www.keil.com/support/docs/1584/default.htm), [UF2](https://github.com/microsoft/uf2).
- [Espressif image format](https://docs.espressif.com/projects/esptool/en/release-v4/esp32/advanced-topics/firmware-image-format.html).
- [CMSIS-SVD](https://arm-software.github.io/CMSIS_5/latest/SVD/html/index.html), [U-Boot FIT](https://docs.u-boot.org/en/latest/usage/fit/index.html).
- [UEFI PI firmware storage](https://uefi.org/specs/PI/1.8/V3_Design_Discussion.html), [littlefs specification](https://github.com/littlefs-project/littlefs/blob/master/SPEC.md).
- [MicroPython v1.24.1](https://github.com/micropython/micropython/tree/v1.24.1), [Lua source](https://www.lua.org/source/).
