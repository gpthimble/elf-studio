**English** | [中文](README.zh-CN.md)

# ELF Studio

A viewer for ELF file structures that runs entirely in the browser, with a focus on RISC-V.

- Online: <https://gpthimble.github.io/elf-studio/>
- Repository: <https://github.com/gpthimble/elf-studio>

Parsing happens locally in the browser; files are never uploaded to a server.

The interface is currently in Chinese.

## Usage

| Method | How |
| --- | --- |
| Online | Open <https://gpthimble.github.io/elf-studio/> |
| Offline | Download [`elf-studio.html`](https://github.com/gpthimble/elf-studio/raw/main/elf-studio.html) and open it |
| Build locally | `python3 build.py` (writes `elf-studio.html` and `index.html`) |

Drag in your own ELF file, or click "Load built-in sample" to open a small RISC-V executable.

## Features

### Hex view

- Colours every byte by its physical ELF structure: ELF header, program header table, section header table, `.text`, `.rodata`, `.data`, `.bss`, symbol tables, string tables, relocation tables, `.dynamic`, notes, debug sections, PLT/GOT, attribute sections, and file padding.
- Each row has a colour bar on the left, and the start of a region is labelled inline. The region map covers the whole file without overlaps or gaps.
- Only visible rows are rendered, so files with tens of thousands of rows still scroll smoothly.

### Fields and bytes

- Hovering a byte shows its file offset, virtual address (with the section or program header it comes from), byte value, containing region, field name and field description; enum fields are decoded on the spot.
- Clicking or dragging pins the inspector; `Esc` unpins it.
- Hovering a field row, symbol row or disassembly line highlights the whole byte range rather than a single byte.
- The jump box accepts an offset, a virtual address, a section name or a symbol name.
- The inspector has step buttons for browsing byte by byte or field by field. Keyboard: `←/→` byte, `↑/↓` one row of 16 bytes, `PageUp/PageDown`, `Home/End`, and `[` `]` for the previous/next structure field. It shows the current offset and field index.

### Enums and field documentation

- 19 enum groups with 300+ values, each with its specification reference, value and explanation, covering `EI_*`, `e_type`, `e_machine`, `p_type`, `p_flags`, `sh_type`, `sh_flags`, `st_bind`, `st_type`, `st_other`, `st_shndx`, `DT_*`, `R_RISCV_*`, `R_X86_64_*` and the RISC-V `e_flags` sub-fields.
- Clicking a field row opens a panel with all possible values for that field, with the value used by the current file highlighted. Packed fields such as `st_info` are split into separate `st_bind` and `st_type` tables.
- The dictionary page is ordered by the offset at which each field appears in the file, and lists the current value, the containing structure and the number of occurrences; each entry can be located in the hex view.
- Includes a layout reference for `Elf32/64_Ehdr`, `Phdr`, `Shdr`, `Sym` and `Rela`.

### Disassembly

- Linear sweep over sections marked `SHF_EXECINSTR`. For RISC-V it covers RV32/RV64 I/M/A/F/D, the compressed C extension, Zicsr/Zifencei and the common Zba/Zbb/Zbs/Zbc instructions, recognises pseudo-instructions (`li/mv/ret/jr/j/nop/beqz/bnez/csrr`) and labels jump and branch targets that match symbols.
- Clicking an instruction line locates the corresponding bytes in the hex view. The "fields" button on a line expands the encoding breakdown for that instruction: one colour block per specification field, the bit layout, and the binary value and meaning of each field, showing which bits produce the mnemonic.
- x86-64 uses a simplified decoder that covers common integer and SSE instructions. Encodings outside that subset are listed as `.byte`, but instruction lengths remain correct.

### Symbol table

- Parses `.symtab` and `.dynsym` and lists name, `st_value`, `st_size`, binding, type, visibility and section, plus separate columns for the offset of the symbol table entry and the offset of the target content. Supports search and filtering by type, binding and table.
- Each row has four actions: entry, content, analysis and disassembly, jumping to the symbol table entry bytes, the section content, the analysis panel, or the disassembly view.
- The analysis panel groups the entry bytes by field and draws the references: `st_name` points into the string table for the name, `st_shndx` points to the section header and its content, `st_value` points to the content offset, and `st_size` gives the byte range. Relocations that reference the symbol are listed as well.

### Relocations

- The section summary lists which symbols a relocation section refers to, how often each is referenced, and whether they are undefined external symbols or defined in a section.
- The per-entry panel groups the bytes of `r_offset`, `r_info` and `r_addend`, splits `r_info` into symbol index and type (high 32 bits and low 32 bits for ELF64; high 24 and low 8 for ELF32), and shows the reconstruction formula plus the complete list of relocation types.
- The patched location is shown as section-relative offset, file offset and section, with the modified instructions highlighted and the modified bit fields labelled: `R_RISCV_CALL` and `R_RISCV_CALL_PLT` mark the `auipc` and `jalr` pair, while `HI20`, `LO12_I`, `LO12_S`, `JAL` and `BRANCH` each follow their own rule. Data relocations show the bytes that will be written.
- Entries that write no data, such as `R_RISCV_RELAX` and `R_RISCV_ALIGN`, are presented as modifiers: the panel states which relocation they modify (the entry immediately above), and highlights the instruction sequence that the modified relocation covers and that may be relaxed.

### Section contents

- `.text` shows an instruction preview, `.symtab` an entry decode table, `.strtab` its strings, `.rela.*` the relocation entries, `.dynamic` its tags and values, and `.note.*` and `.riscv.attributes` are decoded in place.
- `.rodata`, `.data` and similar sections get a decode panel with four views: strings, 32-bit words, 64-bit words and pointer candidates. Word views show hex, decimal and floating-point interpretations, and values that fall inside a mapped section are resolved to "section + offset", including the symbol name when one matches.

### Other

- The overview page shows a colour-coded structure bar and legend; clicking a segment or legend entry jumps to that range.
- Parsing problems (bad magic, invalid class or byte order, out-of-range offsets and so on) produce specific messages.
- Supports ELF32/ELF64, little and big endian, and ET_REL/ET_EXEC/ET_DYN/ET_CORE.

## Screenshots

| Overview | Disassembly |
| --- | --- |
| ![Overview](preview-overview.png) | ![Disassembly](preview-disasm.png) |

| Field value panel | Byte order and bit map |
| --- | --- |
| ![Fields](preview-fields.png) | ![Byte order](preview-byteswap.png) |

| Section contents and instruction encoding | Dictionary |
| --- | --- |
| ![Section contents](preview-instruction-encoding.png) | ![Dictionary](preview-dictionary.png) |

## Testing

Tests run the browser scripts directly under Deno, together with binary fixtures generated by Python:

```sh
sh test/run_all.sh                          # fixtures, tests, syntax check, build
python3 test/make_fixture.py
deno run --allow-read test/run_tests.js     # 1902 assertions
deno run --allow-read test/syntax_check.js  # syntax and DOM reference checks
```

Correctness is checked against three independent sources:

1. The RISC-V decoder against canonical encodings. `test/tests.js` lists hand-verified encodings such as `00100513` for `li a0,1`, `8082` for `ret`, `ff010113` for `addi sp,sp,-16` and `f1402573` for `csrr a0,mhartid`, and compares them with the decoder output.
2. The ELF parser against fixtures assembled byte by byte. `test/make_fixture.py` builds ELF32/ELF64 files by hand, and the tests check header fields, section name resolution, symbol attributes, offset-to-address mapping and whether the region map covers the file exactly. The same `.text` is encoded by Python and decoded by JavaScript, so the two sides are independent implementations.
3. The x86 decoder against real compiler output. An object file is produced with `clang -target x86_64-unknown-linux-gnu -c`, its instruction addresses are recorded with `llvm-objdump`, and the tests compare instruction boundaries one by one.

The tests also scan every piece of documentation text (relocation notes, enum descriptions, field documentation, section purpose dictionary) and reject wording that depends on context, such as "same as above", while requiring a minimum level of detail.

Fixtures: `hello-riscv32.elf` and `hello-riscv64.elf` (small hand-built programs), `big-riscv64.elf` (47 sections, 406 symbols, 39 relocations, 200 functions), `reloc-riscv64.o` (with `R_RISCV_CALL_PLT` followed by `R_RISCV_RELAX`), and `x86-64-sample.o` (clang output).

## Project layout

```
elf-studio.html          Build output: the single-file application
index.html               The same content, served at the site root by GitHub Pages
build.py                 Bundles src/ into the single file
push_to_github.sh        Helper script that creates the repo, pushes and enables Pages
src/
  shell.html             HTML skeleton
  style.css              Styles, including the structure colour scheme
  util.js                Utility functions
  elf-const.js           ELF constants, enum dictionary, field documentation, section dictionary
  elf-enums.js           Enum value decoding
  elf-parse.js           ELF parser
  disasm-riscv.js        RISC-V disassembler and instruction field breakdown
  disasm-x86.js          x86 / x86-64 disassembler (common subset)
  hexview.js             Multi-colour hex view
  app-core.js            State, file loading, synchronisation, byte inspector, overview
  app-panels.js          Structure panels
  app-symbols.js         Symbol table entry analysis and references
  app-relocs.js          Relocation analysis and reference chain
  app-encoding.js        Instruction encoding panel
  app-disasm.js          Disassembly view
test/
  make_fixture.py        Generates the fixtures
  tests.js               Assertions
  run_tests.js           Test runner
  syntax_check.js        Syntax and DOM reference checks
  run_all.sh             Runs everything and rebuilds
```

## Implementation notes

`parseELF()` produces three sets of data in one pass: the structures (header, sections, program headers, symbols, relocations, notes, attributes), a colour region map (`regions`), and a byte annotation table (`annotations`) that maps fields such as `e_machine`, `p_offset` and `sh_flags` to `[start, end)` byte ranges. The inspector only has to query the annotation table to determine which field a byte belongs to.

Section headers and program headers can overlap (a `PT_LOAD` segment usually covers `.text` as well as padding), so each kind of structure is given a priority and the regions are resolved with a single sweep: a higher-priority region cuts off a lower-priority one at its start. The result covers the file exactly and lets the most specific structure win.

The hex view uses a fixed row height, absolute positioning and `translateY` for virtual scrolling. Byte colours are looked up in a `Uint8Array` as long as the file. Selection and highlighting only change classes on visible nodes instead of rebuilding the DOM.

RISC-V uses variable-length encoding, so decoding first checks the low two bits to tell 16-bit instructions from 32-bit ones. Immediates are extracted by their specification bit fields, with special test coverage for the scattered bit fields of the B, J and S formats. If a file does not declare `EF_RISCV_RVC`, 16-bit instructions are shown as data with a note, and the parsing mode can be forced in the settings.

## Known limitations

- The x86/x86-64 decoder covers common integer instructions and part of SSE. Instruction lengths are reliable, but complex encodings such as floating point and AVX may appear as `.byte`.
- ARM, AArch64 and MIPS instructions are not decoded (structures and hex are still available).
- DWARF is not interpreted: `.debug_info` and `.debug_line` are shown as sections only. Disassembly is a linear sweep without a control flow graph, so data embedded in a code section may be decoded as instructions.
- The contents of `.gnu.hash` and SysV `.hash`, and symbol version tables, are not interpreted.
- Very large files (beyond roughly 100 MB) are limited by browser memory.
