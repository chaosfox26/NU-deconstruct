# WildStar64 deconstruction — WildStar64.exe

Full hardware deconstruction (Starlight) of Carbine's client binary. Analysis of
the CLIENT only — a fact source; zero NF, zero corpus, zero emulator input.

- **file**: WildStar64.exe (13,927,576 bytes)
- **image base**: 0x140000000 · **entry**: 0x1400088c0
- **device**: NVIDIA GeForce RTX 5090 · **time**: 18s

## Contents (this folder)

| file | what |
|---|---|
| `pe-structure.json` | headers, sections, entry, subsystem |
| `imports.tsv` / `exports.tsv` | 384 imports · 2 exports |
| `strings.tsv.gz` | 198,016 strings (ASCII + UTF-16LE) with VAs |
| `disasm.txt.gz` | 2,636,637 disassembled instructions (full) |
| `string-xrefs.tsv.gz` | every code reference to a string (the RE workhorse) |
| `functions.tsv` | 13,383 function entry points (call targets) |
| `callgraph.tsv.gz` | call-site → callee edges |
| `rtti-classes.tsv` | 10 MSVC RTTI class descriptors |

## Notes

- Strings are BOTH ASCII and UTF-16LE (the WildStar client stores most UI/config
  strings as UTF-16 — an ASCII-only scan misses them).
- Disassembly is a linear sweep of every executable section; overlaps deduped by
  address. Recursive-traversal refinement can be layered on top from `functions.tsv`.
- `string-xrefs.tsv.gz` + `functions.tsv` + `rtti-classes.tsv` together let you
  locate any subsystem by name and read its code.
