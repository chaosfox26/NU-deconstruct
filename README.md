# NU-deconstruct

A public, reproducible **deconstruction database of the WildStar client** (build
16042, the final 2018 patch). Every binary here is decompressed, disassembled,
and mapped — strings, functions, cross-references, call graph, RTTI classes, and
the full Win32 API surface — so the client can be studied and rebuilt in the open.

WildStar was shut down in 2018 and never shipped a Linux client or a server. This
is preservation and groundwork: understanding Carbine's own binary from the
outside, as facts, to build things it never had.

## What's here

| binary | what it is |
|---|---|
| [`WildStar64.exe/`](WildStar64.exe/) | the main game client (13.9 MB) — **2.64M instructions**, 198K strings, 13,383 functions, and the Win32 dependency surface |
| [`StsConnLib64.MT.dll/`](StsConnLib64.MT.dll/) | the login/STS connection library — 336K instructions, 230 RTTI classes |
| [`tools/`](tools/) | the deconstructor + RE toolkit that produced all of it (reproduce it yourself) |

Each binary folder holds:

- `pe-structure.json` — headers, sections, entry point, subsystem
- `imports.tsv` / `exports.tsv` — the import/export tables
- `strings.tsv.gz` — every printable string (ASCII **and UTF-16LE**) with its virtual address
- `disasm.txt.gz` — the full linear disassembly (every executable section)
- `functions.tsv` — function entry points (call targets)
- `callgraph.tsv.gz` — call-site → callee edges
- `string-xrefs.tsv.gz` — every code reference to a string (the workhorse for finding subsystems by name)
- `rtti-classes.tsv` — MSVC RTTI class descriptors
- `api-surface.tsv` / `api-callsites.tsv.gz` — every Windows API the binary calls and where (**the replacement surface for a native Linux port**)

## Tools

Built for the hardware — GPU (via torch) for the parallel-data passes, all CPU
cores for disassembly, everything held in RAM. See [`tools/`](tools/).

```
pip install pefile capstone torch
python tools/wildstar-deconstruct.py <binary> <output-dir>   # full teardown
python tools/bin-re.py strxref <binary> <substr>             # query: refs to a string
python tools/bin-re.py vtables <binary> <class-substr>       # RTTI classes -> vtables
python tools/bin-re.py disasm  <binary> 0xStart 0xEnd        # annotated disassembly
```

## Provenance

100% analysis of Carbine's own client binaries — a fact source. No emulator
source, no third-party server code. The strings, opcodes, formats, and structure
here are facts about the client, extracted directly from it.
