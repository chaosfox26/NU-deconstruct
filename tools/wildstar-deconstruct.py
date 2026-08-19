#!/usr/bin/env python3
"""wildstar-deconstruct - full hardware deconstruction of a WildStar client binary.

Starlight tooling: pushes the RTX 5090 (torch) + all CPU cores + RAM to take a PE
apart completely and write a durable, queryable deconstruction into Project
Resources. Analysis of Carbine's client only (a fact source); zero NF, zero corpus.

Phases:
  1. PE structure  - headers, sections, imports, exports, resources, debug, TLS
  2. Strings       - ASCII + UTF-16LE, GPU-classified over the whole image
  3. Disassembly   - full linear sweep of every executable section (capstone)
  4. References    - RIP-relative + immediate targets, GPU-matched to strings/funcs
  5. Functions     - call-target set + prologue scan -> function table + call graph
  6. RTTI          - MSVC type descriptors (.?AV/.?AU) -> class names
  7. Report        - README + TSV/JSON, plus a full disassembly dump (gzipped)

Usage:  python wildstar-deconstruct.py <path-to.exe> <output-dir>
Deps:   pip install pefile capstone torch   (torch optional; falls back to CPU)
"""
import os, sys, gzip, json, time, struct, re
from concurrent.futures import ProcessPoolExecutor

import pefile
import capstone

try:
    import torch
    _HAS_TORCH = True
except Exception:
    _HAS_TORCH = False

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

# ---------------------------------------------------------------- device
def device():
    if _HAS_TORCH and torch.cuda.is_available():
        return "cuda", torch.cuda.get_device_name(0)
    return "cpu", "cpu"

# ---------------------------------------------------------------- PE load
class Image:
    def __init__(self, path):
        self.path = path
        self.pe = pefile.PE(path, fast_load=False)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.sections = []
        for s in self.pe.sections:
            self.sections.append({
                "name": s.Name.rstrip(b"\x00").decode("latin1"),
                "va": self.base + s.VirtualAddress,
                "vsize": s.Misc_VirtualSize,
                "rawsize": s.SizeOfRawData,
                "exec": bool(s.Characteristics & 0x20000000),
                "data": s.get_data(),
            })
        with open(path, "rb") as f:
            self.raw = f.read()

    def code_sections(self):
        return [s for s in self.sections if s["exec"]]

# ---------------------------------------------------------------- phase 1: PE structure
def phase_pe(img, out):
    pe = img.pe
    info = {
        "file": os.path.basename(img.path),
        "size": len(img.raw),
        "image_base": hex(img.base),
        "entry_point": hex(img.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "machine": hex(pe.FILE_HEADER.Machine),
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "sections": [{k: (hex(v) if k in ("va",) else v) for k, v in s.items() if k != "data"}
                     for s in img.sections],
    }
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("latin1")
            for imp in entry.imports:
                imports.append((dll, imp.name.decode("latin1") if imp.name else f"ord{imp.ordinal}",
                                hex(imp.address) if imp.address else ""))
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append((exp.name.decode("latin1") if exp.name else f"ord{exp.ordinal}",
                            hex(img.base + exp.address) if exp.address else ""))
    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            rtn = rt.name.string.decode("latin1") if rt.name else str(rt.id)
            cnt = len(rt.directory.entries) if hasattr(rt, "directory") else 0
            resources.append((rtn, cnt))
    json.dump(info, open(os.path.join(out, "pe-structure.json"), "w"), indent=2)
    with open(os.path.join(out, "imports.tsv"), "w", encoding="utf-8") as f:
        f.write("dll\tsymbol\tiat_addr\n")
        for d, n, a in imports: f.write(f"{d}\t{n}\t{a}\n")
    with open(os.path.join(out, "exports.tsv"), "w", encoding="utf-8") as f:
        f.write("symbol\taddr\n")
        for n, a in exports: f.write(f"{n}\t{a}\n")
    log(f"PE: {len(img.sections)} sections, {len(imports)} imports, {len(exports)} exports, {len(resources)} resource types")
    return info, imports, exports

# ---------------------------------------------------------------- phase 2: strings (GPU)
def phase_strings(img, out, dev, minlen=4):
    results = []   # (va, kind, text)
    for s in img.sections:
        data = s["data"]; va = s["va"]
        if not data: continue
        if dev == "cuda":
            t = torch.frombuffer(bytearray(data), dtype=torch.uint8).cuda()
            printable = (t >= 0x20) & (t < 0x7f)
            pr = printable.cpu().numpy()
        else:
            import numpy as np
            arr = np.frombuffer(data, dtype=np.uint8)
            pr = (arr >= 0x20) & (arr < 0x7f)
        # ASCII runs
        i = 0; n = len(pr)
        while i < n:
            if pr[i]:
                j = i
                while j < n and pr[j]: j += 1
                if j - i >= minlen:
                    results.append((va + i, "ascii", data[i:j].decode("latin1")))
                i = j
            else:
                i += 1
        # UTF-16LE runs: even printable, odd == 0
        i = 0
        while i + 1 < n:
            if pr[i] and data[i + 1] == 0:
                j = i; chars = []
                while j + 1 < n and pr[j] and data[j + 1] == 0:
                    chars.append(chr(data[j])); j += 2
                if len(chars) >= minlen:
                    results.append((va + i, "utf16", "".join(chars)))
                i = j
            else:
                i += 1
    results.sort()
    with gzip.open(os.path.join(out, "strings.tsv.gz"), "wt", encoding="utf-8") as f:
        f.write("va\tkind\ttext\n")
        for va, k, txt in results:
            f.write(f"0x{va:X}\t{k}\t{txt}\n")
    log(f"strings: {len(results):,} (ascii+utf16) [{dev}]")
    return results

# ---------------------------------------------------------------- phase 3: disassembly (parallel)
def _disasm_chunk(args):
    va, data = args
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    # SKIPDATA: continue past undecodable bytes instead of halting at the first
    # one (a linear sweep over a real image hits padding/data between functions).
    md.skipdata = True
    out = []  # (addr, size, mnemonic, op_str, rip_target_or_-1, call_imm_or_-1)
    for insn in md.disasm(data, va):
        if insn.id == 0:   # skipped-data pseudo-instruction ('.byte') - not code
            continue
        rip = -1; callimm = -1
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                rip = insn.address + insn.size + op.mem.disp
        if insn.mnemonic == "call" and insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            callimm = insn.operands[0].imm
        out.append((insn.address, insn.size, insn.mnemonic, insn.op_str, rip, callimm))
    return out

def phase_disasm(img, out):
    insns = []
    for s in img.code_sections():
        data, va = s["data"], s["va"]
        # split into chunks with overlap for parallelism; dedup by address
        step = 1 << 20
        overlap = 16
        jobs = []
        off = 0
        while off < len(data):
            end = min(off + step, len(data))
            e2 = min(end + overlap, len(data))
            jobs.append((va + off, data[off:e2]))
            off = end
        with ProcessPoolExecutor(max_workers=os.cpu_count()) as ex:
            for part in ex.map(_disasm_chunk, jobs):
                insns.extend(part)
    # dedup by address (overlap), keep sorted
    seen = {}
    for it in insns:
        seen[it[0]] = it
    allins = [seen[a] for a in sorted(seen)]
    # full disasm dump (gzipped)
    with gzip.open(os.path.join(out, "disasm.txt.gz"), "wt", encoding="utf-8") as f:
        for a, sz, mn, ops, rip, ci in allins:
            f.write(f"0x{a:X}\t{mn}\t{ops}\n")
    log(f"disasm: {len(allins):,} instructions across code sections")
    return allins

# ---------------------------------------------------------------- phase 4+5: refs, functions (GPU match)
def phase_api_callsites(img, allins, imports, out, dev):
    """Map every indirect call `call [rip+IAT]` to the Windows API it invokes -
    the Win32 dependency surface a native Linux port must replace."""
    import numpy as np
    iat = {}  # iat_va -> (dll, symbol)
    for dll, sym, addr in imports:
        if addr:
            iat[int(addr, 16)] = (dll, sym)
    if not iat:
        return
    keys = np.array(sorted(iat), dtype=np.int64)
    kmap = [iat[int(k)] for k in keys]
    # instructions whose rip-target is an IAT slot AND are calls/jmps
    rows = []
    for a, sz, mn, ops, rip, ci in allins:
        if rip >= 0 and (mn == "call" or mn == "jmp"):
            idx = int(np.searchsorted(keys, rip))
            if 0 <= idx < len(keys) and int(keys[idx]) == rip:
                dll, sym = kmap[idx]
                rows.append((a, dll, sym))
    with gzip.open(os.path.join(out, "api-callsites.tsv.gz"), "wt", encoding="utf-8") as f:
        f.write("call_site\tdll\tapi\n")
        for a, dll, sym in rows:
            f.write(f"0x{a:X}\t{dll}\t{sym}\n")
    # per-API tally (the dependency surface at a glance)
    from collections import Counter
    tally = Counter((dll, sym) for _, dll, sym in rows)
    with open(os.path.join(out, "api-surface.tsv"), "w", encoding="utf-8") as f:
        f.write("callsites\tdll\tapi\n")
        for (dll, sym), c in tally.most_common():
            f.write(f"{c}\t{dll}\t{sym}\n")
    log(f"api: {len(rows):,} Win32 call sites across {len(tally):,} distinct APIs")

def phase_refs_functions(img, allins, strings, out, dev):
    import numpy as np
    # string VAs
    str_va = np.array([s[0] for s in strings], dtype=np.uint64)
    str_txt = [s[2] for s in strings]
    order = np.argsort(str_va); str_va = str_va[order]; str_txt = [str_txt[i] for i in order]
    # gather targets
    ins_addr = np.array([i[0] for i in allins], dtype=np.uint64)
    rip_tgt = np.array([i[4] if i[4] >= 0 else 0 for i in allins], dtype=np.uint64)
    rip_has = np.array([i[4] >= 0 for i in allins])
    call_tgt = np.array([i[5] if i[5] >= 0 else 0 for i in allins], dtype=np.uint64)
    call_has = np.array([i[5] >= 0 for i in allins])
    # match rip targets to string starts (exact) on GPU
    def match_exact(targets, keys):
        if dev == "cuda":
            tt = torch.from_numpy(targets.astype(np.int64)).cuda()
            kk = torch.from_numpy(keys.astype(np.int64)).cuda()
            idx = torch.searchsorted(kk, tt)
            idx = torch.clamp(idx, 0, len(kk) - 1)
            hit = kk[idx] == tt
            return idx.cpu().numpy(), hit.cpu().numpy()
        idx = np.searchsorted(keys, targets); idx = np.clip(idx, 0, len(keys) - 1)
        return idx, keys[idx] == targets
    xr_idx, xr_hit = match_exact(rip_tgt, str_va)
    with gzip.open(os.path.join(out, "string-xrefs.tsv.gz"), "wt", encoding="utf-8") as f:
        f.write("insn_addr\tstring_va\ttext\n")
        for k in range(len(allins)):
            if rip_has[k] and xr_hit[k]:
                f.write(f"0x{ins_addr[k]:X}\t0x{str_va[xr_idx[k]]:X}\t{str_txt[xr_idx[k]]}\n")
    # functions = call targets (sorted unique) + call graph
    call_targets = np.unique(call_tgt[call_has])
    with open(os.path.join(out, "functions.tsv"), "w", encoding="utf-8") as f:
        f.write("func_addr\n")
        for a in call_targets: f.write(f"0x{a:X}\n")
    with gzip.open(os.path.join(out, "callgraph.tsv.gz"), "wt", encoding="utf-8") as f:
        f.write("call_site\tcallee\n")
        for k in range(len(allins)):
            if call_has[k]:
                f.write(f"0x{ins_addr[k]:X}\t0x{call_tgt[k]:X}\n")
    log(f"refs: {int(xr_hit.sum()):,} string xrefs; functions: {len(call_targets):,} call targets [{dev}]")
    return call_targets

# ---------------------------------------------------------------- phase 6: RTTI
def phase_rtti(img, out):
    # MSVC RTTI type descriptors carry mangled names like .?AVClassName@@
    names = []
    for s in img.sections:
        for m in re.finditer(rb"\.\?A[UV][\w@?$]+@@", s["data"]):
            va = s["va"] + m.start()
            names.append((va, m.group(0).decode("latin1")))
    names.sort()
    with open(os.path.join(out, "rtti-classes.tsv"), "w", encoding="utf-8") as f:
        f.write("va\tmangled\n")
        for va, nm in names: f.write(f"0x{va:X}\t{nm}\n")
    log(f"RTTI: {len(names):,} type descriptors")
    return names

# ---------------------------------------------------------------- report
def write_report(img, out, dev_name, info, imports, exports, strings, allins, funcs, rtti, took):
    md = f"""# WildStar64 deconstruction — {os.path.basename(img.path)}

Full hardware deconstruction (Starlight) of Carbine's client binary. Analysis of
the CLIENT only — a fact source; zero NF, zero corpus, zero emulator input.

- **file**: {os.path.basename(img.path)} ({len(img.raw):,} bytes)
- **image base**: {hex(img.base)} · **entry**: {info['entry_point']}
- **device**: {dev_name} · **time**: {took:.0f}s

## Contents (this folder)

| file | what |
|---|---|
| `pe-structure.json` | headers, sections, entry, subsystem |
| `imports.tsv` / `exports.tsv` | {len(imports):,} imports · {len(exports):,} exports |
| `strings.tsv.gz` | {len(strings):,} strings (ASCII + UTF-16LE) with VAs |
| `disasm.txt.gz` | {len(allins):,} disassembled instructions (full) |
| `string-xrefs.tsv.gz` | every code reference to a string (the RE workhorse) |
| `functions.tsv` | {len(funcs):,} function entry points (call targets) |
| `callgraph.tsv.gz` | call-site → callee edges |
| `rtti-classes.tsv` | {len(rtti):,} MSVC RTTI class descriptors |

## Notes

- Strings are BOTH ASCII and UTF-16LE (the WildStar client stores most UI/config
  strings as UTF-16 — an ASCII-only scan misses them).
- Disassembly is a linear sweep of every executable section; overlaps deduped by
  address. Recursive-traversal refinement can be layered on top from `functions.tsv`.
- `string-xrefs.tsv.gz` + `functions.tsv` + `rtti-classes.tsv` together let you
  locate any subsystem by name and read its code.
"""
    open(os.path.join(out, "README.md"), "w", encoding="utf-8").write(md)
    log("report written")

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    path, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    dev, dev_name = device()
    log(f"deconstructing {path} -> {out}  [device: {dev_name}, cpus: {os.cpu_count()}]")
    t0 = time.time()
    img = Image(path)
    info, imports, exports = phase_pe(img, out)
    strings = phase_strings(img, out, dev)
    allins = phase_disasm(img, out)
    phase_api_callsites(img, allins, imports, out, dev)
    funcs = phase_refs_functions(img, allins, strings, out, dev)
    rtti = phase_rtti(img, out)
    took = time.time() - t0
    write_report(img, out, dev_name, info, imports, exports, strings, allins, funcs, rtti, took)
    log(f"DONE in {took:.0f}s -> {out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
