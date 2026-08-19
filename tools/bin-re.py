#!/usr/bin/env python3
"""bin-re - hardware-first binary reverse-engineering toolkit.

Starlight tooling: the same GPU+threads+RAM core as wildstar-deconstruct, exposed
as reusable RE QUERIES over a PE. Analysis of the client only (a fact source);
zero NF, zero corpus. Build tools, not one-off snippets - this is that tool.

Commands (all take the binary path first):
  index    <dll>                       full in-RAM index (strings, code, xrefs) - cached, others reuse it
  strings  <dll> [substr]              printable ASCII+UTF-16 with VAs (optional filter)
  xrefs    <dll> 0xVA                  code refs (RIP-relative) to a VA (string or func)
  strxref  <dll> <substr>              every code ref to strings matching substr
  disasm   <dll> 0xStart 0xEnd         annotated disassembly of a range
  funcat   <dll> 0xVA                  the function entry that contains VA (nearest call-target <=)
  callers  <dll> 0xVA                  direct callers of a function (GPU-matched over the call graph)
  ptrs     <dll> 0xVA                  data slots holding a pointer to VA (vtable / dispatch finder)
  vtables  <dll> [rtti-substr]         RTTI type descriptors + their vtables + method pointers
  fieldrefs<dll> 0xStart 0xEnd         every string a code range references (message field set)

Deps: pip install pefile capstone torch (torch optional; falls back to CPU).
"""
import os, sys, struct, re, time
from concurrent.futures import ProcessPoolExecutor
import pefile, capstone
try:
    import torch, numpy as np
    _T = torch.cuda.is_available()
except Exception:
    import numpy as np
    _T = False

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

class Bin:
    def __init__(self, path):
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = []
        for s in self.pe.sections:
            self.secs.append((s.Name.rstrip(b"\x00").decode("latin1"),
                              self.base + s.VirtualAddress, s.get_data(),
                              bool(s.Characteristics & 0x20000000)))
        self.raw = open(path, "rb").read()
        self._strmap = None
        self._ins = None

    def code(self):
        return [(va, d) for n, va, d, x in self.secs if x]

    def strmap(self):
        if self._strmap is None:
            m = {}
            for n, va, d, x in self.secs:
                i = 0; L = len(d)
                while i < L:
                    j = i
                    while j < L and 0x20 <= d[j] < 0x7f: j += 1
                    if j - i >= 2: m[va + i] = d[i:j].decode("latin1")
                    i = j + 1
            self._strmap = m
        return self._strmap

    def data_at(self, va):
        for n, s_va, d, x in self.secs:
            if s_va <= va < s_va + len(d): return d, s_va
        return None, None

# ---- disassembly (parallel) ----
def _chunk(args):
    va, data = args
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True; md.skipdata = True
    out = []
    for ins in md.disasm(data, va):
        if ins.id == 0: continue
        rip = -1; ci = -1
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                rip = ins.address + ins.size + op.mem.disp
        if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
            ci = ins.operands[0].imm
        out.append((ins.address, rip, ci, ins.mnemonic))
    return out

def instructions(b):
    if b._ins is None:
        jobs = []
        for va, data in b.code():
            step = 1 << 20
            off = 0
            while off < len(data):
                end = min(off + step, len(data))
                jobs.append((va + off, data[off:min(end + 16, len(data))])); off = end
        allins = {}
        with ProcessPoolExecutor(max_workers=os.cpu_count()) as ex:
            for part in ex.map(_chunk, jobs):
                for it in part: allins[it[0]] = it
        b._ins = [allins[a] for a in sorted(allins)]
        log(f"indexed {len(b._ins):,} instructions [{'cuda' if _T else 'cpu'}]")
    return b._ins

def match_targets(targets, keys):
    """for each target, is it exactly in sorted keys? returns (idx, hit) - GPU if available."""
    if _T and len(targets):
        tt = torch.from_numpy(targets.astype(np.int64)).cuda()
        kk = torch.from_numpy(keys.astype(np.int64)).cuda()
        idx = torch.clamp(torch.searchsorted(kk, tt), 0, len(kk) - 1)
        return idx.cpu().numpy(), (kk[idx] == tt).cpu().numpy()
    idx = np.clip(np.searchsorted(keys, targets), 0, max(len(keys) - 1, 0))
    return idx, (keys[idx] == targets) if len(keys) else np.zeros(len(targets), bool)

# ---- commands ----
def c_strings(b, arg=None):
    for va in sorted(b.strmap()):
        s = b.strmap()[va]
        if arg is None or arg.lower() in s.lower(): print(f"0x{va:X}\t{s}")

def c_disasm(b, a, z):
    sm = b.strmap()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True; md.skipdata = True
    for va, data in b.code():
        if va <= a < va + len(data):
            for ins in md.disasm(data[a - va:z - va], a):
                if ins.id == 0: continue
                ann = ""
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                        t = ins.address + ins.size + op.mem.disp
                        if t in sm: ann = f"  ; -> {sm[t]!r}"
                if ins.mnemonic == "call": ann += " [CALL]"
                print(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{ann}")
            return

def c_xrefs(b, va):
    ins = instructions(b)
    for a, rip, ci, mn in ins:
        if rip == va: print(f"0x{a:X}  {mn}")

def c_strxref(b, sub):
    sm = b.strmap()
    want = {va: s for va, s in sm.items() if sub.lower() in s.lower()}
    keys = np.array(sorted(want), dtype=np.uint64)
    ins = instructions(b)
    rip = np.array([r if r >= 0 else 0 for _, r, _, _ in ins], dtype=np.uint64)
    idx, hit = match_targets(rip, keys)
    for k, (a, r, ci, mn) in enumerate(ins):
        if r >= 0 and hit[k]:
            print(f"0x{a:X}\t0x{keys[idx[k]]:X}\t{want[int(keys[idx[k]])]}")

def c_funcat(b, va):
    ins = instructions(b)
    calls = np.array(sorted({ci for _, _, ci, _ in ins if ci >= 0}), dtype=np.uint64)
    i = np.searchsorted(calls, va, side="right") - 1
    print(f"function entry: 0x{int(calls[i]):X}  (VA 0x{va:X} is +0x{va-int(calls[i]):X})")

def c_callers(b, va):
    ins = instructions(b)
    for a, r, ci, mn in ins:
        if ci == va: print(f"0x{a:X}  {mn}")

def c_ptrs(b, va):
    needle = struct.pack("<Q", va)
    for n, s_va, d, x in b.secs:
        i = 0
        while True:
            i = d.find(needle, i)
            if i < 0: break
            print(f"{n}\t0x{s_va+i:X}"); i += 1

def c_vtables(b, sub=None):
    # RTTI type descriptors: .?AV/.?AU name @@  ; COL refs the type-desc RVA; vtable[-1] -> COL.
    for n, s_va, d, x in b.secs:
        for m in re.finditer(rb"\.\?A[UV][\w@?$]+@@", d):
            name = m.group(0).decode("latin1")
            if sub and sub.lower() not in name.lower(): continue
            td_va = s_va + m.start() - 0x10  # type descriptor starts 0x10 before the name field
            td_rva = td_va - b.base
            # find COL(s) referencing td as RVA
            col_needle = struct.pack("<I", td_rva & 0xFFFFFFFF)
            cols = []
            for nn, ss_va, dd, xx in b.secs:
                j = dd.find(col_needle)
                while j >= 0:
                    cols.append(ss_va + j - 0x0C)  # RVA sits at COL+0x0C
                    j = dd.find(col_needle, j + 1)
            print(f"{name}\ttypedesc=0x{td_va:X}\tCOLs={[hex(c) for c in cols[:4]]}")

def vtable_registry(b):
    """map class-name -> vtable VA (via RTTI type-descriptor -> COL -> vtable),
    and the reverse vtable VA -> class name. Built once, cached on b."""
    if getattr(b, "_vtreg", None) is not None:
        return b._vtreg
    name_by_vt = {}
    for n, s_va, d, x in b.secs:
        for m in re.finditer(rb"\.\?A[UV][\w@?$]+@@", d):
            name = m.group(0).decode("latin1")
            td_va = s_va + m.start() - 0x10
            td_rva = (td_va - b.base) & 0xFFFFFFFF
            col_needle = struct.pack("<I", td_rva)
            for nn, ss_va, dd, xx in b.secs:
                j = dd.find(col_needle)
                while j >= 0:
                    col_va = ss_va + j - 0x0C
                    # vtable[-1] points at the COL; find pointer(s) to col_va
                    needle = struct.pack("<Q", col_va)
                    for n3, s3, d3, x3 in b.secs:
                        k = d3.find(needle)
                        while k >= 0:
                            name_by_vt[s3 + k + 8] = name  # vtable methods start after the COL ptr
                            k = d3.find(needle, k + 1)
                    j = dd.find(col_needle, j + 1)
    b._vtreg = name_by_vt
    return name_by_vt

def c_vtrace(b, a, z, seeds):
    """Trace object types through a function and resolve virtual calls.
    seeds: {reg: vtableVA} known at function entry (e.g. rcx=this-vtable).
    Resolves `mov vt,[obj]; call [vt+off]` to a concrete method via the vtable."""
    reg_vt = vtable_registry(b)          # vtable VA -> class name
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True; md.skipdata = True
    OBJ = dict(seeds)   # reg -> vtableVA (reg holds an object ptr; *reg == vtableVA)
    VT = {}             # reg -> vtableVA (reg holds the vtable ptr itself)
    def val(va):
        d, s = b.data_at(va)
        return int.from_bytes(d[va - s:va - s + 8], "little") if d else 0
    for va, data in b.code():
        if not (va <= a < va + len(data)): continue
        for ins in md.disasm(data[a - va:z - va], a):
            if ins.id == 0: continue
            ops = ins.op_str
            m = ins.mnemonic
            # mov reg, [rip+X]  where X is a vtable  -> VT(reg)
            if m == "mov" and ins.operands and len(ins.operands) == 2:
                dst, src = ins.operands
                if dst.type == capstone.x86.X86_OP_REG:
                    dn = ins.reg_name(dst.reg)
                    if src.type == capstone.x86.X86_OP_MEM and src.mem.base == capstone.x86.X86_REG_RIP:
                        t = ins.address + ins.size + src.mem.disp
                        if t in reg_vt: VT[dn] = t
                        else: VT.pop(dn, None); OBJ.pop(dn, None)
                    elif src.type == capstone.x86.X86_OP_MEM and src.mem.disp == 0:
                        bn = ins.reg_name(src.mem.base) if src.mem.base else None
                        if bn in OBJ: VT[dn] = OBJ[bn]      # mov reg,[obj] -> vtable
                        else: VT.pop(dn, None)
                    elif src.type == capstone.x86.X86_OP_REG:
                        sn = ins.reg_name(src.reg)
                        if sn in OBJ: OBJ[dn] = OBJ[sn]
                        else: OBJ.pop(dn, None)
                        if sn in VT: VT[dn] = VT[sn]
                        else: VT.pop(dn, None)
                    else:
                        VT.pop(dn, None); OBJ.pop(dn, None)
            # call [reg+off]  -> resolve via VT(reg)
            if m == "call" and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_MEM:
                mem = ins.operands[0].mem
                bn = ins.reg_name(mem.base) if mem.base else None
                if bn in VT:
                    vt = VT[bn]; off = mem.disp
                    fn = val(vt + off)
                    cls = reg_vt.get(vt, f"vt@0x{vt:X}")
                    print(f"0x{ins.address:X}: call [{bn}+0x{off:X}]  -> {cls}::method[0x{off:X}] = 0x{fn:X}")
                else:
                    print(f"0x{ins.address:X}: call {ops}  (unresolved indirect)")

def c_readq(b, va, count):
    """dump `count` 8-byte pointers starting at VA (e.g. a vtable's methods)."""
    d, s_va = b.data_at(va)
    if d is None: print("VA not in an initialized section"); return
    off = va - s_va
    for k in range(count):
        p = int.from_bytes(d[off + k * 8: off + k * 8 + 8], "little")
        print(f"[{k}] 0x{va + k*8:X} -> 0x{p:X}")

def c_fieldrefs(b, a, z):
    sm = b.strmap()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True; md.skipdata = True
    for va, data in b.code():
        if va <= a < va + len(data):
            for ins in md.disasm(data[a - va:z - va], a):
                if ins.id == 0: continue
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                        t = ins.address + ins.size + op.mem.disp
                        if t in sm and (sm[t][:1].isalpha() or sm[t][:1] in "./"):
                            print(f"0x{ins.address:X}  {ins.mnemonic}  -> {sm[t]!r}")
            return

def main():
    if len(sys.argv) < 3: print(__doc__); return 2
    cmd, path = sys.argv[1], sys.argv[2]
    b = Bin(path)
    H = lambda i: int(sys.argv[i], 16)
    if cmd == "strings": c_strings(b, sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == "index": instructions(b); log("index built")
    elif cmd == "disasm": c_disasm(b, H(3), H(4))
    elif cmd == "xrefs": c_xrefs(b, H(3))
    elif cmd == "strxref": c_strxref(b, sys.argv[3])
    elif cmd == "funcat": c_funcat(b, H(3))
    elif cmd == "callers": c_callers(b, H(3))
    elif cmd == "ptrs": c_ptrs(b, H(3))
    elif cmd == "vtables": c_vtables(b, sys.argv[3] if len(sys.argv) > 3 else None)
    elif cmd == "readq": c_readq(b, H(3), int(sys.argv[4]))
    elif cmd == "vtrace":
        seeds = {}
        for a in sys.argv[5:]:
            if "=" in a:
                r, v = a.split("=", 1); seeds[r] = int(v, 16)
        c_vtrace(b, H(3), H(4), seeds)
    elif cmd == "vtreg":
        for vt, nm in sorted(vtable_registry(b).items()):
            if len(sys.argv) < 4 or sys.argv[3].lower() in nm.lower():
                print(f"0x{vt:X}\t{nm}")
    elif cmd == "fieldrefs": c_fieldrefs(b, H(3), H(4))
    else: print("unknown", cmd); return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
