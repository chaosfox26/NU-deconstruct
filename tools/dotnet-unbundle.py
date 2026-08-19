#!/usr/bin/env python3
"""
dotnet-unbundle.py <exe> <outdir>   -- extract a .NET single-file bundle.

Tears a .NET single-file self-contained app (apphost + appended bundle) into
its embedded files: managed assemblies, the runtime, native libs, deps.json,
runtimeconfig.json, resources. Hardware-first (Starlight): the 331-file
extract + per-file raw-deflate decompression fans out across all CPU threads.

Bundle format = Microsoft.NET.HostModel.Bundle (versions 1/2/6). The manifest
is located by the 16-byte bundle signature; the int64 immediately before it is
the absolute header offset. v6 file entries carry a CompressedSize; nonzero =>
raw Deflate (wbits -15). No third-party deps beyond the stdlib.

Writes <outdir>/<relativePath...> and <outdir>/_manifest.tsv (every entry:
type, offset, size, compressedSize, path). Clean-room: reads bytes, decodes a
published, documented container format; no emulator source involved.
"""
import sys, os, struct, zlib, io
from concurrent.futures import ThreadPoolExecutor

SIG = bytes([0x8b,0x12,0x02,0xb9,0x6a,0x61,0x20,0x38,0x72,0x7b,0x93,0x02,0x14,0xd7,0xa0,0x32])
FTYPE = {0:"Unknown",1:"Assembly",2:"NativeBinary",3:"DepsJson",4:"RuntimeConfigJson",5:"Symbols"}

def read_7bit(data, o):
    """.NET BinaryReader.Read7BitEncodedInt -> (value, new_offset)."""
    val = 0; shift = 0
    while True:
        b = data[o]; o += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return val, o

def read_str(data, o):
    n, o = read_7bit(data, o)
    return data[o:o+n].decode("utf-8"), o + n

def parse(data):
    i = data.find(SIG)
    if i < 0: raise SystemExit("not a .NET single-file bundle (signature absent)")
    hdr = struct.unpack_from("<q", data, i - 8)[0]
    o = hdr
    major, minor, count = struct.unpack_from("<iii", data, o); o += 12
    bundle_id, o = read_str(data, o)
    if major >= 2:
        o += 8*4 + 8   # deps(off,size) + runtimeconfig(off,size) + flags(int64)
    entries = []
    for _ in range(count):
        off, size = struct.unpack_from("<qq", data, o); o += 16
        csize = 0
        if major >= 6:
            csize = struct.unpack_from("<q", data, o)[0]; o += 8
        ftype = data[o]; o += 1
        rel, o = read_str(data, o)
        entries.append((rel, ftype, off, size, csize))
    return (major, minor, bundle_id, entries)

def extract_one(data, outdir, e):
    rel, ftype, off, size, csize = e
    raw = data[off:off + (csize if csize else size)]
    blob = zlib.decompress(raw, -15) if csize else raw
    dst = os.path.join(outdir, rel.replace("\\", "/"))
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "wb") as f: f.write(blob)
    return (rel, ftype, off, size, csize, len(blob))

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 2
    exe, outdir = sys.argv[1], sys.argv[2]
    data = open(exe, "rb").read()
    major, minor, bundle_id, entries = parse(data)
    os.makedirs(outdir, exist_ok=True)
    print(f"bundle v{major}.{minor}  id={bundle_id}  files={len(entries)}  ({len(data):,} bytes)")
    results = []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        for r in ex.map(lambda e: extract_one(data, outdir, e), entries):
            results.append(r)
    with open(os.path.join(outdir, "_manifest.tsv"), "w", encoding="utf-8") as m:
        m.write("path\ttype\toffset\tstoredSize\tcompressedSize\tuncompressedSize\n")
        for rel, ftype, off, size, csize, usize in sorted(results):
            m.write(f"{rel}\t{FTYPE.get(ftype,ftype)}\t{off}\t{size}\t{csize}\t{usize}\n")
    asm = sum(1 for r in results if r[1] == 1)
    print(f"extracted {len(results)} files ({asm} assemblies) -> {outdir}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
