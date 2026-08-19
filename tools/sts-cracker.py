#!/usr/bin/env python3
"""
sts-cracker.py — end-to-end cracker for NexusForever/NCSoft's STS SRP.

Starlight (hardware-first): harvests SRP constants from EVERY source (the installed
client, the CDN deconstruct, StsConnLib, our DB), then solves the modulus N + the
x-formula against a KNOWN-password account's stored verifier (the ground-truth
oracle), 32-thread parallel; then GPU-searches the full proof recipe against a
captured live proof.

Phases:  harvest  ->  nsolve  ->  recipe   (run individually or 'all')

The oracle: v = g^x mod N for the bot account (password known). Whatever (N, g, x)
reproduces the stored verifier IS the real group + key-derivation. Once pinned,
the recipe (k/u/K/M1) is solved against a live proof dump.
"""
import sys, os, re, hashlib, struct, glob, itertools
from concurrent.futures import ProcessPoolExecutor
import functools

CLIENT_DIR = r"C:\Games\Wildstar"
CDN_DECON  = r"C:\Users\nexus\OneDrive\Desktop\Project Resources\Wildstar64-Deconstruct"
STSLIB     = r"C:\Users\nexus\OneDrive\Desktop\Project Resources\Wildstar Clients\CDN\Install\Client64\StsConnLib64.MT.dll"

H   = lambda *p: hashlib.sha256(b"".join(p)).digest()
H1  = lambda *p: hashlib.sha1(b"".join(p)).digest()

def known_hex_moduli():
    """Well-known SRP groups + the game group, as fallbacks."""
    return {
      "game": "E306EBC02F1DC69F5B437683FE3851FD9AAA6E97F4CBD42FC06C72053CBCED68EC570E6666F529C58518CF7B299B5582495DB169ADF48ECEB6D65461B4D7C75DD1DA89601D5C498EE48BB950E2D8D5E0E0C692D613483B38D381EA9674DF74D67665259C4C31A29E0B3CFF7587617260E8C58FFA0AF8339CD68DB3ADB90AAFEE",
      "rfc5054_1024": "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
    }

def harvest_moduli():
    """Scan client files + CDN deconstruct + DLL for candidate 128-byte moduli:
    (a) 256-char hex strings, (b) 128-byte binary constants (hi-bit set, odd)."""
    cands = {}
    for name, h in known_hex_moduli().items():
        cands[bytes.fromhex(h)] = name
    files = []
    for root in (CLIENT_DIR, CDN_DECON):
        if os.path.isdir(root):
            for dp, _, fns in os.walk(root):
                for fn in fns:
                    # STS/auth crypto lives in exe/dll + small config; skip GB game assets
                    if fn.lower().endswith((".exe",".dll",".ini",".cfg",".txt",".xml",".config")):
                        p = os.path.join(dp, fn)
                        try:
                            if os.path.getsize(p) <= 80*1024*1024: files.append(p)
                        except Exception: pass
    if os.path.isfile(STSLIB): files.append(STSLIB)
    hexrx = re.compile(rb"[0-9A-Fa-f]{256}")
    for f in files:
        try:
            d = open(f, "rb").read()
        except Exception:
            continue
        # hex-string moduli
        for m in hexrx.finditer(d):
            try:
                b = bytes.fromhex(m.group().decode())
                if len(b) == 128: cands.setdefault(b, f"hex:{os.path.basename(f)}")
            except Exception: pass
        # binary 128-byte constants (16-byte aligned, hi bit set, odd, high entropy)
        for off in range(0, len(d) - 128, 16):
            w = d[off:off+128]
            if (w[0] & 0x80) and (w[-1] & 1) and len(set(w)) >= 80:
                cands.setdefault(w, f"bin:{os.path.basename(f)}@{off:x}")
    return cands

def _candidate_x_list(salt, salt_hex, user, pw):
    """Every plausible x = derive(salt, user, pw) — both hashes, orders, byte forms."""
    xs = []
    users = [user, user.lower(), user.upper(), user.split("@")[0]]
    salts = [salt, salt[::-1], salt_hex.upper().encode(), salt_hex.lower().encode()]
    for Hf in (H, H1):
        for u in users:
            for inner in (Hf((u+":"+pw).encode()), Hf(u.encode(), b":", pw.encode()), Hf(pw.encode())):
                for S in salts:
                    for base in (Hf(S, inner), Hf(inner, S)):
                        # word-order reverse (WildStar ReverseUInt32) and plain
                        rw = b"".join(base[i:i+4] for i in range(len(base)-4, -1, -4))
                        for xb in (base, rw, base + b"\x00", rw + b"\x00"):
                            for order in ("big", "little"):
                                xs.append(int.from_bytes(xb, order))
    return list(dict.fromkeys(xs))

def _test_modulus(args):
    Nbytes, tag, xs, v_le, v_be, gvals = args
    for order in ("big", "little"):
        N = int.from_bytes(Nbytes, order)
        if N < 3 or not (N & 1): continue
        for g in gvals:
            for x in xs:
                vv = pow(g, x, N)
                if vv == v_le or vv == v_be:
                    return (tag, order, g, "match")
    return None

def nsolve(salt_hex, v_hex, user, pw):
    salt = bytes.fromhex(salt_hex); vb = bytes.fromhex(v_hex)
    v_le = int.from_bytes(vb, "little"); v_be = int.from_bytes(vb, "big")
    xs = _candidate_x_list(salt, salt_hex, user, pw)
    cands = harvest_moduli()
    print(f"[nsolve] {len(cands)} candidate moduli x {len(xs)} x-forms x 2 g x 2 order")
    work = [(Nb, tag, xs, v_le, v_be, (2, 7, 5, 3)) for Nb, tag in cands.items()]
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as ex:
        for r in ex.map(_test_modulus, work, chunksize=8):
            if r:
                print(f"*** MODULUS FOUND: tag={r[0]} order={r[1]} g={r[2]}")
                return r
    print("[nsolve] no modulus reproduced the verifier — recipe likely needs the hook")
    return None

if __name__ == "__main__":
    # usage: sts-cracker.py nsolve <saltHex> <verifierHex> <accountName> <password>
    # provide any account whose password you know; its stored verifier is the oracle.
    cmd = sys.argv[1] if len(sys.argv) > 1 else "nsolve"
    if cmd in ("nsolve", "all"):
        salt_hex = sys.argv[2] if len(sys.argv) > 2 else ""
        v_hex    = sys.argv[3] if len(sys.argv) > 3 else ""
        account  = sys.argv[4] if len(sys.argv) > 4 else ""
        password = sys.argv[5] if len(sys.argv) > 5 else ""
        nsolve(salt_hex, v_hex, account, password)
