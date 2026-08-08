"""Emit the exact kSites152 byte arrays and verify each entry's match count
across .text under the SAME masking the C++ matcher will use, per encoding.

SHORT jg: mask jgOff (7F/EB) and jgOff+1 (disp8 wildcard).
NEAR jg : mask jgOff (0F/90), jgOff+1 (8F/E9), jgOff+2..+5 (rel32 wildcard).
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "port152"))
from pe_info import pe_info  # noqa: E402

INFO = pe_info(str(REPO / "chrome152-stock.dll"))
TR, TRAW, TSZ = INFO["text_rva"], INFO["text_raw"], INFO["text_rawsize"]
DATA = open(REPO / "chrome152-stock.dll", "rb").read()
TEXT = DATA[TRAW : TRAW + TSZ]


def off(rva):
    return TRAW + (rva - TR)


# (name, cmp_rva, jgOff, kind, siglen, expectedCount)
SITES = [
    ("OnExtensionSystemReady startup loop", 0x1241098, 4, "SHORT", 25, 1),
    ("MustRemainDisabled (inlined, near jg)", 0x15a8d2d, 4, "NEAR", 28, 1),
    ("ShouldBlockExtensionEnable / IsExtensionAffected (shared body)", 0x3348750, 4, "SHORT", 24, 2),
    ("MaybeReEnableExtension", 0x82d24d2, 4, "SHORT", 25, 1),
    ("manifest_v2_util::IsExtensionAffected (free predicate, reg form)", 0x82d26f2, 3, "SHORT", 24, 1),
    ("UserMayInstall (inlined)", 0x8ddc23d, 4, "SHORT", 25, 1),
]


def matches_for(sig, jgoff, kind):
    n = len(sig)
    s0 = sig[0]
    res = []
    limit = len(TEXT) - n
    if kind == "SHORT":
        maskset = {jgoff, jgoff + 1}
    else:  # NEAR
        maskset = {jgoff, jgoff + 1, jgoff + 2, jgoff + 3, jgoff + 4, jgoff + 5}
    for r in range(0, limit + 1):
        if TEXT[r] != s0:
            continue
        ok = True
        for k in range(n):
            if k in maskset:
                if kind == "SHORT" and k == jgoff:
                    if TEXT[r + k] not in (0x7F, 0xEB):
                        ok = False
                        break
                elif kind == "NEAR" and k == jgoff:
                    if TEXT[r + k] not in (0x0F, 0x90):
                        ok = False
                        break
                elif kind == "NEAR" and k == jgoff + 1:
                    if TEXT[r + k] not in (0x8F, 0xE9):
                        ok = False
                        break
                # disp bytes: wildcard
                continue
            if TEXT[r + k] != sig[k]:
                ok = False
                break
        if ok:
            res.append(TR + r)
    return res


print("// ---- kSites152 (generated, verified unique/expected across .text) ----\n")
all_ok = True
for name, cmp_rva, jgoff, kind, siglen, expected in SITES:
    o = off(cmp_rva)
    sig = DATA[o : o + siglen]
    m = matches_for(sig, jgoff, kind)
    ok = len(m) == expected
    all_ok &= ok
    status = "OK" if ok else f"MISMATCH got {len(m)}"
    hexsig = ",".join(f"0x{b:02x}" for b in sig)
    jg_rva = cmp_rva + jgoff
    print(f"// {name}")
    print(f"//   kind={kind} jgOff={jgoff} jgRVA={jg_rva:#x} expected={expected} -> {status}")
    if not ok:
        print("//   matches: " + ", ".join(f"{x:#x}" for x in m[:8]))
    print(f"//   {{ {kind}, {jg_rva:#x}, {{ {hexsig} }}, {jgoff}, {expected} }},\n")

print("// ALL SITES VERIFIED:", all_ok)
