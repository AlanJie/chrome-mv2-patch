"""Analysis for the 152 port:
  1. Confirm ManifestV2Handler::IsExtensionAffected (#2) and
     ShouldBlockExtensionEnable (#4) are byte-identical bodies.
  2. Dump the MustRemainDisabled near-jg window exactly.
  3. Find callers (call rel32 / jmp rel32) of the free predicate #1 (0x82d26f0)
     and the object-form IsExtensionAffected #2 (0x82d23a0).
  4. Count matches across .text for each proposed short-jg signature using the
     SAME masking the C++ matcher uses (jgOff byte = 0x7F/0xEB, jgOff+1 = wild).
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


def win(rva, n=24):
    o = off(rva)
    return DATA[o : o + n]


# 1. identical-body check
b2 = win(0x82d23a0, 0x3e)
b4 = win(0x3348750, 0x3e)
print(f"1) #2 vs #4 identical over 0x3e bytes: {b2 == b4}")

# 2. MustRemainDisabled window (cmp at 0x15a8d2d)
mrd = win(0x15a8d2d, 28)
print("\n2) MustRemainDisabled cmp/near-jg window @0x15a8d2d:")
print("   " + " ".join(f"{b:02x}" for b in mrd))
print("   cmp bytes:", " ".join(f"{b:02x}" for b in mrd[:4]),
      " near-jg:", " ".join(f"{b:02x}" for b in mrd[4:10]))

# 3. callers of a target rva via E8 (call rel32) and E9 (jmp rel32)
def find_callers(target_rva):
    hits = []
    for opc, kind in ((0xE8, "call"), (0xE9, "jmp")):
        i = 0
        while True:
            i = TEXT.find(bytes([opc]), i)
            if i == -1 or i + 5 > len(TEXT):
                break
            rel = int.from_bytes(TEXT[i + 1 : i + 5], "little", signed=True)
            src_rva = TR + i
            dst = src_rva + 5 + rel
            if dst == target_rva:
                hits.append((src_rva, kind))
            i += 1
    return hits


for name, rva in (("#1 free predicate", 0x82d26f0),
                  ("#2 obj IsExtensionAffected", 0x82d23a0),
                  ("ShouldBlockExtensionInstallation thunk", 0x82d23e0),
                  ("ShouldBlockExtensionEnable", 0x3348750)):
    callers = find_callers(rva)
    print(f"\n3) callers of {name} ({rva:#x}): {len(callers)}")
    for src, kind in callers[:20]:
        print(f"     {kind} from {src:#x}")


# 4. uniqueness of short-jg 24-byte signatures (C++ matcher masking)
SITES_SHORT = {
    "#1 free predicate":            (0x82d26f2, 3),
    "#2 obj IsExtensionAffected":   (0x82d23a0, 4),
    "#4 ShouldBlockExtensionEnable":(0x3348750, 4),
    "#5 OnExtensionSystemReady":    (0x1241098, 4),
    "#6 MaybeReEnableExtension":    (0x82d24d2, 4),
    "#7 UserMayInstall":            (0x8ddc23d, 4),
}


def count_matches(cmp_rva, jgoff, siglen=24):
    sig = win(cmp_rva, siglen)
    n = len(sig)
    matches = []
    limit = len(TEXT) - n
    s0 = sig[0]
    for r in range(0, limit + 1):
        if TEXT[r] != s0:
            continue
        ok = True
        for k in range(n):
            if k == jgoff:
                if TEXT[r + k] not in (0x7F, 0xEB):
                    ok = False
                    break
            elif k == jgoff + 1:
                continue
            elif TEXT[r + k] != sig[k]:
                ok = False
                break
        if ok:
            matches.append(TR + r)
    return sig, matches


print("\n4) short-jg signature uniqueness across .text (masked like the matcher):")
for name, (cmp_rva, jgoff) in SITES_SHORT.items():
    sig, matches = count_matches(cmp_rva, jgoff)
    tag = "UNIQUE" if len(matches) == 1 else f"*** {len(matches)} MATCHES ***"
    print(f"  {name:32} cmp@{cmp_rva:#x} jgOff={jgoff}: {tag}")
    if len(matches) != 1:
        print("      at " + ", ".join(f"{m:#x}" for m in matches[:8]))
