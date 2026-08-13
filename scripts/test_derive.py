"""Safety checks for the arm64 bcond finder/masker in derive_milestone.py."""
import struct, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import derive_milestone as dm

W = lambda *ws: b"".join(struct.pack("<I", w) for w in ws)
CMP2 = 0x7100091F   # cmp w8,#2
CMP1 = 0x7100051F   # cmp w8,#1  (type follow-up)
BGT  = 0x5400008C   # b.gt +?    (cond GT)
BAL  = 0x5400008E   # b.al +?    (cond AL, i.e. already patched)
BLE  = 0x5400008D   # b.le +?    (cond LE, inverted-sense)
NOP  = 0xD503201F
MOVZ0 = 0x52800000  # movz w0,#0
RET  = 0xD65F03C0


class Img:
    """Minimal stand-in exposing .text/.container/.rva for the finder."""
    def __init__(self, container, text):
        self.container, self._t = container, text
    @property
    def text(self):
        return self._t
    def rva(self, p):
        return p + 0x100000000


def gates(text):
    return dm.find_gates_arm64(Img("macho-arm64", text))


def n_matches(sig_text, sig_hex, jg_off):
    return len(dm.masked_match_count(sig_text, bytes.fromhex(sig_hex), jg_off, "bcond", cap=8))


ok = True

# 1. Stock gate is found; derive a site from it.
stock = W(CMP2, BGT, NOP, CMP1)
g = gates(stock)
assert len(g) == 1 and g[0][2] == "bcond", g
site, cnt = dm.build_site(Img("macho-arm64", stock), g[0][0], g[0][1], "bcond", "s")
print(f"[1] stock gate found: sig={site['sig']} matches={cnt}")
ok &= cnt == 1

# 2. Idempotency: the stock-derived signature still matches a PATCHED (AL) binary,
#    so a re-run relocates/recognizes it instead of double-writing.
patched = W(CMP2, BAL, NOP, CMP1)
m = n_matches(patched, site["sig"], site["jgOff"])
print(f"[2] patched(AL) still matches stock sig: {m} (expect 1)")
ok &= m == 1

# 3. find_gates_arm64 does NOT re-anchor on an already-patched binary (anchor=GT),
#    so it never emits a fresh 'stock' gate for patched bytes.
print(f"[3] find_gates on patched(AL): {len(gates(patched))} (expect 0)")
ok &= len(gates(patched)) == 0

# 4. Inverted polarity: fall-through is `movz w0,#0 ; ret` (the not-affected return),
#    no #1/#5 type follow-up -> DECLINE (flipping would force the wrong outcome).
inverted = W(CMP2, BGT, MOVZ0, RET)
print(f"[4] inverted-polarity gate: {len(gates(inverted))} (expect 0 = declined)")
ok &= len(gates(inverted)) == 0

# 5. A wrong condition (LE) in the branch word must NOT match the stock sig.
wrong = W(CMP2, BLE, NOP, CMP1)
m = n_matches(wrong, site["sig"], site["jgOff"])
print(f"[5] LE-condition binary matches stock sig: {m} (expect 0)")
ok &= m == 0

# 6. The arm64 bcond finder is shared by macOS arm64 AND Windows-on-ARM (pe-arm64):
#    find_gates_for must dispatch BOTH arm64 containers to find_gates_arm64, and
#    the x86 containers to the jg finder. A pe-arm64 image finds the same gate.
g_win = dm.find_gates_for(Img("pe-arm64", stock))
print(f"[6] pe-arm64 dispatch -> arm64 finder: {len(g_win)} gate(s) kind={g_win[0][2] if g_win else None} (expect 1 bcond)")
ok &= len(g_win) == 1 and g_win[0][2] == "bcond"
g_x64 = dm.find_gates_for(Img("pe", stock))  # x64 jg finder must NOT match arm64 bytes
print(f"[7] pe (x64) dispatch -> jg finder on arm64 bytes: {len(g_x64)} (expect 0)")
ok &= len(g_x64) == 0

print("ALL bcond SAFETY CHECKS:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
