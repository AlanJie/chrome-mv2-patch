"""Ground-truth sweep: find EVERY IsExtensionAffected gate in 152 .text,
covering BOTH short jg (0x7F) and near jg (0x0F 0x8F) encodings. This is how we
guarantee no gate is missed (MustRemainDisabled compiled to a near jg, which a
short-jg-only scan never sees).

Two skeletons:
  OBJECT/INLINED form:
     cmp [reg+0x50], 2            83 /7 [reg+0x50] 02   (78..7f 50 02)
     jg  <short|near>             7F xx   |  0F 8F xx xx xx xx
     mov reg64, [reg+0x228]       48 8B .. 28 02 00 00
     mov eax, [reg+0x30]          8B .. 30
     cmp byte [reg+0x208], 0      80 .. 08 02 00 00 00
     jne ...                      75 ..
  REGISTER (free-predicate) form:
     cmp e_x, 2                   83 F8..FF 02
     jg  short                    7F xx
     cmp e_x, 8                   83 F8..FF 08
     ja  ...                      77 xx
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
N = len(TEXT)


def rva(i):
    return TR + i


hits = []

# ---- OBJECT/INLINED form: ... 50 02 <jg> 48 8B .. 28 02 00 00 8B .. 30 80 .. 08 02 00 00 00 75
# Anchor on the very distinctive "28 02 00 00 8B" (offset 0x228 load) then walk back.
i = 0
while True:
    i = TEXT.find(b"\x28\x02\x00\x00", i)
    if i == -1:
        break
    # need: preceding "48 8B <modrm>" (3 bytes) then a jg (short 2B or near 6B)
    # then before that "83 7x 50 02" (cmp [reg+0x50],2). Try both jg widths.
    for jglen, is_near in ((2, False), (6, True)):
        movpos = i - 3          # 48 8B modrm
        jgpos = movpos - jglen
        cmppos = jgpos - 4      # 83 7x 50 02
        if cmppos < 0:
            continue
        if TEXT[movpos] != 0x48 or TEXT[movpos + 1] != 0x8B:
            continue
        if is_near:
            if TEXT[jgpos] != 0x0F or TEXT[jgpos + 1] != 0x8F:
                continue
        else:
            if TEXT[jgpos] != 0x7F:
                continue
        if TEXT[cmppos] != 0x83 or (TEXT[cmppos + 1] & 0xF8) != 0x78:
            continue
        if TEXT[cmppos + 2] != 0x50 or TEXT[cmppos + 3] != 0x02:
            continue
        # confirm the tail: after "28 02 00 00" -> 8B .. 30 80 .. 08 02 00 00 00
        tail = i + 4
        if not (TEXT[tail] == 0x8B and TEXT[tail + 2] == 0x30 and
                TEXT[tail + 3] == 0x80 and TEXT[tail + 5] == 0x08 and
                TEXT[tail + 6] == 0x02):
            continue
        hits.append(("OBJ", "near" if is_near else "short", rva(cmppos), rva(jgpos)))
    i += 1

# ---- REGISTER (free predicate) form: 83 F8..FF 02 7F xx 83 F8..FF 08 77 xx
i = 0
while True:
    # find "02 7F" preceded by 83 F8..FF
    j = TEXT.find(b"\x02\x7f", i)
    if j == -1:
        break
    cmppos = j - 2
    if cmppos >= 0 and TEXT[cmppos] == 0x83 and (TEXT[cmppos + 1] & 0xF8) == 0xF8:
        # follow: 83 F8..FF 08 77
        f = j + 2  # after 02 7F: this is the jg disp; next insn at f+1
        after = f + 1
        if (TEXT[after] == 0x83 and (TEXT[after + 1] & 0xF8) == 0xF8 and
                TEXT[after + 2] == 0x08 and TEXT[after + 3] == 0x77):
            hits.append(("REG", "short", rva(cmppos), rva(j + 1)))
    i = j + 1

print(f"Found {len(hits)} IsExtensionAffected gate(s) in .text:\n")
for kind, jgkind, cmp_rva, jg_rva in sorted(hits, key=lambda h: h[2]):
    o = TRAW + (cmp_rva - TR)
    span = 28
    raw = " ".join(f"{b:02x}" for b in DATA[o : o + span])
    print(f"  [{kind:3} {jgkind:5}] cmp@{cmp_rva:#011x} jg@{jg_rva:#011x}")
    print(f"       {raw}")
