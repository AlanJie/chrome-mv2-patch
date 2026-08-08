"""Disassemble each resolved gate function and locate the MV2 manifest-version
check (cmp <r/m32>, 2 ; jg short) plus its confirming follow-up. Prints full
disassembly for the semantically-interesting functions so each flip can be
justified, and emits a 24-byte signature (start=cmp, jgOff, jg RVA) per site.
"""
import json
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "port152"))
from pe_info import pe_info  # noqa: E402

INFO = pe_info(str(REPO / "chrome152-stock.dll"))
TEXT_RVA = INFO["text_rva"]
TEXT_RAW = INFO["text_raw"]
with open(REPO / "chrome152-stock.dll", "rb") as f:
    DATA = f.read()
SYMS = json.load(open(REPO / "port152" / "symbols.json"))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def off(rva):
    return TEXT_RAW + (rva - TEXT_RVA)


def body(rva, size):
    o = off(rva)
    return DATA[o : o + size]


def disasm(rva, size, full=False, note=""):
    print(f"\n===== {note}  rva={rva:#x} size={size:#x} =====")
    code = body(rva, size)
    insns = list(md.disasm(code, rva))
    for ins in insns:
        raw = " ".join(f"{b:02x}" for b in ins.bytes)
        mark = ""
        # highlight interesting things
        if ins.mnemonic == "cmp" and ins.op_str.endswith(", 2"):
            mark = "   <-- cmp ...,2"
        if ins.mnemonic == "jg":
            mark = "   <-- JG"
        if ins.mnemonic == "call":
            mark = "   (call)"
        if "0x2150" in ins.op_str:
            mark += "   <-- IDS_..CANT_INSTALL_MV2 (0x2150)"
        if full or mark:
            print(f"  {ins.address:#010x}: {raw:<28} {ins.mnemonic} {ins.op_str}{mark}")
    return insns


def find_sites(rva, size):
    """Return [(cmp_rva, jg_rva, sig24, jgOff)] for every cmp<r/m>,2;jg with a
    manifest-type/location follow-up within 40 bytes."""
    code = body(rva, size)
    insns = list(md.disasm(code, rva))
    out = []
    for i, ins in enumerate(insns):
        if ins.mnemonic != "cmp":
            continue
        # operand must be an imm 2
        if not ins.op_str.rstrip().endswith(", 2"):
            continue
        # next instruction must be jg short (0x7f)
        if i + 1 >= len(insns) or insns[i + 1].mnemonic != "jg":
            continue
        jg = insns[i + 1]
        if jg.bytes[0] != 0x7F:
            continue
        # follow-up within 40 bytes: cmp reg,1 / cmp reg,5  OR  cmp byte[reg+d32],0
        follow = None
        end_addr = jg.address + 2 + 40
        for j in range(i + 2, len(insns)):
            f = insns[j]
            if f.address >= end_addr:
                break
            if f.mnemonic == "cmp" and (f.op_str.rstrip().endswith(", 1") or
                                         f.op_str.rstrip().endswith(", 5")):
                follow = f"type-enum: {f.mnemonic} {f.op_str}"
                break
            if f.mnemonic == "cmp" and f.op_str.rstrip().endswith(", 0") and "byte" in f.op_str:
                follow = f"location: {f.mnemonic} {f.op_str}"
                break
        if not follow:
            continue
        cmp_rva = ins.address
        jg_rva = jg.address
        jgoff = jg_rva - cmp_rva
        o = off(cmp_rva)
        sig = DATA[o : o + 24]
        out.append((cmp_rva, jg_rva, sig, jgoff, follow,
                    f"{ins.mnemonic} {ins.op_str}"))
    return out


def show_sites(label, rva, size):
    sites = find_sites(rva, size)
    print(f"\n#### {label}: {len(sites)} candidate site(s) in body ####")
    for cmp_rva, jg_rva, sig, jgoff, follow, cmpstr in sites:
        hexsig = ",".join(f"0x{b:02x}" for b in sig)
        print(f"  cmp @ {cmp_rva:#x}  '{cmpstr}'  jg @ {jg_rva:#x}  jgOff={jgoff}")
        print(f"    follow: {follow}")
        print(f"    sig24 = {{ {hexsig} }}")
    return sites


# --- the free predicate: the central gate --------------------------------
print("############ manifest_v2_util::IsExtensionAffected (free predicate) ############")
disasm(0x082d26f0, 0x27, full=True, note="manifest_v2_util::IsExtensionAffected")

print("\n############ ManifestV2Handler::IsExtensionAffected ############")
disasm(0x082d23a0, 0x3e, full=True, note="ManifestV2Handler::IsExtensionAffected")

print("\n############ ShouldBlockExtensionInstallation (0xd) ############")
disasm(0x082d23e0, 0xd, full=True, note="ShouldBlockExtensionInstallation")

print("\n############ ShouldBlockExtensionEnable ############")
disasm(0x03348750, 0x3e, full=True, note="ShouldBlockExtensionEnable")

print("\n############ MaybeReEnableExtension ############")
disasm(0x082d24a0, 0xab, full=True, note="MaybeReEnableExtension")

# larger bodies: just show sites + calls
for label, rva, size in [
    ("OnExtensionSystemReady", 0x01240f90, 0x60b),
    ("UserMayInstall", 0x08ddc190, 0x1f9),
    ("MustRemainDisabled(StandardMPP)", 0x015a8c70, 0x1c3),
]:
    print(f"\n############ {label} (calls + cmp2/jg) ############")
    disasm(rva, size, full=False, note=label)

print("\n\n================= SITE SUMMARY =================")
for label, rva, size in [
    ("manifest_v2_util::IsExtensionAffected", 0x082d26f0, 0x27),
    ("ManifestV2Handler::IsExtensionAffected", 0x082d23a0, 0x3e),
    ("ShouldBlockExtensionInstallation", 0x082d23e0, 0xd),
    ("ShouldBlockExtensionEnable", 0x03348750, 0x3e),
    ("OnExtensionSystemReady", 0x01240f90, 0x60b),
    ("MaybeReEnableExtension", 0x082d24a0, 0xab),
    ("UserMayInstall", 0x08ddc190, 0x1f9),
    ("MustRemainDisabled", 0x015a8c70, 0x1c3),
]:
    show_sites(label, rva, size)
