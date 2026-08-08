"""Resolve the seven MV2 gate functions in the 152 PDB via dbghelp, disassemble
each with capstone, and emit the cmp<mv>,2 ; jg signatures the C++ patcher needs.

Load-once: the 5.5 GB PDB parse (~2 min) happens a single time; every gate is
resolved and disassembled in this one process.

RVA convention: we load the module at its real image base (0x180000000) so a
symbol's dbghelp Address minus the base is exactly the RVA the C++ side uses.
"""
import ctypes as C
import struct
import sys
from ctypes import wintypes
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

REPO = Path(__file__).resolve().parent.parent
DLL = str(REPO / "chrome152-stock.dll")
SYMPATH = str(REPO)
IMAGE_BASE = 0x180000000

# --- section/base info from the DLL itself -----------------------------------
sys.path.insert(0, str(REPO / "port152"))
from pe_info import pe_info  # noqa: E402

INFO = pe_info(DLL)
TEXT_RVA = INFO["text_rva"]
TEXT_RAW = INFO["text_raw"]
TEXT_SIZE = INFO["text_rawsize"]
with open(DLL, "rb") as f:
    DATA = f.read()


def rva_to_off(rva):
    return TEXT_RAW + (rva - TEXT_RVA)


# --- dbghelp -----------------------------------------------------------------
dbghelp = C.WinDLL("dbghelp.dll")
kernel32 = C.WinDLL("kernel32.dll")

SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEBUG = 0x80000000
SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
SYMOPT_NO_PROMPTS = 0x00080000

MAX_SYM_NAME = 2000


class SYMBOL_INFOW(C.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", C.c_ulonglong * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", C.c_ulonglong),
        ("Flags", wintypes.ULONG),
        ("Value", C.c_ulonglong),
        ("Address", C.c_ulonglong),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", wintypes.WCHAR * (MAX_SYM_NAME + 1)),
    ]


dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
dbghelp.SymInitializeW.restype = wintypes.BOOL
dbghelp.SymLoadModuleExW.argtypes = [
    wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
    C.c_ulonglong, wintypes.DWORD, C.c_void_p, wintypes.DWORD,
]
dbghelp.SymLoadModuleExW.restype = C.c_ulonglong

SYMENUM = C.WINFUNCTYPE(wintypes.BOOL, C.POINTER(SYMBOL_INFOW), wintypes.ULONG, C.c_void_p)
dbghelp.SymEnumSymbolsW.argtypes = [
    wintypes.HANDLE, C.c_ulonglong, wintypes.LPCWSTR, SYMENUM, C.c_void_p,
]
dbghelp.SymEnumSymbolsW.restype = wintypes.BOOL


class IMAGEHLP_MODULEW64(C.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.DWORD),
        ("BaseOfImage", C.c_ulonglong),
        ("ImageSize", wintypes.DWORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("NumSyms", wintypes.DWORD),
        ("SymType", wintypes.DWORD),
        ("ModuleName", wintypes.WCHAR * 32),
        ("ImageName", wintypes.WCHAR * 256),
        ("LoadedImageName", wintypes.WCHAR * 256),
        ("LoadedPdbName", wintypes.WCHAR * 256),
        ("CVSig", wintypes.DWORD),
        ("CVData", wintypes.WCHAR * 780),
        ("PdbSig", wintypes.DWORD),
        ("PdbSig70", C.c_byte * 16),
        ("PdbAge", wintypes.DWORD),
        ("PdbUnmatched", wintypes.BOOL),
        ("DbgUnmatched", wintypes.BOOL),
        ("LineNumbers", wintypes.BOOL),
        ("GlobalSymbols", wintypes.BOOL),
        ("TypeInfo", wintypes.BOOL),
        ("SourceIndexed", wintypes.BOOL),
        ("Publics", wintypes.BOOL),
        ("CVSig2", wintypes.DWORD),
        ("CVData2", wintypes.WCHAR * 780),
    ]


dbghelp.SymGetModuleInfoW64.argtypes = [
    wintypes.HANDLE, C.c_ulonglong, C.POINTER(IMAGEHLP_MODULEW64),
]
dbghelp.SymGetModuleInfoW64.restype = wintypes.BOOL

hProc = kernel32.GetCurrentProcess()
dbghelp.SymSetOptions(
    SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS
)

if not dbghelp.SymInitializeW(hProc, SYMPATH, False):
    raise OSError("SymInitializeW failed", C.get_last_error())

print("[*] Loading module + PDB (first parse of the 5.5 GB PDB is slow)...", flush=True)
base = dbghelp.SymLoadModuleExW(hProc, None, DLL, None, IMAGE_BASE, len(DATA), None, 0)
if base == 0:
    err = C.get_last_error()
    if err != 0:
        raise OSError(f"SymLoadModuleExW failed, err={err}")
print(f"[+] Module loaded at base {base:#x}", flush=True)

mod = IMAGEHLP_MODULEW64()
mod.SizeOfStruct = C.sizeof(IMAGEHLP_MODULEW64)
if dbghelp.SymGetModuleInfoW64(hProc, IMAGE_BASE, C.byref(mod)):
    print(f"[+] SymType={mod.SymType} (8=PDB)  LoadedPdb={mod.LoadedPdbName}")
    print(f"[+] PdbAge={mod.PdbAge}  PdbUnmatched={mod.PdbUnmatched}  NumSyms={mod.NumSyms}")
    if mod.PdbUnmatched:
        raise SystemExit("[-] PDB does NOT match the DLL — wrong symbols. Aborting.")


def enum(mask):
    """Return [(name, rva, size)] for every symbol matching mask."""
    out = []

    @SYMENUM
    def cb(pinfo, size, ctx):
        s = pinfo.contents
        out.append((s.Name, s.Address - IMAGE_BASE, s.Size))
        return True

    dbghelp.SymEnumSymbolsW(hProc, IMAGE_BASE, mask, cb, None)
    return out


# ---------------------------------------------------------------------------
# The seven gates. For standalone functions the MV2 check is early in the body;
# for inlined copies we search the enclosing function's whole body.
# ---------------------------------------------------------------------------
GATES = [
    ("IsExtensionAffected", "*IsExtensionAffected*"),
    ("ShouldBlockExtensionInstallation", "*ShouldBlockExtensionInstallation*"),
    ("ShouldBlockExtensionEnable", "*ShouldBlockExtensionEnable*"),
    ("OnExtensionSystemReady", "*OnExtensionSystemReady*"),
    ("MaybeReEnableExtension", "*MaybeReEnableExtension*"),
    ("UserMayInstall", "*UserMayInstall*"),
    ("MustRemainDisabled", "*MustRemainDisabled*"),
]

print("\n[*] Enumerating gate symbols...\n")
resolved = {}
for label, mask in GATES:
    syms = enum(mask)
    # keep only real code (nonzero size, inside .text)
    syms = [s for s in syms if s[2] > 0 and TEXT_RVA <= s[1] < TEXT_RVA + TEXT_SIZE]
    resolved[label] = syms
    print(f"=== {label}: {len(syms)} symbol(s) ===")
    for name, rva, size in syms:
        print(f"    rva={rva:#010x} size={size:#x}  {name}")

# stash for the disassembly pass (next script reads this)
import json  # noqa: E402
with open(REPO / "port152" / "symbols.json", "w", encoding="utf-8") as f:
    json.dump(
        {k: [[n, r, s] for (n, r, s) in v] for k, v in resolved.items()},
        f, indent=2,
    )
print("\n[+] Wrote port152/symbols.json")
