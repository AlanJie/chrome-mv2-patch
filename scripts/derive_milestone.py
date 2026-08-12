"""Cross-platform MV2 gate derivation and verification for the patch scripts.

One tool, both containers (PE `chrome.dll` on Windows — 64-bit PE32+ tagged
`pe` and 32-bit PE32 tagged `pe32` — and ELF `chrome` on Linux) and both `jg`
encodings (short `0x7F`, near `0x0F 0x8F`). It is a single symbol-free finder
that works for any future Chrome version on x86 or x86-64, replacing an earlier
version- and Windows-specific derivation.

  derive   (default)  scan a stock binary for IsExtensionAffected gate sites and
                      print a signatures.json entry (container + sites[]).
  --verify JSON       re-check an existing signatures.json against a binary: every
                      site's masked match count must equal expectedMatches.
                      Prints `ALL SITES VERIFIED: True` on success (the static
                      check that a table still fits a build).

No third-party dependencies (capstone/pyelftools/pefile not required), so it runs
on the bare reference boxes. Symbols are optional and only used for *naming*
candidates — see resolve_symbols.py (Windows PDB) or `nm chrome.debug` (Linux).

The finder mirrors the report-only scanners and masked matchers in
chrome-mv2.ps1 and chrome-mv2.sh, extended to the near-jg encoding. Only the jg
opcode and its displacement are wild.

Usage:
    python scripts/derive_milestone.py <stock-binary> [--name NAME] [--json]
    python scripts/derive_milestone.py <stock-binary> --verify signatures.json
"""

import argparse
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_JSON = REPO / "signatures.json"


# ---------------------------------------------------------------------------
# Image parsing: PE and ELF, hand-rolled (no pefile / pyelftools).
# Returns the .text virtual start, file offset, size, and container tag. The
# "virtual start" is the PE section VirtualAddress (an RVA) or the ELF section
# sh_addr. The finder works on the .text slice, so positions are relative to
# .text's start; rva() maps such a slice-relative index to jgRVA = pos +
# text_virt (the address a disassembler shows and the patch scripts store).
# ---------------------------------------------------------------------------
class Image:
    def __init__(self, container, text_virt, text_raw, text_size, data):
        self.container = container      # "pe" | "pe32" | "elf"
        self.text_virt = text_virt
        self.text_raw = text_raw
        self.text_size = text_size
        self.data = data
        self._text = None

    @property
    def text(self):
        if self._text is None:  # slice the ~250 MB .text once, then reuse
            self._text = self.data[self.text_raw:self.text_raw + self.text_size]
        return self._text

    def rva(self, textpos):
        """Index within the .text slice -> the address the scripts store (jgRVA)."""
        return textpos + self.text_virt

    def off(self, rva):
        """Inverse of rva(): jgRVA -> index within the .text slice."""
        return rva - self.text_virt


def parse_pe(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (bad NT signature)")
    num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("unsupported PE optional header magic 0x%X" % magic)
    # PE32 (x86) and PE32+ (x64) share the same section-table format; only the
    # gate machine code differs, so tag the container distinctly ("pe32" vs "pe")
    # to keep 32- and 64-bit milestone tables from cross-probing.
    container = "pe32" if magic == 0x10B else "pe"
    sec_off = opt + size_opt
    for i in range(num_sections):
        b = sec_off + i * 40
        name = data[b:b + 8].split(b"\x00")[0].decode("latin1")
        v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, b + 8)
        if name == ".text":
            return Image(container, v_addr, raw_ptr, raw_size, data)
    raise ValueError("no .text section")


def parse_elf(data):
    if data[4] != 2 or data[5] != 1:
        raise ValueError("not little-endian ELF64")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    str_hdr = shoff + shstrndx * shentsize
    str_off = struct.unpack_from("<Q", data, str_hdr + 0x18)[0]
    str_size = struct.unpack_from("<Q", data, str_hdr + 0x20)[0]
    strtab = data[str_off:str_off + str_size]
    for i in range(shnum):
        sh = shoff + i * shentsize
        name_off = struct.unpack_from("<I", data, sh)[0]
        name = strtab[name_off:strtab.find(b"\x00", name_off)].decode("latin1")
        if name == ".text":
            addr = struct.unpack_from("<Q", data, sh + 0x10)[0]
            off = struct.unpack_from("<Q", data, sh + 0x18)[0]
            size = struct.unpack_from("<Q", data, sh + 0x20)[0]
            return Image("elf", addr, off, size, data)
    raise ValueError("no .text section")


def open_image(path):
    data = Path(path).read_bytes()
    if data[:2] == b"MZ":
        return parse_pe(data)
    if data[:4] == b"\x7fELF":
        return parse_elf(data)
    raise ValueError("unrecognized binary (not PE 'MZ' or ELF '\\x7fELF')")


# ---------------------------------------------------------------------------
# Masked matcher - mirrors the matchers in both runtime patch scripts.
# Exact on every signature byte except the jg opcode and its displacement.
#
# A naive per-offset scan of the ~250 MB .text is far too slow in pure Python,
# so we anchor on the longest fixed (unmasked) run in the signature via
# bytes.find and only full-check at those few candidate offsets. The result is
# identical to the naive scan; it just skips the offsets that cannot match.
# ---------------------------------------------------------------------------
def _masked_indices(jg_off, kind):
    if kind == "short":
        return {jg_off, jg_off + 1}
    return {jg_off, jg_off + 1, jg_off + 2, jg_off + 3, jg_off + 4, jg_off + 5}


def _longest_fixed_run(n, masked):
    """Return (start, length) of the longest contiguous unmasked span in [0,n)."""
    best_start, best_len = 0, 0
    i = 0
    while i < n:
        if i in masked:
            i += 1
            continue
        j = i
        while j < n and j not in masked:
            j += 1
        if j - i > best_len:
            best_start, best_len = i, j - i
        i = j
    return best_start, best_len


def masked_match_count(text, sig, jg_off, kind, cap=None):
    """Offsets in .text where sig matches under per-encoding masking."""
    n = len(sig)
    masked = _masked_indices(jg_off, kind)
    anchor_off, anchor_len = _longest_fixed_run(n, masked)
    anchor = bytes(sig[anchor_off:anchor_off + anchor_len])

    def full_ok(r):
        for k in range(n):
            if k in masked:
                b = text[r + k]
                if kind == "short" and k == jg_off:
                    if b != 0x7F and b != 0xEB:
                        return False
                elif kind == "near" and k == jg_off:
                    if b != 0x0F and b != 0x90:
                        return False
                elif kind == "near" and k == jg_off + 1:
                    if b != 0x8F and b != 0xE9:
                        return False
                # displacement bytes: wildcard
                continue
            if text[r + k] != sig[k]:
                return False
        return True

    hits = []
    pos = 0
    tlen = len(text)
    while True:
        h = text.find(anchor, pos)
        if h < 0:
            break
        start = h - anchor_off
        if start >= 0 and start + n <= tlen and full_ok(start):
            hits.append(start)
            if cap is not None and len(hits) > cap:
                break
        pos = h + 1
    return hits


# ---------------------------------------------------------------------------
# The finder: cmp <mv>,2 ; jg (short|near) ; ... type/location follow-up.
# Byte skeleton (both cmp encodings, matching the runtime scripts' scanners):
#   reg   : 83 F8..FF 02              cmp <reg32>, 2         (mod=11, reg=/7)
#   disp8 : 83 78..7F <disp8> 02      cmp [reg+disp8], 2     (mod=01, reg=/7)
# then the jg: short 7F | near 0F 8F. A real gate also carries, within ~40
# bytes, a Manifest::Type compare (83 F8..FF {01|05}) or the location byte test
# (80 B8..BF <disp32> 00) - the same follow-up the runtime scripts require.
# ---------------------------------------------------------------------------
def find_gates(img):
    text = img.text
    n = len(text)
    gates = []  # (cmp_pos, jg_pos, kind)
    seen = set()

    def has_followup(after):
        end = min(after + 40, n - 2)
        j = after
        while j + 2 < end:
            if text[j] == 0x83 and (text[j + 1] & 0xF8) == 0xF8 and text[j + 2] in (0x01, 0x05):
                return True  # cmp reg, 1/5  (Manifest::Type enum)
            if text[j] == 0x80 and (text[j + 1] & 0xF8) == 0xB8 and j + 6 < end and text[j + 6] == 0x00:
                return True  # cmp byte [reg+disp32], 0  (location gate)
            j += 1
        return False

    def cmp_start(imm_pos):
        """If imm_pos is the imm8 `02` of a `cmp r/m32,2` (opcode 83 /7), return
        the cmp start, else None. Handles the reg (mod=11) and disp8 (mod=01)
        encodings, matching the runtime scripts' scanners."""
        if imm_pos >= 2 and text[imm_pos - 2] == 0x83 and (text[imm_pos - 1] & 0xF8) == 0xF8:
            return imm_pos - 2
        if imm_pos >= 3 and text[imm_pos - 3] == 0x83 and (text[imm_pos - 2] & 0xF8) == 0x78:
            return imm_pos - 3
        return None

    # Short jg: the imm8 `02` is immediately followed by `7F`. Anchor on `02 7F`.
    pos = 0
    while True:
        h = text.find(b"\x02\x7f", pos)
        if h < 0:
            break
        pos = h + 1
        cp = cmp_start(h)
        if cp is None:
            continue
        jg_pos = h + 1
        if has_followup(jg_pos + 2) and jg_pos not in seen:
            seen.add(jg_pos)
            gates.append((cp, jg_pos, "short"))

    # Near jg: the imm8 `02` is followed by `0F 8F`. Anchor on `02 0F 8F`.
    pos = 0
    while True:
        h = text.find(b"\x02\x0f\x8f", pos)
        if h < 0:
            break
        pos = h + 1
        cp = cmp_start(h)
        if cp is None:
            continue
        jg_pos = h + 1
        if has_followup(jg_pos + 6) and jg_pos not in seen:
            seen.add(jg_pos)
            gates.append((cp, jg_pos, "near"))

    gates.sort(key=lambda g: g[0])
    return gates


# Default signature window past the cmp, matching the shipping entries (24-28B).
# Long enough to span the follow-up type/location check, so the anchor is a
# distinctive fixed run and the masked count is meaningful.
SIGLEN = {"short": 25, "near": 28}


def build_site(img, cmp_pos, jg_pos, kind, name):
    """Package one candidate as a signatures.json site dict, measuring how many
    times its fixed-window signature matches .text under the scripts' masking."""
    text = img.text
    jg_off = jg_pos - cmp_pos
    siglen = min(max(SIGLEN[kind], jg_off + (2 if kind == "short" else 6) + 4),
                 len(text) - cmp_pos)
    sig = text[cmp_pos:cmp_pos + siglen]
    count = len(masked_match_count(text, sig, jg_off, kind, cap=16))
    return {
        "name": name,
        "kind": kind,
        "jgRVA": "0x%08X" % img.rva(jg_pos),
        "jgOff": jg_off,
        "expectedMatches": count,
        "sig": sig.hex().upper(),
    }, count


# ---------------------------------------------------------------------------
# Optional symbol filter: without symbols the finder surfaces every gate-shaped
# idiom in .text (the real gates plus many unrelated enum dispatches). Given a
# symbol table it keeps only candidates that fall inside one of the MV2 gate
# functions, and names them after it. Accepts either JSON (flat
# [{name,rva,size}] or resolve_symbols.py's {label: [[name,rva,size],...]}) or
# raw `nm -S` output, so the same flag works from a Windows PDB or a Linux
# chrome.debug.
# ---------------------------------------------------------------------------
GATE_KEYWORDS = (
    "isextensionaffected", "shouldblockextension", "onextensionsystemready",
    "maybereenableextension", "usermayinstall", "mustremaindisabled",
)


def _is_gate_name(name):
    low = name.lower()
    return any(k in low for k in GATE_KEYWORDS)


def load_symbols(path):
    """Return [(name, start_rva, end_rva)] for gate functions. Missing sizes get
    a conservative default span so inlined checks near the entry still fall in."""
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    entries = []  # (name, rva, size)
    text = raw.strip()
    if text[:1] in "[{":
        doc = json.loads(text)
        rows = []
        if isinstance(doc, dict):
            for v in doc.values():
                rows.extend(v)
        else:
            rows = doc
        for r in rows:
            if isinstance(r, dict):
                entries.append((r.get("name", "?"), int(r["rva"], 0) if isinstance(r["rva"], str) else int(r["rva"]), int(r.get("size", 0))))
            else:  # [name, rva, size]
                entries.append((r[0], int(r[1]), int(r[2]) if len(r) > 2 else 0))
    else:
        # nm output: "<hex addr> [<hex size>] <type> <name>"
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if len(parts) >= 4:  # nm -S: addr size type name
                try:
                    size = int(parts[1], 16)
                except ValueError:
                    size = 0
                name = " ".join(parts[3:])
            else:                # nm: addr type name
                size, name = 0, " ".join(parts[2:])
            entries.append((name, addr, size))

    ranges = []
    for name, rva, size in entries:
        if not _is_gate_name(name):
            continue
        span = size if size > 0 else 0x600
        ranges.append((name, rva, rva + span))
    return ranges


def name_for(ranges, jg_rva):
    for name, lo, hi in ranges:
        if lo <= jg_rva < hi:
            return name
    return None


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def cmd_derive(img, milestone_name, as_json, ranges):
    gates = find_gates(img)
    sites = []
    dropped = 0
    for idx, (cmp_pos, jg_pos, kind) in enumerate(gates, 1):
        jg_rva = img.rva(jg_pos)
        name = name_for(ranges, jg_rva) if ranges else f"site{idx}"
        if ranges and name is None:
            dropped += 1
            continue  # not inside a gate function - discard the false positive
        site, count = build_site(img, cmp_pos, jg_pos, kind, name)
        sites.append(site)

    if as_json:
        entry = {"name": milestone_name, "container": img.container, "sites": sites}
        print(json.dumps({"milestones": [entry]}, indent=2))
        return 0

    print(f"# container={img.container}  .text virt=0x{img.text_virt:X} "
          f"raw=0x{img.text_raw:X} size=0x{img.text_size:X}")
    if ranges:
        print(f"# {len(sites)} gate site(s) inside {len(ranges)} named gate function(s); "
              f"{dropped} non-gate candidate(s) dropped:\n")
    else:
        print(f"# {len(sites)} IsExtensionAffected gate candidate(s) "
              f"(no --symbols: run resolve_symbols.py or nm to name/filter these):\n")
    for s in sites:
        flag = "" if s["expectedMatches"] <= 2 else "  <-- WIDEN (count>2, sig not unique)"
        print(f"  {s['kind']:5} jg@{s['jgRVA']}  jgOff={s['jgOff']:>2}  "
              f"matches={s['expectedMatches']}{flag}  {s['name']}")
        print(f"        sig={s['sig']}")
    if as_json:
        return 0
    print("\n# Re-run with --json to emit a signatures.json entry.")
    return 0


def cmd_verify(img, json_path):
    """Report each milestone's fit against this one binary. A binary is a single
    Chrome version, so only its matching milestone verifies fully - success is
    "at least one milestone of this container fully covers the build", which is
    how the runtime scripts pick the best-matching milestone to apply."""
    doc = json.loads(Path(json_path).read_text(encoding="utf-8"))
    text = img.text
    candidates = [ms for ms in doc.get("milestones", []) if ms.get("container") == img.container]
    if not candidates:
        print(f"# no '{img.container}' milestones in {json_path} to verify against this binary")
        return 1

    any_full = False
    for ms in candidates:
        ok_count = 0
        rows = []
        for s in ms["sites"]:
            expected = s["expectedMatches"]
            hits = masked_match_count(text, bytes.fromhex(s["sig"]), s["jgOff"], s["kind"],
                                      cap=expected + 2)
            ok = len(hits) == expected
            ok_count += ok
            rows.append(f"    [{'OK ' if ok else f'x got {len(hits)}'}] "
                        f"{s['kind']:5} exp={expected} {s['name'][:52]}")
        full = ok_count == len(ms["sites"])
        any_full |= full
        verdict = "VERIFIED" if full else "partial"
        print(f"milestone {ms['name']}: {verdict} ({ok_count}/{len(ms['sites'])})")
        print("\n".join(rows))
    print("\nALL SITES VERIFIED:", any_full,
          "(binary is fully covered by a milestone)" if any_full else "(no milestone fully matches)")
    return 0 if any_full else 1


def main():
    ap = argparse.ArgumentParser(description="Cross-platform MV2 gate derivation/verification.")
    ap.add_argument("binary", help="stock chrome.dll (PE) or chrome (ELF)")
    ap.add_argument("--name", default="NEW", help="milestone name for the emitted entry (e.g. 153)")
    ap.add_argument("--json", action="store_true", help="emit a signatures.json entry")
    ap.add_argument("--symbols", metavar="FILE",
                    help="symbol table (resolve_symbols.py JSON, or `nm -S` output) to "
                         "name and filter candidates to real gate functions")
    ap.add_argument("--verify", metavar="signatures.json", nargs="?", const=str(DEFAULT_JSON),
                    help="verify an existing table against the binary (default: signatures.json)")
    args = ap.parse_args()

    try:
        img = open_image(args.binary)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.verify is not None:
        return cmd_verify(img, args.verify)

    ranges = []
    if args.symbols:
        try:
            ranges = load_symbols(args.symbols)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error reading --symbols: {e}", file=sys.stderr)
            return 2
        if not ranges:
            print("warning: no MV2 gate functions found in the symbol file; "
                  "showing all candidates unfiltered", file=sys.stderr)
    return cmd_derive(img, args.name, args.json, ranges)


if __name__ == "__main__":
    sys.exit(main())
