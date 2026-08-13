# Agent Workspace Guidelines and Manifest V2 Patcher References

## Repository overview

This repository ships three self-contained patch scripts:

- `chrome-mv2.ps1` is the Windows implementation. It patches PE32+ x64 (`pe`),
  PE32 x86 (`pe32`), and PE32+ arm64 (`pe-arm64`, Windows on ARM — the machine
  field `0xAA64` selects it, and it uses the same `bcond` flip as macOS arm64)
  `chrome.dll` files.
- `chrome-mv2.sh` is the Linux implementation. It patches the x86-64 ELF
  `chrome` executable.
- `chrome-mv2-mac.sh` is the macOS implementation. It patches the universal
  `Google Chrome Framework` Mach-O — the x86_64 slice (`macho-x64`, reusing the
  `jg` flip) and the arm64 slice (`macho-arm64`, a `B.cond` GT→AL flip); each Mac
  patches only its own CPU's slice — then ad-hoc re-signs the app so it launches.

There is no compiled patcher or build step. Do not add instructions for the
removed Go application, `cmd/chrome-mv2`, `internal/app`, `build.bat`, or
platform executables. The PowerShell, Linux Bash, and macOS Bash scripts own all
runtime behavior: target discovery, signature loading, layout matching,
patching, backup and restore safety, elevation/signing, diagnostics, and output.

The patch re-enables Manifest V2 (MV2) extensions by flipping the existing
`IsExtensionAffected` conditional branches in Chrome's browser binary. It uses
per-milestone signature tables and applies only a complete, unambiguous match by
default.

Before modifying patching logic, read
[`mv2-reversing.md`](../mv2-reversing.md). It records the rationale, verified
gate layouts, container details, porting procedure, and failed approaches that
must not be repeated.

## Cardinal rule

Only flip the direction of an existing branch to its existing target:

- short `jg`: `7F disp8` -> `EB disp8`
- near `jg`: `0F 8F disp32` -> `90 E9 disp32`
- arm64 `b.cond` (`bcond` kind — macOS arm64 and Windows on ARM): rewrite ONLY
  the condition nibble GT(0xC) -> AL(0xE) in the little-endian branch word; the
  opcode (0x54), bit4, and the entire `imm19` displacement are preserved.

Never delete or blank a `call`, edit the compared manifest-version value, or
invent control flow. Structurally valid but semantically wrong edits have
previously crashed Chrome or hidden extensions. See `mv2-reversing.md` section
7 before changing the byte strategy.

## Runtime ownership

Keep platform behavior in its owning script:

- Windows/PE logic: `chrome-mv2.ps1`
- Linux/ELF logic: `chrome-mv2.sh`
- macOS/Mach-O logic: `chrome-mv2-mac.sh` (fat parsing, per-slice patching,
  `LC_UUID` identity, inside-out ad-hoc `codesign` re-seal). Must stay bash-3.2
  compatible (stock macOS) and needs no `python3` on the default path.
- Cross-platform signature derivation only: `scripts/*.py`

The runtime scripts intentionally implement the same safety contract:

- Strictly validate signature data and image bounds.
- Probe the recorded RVA first, then relocate with a masked `.text` scan.
- Mask only the jump opcode and displacement.
- Require each site's exact `expectedMatches` count.
- Choose the best milestone and decline ambiguous or incomplete layouts by
  default.
- Treat stock and already-patched opcodes as valid for idempotent reruns.
- Verify prepared and written output.
- Preserve a validated, build-specific stock backup.
- Report structural candidates without modifying an unknown layout.

Do not assume implementation details are interchangeable. PowerShell parses PE,
strips the Authenticode Security directory, and recomputes the PE checksum.
Bash parses ELF, preserves ownership/mode, and atomically replaces the executable.

## Signature sources

`signatures.json` is the canonical editable table used by the derivation tools
and external override mode. The patch scripts are also self-contained and carry
platform-specific embedded copies:

- `$EmbeddedSignatures` in `chrome-mv2.ps1` contains the Windows `pe`, `pe32`,
  and `pe-arm64` milestones.
- `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` contains the Linux `elf` milestones.
- `EMBEDDED_SIGNATURES` in `chrome-mv2-mac.sh` contains the macOS `macho-x64`
  and `macho-arm64` milestones, **pre-tokenized** (pipe-delimited records) so the
  default path needs no `python3`/JSON parser. Each runtime script skips
  milestones whose container it does not own.

Runtime precedence is an explicitly supplied signature file, then a
`signatures.json` beside the script, then the embedded table. A file in the
caller's current directory must not be loaded implicitly.

When adding or changing a milestone, update `signatures.json` and the matching
embedded table in the same change. A release must not depend on an external JSON
file merely because the embedded copy was forgotten. Keep older milestones so
the scripts can continue probing supported Chrome versions.

## Derivation toolkit

The tools under `scripts/` fetch stock Chrome artifacts and symbols, derive new
milestones, and verify signature tables. They do not patch installed Chrome.
See [`scripts/README.md`](../scripts/README.md) for the complete workflow.

- `fetch_chrome_binary.py`: fetch and unwrap a stock `chrome.dll` (x64, x86, or
  arm64 `win-arm64` via the enterprise MSI), Linux `chrome`, or the macOS
  universal framework (`mac-x64`/`mac-arm64`) into `_scratch/`. Requires Python
  and 7-Zip.
- `fetch_symbols.py`: fetch the matching PDB (Windows), `chrome.debug` (Linux),
  or stream the official dSYM's symtab (macOS) into `_scratch/`.
- `symbols_from_pdb.py`: resolve Windows PDB symbols through `dbghelp`.
- `symbols_from_elf.py`: stream Linux `.symtab` data without the cost of `nm -SC`.
- `derive_milestone.py`: find short/near (`jg`) and arm64 `bcond` gate sites,
  emit a milestone (one per Mach-O slice), and verify a table against a stock
  binary.

Porting checklist:

1. Fetch a stock binary and its matching symbols (macOS: `fetch_symbols.py`
   streams the official dSYM's symtab, UUID-matched to consumer Chrome).
2. Resolve or dump symbols to name/filter candidate gates.
3. Run `derive_milestone.py --symbols ... --name ... --json`.
4. Add the entry to `signatures.json` and the correct embedded script table
   (`chrome-mv2.ps1` pe/pe32/pe-arm64, `chrome-mv2.sh` elf, `chrome-mv2-mac.sh`
   macho-x64/macho-arm64).
5. Run `derive_milestone.py <binary> --verify signatures.json` and require
   `ALL SITES VERIFIED: True`.
6. Run the script regression suite.
7. Patch only a scratch copy for byte inspection, then perform a platform GUI
   or runtime test before declaring the milestone supported.

Do not hand-patch a live install while deriving signatures. If the
`cmp <mv>,2 ; jg` skeleton disappears, stop and re-analyze Chrome's gate logic
from source before changing bytes.

## Verification

Run the full local suite from the repository root:

```bash
python scripts/run_tests.py
```

The suite (`scripts/run_tests.py`, pure Python) exercises synthetic PE (incl. an
arm64 `pe-arm64` fixture), ELF, and Mach-O (fat) fixtures, parses all three
runtime scripts, and covers patch, restore, check, malformed signatures, partial
layouts, ambiguity, host-aware slice selection (each Mac patches only its own
CPU's slice), backup validation, and race protection. It drives the shell
patchers via `bash` and the PowerShell patcher via `pwsh` (the PE test is
skipped off-Windows). A native-arm64 `windows-11-arm` GitHub runner also
round-trips patch/restore against a real arm64 `chrome.dll`. The real-macOS
runtime proof (patch → ad-hoc re-sign → headless launch → functional MV2 A/B →
restore, on both Intel and Apple Silicon) runs in GitHub Actions
(`.github/workflows/tests.yml`), since it needs `codesign` and real hardware. The
MV2 A/B (`.github/mv2_probe.py`, a CI helper — not part of the derivation
toolkit) loads a Manifest V2 extension whose persistent background page pings a
local listener the instant it is enabled, and asserts the patched build enables
what the stock build disables. At Chrome 151/152 the MV2 disable is a compiled-in
feature default, so `--enable-features` cannot toggle it and the stock-vs-patched
differential is the only lever; a build that does not enforce the deprecation is
reported as inconclusive, never a false pass.

For focused syntax checks:

```powershell
$tokens = $null; $errors = $null
[Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\chrome-mv2.ps1), [ref]$tokens, [ref]$errors) | Out-Null
$errors
```

```bash
bash -n chrome-mv2.sh
bash -n chrome-mv2-mac.sh
```

For a real stock artifact, also run:

```text
python scripts/derive_milestone.py <stock chrome.dll|chrome|Google Chrome Framework> --verify signatures.json
```

Use the read-only runtime diagnostics when appropriate:

```powershell
.\chrome-mv2.ps1 check "C:\path\to\chrome.dll" -Quiet
```

```bash
./chrome-mv2.sh check /path/to/chrome --quiet
./chrome-mv2-mac.sh check "/Applications/Google Chrome.app" --quiet
```

Never weaken a decline, backup, identity, bounds, or post-write check merely to
make a new Chrome build pass. A declined unknown layout is the safe and expected
result until its signatures are derived and verified.
