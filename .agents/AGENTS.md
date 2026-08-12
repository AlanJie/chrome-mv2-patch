# Agent Workspace Guidelines and Manifest V2 Patcher References

## Repository overview

This repository ships two self-contained patch scripts:

- `chrome-mv2.ps1` is the Windows implementation. It patches PE32+ (x64) and
  PE32 (x86) `chrome.dll` files.
- `chrome-mv2.sh` is the Linux implementation. It patches the x86-64 ELF
  `chrome` executable.

There is no compiled patcher or build step. Do not add instructions for the
removed Go application, `cmd/chrome-mv2`, `internal/app`, `build.bat`, or
platform executables. The PowerShell and Bash scripts own all runtime behavior:
target discovery, signature loading, layout matching, patching, backup and
restore safety, elevation, diagnostics, and user output.

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

Never delete or blank a `call`, edit the compared manifest-version value, or
invent control flow. Structurally valid but semantically wrong edits have
previously crashed Chrome or hidden extensions. See `mv2-reversing.md` section
7 before changing the byte strategy.

## Runtime ownership

Keep platform behavior in its owning script:

- Windows/PE logic: `chrome-mv2.ps1`
- Linux/ELF logic: `chrome-mv2.sh`
- Cross-platform signature derivation only: `scripts/*.py`

The two runtime scripts intentionally implement the same safety contract:

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

- `$EmbeddedSignatures` in `chrome-mv2.ps1` contains the Windows `pe` and `pe32`
  milestones.
- `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` contains the Linux `elf` milestones.

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

- `fetch_chrome_binary.py`: fetch and unwrap a stock `chrome.dll` or Linux
  `chrome` into `_scratch/`. Requires Python and 7-Zip.
- `fetch_symbols.py`: fetch the matching PDB or `chrome.debug` into `_scratch/`.
- `resolve_symbols.py`: resolve Windows PDB symbols through `dbghelp`.
- `dump_symtab.py`: stream Linux `.symtab` data without the cost of `nm -SC`.
- `derive_milestone.py`: find short and near gate sites, emit a milestone, and
  verify a table against a stock binary.

Porting checklist:

1. Fetch a stock binary and its matching symbols.
2. Resolve or dump symbols to name/filter candidate gates.
3. Run `derive_milestone.py --symbols ... --name ... --json`.
4. Add the entry to `signatures.json` and the correct embedded script table.
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

```powershell
pwsh -NoProfile -File scripts/tests/run-tests.ps1
```

The suite exercises synthetic PE and ELF fixtures, parses both runtime scripts,
and covers patch, restore, check, malformed signatures, partial layouts,
ambiguity, backup validation, and race protection. It requires PowerShell and a
`bash` environment capable of running the Linux tests.

For focused syntax checks:

```powershell
$tokens = $null; $errors = $null
[Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\chrome-mv2.ps1), [ref]$tokens, [ref]$errors) | Out-Null
$errors
```

```bash
bash -n chrome-mv2.sh
```

For a real stock artifact, also run:

```text
python scripts/derive_milestone.py <stock chrome.dll|chrome> --verify signatures.json
```

Use the read-only runtime diagnostics when appropriate:

```powershell
.\chrome-mv2.ps1 check "C:\path\to\chrome.dll" -Quiet
```

```bash
./chrome-mv2.sh check /path/to/chrome --quiet
```

Never weaken a decline, backup, identity, bounds, or post-write check merely to
make a new Chrome build pass. A declined unknown layout is the safe and expected
result until its signatures are derived and verified.
