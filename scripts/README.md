# scripts — MV2 gate derivation toolkit

Cross-platform, dependency-free tooling to fetch symbols for, derive, and verify
the Chrome MV2 gate signatures the Go patcher reads at runtime
(`../signatures.json`). Works for any future Chrome version on x86 or x86-64:
64-bit PE `chrome.dll` (container `pe`), 32-bit PE `chrome.dll` (container
`pe32`), and the ELF `chrome` on Linux (container `elf`). Replaces the old
single-build `port152/` workspace, and the `fetch-symbols` subcommand that used
to live in the patcher binary.

Full rationale: [`../mv2-reversing.md`](../mv2-reversing.md) §"Porting to a new version".

| Script | What it does | Deps |
| :--- | :--- | :--- |
| `fetch_symbols.py` | Download the symbols matching a binary — PDB (PE) from the Chromium symbol server, or `chrome.debug` (ELF) streamed from the per-version zip. Saves to `_scratch/` (gitignored). | stdlib only |
| `derive_milestone.py` | Find gate sites (`cmp <mv>,2 ; jg`, short **and** near), emit a `signatures.json` entry, and `--verify` an existing table against a binary. | stdlib only |
| `resolve_symbols.py` | Windows only: name gate functions from a PDB via `dbghelp`. Optional — used to filter/name candidates. | Windows + PDB |

## Verify the shipping table still fits a build

```
python scripts/derive_milestone.py <stock chrome.dll|chrome>  --verify
# -> "ALL SITES VERIFIED: True" when a milestone fully covers the binary
```

## Derive a new milestone (e.g. Chrome 153)

1. **Get a stock binary** for the new version (a channel's `chrome.dll` / the ELF,
   or a `.bak`).
2. **Get symbols** to name/filter candidates (optional but recommended — a
   symbol-free scan surfaces ~150 gate-shaped idioms). `fetch_symbols.py`
   downloads them into `_scratch/`:
   - Windows: `python scripts/fetch_symbols.py <chrome.dll>` then
     `python scripts/resolve_symbols.py <chrome.dll> --symdir _scratch --json _scratch/syms.json`
   - Linux: `python scripts/fetch_symbols.py /opt/google/chrome/chrome` then
     `nm -SC _scratch/chrome.debug > _scratch/syms.txt` (both feed `--symbols`)
3. **Find + emit** the entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name 153 --json
   ```
   Each site should show `matches=1` (or `2` for a byte-identical shared body).
   A `matches>2` site needs a wider signature.
4. **Add** the emitted entry to the `milestones` array in `../signatures.json`
   (read at runtime from next to the binary — no rebuild needed; ship the updated
   file alongside the exe).
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must
   print `ALL SITES VERIFIED: True`, then patch a scratch copy and GUI-test.

The original 151/152 entries were derived from a Windows-only C++ reference
patcher (preserved in git history at commit `e12fe16`); new versions are added to
`signatures.json` directly, per the steps above.

**32-bit (x86) Chrome** is handled the same way: point the same three commands at
a 32-bit `chrome.dll`. `derive_milestone.py` tags it `container: "pe32"` (vs `pe`
for 64-bit), and `resolve_symbols.py` reads the PE32 `ImageBase`, so a 32-bit
build only ever probes/verifies against `pe32` milestones. The shipped `151-x86`
entry was derived this way from a 32-bit `chrome.dll` + its matching PDB.

The masking and match-count rules mirror the patcher's engine
(`../internal/app/engine.go`), so a table that verifies here is one the shipping
binary will accept.
