# scripts — MV2 gate derivation toolkit

Cross-platform, dependency-free tooling to fetch symbols for, derive, and verify
the Chrome MV2 gate signatures used by `../chrome-mv2.ps1` and
`../chrome-mv2.sh`. The canonical editable table is `../signatures.json`.
Works for any future Chrome version on x86 or x86-64:
64-bit PE `chrome.dll` (container `pe`), 32-bit PE `chrome.dll` (container
`pe32`), and the ELF `chrome` on Linux (container `elf`). Replaces the old
single-build `port152/` workspace.

Full rationale: [`../mv2-reversing.md`](../mv2-reversing.md) §"Porting to a new version".

| Script | What it does | Deps |
| :--- | :--- | :--- |
| `fetch_chrome_binary.py` | Download the stock, gate-bearing binary itself — a channel's current `chrome.dll` (PE64/PE32) or Linux `chrome` (ELF) — unwrap it out of the installer, and drop it in `_scratch/` arch-tagged. `--version` falls back to Chrome for Testing. This is step 1 (below). | stdlib + 7-Zip |
| `fetch_symbols.py` | Download the symbols matching a binary — PDB (PE) from the Chromium symbol server, or `chrome.debug` (ELF) streamed from the per-version zip. Saves to `_scratch/` (gitignored). | stdlib only |
| `derive_milestone.py` | Find gate sites (`cmp <mv>,2 ; jg`, short **and** near), emit a `signatures.json` entry, and `--verify` an existing table against a binary. | stdlib only |
| `dump_symtab.py` | Linux: dump an ELF's `.symtab` as `nm -S`-style lines, fast and low-memory — a stand-in for `nm -SC` on the multi-GB `chrome.debug` (see note in step 2). | stdlib only |
| `resolve_symbols.py` | Windows only: name gate functions from a PDB via `dbghelp`. Optional — used to filter/name candidates. | Windows + PDB |

## Verify the shipping table still fits a build

```
python scripts/derive_milestone.py <stock chrome.dll|chrome>  --verify
# -> "ALL SITES VERIFIED: True" when a milestone fully covers the binary
```

## Derive a new milestone (e.g. Chrome 153)

1. **Get a stock binary** for the new version. `fetch_chrome_binary.py`
   downloads the channel's current installer, unwraps it, and leaves just the
   gate binary in `_scratch/`:
   - Windows x64: `python scripts/fetch_chrome_binary.py --platform win64`
   - Windows x86: `python scripts/fetch_chrome_binary.py --platform win`
   - Linux:       `python scripts/fetch_chrome_binary.py --platform linux`

   Defaults to the host's platform and the `stable` channel; `--channel beta`
   or `--version X.Y.Z.W` (Chrome for Testing fallback) pick another build, and
   `--list` just prints the current versions. A `.bak` or hand-copied
   `chrome.dll`/`chrome` works just as well — the fetch is a convenience, not a
   requirement.
2. **Get symbols** to name/filter candidates (optional but recommended — a
   symbol-free scan surfaces ~150 gate-shaped idioms). `fetch_symbols.py`
   downloads them into `_scratch/`:
   - Windows: `python scripts/fetch_symbols.py <chrome.dll>` then
     `python scripts/resolve_symbols.py <chrome.dll> --symdir _scratch --json _scratch/syms.json`
   - Linux: `python scripts/fetch_symbols.py <the ELF from step 1>` then
     `python scripts/dump_symtab.py _scratch/chrome.debug _scratch/syms.txt`
     (feeds `--symbols`). Prefer `dump_symtab.py` over `nm -SC chrome.debug`:
     `nm` demangles and sorts the whole 1.4 GB debug file and runs many minutes
     (and can thrash a small-RAM box); the dumper streams just `.symtab` in a
     few minutes, and the finder's keyword filter matches the still-mangled
     names fine.
3. **Find + emit** the entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name 153 --json
   ```
   Each site should show `matches=1` (or `2` for a byte-identical shared body).
   A `matches>2` site needs a wider signature.
4. **Add** the emitted entry to the `milestones` array in
   `../signatures.json`, then copy the platform entry into the matching embedded
   table: `$EmbeddedSignatures` in `../chrome-mv2.ps1` for `pe`/`pe32`, or
   `EMBEDDED_SIGNATURES` in `../chrome-mv2.sh` for `elf`. The scripts use an
   explicit signature path first, then `signatures.json` beside the script, then
   their embedded table. Keep the JSON and embedded copy synchronized.
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must
   print `ALL SITES VERIFIED: True`.
6. **Run the script tests**:
   `pwsh -NoProfile -File scripts/tests/run-tests.ps1` from the repository root.
7. Patch a scratch copy, inspect the changed bytes, and GUI/runtime-test on the
   target platform.

The original 151/152 entries were derived from a Windows-only C++ reference
patcher (preserved in git history at commit `e12fe16`); new versions are added to
`signatures.json` directly, per the steps above. `152-linux` was derived on a
**Windows** host from the fetched beta `.deb` — no Linux box is needed for steps
1-5, only for the final GUI/runtime test.

**32-bit (x86) Chrome** is handled the same way: point the same three commands at
a 32-bit `chrome.dll`. `derive_milestone.py` tags it `container: "pe32"` (vs `pe`
for 64-bit), and `resolve_symbols.py` reads the PE32 `ImageBase`, so a 32-bit
build only ever probes/verifies against `pe32` milestones. The shipped `151-x86`
entry was derived this way from a 32-bit `chrome.dll` + its matching PDB.

The masking and match-count rules mirror both runtime scripts:
`Find-AffectedJgSites` / `Invoke-PatchMilestones` in `chrome-mv2.ps1` and
`find_site_matches` / `probe_milestones` in `chrome-mv2.sh`. A table that
verifies here must still be synchronized into the appropriate embedded table
and exercised through the script tests.
