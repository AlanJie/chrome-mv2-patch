# scripts — MV2 gate derivation toolkit

Cross-platform, dependency-free tooling to fetch symbols for, derive, and verify
the Chrome MV2 gate signatures used by `../chrome-mv2.ps1`, `../chrome-mv2.sh`,
and `../chrome-mv2-mac.sh`. The canonical editable table is `../signatures.json`.
Works for any future Chrome version on x86, x86-64, and arm64:
64-bit PE `chrome.dll` (container `pe`), 32-bit PE `chrome.dll` (container
`pe32`), 64-bit **arm64** PE `chrome.dll` on Windows-on-ARM (container
`pe-arm64`, the same `bcond` flip as macOS arm64), the ELF `chrome` on Linux
(container `elf`), and the universal `Google Chrome Framework` Mach-O on macOS —
its x86_64 slice (`macho-x64`) and arm64 slice (`macho-arm64`).
Replaces the old single-build `port152/` workspace.

Full rationale: [`../mv2-reversing.md`](../mv2-reversing.md) §"Porting to a new version".

| Script | What it does | Deps |
| :--- | :--- | :--- |
| `fetch_chrome_binary.py` | Download the stock, gate-bearing binary itself — a channel's current `chrome.dll` (PE64/PE32), Linux `chrome` (ELF), or the macOS universal framework Mach-O (`mac-x64`/`mac-arm64`, always via Chrome for Testing) — unwrap it and drop it in `_scratch/` arch-tagged. `--version` falls back to Chrome for Testing. This is step 1 (below). | stdlib + 7-Zip |
| `fetch_symbols.py` | Download the symbols matching a binary — PDB (PE) from the Chromium symbol server, `chrome.debug` (ELF) streamed from the per-version zip, or the macOS dSYM's symtab streamed from `dl.google.com/…/dsym/` (emits `nm`-style names directly). Saves to `_scratch/` (gitignored). | stdlib only |
| `derive_milestone.py` | Find gate sites (`cmp <mv>,2 ; jg`, short **and** near), emit a `signatures.json` entry, and `--verify` an existing table against a binary. | stdlib only |
| `symbols_from_elf.py` | Linux: dump an ELF's `.symtab` as `nm -S`-style lines, fast and low-memory — a stand-in for `nm -SC` on the multi-GB `chrome.debug` (see note in step 2). | stdlib only |
| `symbols_from_pdb.py` | Windows only: name gate functions from a PDB via `dbghelp`. Optional — used to filter/name candidates. | Windows + PDB |

The test suite is Python too and lives flat in this folder (no subfolder):
`run_tests.py` (entry point) drives `test_linux.py` (ELF), `test_macos.py`
(Mach-O), `test_windows.py` (PE, Windows-only), and `test_derive.py`
(arm64 finder unit checks); `make_macho_fixture.py` builds a synthetic universal
Mach-O and `_testutil.py` holds the shared fixture builders/helpers. Run all of
it with `python scripts/run_tests.py`.

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
   - Windows arm64: `python scripts/fetch_chrome_binary.py --platform win-arm64`
     (fetches the current stable arm64 build from the arm64 enterprise MSI;
     Chrome for Testing has no arm64 build, so pin an older build with
     `--url <per-build installer>` rather than `--version`, or hand-copy an
     arm64 `chrome.dll`.)
   - Linux:       `python scripts/fetch_chrome_binary.py --platform linux`
   - macOS Intel: `python scripts/fetch_chrome_binary.py --platform mac-x64`
   - macOS ARM:   `python scripts/fetch_chrome_binary.py --platform mac-arm64`

   Defaults to the host's platform and the `stable` channel; `--channel beta`
   or `--version X.Y.Z.W` (Chrome for Testing fallback) pick another build, and
   `--list` just prints the current versions. A `.bak` or hand-copied
   `chrome.dll`/`chrome` works just as well — the fetch is a convenience, not a
   requirement.
2. **Get symbols** to name/filter candidates (optional but recommended — a
   symbol-free scan surfaces ~150 gate-shaped idioms). `fetch_symbols.py`
   downloads them into `_scratch/`:
   - Windows: `python scripts/fetch_symbols.py <chrome.dll>` then
     `python scripts/symbols_from_pdb.py <chrome.dll> --symdir _scratch --json _scratch/syms.json`
   - Linux: `python scripts/fetch_symbols.py <the ELF from step 1>` then
     `python scripts/symbols_from_elf.py _scratch/chrome.debug _scratch/syms.txt`
     (feeds `--symbols`). Prefer `symbols_from_elf.py` over `nm -SC chrome.debug`:
     `nm` demangles and sorts the whole 1.4 GB debug file and runs many minutes
     (and can thrash a small-RAM box); the dumper streams just `.symtab` in a
     few minutes, and the finder's keyword filter matches the still-mangled
     names fine.
   - macOS: symbols come from Google's official dSYMs. `fetch_symbols.py` reads
     the framework's per-slice UUID, streams the matching
     `googlechrome-{ver}-{arch}-dsym.tar.bz2`, keeps only its `LC_SYMTAB`
     (symtab/strtab sit near the front, so the multi-GB DWARF is never fully
     decompressed), and writes `_scratch/mac-<arch>-syms.txt` for `--symbols`.
     The dSYMs are UUID-matched to **consumer** Chrome (unwrap the `.dmg`), not
     Chrome for Testing (same version, different UUID). A universal binary emits
     one milestone per slice (`--json` returns both). See mv2-reversing.md §4e.
3. **Find + emit** the entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name 153 --json
   ```
   Each site should show `matches=1` (or `2` for a byte-identical shared body).
   A `matches>2` site needs a wider signature.
4. **Add** the emitted entry to the `milestones` array in
   `../signatures.json`, then copy the platform entry into the matching embedded
   table: `$EmbeddedSignatures` in `../chrome-mv2.ps1` for `pe`/`pe32`/`pe-arm64`,
   `EMBEDDED_SIGNATURES` in `../chrome-mv2.sh` for `elf`, or the pre-tokenized
   `EMBEDDED_SIGNATURES` in `../chrome-mv2-mac.sh` for `macho-x64`/`macho-arm64`.
   The scripts use an explicit signature path first, then `signatures.json`
   beside the script, then their embedded table. Keep the JSON and embedded copy
   synchronized.
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must
   print `ALL SITES VERIFIED: True`.
6. **Run the script tests**:
   `python scripts/run_tests.py` from the repository root.
7. Patch a scratch copy, inspect the changed bytes, and GUI/runtime-test on the
   target platform.

The original 151/152 entries were derived from a Windows-only C++ reference
patcher (preserved in git history at commit `e12fe16`); new versions are added to
`signatures.json` directly, per the steps above. `152-linux` was derived on a
**Windows** host from the fetched beta `.deb` — no Linux box is needed for steps
1-5, only for the final GUI/runtime test.

**32-bit (x86) Chrome** is handled the same way: point the same three commands at
a 32-bit `chrome.dll`. `derive_milestone.py` tags it `container: "pe32"` (vs `pe`
for 64-bit), and `symbols_from_pdb.py` reads the PE32 `ImageBase`, so a 32-bit
build only ever probes/verifies against `pe32` milestones. The shipped `151-x86`
entry was derived this way from a 32-bit `chrome.dll` + its matching PDB.

**Windows-on-ARM (arm64) Chrome** is handled the same way too, but its
`chrome.dll` is a PE32+ like x64 — the COFF machine field (`0xAA64` arm64 vs
`0x8664` x64) is what `derive_milestone.py` reads to tag `container: "pe-arm64"`,
so arm64 and x64 never cross-probe. arm64 has no `cmp/jg`; the gate is
`cmp w,#2 ; b.gt` and the flip rewrites only the `B.cond` condition GT→AL (kind
`bcond`, byte-for-byte the same flip as the macOS arm64 slice — see
mv2-reversing.md). The shipped `151-win-arm64` entry was derived from the
consumer arm64 `chrome.dll` (fetched via `--url`) and symbol-verified against its
PDB (`symbols_from_pdb.py` reads the PE32+ `ImageBase` regardless of machine).

The masking and match-count rules mirror both runtime scripts:
`Find-AffectedJgSites` / `Invoke-PatchMilestones` in `chrome-mv2.ps1` and
`find_site_matches` / `probe_milestones` in `chrome-mv2.sh`. A table that
verifies here must still be synchronized into the appropriate embedded table
and exercised through the script tests.
