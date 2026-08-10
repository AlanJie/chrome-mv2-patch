# Agent Workspace Guidelines & Manifest V2 Patcher References

## Repository knowledge & research document

This repository contains a binary patcher that re-enables Manifest V2 (MV2)
extensions in Google Chrome by flipping the inlined `IsExtensionAffected` `jg`
branches in the browser binary (`chrome.dll` on Windows, the ELF on Linux). It
carries a per-milestone signature table and currently targets **Chrome 151 and
152** (64-bit) plus **Chrome 151 x86** (32-bit `chrome.dll`) on Windows; it probes
each milestone and applies only the best match. Both 32-bit (`GOARCH=386`,
`chrome-mv2-x86.exe`) and 64-bit Windows binaries are built; the flip primitive is
identical across x86/x64, only the byte signatures differ.

The shipping tool is the Go program under `cmd/chrome-mv2` (logic in
`internal/app`). The signature table is `signatures.json` at the repo root, read
at runtime from next to the binary (NOT embedded — `os.ReadFile`, not `go:embed`),
so it updates without a rebuild and must ship beside the exe. It is the forward
source of truth for new milestones. Its original 151/152 entries were derived from
a Windows-only C++ reference patcher (the historical parity oracle — the Go PE
output was verified byte-identical to it), which is preserved in git history at
commit `e12fe16` should re-derivation ever be needed.

**Before modifying any patching logic, agents MUST read
[mv2-reversing.md](../mv2-reversing.md)** — one document covering both platforms.
It holds the full rationale, the verified addresses/encodings, and a table of
superseded approaches with the exact symptom each produced. Do not re-derive a
strategy it already records as failed.

**Platform status:** Windows ships (151/152). Linux — the engine is wired up and
the gate skeleton + flip are verified identical to Windows (mv2-reversing.md §4c),
but **no Linux signature table is derived yet**, so the Linux patcher declines
cleanly. Symbols for both platforms come from `python scripts/fetch_symbols.py`
(PDB on Windows, `chrome.debug` on Linux — it dispatches on the target's file
magic, saving into `_scratch/`).

---

## The one rule that matters most

**Only flip the direction of an existing branch. Never delete or blank a `call`,
and never invent control flow.** A reverted approach blanked a side-effecting
`call` to fake a return value and crashed Chrome on startup; byte-level
verification did not catch it because the replacement bytes were structurally
valid. See mv2-reversing.md §7 (CARDINAL RULE).

---

## Key references in `mv2-reversing.md`

- **Why MV2 is blocked (§1)**: `IsExtensionAffected` (`manifest_version < 3`
  early-out) is the real gate. `g_allow_mv2_for_testing`'s only writer is
  test-only and stripped, so LTO constant-folds the flag away — not even in the
  PDB. Toggling it works only on Canary/debug.
- **The flip (§2)**: each inlined site opens `cmp <mv>,2 ; jg not_affected`. Flip
  the `jg` → unconditional jump, in either encoding: short `7F`→`EB`, or near
  `0F 8F`→`90 E9` (both keep the displacement, pure direction change). The matcher
  masks the `jg` opcode and displacement and requires an exact `expectedMatches`
  count.
- **Containers (§3)**: PE fixups (zero the Security directory, recompute the
  checksum) vs ELF (none — no signature, no checksum; `.text` vaddr ≠ file offset,
  delta computed from headers). PE parsing accepts both PE32+ (64-bit, container
  `pe`) and PE32 (32-bit x86, container `pe32`); container tags keep 32- and
  64-bit tables from cross-probing.
- **Site tables (§4)**: Windows 151 = seven short-`jg` sites; Windows 152
  rearchitected (shared free predicate + tail-call thunk, two byte-identical
  bodies flipped by one `expectedMatches=2` signature, a near-`jg`
  `MustRemainDisabled`); Windows 151 x86 = the same seven as 151, 32-bit codegen,
  all short `jg` (§4b′). Linux 151 resembles Windows *152* (shared predicate +
  thunks) — table not yet derived.
- **Porting to a new version (§5)**: the cross-platform `scripts/` recipe (below).
- **Superseded approaches (§7)**: unanchored wildcard searches (crash),
  fixed-register patterns (miss), struct-operand edits (hide all extensions),
  hand-rolled PDB parser (~0x1000 off), short-jg-only scan (missed the near-jg
  site), third-party beta signatures (corrupt unrelated functions). Read before
  proposing anything "new."

---

## Derivation toolkit (`scripts/`)

Cross-platform, dependency-free. Replaces the old single-build `port152/`
workspace. See `scripts/README.md`.

- `fetch_symbols.py` — download the symbols matching a binary (PE→PDB from the
  Chromium symbol server, ELF→`chrome.debug` streamed from the per-version zip),
  saving to `_scratch/`. stdlib only. Dispatches on file magic. (Moved here from
  the patcher binary's old `fetch-symbols` subcommand.)
- `derive_milestone.py` — parses PE **and** ELF, finds gate sites (`cmp <mv>,2 ;
  jg`, short and near) with the engine's own masking, filters/names them via
  `--symbols`, emits a `signatures.json` entry (`--json`), and `--verify`s an
  existing table against a binary (`ALL SITES VERIFIED: True`). stdlib only.
- `resolve_symbols.py` — Windows-only PDB symbol resolver (dbghelp via ctypes),
  emits the `--symbols` JSON. On Linux the equivalent is `nm -SC chrome.debug`.

Porting checklist: `fetch_symbols.py` → name gates (`resolve_symbols.py` / `nm`) →
`derive_milestone.py --symbols … --json` → add the entry to `signatures.json` →
`derive_milestone.py --verify` must pass → patch a scratch copy and GUI-test.
Full detail in mv2-reversing.md §5.

---

## Build & verify

- Build: `.\build.bat` (Go toolchain only, no Visual Studio) builds one binary
  per platform and a release zip each, all under `build/`:
  `build\chrome-mv2.exe` (windows/amd64) + `chrome-mv2-v<ver>-windows-amd64.zip`,
  `build\chrome-mv2-x86.exe` (windows/386) + `…-windows-386.zip`, and
  `build\chrome-mv2` (linux/amd64) + `…-linux-amd64.zip` (each zip bundles the
  binary + `signatures.json` + LICENSE + README, and `signatures.json` is also
  copied next to each loose binary in `build\`). Version is read from `appVersion`
  in `internal/app/app.go`. (ARM is intentionally not built: the engine flips
  x86/x64 branches, so an ARM binary would have no native-ARM Chrome to patch.)
- Windows UAC manifest: `build.bat`'s `:manifest` subroutine regenerates one
  `cmd/chrome-mv2/rsrc_windows_<arch>.syso` per Windows arch (amd64 + 386) from
  `cmd/chrome-mv2/chrome-mv2.exe.manifest` via
  `go run github.com/akavel/rsrc@v0.10.2` (fetched to the module cache, never
  added to `go.mod`), so each release exe embeds `requireAdministrator`. Go
  auto-links the `rsrc_windows_<GOARCH>.syso` matching each target. The `.syso`s
  are transient — build.bat deletes them in the tidy step, so a plain
  `go build ./cmd/chrome-mv2` stays manifest-free and runnable unelevated for
  offline `MV2_TEST_NO_ELEVATION` testing. Only the `.manifest` XML is tracked.
- The patcher is idempotent, verifies every site on disk after writing, and on
  Windows clears the Security directory and recomputes the PE checksum (both moot
  on ELF). If all signatures miss, it reports structural candidates and **refuses
  to write** — correct behaviour on an unrecognized milestone, not a bug to patch
  around. A partial match reports `PARTIALLY patched`, never a false success.
- Offline verify without elevation: run the tool with `MV2_TEST_NO_ELEVATION=1`
  against a scratch stock-binary copy (never the live install).
- Runtime note: the signature-stripped binary loads on a default install with no
  registry/config change; the patcher never touches the registry.
