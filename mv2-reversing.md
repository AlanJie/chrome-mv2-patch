# Chrome Manifest V2 Re-Enable — Reverse-Engineering Notes

## Purpose & status

Google Chrome blocks Manifest V2 (MV2) extensions by default: the command-line flags and enterprise policies that used to re-enable them have been removed. `chrome-mv2-patch.exe` re-enables MV2 by making seven one-byte edits to `chrome.dll`.

This document is the *why* behind those seven bytes. The current target is **Chrome 151.0.7922.76** (`branch-heads/7922`); the engine relocates automatically across point releases and declines (without writing) on layouts it does not recognize.

---

## 1. Why MV2 is blocked (Chrome 138+)

Chrome 138 (2024) replaced `ManifestV2ExperimentManager` with a new `ManifestV2Handler` `KeyedService` (`extensions/browser/manifest_v2_handler.cc` + `mv2_deprecation_impact_checker.cc`). Every MV2 block reduces to two predicates:

```cpp
namespace { bool g_allow_mv2_for_testing = false; }

bool ShouldDisableLegacyExtensions() {
  if (g_allow_mv2_for_testing) return false;   // stripped in release
  return true;
}

// MV2DeprecationImpactChecker::IsExtensionAffected
bool IsExtensionAffected(int mv, Manifest::Type t, mojom::ManifestLocation loc) {
  if (mv >= 3) return false;                    // <-- the branch we flip
  if (t != kExtension && t != kLoginScreenExtension && t != kUserScript) return false;
  if (Manifest::IsComponentLocation(loc)) return false;
  return true;
}
```

`ShouldBlockExtensionInstallation`, `ShouldBlockExtensionEnable`, `DisableAffectedExtensions` (in `OnExtensionSystemReady`), and `MaybeReEnableExtension` all reduce to `ShouldDisableLegacyExtensions() && IsExtensionAffected(...)`.

### The flag cannot be flipped in the stable binary

`g_allow_mv2_for_testing` is the switch the WinDbg/Canary guides toggle. It has a single writer — `ManifestV2Handler::AllowMV2ExtensionsForTesting` (`IN-TEST`, `PassKey<ScopedTestMV2Enabler>`) — which is **stripped from release**. With no writer, LTO constant-folds `ShouldDisableLegacyExtensions()` to `return true` and deletes the global. Confirmed via `dbghelp`: there is **no** symbol for `g_allow_mv2_for_testing` / `AllowMV2` / `ShouldDisableLegacyExtensions`, and the disassembled gates contain no global read.

So the real, reachable gate is **`IsExtensionAffected`** — specifically its `mv >= 3` early-out.

---

## 2. The working patch — seven `jg` → `jmp` flips

The release build **inlines** `IsExtensionAffected` into seven enforcement sites. Each opens with the manifest-version check compiled as:

```asm
    cmp <manifest_version>, 2
    jg  <not_affected>          ; manifest_version >= 3  -> not an MV2 extension
```

Flipping that single `jg` (`0x7F`) to an unconditional `jmp short` (`0xEB`, same displacement byte) forces the *"not an affected MV2 extension"* outcome for every extension — byte-for-byte the effect of `g_allow_mv2_for_testing == true`, but reachable in the stripped release binary. Only a branch direction changes: no call is removed and no return value is synthesized (see §5 CARDINAL RULE).

### The seven sites (151.0.7922.76)

| Site | `jg` RVA | Effect of the flip |
| :--- | :--- | :--- |
| `IsExtensionAffected` | `0x083012E4` | the standalone predicate → not affected |
| `ShouldBlockExtensionInstallation` | `0x08301323` | don't block install |
| `ShouldBlockExtensionEnable` | `0x03291F6B` | don't block enable (also covers `chrome.management` `CheckManifestV2Deprecation`) |
| `OnExtensionSystemReady` (inlined loop) | `0x01618C4C` | skip the per-extension disable in the startup loop |
| `MaybeReEnableExtension` | `0x08301436` | re-enable already-disabled MV2 extensions |
| `UserMayInstall` (inlined) | `0x08E736BA` | don't block **Load Unpacked** (carries its own inlined copy that builds `IDS_EXTENSIONS_CANT_INSTALL_MV2_EXTENSION`) |
| `MustRemainDisabled` (inlined) | `0x016448AA` | don't force an installed MV2 extension back to disabled on restart |

The first analysis found five sites; the patch applied and verified on disk, but Load-Unpacked still failed with *"Cannot install extension because it uses an unsupported manifest version"*. `UserMayInstall` — the actual load-unpacked gate — carries its **own** inlined copy of the predicate and is reached *before* the other five. `MustRemainDisabled` carries a private copy too, which would otherwise re-disable an installed MV2 extension on the next restart. Both must be flipped; hence seven.

### How each site is located (relocation-tolerant, never guessed)

Each site is pinned by a `.text`-**unique** ~24-byte signature that surrounds the `jg`. Location proceeds:

1. **Fast path** — check the site's known absolute RVA for the reference build.
2. **Relocation scan** — if the fast path misses, scan all of `.text` for the signature and accept it **only if it matches at exactly one offset**. Ambiguous or absent → the site is declined, never guessed.

The matcher is exact on every signature byte **except two**: the `jg` opcode itself (`0x7F` stock / `0xEB` if already flipped) and the **`jg` displacement byte** immediately after it. The displacement is wildcarded because a point release often moves the not-affected target — which sits outside the signature window — while leaving every byte *inside* the window identical. Masking only that one byte lets such a shift relocate cleanly, while a genuine layout change (reordered `Extension` fields, different codegen) still misses rather than false-matching.

The write happens only if the byte is currently `0x7F` (or is already `0xEB`, for idempotent re-runs). If the seven signatures match nothing at all, the patcher runs a **report-only** structural scan (the `cmp …,2 ; jg ; … ; cmp …,{1,5}` skeleton), prints candidates, and **refuses to write** — see §4.

### PE fixups

- **Security directory**: `IMAGE_DIRECTORY_ENTRY_SECURITY` (RVA + size) is zeroed so the Windows loader accepts the now-unsigned DLL. This also doubles as the stock/patched discriminator (a non-zero security dir means untouched stock).
- **Checksum**: `OptionalHeader.CheckSum` is recomputed over the whole file.

On a default consumer install the signature-stripped `chrome.dll` loads and runs without any registry change — confirmed on 151.0.7922.109 with no `RendererCodeIntegrityEnabled` policy set.

---

## 3. Section layout of the reference build

`151.0.7922.76 chrome.dll`, PE32+, RSDS GUID `30dfcd7159e8bb144c4c44205044422e` (age 1). RVA → file-offset deltas (subtract to convert an RVA to a raw file offset):

| Section | RVA − file |
| :--- | :--- |
| `.text` | `0xA00` |
| `.rdata` | `0xE00` |
| `.data` | `0x1400` |

These deltas are build-specific — recompute them from the target's own section headers when porting.

---

## 4. Porting to a new Chrome version

When Chrome bumps a milestone it may reorder `Extension` struct fields or change codegen, and the seven byte-signatures stop matching. The patcher then declines and prints structural candidates. Re-deriving the signatures is a bounded job — the mechanism never changes, only the bytes:

1. **Get the matching PDB.** Run `fetch-chrome-pdb.py` (reads the DLL's RSDS key, pulls the exact PDB from the Chromium symbol server).
2. **Resolve the seven gate symbols** from the PDB with `dbghelp.dll` via `ctypes` (it memory-maps the multi-GB PDB; IDA/Ghidra OOM). Enumerate `IsExtensionAffected`, `ShouldBlockExtensionInstallation`, `ShouldBlockExtensionEnable`, `OnExtensionSystemReady`, `MaybeReEnableExtension`, plus the enclosing functions for the `UserMayInstall` / `MustRemainDisabled` inlined copies (`StandardManagementPolicyProvider::UserMayInstall`, and the `MustRemainDisabled` gate). RVA = symbol address − module base.
3. **Disassemble each** with capstone and find the opening `cmp <mv>, 2 ; jg` (the inlined copies may sit mid-function; search the function body). For the two inlined-copy sites, confirm you are at the MV2 check (`UserMayInstall`'s copy builds `IDS_EXTENSIONS_CANT_INSTALL_MV2_EXTENSION`).
4. **Capture a ~24-byte signature** around each `jg`, note the `jg`'s offset within it (`jgOff`), and record the `jg`'s absolute RVA.
5. **Verify uniqueness**: each signature must occur exactly once across the whole `.text` (with the `jg` byte treated as `0x7F`/`0xEB` and its displacement masked, matching the runtime matcher). If a signature is not unique, widen it.
6. **Update `kSites`** in `chrome-mv2-patch.cpp` (name, `knownJgRVA`, `sig`, `jgOff`) and rebuild with `build.bat`.
7. **Re-verify**: run the patcher against a stock copy — it should locate 7/7 and pass on-disk verification — then do the runtime GUI test.

**If the `cmp …,2 ; jg` skeleton is gone entirely** (Google changed the check itself, or added a real manifest parser floor that hard-rejects MV2 before these gates), the seven-flip strategy no longer applies; the gate logic must be re-analyzed from source (`manifest_v2_handler.cc` / `mv2_deprecation_impact_checker.cc` at the new `branch-heads/*` tag) before any bytes are touched.

---

## 5. Superseded approaches & lessons

The path to the seven-flip patch produced several wrong turns. They are recorded here so they are not repeated.

**CARDINAL RULE: only flip the direction of an existing branch. Never delete or blank a call, and never invent control flow.** An earlier approach blanked a side-effecting `call` (to force a return value) — the call was invoked purely for its side effects, so deleting it corrupted `KeyedService` state and crashed the browser on startup. Byte-level verification did not catch it: the replacement bytes were structurally valid instructions, so the crash was semantic, not structural.

| Approach | Symptom | Root cause |
| :--- | :--- | :--- |
| Unanchored wildcard byte search | `STATUS_BREAKPOINT` on startup | Blindly scanning the ~250 MB `.text` for a short pattern hit 200+ unrelated instructions in V8/Blink and corrupted them. |
| Fixed register in the pattern (`80 BF …`) | Patch skipped; MV2 still blocked | MSVC register allocation is non-deterministic between releases; the object pointer was in a different register. |
| `cmp [rax+0x18], 2` → `3` | All installed extensions vanished | That operand *identifies* MV2 extensions during parsing; changing it broke recognition of every extension. |
| Toggle `g_allow_mv2_for_testing` (WinDbg-style) | No such symbol in stable | Its only writer is test-only and stripped; LTO constant-folds the gate and deletes the global. Works only on Canary/debug. |
| Blank a side-effecting `call` to fake a return | Browser crashes on startup | See CARDINAL RULE above. |
| Third-party beta signatures (onlytrisdev `patch-chrome-151.bat`) | All 20 patterns *found*, MV2 still blocked | Authored against a **beta** build; on stable every pattern matched an *unrelated* function (`blink::EventHandler::Trace`, `Archive::ReadHeader15`, …), so the writes corrupted innocent code. |
| Trusting PDB `PROC` RVAs from a hand-rolled parser | "Verified" the wrong bytes; MV2 still blocked | An in-house PDB parser landed ~`0x1000` low, so every address pointed into a neighbouring function. Re-resolving with Microsoft's `dbghelp.dll` gives the true entries. **Lesson: resolve symbols with `dbghelp`, not a bespoke parser.** |
| Legacy string-anchored engine (former "Stage C", 138–150) | Removed | It targeted Chrome versions that have long since auto-updated away, and its techniques are precisely the ones in this table that proved fragile. Leaving a string-anchored engine in place to half-match a *future* shifted binary is itself the top corruption risk. Removed in favour of declining cleanly and reporting candidates. (Recoverable from git history if ever needed.) |

---

## 6. Tooling notes

- **PDB query without IDA/Ghidra**: the PDB is multi-GB; IDA/Ghidra OOM. Use `dbghelp.dll` via Python `ctypes`: `SymSetOptions` + `SymInitialize`, `SymLoadModuleExW` (first load ~2 min — background it), then `SymEnumSymbolsW` / `SymFromAddrW`. RVA = symbol address − module base.
- **Disassembly/verification**: capstone 5.x. Pure-Python byte scans over the ~250 MB `.text` take a few minutes — anchor on the longest fixed byte run first.
- **Symbol download**: `fetch-chrome-pdb.py` derives the RSDS key from the DLL and fetches the exact PDB from the Chromium symbol server.
- The reference-build symbol RVAs and section deltas are in §2 and §3; the live signature table is `kSites` in `chrome-mv2-patch.cpp`.
