# Chrome Manifest V2 Re-Enable — Reverse-Engineering Notes

## Purpose & status

Google Chrome blocks Manifest V2 (MV2) extensions by default: the command-line flags and the `ExtensionManifestV2Availability` enterprise policy that used to re-enable them have been removed. The `chrome-mv2` patcher re-enables MV2 by flipping a single branch at each inlined copy of one predicate in the browser binary — `chrome.dll` on Windows, the `chrome` ELF on Linux.

This document is the *why* behind those byte edits, for both platforms. The gate is the same C++ in the same source files; only the container, the toolchain's codegen, and the OS plumbing differ. The engine relocates automatically across point releases and **declines without writing** on layouts it does not recognize.

**Platform status:**
- **Windows** — shipping. Targets **Chrome 151 and 152** (64-bit `chrome.dll`, PE32+) and **Chrome 151 x86** (32-bit `chrome.dll`, PE32); the Go patcher's PE output is byte-for-byte identical to the original C++ reference patcher.
- **Linux** — engine wired up, **no signature table derived yet**, so it declines cleanly. The gate skeleton and edit primitive are verified identical to Windows (§4b); what remains is enumerating the full site set (§6).

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

`g_allow_mv2_for_testing` is the switch the WinDbg/Canary guides toggle. Its single writer — `ManifestV2Handler::AllowMV2ExtensionsForTesting` (`IN-TEST`, `PassKey<ScopedTestMV2Enabler>`) — is **stripped from release**. With no writer, LTO constant-folds `ShouldDisableLegacyExtensions()` to `return true` and deletes the global (confirmed via `dbghelp`: there is no symbol for it, and the disassembled gates contain no global read).

So the real, reachable gate is **`IsExtensionAffected`** — specifically its `mv >= 3` early-out.

---

## 2. The patch — flip `cmp <mv>,2 ; jg` at each inlined site

The release build **inlines** `IsExtensionAffected` into its enforcement sites. Each opens with the manifest-version check compiled as:

```asm
    cmp <manifest_version>, 2
    jg  <not_affected>          ; manifest_version >= 3  -> not an MV2 extension
```

Flipping that single `jg` to an unconditional jump forces the *"not an affected MV2 extension"* outcome for every extension — the reachable equivalent of `g_allow_mv2_for_testing == true`. **Only a branch direction changes**: no call is removed and no return value is synthesized (see §7, CARDINAL RULE).

The compiler emits the bail-out in one of two encodings, depending on how far the not-affected label sits, and both flip to a pure direction change to the same target:

| Encoding | Bytes | Flip | Reach |
| :--- | :--- | :--- | :--- |
| **short** `jg` | `7F disp8` (2 B) | `7F` → `EB` (`jmp short`, same disp8) | ±127 |
| **near** `jg` | `0F 8F disp32` (6 B) | `0F 8F` → `90 E9` (`nop ; jmp near`, same disp32) | ±2 GB |

For the near flip, the `E9` ends at the same address the `jg` did, so the identical `disp32` targets the same label — still direction-only, just length-6 instead of length-1.

### How each site is located (relocation-tolerant, never guessed)

Each site is pinned by a `.text`-**unique** ~24-byte signature that surrounds the `jg`. Location proceeds:

1. **Fast path** — check the site's known absolute RVA for the reference build.
2. **Relocation scan** — if the fast path misses, scan all of `.text` for the signature and accept it **only if it matches at exactly `expectedMatches` offsets** (normally 1; 2 for a milestone that folds two gates to byte-identical bodies). Any other count → declined, never guessed.

The matcher is exact on every signature byte **except** the `jg` opcode (`7F`/`EB`, or `0F 8F`/`90 E9`) and its **displacement**, which are wildcarded. The displacement is masked because a point release often moves the not-affected target — outside the signature window — while leaving every byte *inside* the window identical. Masking only the displacement lets such a shift relocate cleanly, while a genuine layout change still misses rather than false-matching.

A write happens only if the byte is currently the stock opcode (or is already flipped, for idempotent re-runs). If nothing matches, the patcher runs a **report-only** structural scan (the `cmp …,2 ; jg ; … ; cmp …,{1,5}` skeleton), prints candidates, and **refuses to write** — see §5.

---

## 3. The two containers

### 3a. Windows — `chrome.dll` (PE32+)

`151.0.7922.76 chrome.dll`, PE32+, RSDS GUID `30dfcd7159e8bb144c4c44205044422e` (age 1). RVA → file-offset deltas (subtract to convert an RVA to a raw file offset):

| Section | RVA − file |
| :--- | :--- |
| `.text` | `0xA00` |
| `.rdata` | `0xE00` |
| `.data` | `0x1400` |

These deltas are build-specific — recompute them from the target's own section headers when porting. (The stock 152.0.7977.30 build's `.text` delta is `0xA00`, image base `0x180000000`.)

**PE fixups after the flips:**
- **Security directory**: `IMAGE_DIRECTORY_ENTRY_SECURITY` (RVA + size) is zeroed so the loader accepts the now-unsigned DLL. This also doubles as the stock/patched discriminator (a non-zero security dir means untouched stock).
- **Checksum**: `OptionalHeader.CheckSum` is recomputed over the whole file.

On a default consumer install the signature-stripped `chrome.dll` loads and runs without any registry change — confirmed on 151.0.7922.109 with no `RendererCodeIntegrityEnabled` policy set.

**32-bit (x86) `chrome.dll` (PE32).** The parser accepts PE32 (`OptionalHeader.Magic 0x10B`) as well as PE32+ (`0x20B`); the two differ only in the fixed optional-header length before the data directories (96 vs 112 bytes), so the Security-directory offset is picked by magic while the CheckSum field (offset 64) and the whole checksum algorithm are identical. Crucially, **the flip primitive is unchanged** — the `cmp <mv>,2 ; jg` idiom and the `7F`→`EB` / `0F 8F`→`90 E9` edits are byte-identical in 32- and 64-bit x86 — so only *new signatures* are needed, not a new engine. The 32-bit codegen drops the REX prefixes and uses smaller struct offsets (e.g. `IsExtensionAffected` opens `83 7A 28 02` = `cmp [edx+0x28],2` where 64-bit has `83 7A 50 02` = `cmp [edx+0x50],2`), so its byte windows differ entirely and are derived fresh. A 32-bit build is tagged `container: "pe32"` (§4) so it never cross-probes the 64-bit `pe` tables. 32-bit Chrome installs under `Program Files (x86)`; a loose copy elsewhere is reached with the tool's custom-path prompt.

### 3b. Linux — one ELF

Official builds are non-component (`is_component_build = false`), so the entire browser links into a single stripped PIE executable — there is no separate `libchrome.so`:

| Property | Value (151.0.7922.108) |
| :--- | :--- |
| Path | `/opt/google/chrome/chrome` |
| Size | 290,897,224 bytes |
| Type | `ELF 64-bit LSB pie executable, x86-64`, `DYN`, stripped |
| Build ID | `014c38679139be4a5f6fa4ae33bd82ef72d07f56` |
| `.gnu_debuglink` | `chrome.debug`, CRC-32 `0x84f46212` |
| `.text` | vaddr `0x031a8000`, file offset `0x31a7000`, size `0xd6e81b5` (~215 MiB) |
| `.rodata` | vaddr `0x01969000`, file offset `0x1969000` |
| Owner / mode | `root:root`, `0755` |

**`.text` vaddr ≠ file offset.** The delta here is `0x1000` (`0x031a8000` → `0x31a7000`). Compute it from the section headers; assuming equality would silently point every signature `0x1000` into a neighbouring function.

ELF has **no security directory and no checksum**, so writing the flipped bytes is the whole job — no post-fixups. There is no versioned install subdirectory (the binary sits directly in the install dir), so version discovery cannot come from the path. Sibling files that are **not** targets but matter operationally: `chrome-sandbox` (setuid root `4755`), `chrome_crashpad_handler`, `apparmor.d/google-chrome-stable`, `CHROME_VERSION_EXTRA` (holds the channel).

---

## 4. The per-platform site tables

The engine carries one signature table per known milestone (`signatures.json`, read at runtime from next to the binary — not embedded, so it updates without a rebuild). It probes every milestone and applies only the best-matching one, so a single binary supports several versions without their signatures interfering. Each milestone is tagged with its `container` (`pe` 64-bit PE / `pe32` 32-bit PE / `elf`) so a target never probes a table for a different container.

### 4a. Windows 151 — seven short-`jg` flips (151.0.7922.76)

| Site | `jg` RVA | Effect of the flip |
| :--- | :--- | :--- |
| `IsExtensionAffected` | `0x083012E4` | the standalone predicate → not affected |
| `ShouldBlockExtensionInstallation` | `0x08301323` | don't block install |
| `ShouldBlockExtensionEnable` | `0x03291F6B` | don't block enable (also covers `chrome.management`) |
| `OnExtensionSystemReady` (inlined loop) | `0x01618C4C` | skip the per-extension disable in the startup loop |
| `MaybeReEnableExtension` | `0x08301436` | re-enable already-disabled MV2 extensions |
| `UserMayInstall` (inlined) | `0x08E736BA` | don't block **Load Unpacked** (own inlined copy; builds `IDS_EXTENSIONS_CANT_INSTALL_MV2_EXTENSION`) |
| `MustRemainDisabled` (inlined) | `0x016448AA` | don't force an installed MV2 extension back to disabled on restart |

The first analysis found only the five non-inlined sites; the patch verified on disk but Load-Unpacked still failed, because `UserMayInstall` carries its **own** inlined copy reached *before* the other five, and `MustRemainDisabled` carries a private copy that would re-disable on restart. Both must be flipped — hence seven.

### 4b. Windows 152 — a milestone rearchitecture (152.0.7977.30)

Chrome 152 is **not** a point-release relocation: Google restructured the gates, so five of the seven 151 signatures stopped matching. The old build located the two unchanged sites, applied them, and printed `[SUCCESS]` — but with five gates live, MV2 stayed blocked. This is why the engine now carries per-milestone tables and reports a partial match honestly (`… detected (2/7 …)` followed by success was the bug). What changed:

- **A shared free predicate.** `IsExtensionAffected` became `extensions::manifest_v2_util::IsExtensionAffected`, taking `(mv, type, loc)` in registers. `ShouldBlockExtensionInstallation` compiled to a 13-byte **thunk** that tail-calls it — no inlined check of its own, so flipping the free predicate covers install-blocking and there is no separate install site.
- **Two byte-identical bodies.** `ManifestV2Handler::IsExtensionAffected` and `ShouldBlockExtensionEnable` are the same `0x3e` bytes. No signature can be unique between them, so that site carries `expectedMatches = 2`: the one signature must match — and flip — **both**. A count other than 2 means the layout changed and the site is declined.
- **A near `jg`.** `MustRemainDisabled`'s bail-out is out of short range and compiled to a near `jg` (`0F 8F rel32`), which a short-jg-only scan never even saw.

| Entry | `jg` RVA | Enc. | Matches |
| :--- | :--- | :--- | :--- |
| `manifest_v2_util::IsExtensionAffected` (covers the install thunk) | `0x82d26f5` | short | 1 |
| `ManifestV2Handler::IsExtensionAffected` + `ShouldBlockExtensionEnable` (shared body) | `0x3348754` | short | **2** |
| `OnExtensionSystemReady` startup loop | `0x124109c` | short | 1 |
| `MaybeReEnableExtension` | `0x82d24d6` | short | 1 |
| `UserMayInstall` (inlined, Load-Unpacked gate) | `0x8ddc241` | short | 1 |
| `MustRemainDisabled` (inlined) | `0x15a8d31` | **near** | 1 |

Six entries → seven physical flips. `OnExtensionSystemReady` and `MaybeReEnableExtension` have byte-identical signatures across 151 and 152, so both tables match them; "most sites located wins" disambiguates cleanly (a real 152 build satisfies 6 of the 152 entries and only ~2 of 151, and vice-versa).

### 4b′. Windows 151 x86 — the same seven, 32-bit codegen (151.0.7922.109)

The 32-bit `chrome.dll` carries the **same seven gates as 64-bit 151**, all short `jg`, each matching exactly once — the milestone is `container: "pe32"`, name `151-x86`. Derived from the 32-bit build + its PDB with the standard `scripts/` recipe (§5); the PDB named all seven gate functions cleanly.

| Site | `jg` RVA | Enc. |
| :--- | :--- | :--- |
| `IsExtensionAffected` | `0x07022F9A` | short |
| `ShouldBlockExtensionInstallation` | `0x07022FE7` | short |
| `ShouldBlockExtensionEnable` | `0x029E11BE` | short |
| `OnExtensionSystemReady` startup loop | `0x00B20DB9` | short |
| `MaybeReEnableExtension` | `0x0702310D` | short |
| `UserMayInstall` (inlined) | `0x079D46E7` | short |
| `MustRemainDisabled` (inlined) | `0x0111E3EC` | short |

The bytes differ from 64-bit 151 (no REX prefixes, smaller struct offsets — §3a), but the structure is identical: seven inlined `cmp <mv>,2 ; jg` sites, same seven functions. Because the container tag differs, a 32-bit target only ever probes this table and a 64-bit target only the `pe` tables — no cross-arch false match is possible. (Note `MustRemainDisabled` is a **short** `jg` here, unlike 64-bit *152* where it went near — encoding is per-build, always sweep both.)

### 4c. Linux — verified skeleton, table not yet derived

Disassembling the resolved gates on 151.0.7922.108 shows the **identical skeleton to Windows** — `cmp <manifest_version>, 2 ; jg not_affected`, short `jg` (`0x7F`) at every site found so far:

```
; MV2DeprecationImpactChecker::IsExtensionAffected  (the shared predicate)
67d9f10:  83 7e 50 02    cmp  DWORD PTR [rsi+0x50], 0x2
67d9f14:  7f 2f          jg   67d9f45              ; -> xor eax,eax ; ret  (not affected)

; ManifestV2Handler::ShouldBlockExtensionInstallation
98d3cc4:  83 fe 02       cmp  esi, 0x2
98d3cc7:  7f 1f          jg   98d3ce8

; ManifestV2Handler::ShouldBlockExtensionEnable
98d3d0a:  83 fa 02       cmp  edx, 0x2
98d3d0d:  7f 29          jg   98d3d38
```

So the flip carries over unchanged (`7F` → `EB`, same disp8). The `.text` vaddr → file-offset conversion was validated against these three addresses: raw bytes at `vaddr − 0x1000` match the disassembly exactly.

**Architecture note — Linux 151 resembles Windows *152*, not 151.** `ManifestV2Handler::IsExtensionAffected` (`0x98d3cb0`) is a bare thunk that tail-calls the shared predicate and carries no gate; `MaybeReEnableExtension` (`0x98d3df0`) calls out. So not every gate symbol is a flip site, and the number of inlined copies is a property of this build's outlining, not a fixed count. **Do not assume a site count — sweep `.text` for ground truth (§6).** Still to enumerate: the `OnExtensionSystemReady` loop, whatever `MaybeReEnableExtension` reaches, and the `UserMayInstall` / `MustRemainDisabled` inlined copies. (The `scripts/derive_milestone.py` finder already surfaces these bodies on the current WSL build.)

---

## 5. Porting to a new Chrome version

When Chrome bumps a milestone it may reorder `Extension` fields or change codegen, and the signatures stop matching. The patcher declines and prints structural candidates. Re-deriving is a bounded, cross-platform job — the mechanism never changes, only the bytes. The toolkit lives in `scripts/` (see `scripts/README.md`); it is dependency-free and works on both PE and ELF, both `jg` encodings.

1. **Get a stock binary** and its symbols. `python scripts/fetch_symbols.py <target>` pulls the matching PDB (Windows) or `chrome.debug` (Linux) into `_scratch/`, dispatching on the file's magic. A very fresh channel whose symbols aren't indexed yet returns HTTP 404 — pick one that exists.
2. **Name the gate functions** (optional but strongly recommended — a symbol-free scan surfaces ~150 gate-shaped idioms). Windows: `python scripts/resolve_symbols.py <chrome.dll> --json syms.json` (dbghelp memory-maps the multi-GB PDB; IDA/Ghidra OOM). Linux: `nm -SC chrome.debug > syms.txt`.
3. **Find, name, and emit** the milestone entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name <ver> --json
   ```
   The finder scans `.text` for `cmp <mv>,2 ; jg` in **both** encodings, applies the same follow-up (`cmp reg,{1,5}` type / `cmp byte[reg+disp32],0` location) and the same masking the engine uses, and reports each site's match count. Each real site shows `matches=1` (or `2` for a shared body); a `matches>2` site needs a wider signature.
4. **Add** the entry to `signatures.json` (`container` = `pe` 64-bit / `pe32` 32-bit / `elf`). No rebuild needed — the binary reads it at runtime; just ship the updated `signatures.json` beside the exe. Keep older milestones — the engine probes all and applies the best match.
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must print `ALL SITES VERIFIED: True` (a milestone fully covers the build). Then patch a **scratch copy**, confirm on-disk bytes, and GUI-test. A partial match now reports `PARTIALLY patched` instead of a false success — the signal a milestone shifted and needs re-signing.

**If the `cmp …,2 ; jg` skeleton is gone entirely** (Google changed the check, or added a manifest-parser floor that hard-rejects MV2 earlier), the flip strategy no longer applies; re-analyze the gate logic from source (`manifest_v2_handler.cc` / `mv2_deprecation_impact_checker.cc` at the new `branch-heads/*` tag) before touching any bytes.

---

## 6. Linux derivation — remaining work & scope

The gate skeleton and flip are proven (§4c); the outstanding work is enumerating the complete site set and shipping the table:

1. Fetch symbols — `python scripts/fetch_symbols.py /opt/google/chrome/chrome` (≈1.46 GB `chrome.debug` into `_scratch/`).
2. `nm -SC chrome.debug` to name the gate functions; feed as `--symbols`.
3. `python scripts/derive_milestone.py <chrome> --symbols … --json` — the finder already locates the shared predicate and both `ShouldBlock*` bodies on the current build.
4. For the inlined copies (`UserMayInstall` / `MustRemainDisabled`), the DWARF's `DW_TAG_inlined_subroutine` ranges name the enclosing function; the finder locates the inlined `cmp/jg` inside them.
5. Verify (`--verify` → `ALL SITES VERIFIED: True`), then patch a `/tmp` copy first — never the live install in place.

**Scope: x86-64 only for now.** Chrome shipped official arm64 Linux `.deb`s in 2026, so aarch64 is a real future target — but a separate engine: there is no `jg` (the analogue is rewriting a `B.cond` condition field to `AL`, keeping `imm19`, **unverified**), and no arm64 debug-info archive appears to be published (four plausible URL names all 404). Ship x86-64 first.

**Linux patcher specifics** (already implemented in the Go tool):
- **Atomic write.** Writing a running binary in place fails with `ETXTBSY`; the tool writes a sibling temp file, `fsync`s, and `rename()`s over the target — atomic, and it preserves the path so the AppArmor profile keyed on it still applies (`root:root 0755` re-applied).
- **A mid-session swap is not "done".** Running Chrome keeps the old inode mapped; a full restart applies the patch.
- **Snap/Flatpak cannot be patched** (read-only squashfs / OSTree) — detect and decline. Ubuntu's own `chromium` is a snap and a different build entirely.
- **`apt upgrade` reverts the patch** (like Chrome's updater on Windows); `dpkg --verify` will flag the modified binary — expected.
- **`LD_PRELOAD` cannot reach the gate** — it is inlined, internal, and LTO'd, not an exported dynamic symbol.

---

## 7. Superseded approaches & lessons

**CARDINAL RULE: only flip the direction of an existing branch to its existing target. Never delete or blank a call, and never invent control flow.** An earlier approach blanked a side-effecting `call` (to force a return value) — the call was invoked purely for its side effects, so deleting it corrupted `KeyedService` state and crashed the browser on startup. Byte-level verification did not catch it: the replacement bytes were structurally valid instructions, so the crash was semantic, not structural. A branch-direction flip is the only sanctioned edit.

| Approach | Symptom | Root cause |
| :--- | :--- | :--- |
| Unanchored wildcard byte search | `STATUS_BREAKPOINT` on startup | Scanning the ~250 MB `.text` for a short pattern hit 200+ unrelated instructions in V8/Blink and corrupted them. |
| Fixed register in the pattern (`80 BF …`) | Patch skipped; MV2 still blocked | Register allocation is non-deterministic between releases; the object pointer was in a different register. |
| `cmp [rax+0x18], 2` → `3` | All installed extensions vanished | That operand *identifies* MV2 extensions during parsing; changing the compared value broke recognition of every extension. Flip the branch, not the data. |
| Toggle `g_allow_mv2_for_testing` (WinDbg-style) | No such symbol in stable | Its only writer is test-only and stripped; LTO constant-folds the gate and deletes the global. Works only on Canary/debug. |
| Blank a side-effecting `call` to fake a return | Browser crashes on startup | See CARDINAL RULE. |
| Third-party beta signatures (onlytrisdev `patch-chrome-151.bat`) | All 20 patterns *found*, MV2 still blocked | Authored against a **beta** build; on stable every pattern matched an *unrelated* function, so the writes corrupted innocent code. |
| Trusting PDB `PROC` RVAs from a hand-rolled parser | "Verified" the wrong bytes; MV2 still blocked | An in-house PDB parser landed ~`0x1000` low, so every address pointed into a neighbouring function. **Resolve symbols with `dbghelp`, not a bespoke parser.** (The same class of bug as assuming `.text` vaddr == file offset on ELF — §3b.) |
| `derive_milestone.py` `rva()` fed a slice-relative index but subtracting `text_raw` | Symbol-filtered derive emitted `sites: []` (every candidate's RVA fell outside its gate function) | The finder returns positions relative to the `.text` slice; `rva()` must be `pos + text_virt`, not `pos − text_raw + text_virt`. Latent because the shipped 64-bit tables came from the C++ tool and both `--verify` and the engine ignore `jgRVA` (fast-path only, falls back to a full scan). Fixed when deriving 151-x86. Same "off by a section delta" family as the PDB-parser and ELF-offset bugs. |
| Short-jg-only scan (pre-152) | Missed `MustRemainDisabled` silently | It compiled to a near `jg`. **Always sweep both encodings.** |
| Legacy string-anchored engine (former "Stage C", 138–150) | Removed | Targeted versions that have long since auto-updated away, using the fragile techniques above. Removed in favour of declining cleanly and reporting candidates. (Recoverable from git history.) |

**Other standing rules:** never guess bytes (anchor on the longest fixed run, require an exact match count, or decline); a partial match is not success (write what was found but report it partial — a false "success" on a half-patched build is worse than declining).

---

## 8. Tooling notes

- **Symbol download**: `scripts/fetch_symbols.py` (stdlib-only) derives the RSDS key from a PE and pulls the exact PDB from the Chromium symbol server, or reads an ELF's build-id + `.gnu_debuglink` and streams `debug-info/chrome.debug` out of the per-version zip via HTTP range requests — verified against the binary's build-id and CRC both ways. Output lands in `_scratch/` (gitignored). This was a `chrome-mv2 fetch-symbols` subcommand until it was moved to `scripts/` (the patcher binary now only patches; the Go original is in git history as `internal/app/fetch.go`).
- **PDB query without IDA/Ghidra** (Windows): the PDB is multi-GB; IDA/Ghidra OOM. `scripts/resolve_symbols.py` uses `dbghelp.dll` via `ctypes` — `SymInitialize`, `SymLoadModuleExW` (first load ~2 min), `SymEnumSymbolsW`. RVA = symbol address − image base.
- **Derivation/verification**: `scripts/derive_milestone.py` is stdlib-only (no capstone/pyelftools/pefile), parses PE (PE32 `pe32` and PE32+ `pe`) and ELF, and anchors its `.text` scans on the longest fixed byte run so a pure-Python pass over ~250 MB is fast. It mirrors the engine's own matcher and report-only scanner, extended to the near-`jg` encoding.
- The live signature table is `signatures.json` (read at runtime from beside the binary). Its original 151/152 entries were derived from a Windows-only C++ reference patcher (preserved in git history at commit `e12fe16`); new milestones are authored into the JSON directly, verified with `scripts/derive_milestone.py --verify`.
