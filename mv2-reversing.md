# Chrome Manifest V2 Re-Enable — Reverse-Engineering Notes

## Purpose & status

Google Chrome blocks Manifest V2 (MV2) extensions by default: the command-line flags and the `ExtensionManifestV2Availability` enterprise policy that used to re-enable them have been removed. The `chrome-mv2` patcher re-enables MV2 by flipping a single branch at each inlined copy of one predicate in the browser binary — `chrome.dll` on Windows, the `chrome` ELF on Linux.

This document is the *why* behind those byte edits, for both platforms. The gate is the same C++ in the same source files; only the container, the toolchain's codegen, and the OS plumbing differ. Both scripts relocate signatures automatically across point releases and **decline without writing** on layouts they do not recognize.

**Platform status:**
- **Windows** — shipping through `chrome-mv2.ps1`. Targets **Chrome 151 and 152** (64-bit `chrome.dll`, PE32+) and **Chrome 151 x86** (32-bit `chrome.dll`, PE32); its PE edits preserve the branch-flip behavior verified against the original C++ reference patcher.
- **Linux** — shipping through `chrome-mv2.sh`. Targets **Chrome 151 and 152** (64-bit ELF). Chrome 151's five gate sites were derived and runtime-verified; Chrome 152's five-site table was derived from beta and statically verified, with its remaining Linux runtime check recorded in §4d.

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

**32-bit (x86) `chrome.dll` (PE32).** The parser accepts PE32 (`OptionalHeader.Magic 0x10B`) as well as PE32+ (`0x20B`); the two differ only in the fixed optional-header length before the data directories (96 vs 112 bytes), so the Security-directory offset is picked by magic while the CheckSum field (offset 64) and the whole checksum algorithm are identical. Crucially, **the flip primitive is unchanged** — the `cmp <mv>,2 ; jg` idiom and the `7F`→`EB` / `0F 8F`→`90 E9` edits are byte-identical in 32- and 64-bit x86 — so only *new signatures* are needed, not a separate patch strategy. The 32-bit codegen drops the REX prefixes and uses smaller struct offsets (e.g. `IsExtensionAffected` opens `83 7A 28 02` = `cmp [edx+0x28],2` where 64-bit has `83 7A 50 02` = `cmp [edx+0x50],2`), so its byte windows differ entirely and are derived fresh. A 32-bit build is tagged `container: "pe32"` (§4) so it never cross-probes the 64-bit `pe` tables. 32-bit Chrome installs under `Program Files (x86)`; a loose copy elsewhere is reached with the script's custom-path prompt.

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

**`.deb` and `.rpm` ship the identical ELF.** Google builds the Linux x86-64 `chrome` once per release and wraps that same payload in both the Debian and RPM packages. Verified on 151.0.7922.108: the `chrome` ELF extracted from `google-chrome-stable_current_x86_64.rpm` has the same **build-id** (`014c3867…`) as the installed `.deb` binary and is **byte-for-byte identical** to the stock `.deb` (the only diffs observed were the 5 gate sites, and only because the live install had already been patched — its `chrome.bak` is bit-identical to the RPM ELF). So **one `elf` signature table covers both package families** — the signatures key on the ELF, never on the packaging. An RPM host (Fedora/RHEL/openSUSE) installs to the same `/opt/google/chrome/chrome`, so the patcher's existing target enumeration and atomic-write path apply unchanged; only the revert-on-update mechanism differs (`dnf/zypper` + `rpm -V` flags the modified binary, the analogue of `apt upgrade` / `dpkg --verify`). The RPM payload is an `xz`-compressed `cpio` (`070701` newc); `rpm2cpio` isn't needed — the header's `PAYLOADCOMPRESSOR`/`PAYLOADFORMAT` tags name it and stdlib `lzma` streams one member out.

---

## 4. The per-platform site tables

The PowerShell and Bash scripts carry embedded, platform-specific milestone tables and also accept an external `signatures.json`. Runtime precedence is an explicitly selected signature file, then `signatures.json` beside the script, then the embedded table. Both scripts probe every applicable milestone and apply only the best unambiguous match, so one script supports several versions without their signatures interfering. Each milestone is tagged with its `container` (`pe` 64-bit PE / `pe32` 32-bit PE / `elf`) so a target never probes a table for a different container. `signatures.json` is the canonical derivation table; every shipped entry must also be synchronized into `$EmbeddedSignatures` in `chrome-mv2.ps1` or `EMBEDDED_SIGNATURES` in `chrome-mv2.sh`.

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

Chrome 152 is **not** a point-release relocation: Google restructured the gates, so five of the seven 151 signatures stopped matching. The old implementation located the two unchanged sites, applied them, and printed `[SUCCESS]` — but with five gates live, MV2 stayed blocked. This is why the scripts use per-milestone tables and decline partial matches by default (`… detected (2/7 …)` followed by success was the bug). What changed:

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

### 4c. Linux 151 — five sites, derived and verified (151.0.7922.108)

Disassembling the resolved gates on 151.0.7922.108 shows the **identical skeleton to Windows** — `cmp <manifest_version>, 2 ; jg not_affected`, short `jg` (`0x7F`) at the enforcement sites:

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

**The full site table (`container: "elf"`, name `151-linux`):**

| Site | `jg` RVA | Enc. | Effect of the flip |
| :--- | :--- | :--- | :--- |
| `MV2DeprecationImpactChecker::IsExtensionAffected` (shared predicate) | `0x67D9F14` | short | the reachable gate → not affected; also covers the `ManifestV2Handler` thunk and the out-of-line `OnExtensionSystemReady` / `MaybeReEnableExtension`, which **call** it |
| `ManifestV2Handler::ShouldBlockExtensionInstallation` | `0x98D3CC7` | short | don't block install |
| `ManifestV2Handler::ShouldBlockExtensionEnable` | `0x98D3D0D` | short | don't block enable |
| `StandardManagementPolicyProvider::UserMayInstall` (inlined) | `0xA3224A3` | **near** | don't block Load-Unpacked (its `jg` shares the target with the adjacent allowed-type exit) |
| `StandardManagementPolicyProvider::MustRemainDisabled` (inlined) | `0x5E5DB24` | short | don't force an installed MV2 extension back to disabled on restart |

**Architecture note — Linux 151 resembles Windows *152*, not 151.** `ManifestV2Handler::IsExtensionAffected` (`0x98d3cb0`) is a bare 14-byte thunk that tail-calls the shared predicate and carries no gate; `MaybeReEnableExtension` (`0x98d3df0`) and the tiny `OnExtensionSystemReady` (`0x67d9af0`, 0x24 bytes) both **call** the shared predicate out-of-line rather than inlining a `cmp/jg` — so, unlike Windows, there is no separate `OnExtensionSystemReady` flip site; the shared-predicate flip covers them. The two `StandardManagementPolicyProvider` copies **are** inlined and need their own flips, and `UserMayInstall`'s is a **near** `jg` — invisible to a short-only sweep, the §7 lesson. Six gate symbols, five physical flips.

**Flip verified by execution.** Beyond byte-diffing (5 edits, 6 bytes, all direction-only — §7 CARDINAL RULE), the shared predicate was mapped and called in-process against a synthetic Extension: **stock** returns 1 (affected) for `mv=2` and 0 for `mv=3`; **patched** returns 0 for both — MV2 unblocked, MV3 unchanged. Chrome itself starts and renders cleanly on the patched binary (headless, full install tree). The derivation used the `.symtab`-direct dump (`scripts/dump_symtab.py`, ~3 min) rather than `nm -SC`, which is impractically slow on the 1.4 GB `chrome.debug` with 3 GB RAM.

---

### 4d. Linux 152 — the same five gates, rearchitected like Windows 152 (152.0.7977.30 beta)

Derived from the `google-chrome-beta` `.deb` (`--platform linux --channel beta`), the first Linux entry taken from beta rather than stable. Linux 152 picks up exactly the Windows 152 rearchitecture (§4b), so the 151 signatures mostly stop matching: of the five `151-linux` entries only the shared predicate's bytes survive, and that lone carry-over is the *whole* overlap between the two tables.

| Site | `jg` RVA | Enc. | Matches | Effect of the flip |
| :--- | :--- | :--- | :--- | :--- |
| `manifest_v2_util::IsExtensionAffected` (free predicate) | `0x0985B449` | short | 1 | not affected; also covers `ShouldBlockExtensionInstallation`, a 16-byte thunk that tail-jumps here |
| `ManifestV2Handler::IsExtensionAffected` / `ShouldBlockExtensionEnable` (shared body) | `0x0985B0F4` | short | 1 | don't block enable; also covers the out-of-line `OnExtensionSystemReady` / `MaybeReEnableExtension` calls |
| `ManifestV2Handler::MaybeReEnableExtension` (inlined) | `0x0985B238` | short | 1 | re-enable already-disabled MV2 extensions |
| `StandardManagementPolicyProvider::UserMayInstall` (inlined) | `0x0A256BAA` | **near** | 1 | don't block **Load Unpacked** |
| `StandardManagementPolicyProvider::MustRemainDisabled` (inlined) | `0x0599A69A` | **near** | 1 | don't force an installed MV2 extension back to disabled on restart |

Three differences worth recording against the other tables:

- **ICF folds the shared body, so `expectedMatches` is 1, not 2.** `ManifestV2Handler::IsExtensionAffected` and `ShouldBlockExtensionEnable` are the same *address* here (`0x985b0f0`, `0x47` bytes), not two byte-identical copies at different addresses as on Windows 152. One symbol, one site, one flip — the `expectedMatches = 2` of the Windows entry would be *wrong* on Linux.
- **`MaybeReEnableExtension` regained its own inlined copy.** On Linux 151 it called the shared predicate out-of-line and needed no site of its own; on 152 it carries an inlined `cmp/jg` again, which is the extra entry relative to §4c. `OnExtensionSystemReady` (`0x422d810`, `0x24` bytes) still only calls out, so it still has no site — the count stays five, but not the same five.
- **Both `StandardManagementPolicyProvider` gates are now near `jg`.** On Linux 151 only `UserMayInstall` was; `MustRemainDisabled` was short. A short-only sweep would now miss *two* sites — §7's lesson, third platform.

Byte-diff of the patched scratch copy: **7 bytes across 5 edits, all direction-only** — three short `7F` → `EB`, two near `0F 8F` → `90 E9`, every disp8/disp32 preserved and the file size unchanged (§7 CARDINAL RULE). `restore` reproduces the stock binary byte-for-byte.

**Table disambiguation, both directions.** The one shared signature means each table partially matches the other's build, and "most sites located wins" resolves it with margin: on the 152 beta ELF `152-linux` satisfies 5/5 and `151-linux` 1/5; on the 151.0.7922.108 stable ELF `151-linux` satisfies 5/5 and `152-linux` 1/5. Both were confirmed by running the Linux script against a scratch copy, not just `--verify`. This is the guard-rail the third-party beta signatures in §7 lacked: a beta-derived entry is safe to ship precisely because it is container- and milestone-tagged and every site is accepted only on an exact match count, so on a stable build it declines instead of matching an unrelated function.

**Not yet runtime-tested.** The 151 entry was confirmed by executing the patched predicate in-process and a headless startup (§4c); this one is verified statically (on-disk bytes + Linux-script acceptance) on a Windows host. Chrome 152 beta on a Linux box is the remaining check before treating it as proven.

---

## 5. Porting to a new Chrome version

When Chrome bumps a milestone it may reorder `Extension` fields or change codegen, and the signatures stop matching. The patcher declines and prints structural candidates. Re-deriving is a bounded, cross-platform job — the mechanism never changes, only the bytes. The toolkit lives in `scripts/` (see `scripts/README.md`); it is dependency-free and works on both PE and ELF, both `jg` encodings.

1. **Get a stock binary** and its symbols. `python scripts/fetch_chrome_binary.py`
   downloads the channel's current installer, unwraps it, and leaves the bare
   gate binary in `_scratch/` (`--platform win64|win|linux`, `--channel`,
   `--version` for the Chrome for Testing fallback, `--list` to just print
   current versions); a `.bak` or hand-copied binary works too. Then
   `python scripts/fetch_symbols.py <target>` pulls the matching PDB (Windows)
   or `chrome.debug` (Linux) into `_scratch/`, dispatching on the file's magic.
   A very fresh channel whose symbols aren't indexed yet returns HTTP 404 — pick
   one that exists.
2. **Name the gate functions** (optional but strongly recommended — a symbol-free scan surfaces ~150 gate-shaped idioms). Windows: `python scripts/resolve_symbols.py <chrome.dll> --json syms.json` (dbghelp memory-maps the multi-GB PDB; IDA/Ghidra OOM). Linux: `python scripts/dump_symtab.py _scratch/chrome.debug _scratch/syms.txt` (see §6 step 2 for why not `nm -SC`).
3. **Find, name, and emit** the milestone entry:
   ```
   python scripts/derive_milestone.py <binary> --symbols syms.(json|txt) --name <ver> --json
   ```
   The finder scans `.text` for `cmp <mv>,2 ; jg` in **both** encodings, applies the same follow-up (`cmp reg,{1,5}` type / `cmp byte[reg+disp32],0` location) and the same masking the runtime scripts use, and reports each site's match count. Each real site shows `matches=1` (or `2` for a shared body); a `matches>2` site needs a wider signature.
4. **Add** the entry to `signatures.json` (`container` = `pe` 64-bit / `pe32` 32-bit / `elf`) and synchronize it into the matching embedded table: `$EmbeddedSignatures` in `chrome-mv2.ps1` for Windows or `EMBEDDED_SIGNATURES` in `chrome-mv2.sh` for Linux. Keep older milestones — each script probes all applicable entries and applies the best match. An external JSON can update signatures without editing the script, but the self-contained release scripts must embed every supported entry.
5. **Re-verify**: `python scripts/derive_milestone.py <binary> --verify` must print `ALL SITES VERIFIED: True` (a milestone fully covers the build). Run `pwsh -NoProfile -File scripts/tests/run-tests.ps1`, then patch a **scratch copy**, confirm on-disk bytes, and GUI-test. Partial or ambiguous layouts are declined by default; developer overrides exist for investigation, not normal releases.

**If the `cmp …,2 ; jg` skeleton is gone entirely** (Google changed the check, or added a manifest-parser floor that hard-rejects MV2 earlier), the flip strategy no longer applies; re-analyze the gate logic from source (`manifest_v2_handler.cc` / `mv2_deprecation_impact_checker.cc` at the new `branch-heads/*` tag) before touching any bytes.

---

## 6. Linux derivation — the recipe used (151 + 152, done) & scope

The 151 and 152 tables are derived, shipped, and verified (§4c, §4d). The exact steps, for the next milestone:

1. Fetch the binary and symbols — `python scripts/fetch_chrome_binary.py --platform linux [--channel beta]` unwraps the `.deb` and leaves the bare ELF in `_scratch/`, then `python scripts/fetch_symbols.py <that ELF>` pulls the matching `chrome.debug` (≈1.46 GB, ~1388 MiB inflated). Build-id and `.gnu_debuglink` CRC are checked both ways. Passing the fetched binary rather than `/opt/google/chrome/chrome` is what makes the whole derivation runnable from a Windows host.
2. Name the gate functions. `nm -SC chrome.debug` is correct but **impractically slow** on a 1.4 GB debug file with limited RAM (demangling + sort ran past 10 min on the 3 GB WSL box). Instead dump `.symtab` directly — a ~250-line stdlib script that streams the symbol + string tables and emits `nm -S`-style lines finishes in ~3 min. Mangled names embed the source identifier verbatim (`…19IsExtensionAffected…`), so `derive_milestone.py`'s keyword filter matches without demangling.
3. `python scripts/derive_milestone.py <chrome> --symbols syms.txt --name <ver>-linux --json` — on 151 this surfaces exactly the five sites, each `matches=1`, sweeping short **and** near.
4. The two inlined copies fall inside `StandardManagementPolicyProvider::{UserMayInstall,MustRemainDisabled}`, so the symbol filter attributes them by function range directly — no manual DWARF `DW_TAG_inlined_subroutine` walk was needed on this build. The out-of-line callers (`OnExtensionSystemReady`, `MaybeReEnableExtension`) are *not* separate sites — they call the shared predicate, which the first flip covers.
5. Add the entry to `signatures.json` (`container: "elf"`) and to `EMBEDDED_SIGNATURES` in `chrome-mv2.sh`; `--verify` -> `ALL SITES VERIFIED: True`, then run the script tests and patch a scratch **copy of the whole install tree** (the binary needs its sibling `.pak`/`icudtl.dat` to start) — never the live install in place. Confirm the flip by executing the patched predicate (see §4c) and by a headless startup.

**Scope: x86-64 only for now.** Chrome shipped official arm64 Linux `.deb`s in 2026, so aarch64 is a real future target — but it needs a separate implementation: there is no `jg` (the analogue is rewriting a `B.cond` condition field to `AL`, keeping `imm19`, **unverified**), and no arm64 debug-info archive appears to be published (four plausible URL names all 404). Ship x86-64 first.

**Linux patcher specifics** (implemented in `chrome-mv2.sh`):
- **Atomic write.** Writing a running binary in place fails with `ETXTBSY`; the script writes a sibling temp file, `fsync`s, and `rename()`s over the target — atomic, and it preserves the path so the AppArmor profile keyed on it still applies (`root:root 0755` re-applied).
- **A mid-session swap is not "done".** Running Chrome keeps the old inode mapped; a full restart applies the patch.
- **Snap/Flatpak cannot be patched** (read-only squashfs / OSTree) — detect and decline. Ubuntu's own `chromium` is a snap and a different build entirely.
- **`apt upgrade` reverts the patch** (like Chrome's updater on Windows); `dpkg --verify` will flag the modified binary — expected. On RPM hosts the analogue is `dnf`/`zypper` upgrading `google-chrome-stable` and `rpm -V google-chrome-stable` reporting the changed `chrome` (`5` = MD5/digest differs) — same cause, same expected flag. Google ships the same `/opt/google/chrome` for both, so no package-specific handling is needed; the identical ELF means the identical signature table (§3b).
- **AppArmor (`.deb`/Ubuntu) vs SELinux (`.rpm`/Fedora, RHEL).** The atomic sibling-write + `rename()` preserves the target path, so the AppArmor profile keyed on it still applies; on SELinux systems the file context is likewise path-derived, but if a relabel is ever needed the script leaves the path in place for `restorecon` to fix. Neither MAC layer blocks the in-place edit as root.
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
| `derive_milestone.py` `rva()` fed a slice-relative index but subtracting `text_raw` | Symbol-filtered derive emitted `sites: []` (every candidate's RVA fell outside its gate function) | The finder returns positions relative to the `.text` slice; `rva()` must be `pos + text_virt`, not `pos − text_raw + text_virt`. Latent because the shipped 64-bit tables came from the C++ tool and full signature verification did not depend on `jgRVA`; the current scripts use it as a fast path and fall back to a full masked scan. Fixed when deriving 151-x86. Same "off by a section delta" family as the PDB-parser and ELF-offset bugs. |
| Short-jg-only scan (pre-152) | Missed `MustRemainDisabled` silently | It compiled to a near `jg`. **Always sweep both encodings.** (Linux 151's `UserMayInstall` is likewise a near `jg` — same lesson, second platform.) |
| In-process gate verification passed the Extension in `rdi` | Stock predicate returned 0 (not affected) for an MV2 input — the opposite of the source, so the "test" proved nothing | `IsExtensionAffected` reads its argument from **`rsi`** (`cmp [rsi+0x50],2`): it is a method, so `rdi` is the unused `this` and the Extension is the *second* SysV arg. Passing it in `rdi` fed the gate garbage. Once handed `(this=0, ext)`, stock returned 1 for `mv=2` / 0 for `mv=3` as the C++ predicts, and the patched bytes returned 0 for both — read the register the code actually dereferences, don't assume arg0. |
| Legacy string-anchored engine (former "Stage C", 138–150) | Removed | Targeted versions that have long since auto-updated away, using the fragile techniques above. Removed in favour of declining cleanly and reporting candidates. (Recoverable from git history.) |

**Other standing rules:** never guess bytes (anchor on the longest fixed run, require an exact match count, or decline); a partial match is not success (write what was found but report it partial — a false "success" on a half-patched build is worse than declining).

---

## 8. Tooling notes

- **Stock binary download**: `scripts/fetch_chrome_binary.py` (stdlib + 7-Zip) downloads a channel's current offline installer, unwraps the nested container chain (Windows `.exe`/`.msi` → `updater.7z` → `chrome.7z` → `Chrome-bin/`; Linux `.deb` → `data.tar.xz` → `opt/google/chrome/`), and leaves just the gate binary — `chrome.dll` (PE32+/PE32) or the `chrome` ELF — in `_scratch/`, arch-tagged and magic-checked. `--version` falls back to the Chrome for Testing archive (unbranded — re-verify against the real install). Adapted from a broader multi-platform release fetcher; macOS is dropped since it is not a patcher target.
- **Symbol download**: `scripts/fetch_symbols.py` (stdlib-only) derives the RSDS key from a PE and pulls the exact PDB from the Chromium symbol server, or reads an ELF's build-id + `.gnu_debuglink` and streams `debug-info/chrome.debug` out of the per-version zip via HTTP range requests — verified against the binary's build-id and CRC both ways. Output lands in `_scratch/` (gitignored).
- **PDB query without IDA/Ghidra** (Windows): the PDB is multi-GB; IDA/Ghidra OOM. `scripts/resolve_symbols.py` uses `dbghelp.dll` via `ctypes` — `SymInitialize`, `SymLoadModuleExW` (first load ~2 min), `SymEnumSymbolsW`. RVA = symbol address − image base.
- **ELF symbol names without `nm`** (Linux): `nm -SC` on the 1.4 GB `chrome.debug` demangles and sorts the whole file and runs many minutes (impractical on a small-RAM box). `scripts/dump_symtab.py` streams just `.symtab` + its string table and emits `nm -S`-style lines in ~3 min; the finder's keyword filter matches the still-mangled names. Feed its output to `derive_milestone.py --symbols`.
- **Derivation/verification**: `scripts/derive_milestone.py` is stdlib-only (no capstone/pyelftools/pefile), parses PE (PE32 `pe32` and PE32+ `pe`) and ELF, and anchors its `.text` scans on the longest fixed byte run so a pure-Python pass over ~250 MB is fast. It mirrors the match-count, masking, and report-only scan rules in both runtime scripts, extended to the near-`jg` encoding.
- The canonical derivation table is `signatures.json`. Its original 151/152 entries were derived from a Windows-only C++ reference patcher (preserved in git history at commit `e12fe16`); new milestones are authored into the JSON, verified with `scripts/derive_milestone.py --verify`, and synchronized into the appropriate embedded script table.
