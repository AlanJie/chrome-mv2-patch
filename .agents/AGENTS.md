# Agent Workspace Guidelines & Manifest V2 Patcher References

## Repository knowledge & research document

This repository contains a standalone PE binary patcher (`chrome-mv2-patch.cpp` →
`chrome-mv2-patch.exe`) that re-enables Manifest V2 (MV2) extensions in Google Chrome
by flipping the inlined `IsExtensionAffected` `jg` branches in `chrome.dll`. It
carries a per-milestone site table (`kMilestones`) and currently targets
**Chrome 151 and 152**; it probes each milestone and applies only the best match.

Before modifying `chrome-mv2-patch.cpp` or attempting an alternative patching strategy,
**agents MUST read [mv2-reversing.md](../mv2-reversing.md)** —
it holds the full rationale, the verified addresses, and a table of superseded
approaches with the exact symptom each produced. Do not re-derive a strategy that
mv2-reversing.md already records as failed.

---

## The one rule that matters most

**Only flip the direction of an existing branch. Never delete or blank a `call`, and
never invent control flow.** A reverted approach blanked a side-effecting `call` to
fake a return value and crashed Chrome on startup; byte-level verification did not
catch it because the replacement bytes were structurally valid. See mv2-reversing.md §6
(CARDINAL RULE).

---

## Key references in `mv2-reversing.md`

- **Why MV2 is blocked (§1)**: `MV2DeprecationImpactChecker::IsExtensionAffected`
  (`manifest_version < 3` early-out) is the real gate. `g_allow_mv2_for_testing`'s
  only writer is test-only and stripped from release, so LTO constant-folds the flag
  away — it is not even in the PDB. Toggling it works only on Canary/debug builds.
- **The seven-flip patch (§2)**: the gate is inlined into enforcement sites, each
  `cmp manifest_version, 2 ; jg not_affected`. Flip each `jg` → `jmp`. On 151 that
  is seven `.text`-unique short-`jg` sites. **152 (§2a)** rearchitected the layout:
  a shared free predicate that install-blocking tail-calls, two byte-identical
  bodies flipped by one signature (`expectedMatches = 2`), and a `MustRemainDisabled`
  that uses a **near** `jg` (`0F 8F`→`90 E9`). Sites live in the per-milestone
  `kMilestones` table in `chrome-mv2-patch.cpp`; the matcher masks the `jg` opcode
  and displacement per encoding. `UserMayInstall` (Load-Unpacked) and
  `MustRemainDisabled` carry their own inlined copies on both milestones.
- **Section deltas (§3)**: RVA→file-offset for the reference build.
- **Porting to a new milestone (§4)**: the PDB + `dbghelp` + capstone re-signing
  checklist for when a milestone's signatures stop matching. The 152 derivation is
  reproducible under `port152/` (sweep covers short **and** near `jg`).
- **Superseded approaches & lessons (§6)**: unanchored wildcard searches (crash),
  fixed-register patterns (miss), struct-operand edits (hide all extensions),
  trusting a hand-rolled PDB parser (~0x1000 off), third-party beta signatures
  (corrupt unrelated functions). Read this before proposing anything "new."
- **Tooling (§7)**: query the multi-GB PDB with `dbghelp.dll` via `ctypes`
  (IDA/Ghidra OOM); disassemble/verify with capstone.

---

## Build & verify

- Build: `.\build.bat` (auto-detects x64 MSVC; embeds a `requireAdministrator`
  manifest). Produces `chrome-mv2-patch.exe`.
- The patcher is idempotent, verifies every site on disk after writing, clears the
  Security directory, and recomputes the PE checksum. If all seven signatures miss,
  it reports structural candidates and **refuses to write** — that is correct
  behaviour on an unrecognized milestone, not a bug to patch around.
- Runtime note: the signature-stripped DLL loads on a default install with no
  registry change; the patcher never touches the registry.
