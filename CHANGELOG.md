# Changelog

## [1.3.0] - 2026-08-13

- macOS support (`chrome-mv2-mac.sh`): patches the universal Google Chrome
  Framework Mach-O and ad-hoc re-signs the app so it launches.
  - Intel (x86_64) reuses the proven `jg` branch flip.
  - Apple Silicon (arm64) is experimental and opt-in (`--arm64`): a new
    `B.cond` condition flip (GT→AL), CI-verified on real hardware.
  - Both slices ship the complete seven-gate table, **symbol-verified** against
    Google's official macOS dSYMs (streamed from the dl.google.com dSYM
    endpoint; symtab-only, UUID-matched to consumer Chrome).
- Mach-O/fat support and an arm64 `bcond` gate finder in
  `scripts/derive_milestone.py`; `mac-x64`/`mac-arm64` fetch in
  `scripts/fetch_chrome_binary.py`; dSYM symbol streaming in
  `scripts/fetch_symbols.py`.
- GitHub Actions CI: static engine tests on Linux/macOS, a real-hardware
  patch/re-sign/launch/restore proof on Intel and Apple Silicon — including a
  functional MV2 A/B that confirms the patched build enables a Manifest V2
  extension the stock build disables — and a dSYM symbol cross-check that the
  shipped gates are the named MV2 functions.

## [1.2.0] - 2026-08-12

- Linux support.
- Windows x86 support.
- Migrated from a binary to PowerShell and Bash scripts.

## [1.1.0] - 2026-08-09

- Chrome 152 support.
- Patch one channel without closing other Chrome windows.

## [1.0.0] - 2026-08-07

- First public release. Re-enables Manifest V2 in Chrome 151.
