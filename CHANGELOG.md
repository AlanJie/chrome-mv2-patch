# Changelog

## [1.0.1] - 2026-08-08

- Patch one channel without closing the others. The old check matched every
  `chrome.exe` by name and killed all of them; it now opens the target
  `chrome.dll` for write with no sharing and resolves holders via the Restart
  Manager, which maps a *file* to the processes using it.
- Detect all four channels (Stable/Beta/Dev/Canary) across every install root
  and choose which to patch.
- Warn before force-closing a running channel, naming it and its process count.
  `--yes` skips the prompt; `--quiet` refuses to force close without it.
- `fetch-chrome-pdb.py` finds all four channels and asks which one's symbols to
  download, instead of always picking Stable.

## [1.0.0] - 2026-08-07

First public release. Re-enables Manifest V2 in Chrome by flipping seven
`IsExtensionAffected()` gates in `chrome.dll` (`jg` -> `jmp`).
Tested on Chrome 151.0.7922.76 and 151.0.7922.109.
