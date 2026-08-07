# Changelog

## [1.0.0] - 2026-08-07

First public release. Re-enables Manifest V2 in Chrome by flipping seven
`IsExtensionAffected()` gates in `chrome.dll` (`jg` -> `jmp`).
Tested on Chrome 151.0.7922.76 and 151.0.7922.109.
