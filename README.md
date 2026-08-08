# Chrome Manifest V2 Patcher (`chrome-mv2-patch.exe`)

A standalone 64-bit binary patcher that re-enables Manifest V2 extension support in Google Chrome by flipping seven `jg` → `jmp` branches in `chrome.dll`. Verified against Chrome **151.0.7922.76** and **151.0.7922.109** (138+ architecture).

## How it works

In current Chrome, every MV2 block reduces to one predicate — `IsExtensionAffected()` (true iff `manifest_version < 3`). LTO inlines it into seven enforcement sites, each starting with `cmp manifest_version, 2 ; jg not_affected`. The patcher flips that one `jg` (`0x7F` → `0xEB`) at all seven, forcing the "not affected" path everywhere — the release-build equivalent of `g_allow_mv2_for_testing == true`.

The seven sites: `IsExtensionAffected`, `ShouldBlockExtensionInstallation`, `ShouldBlockExtensionEnable`, the `OnExtensionSystemReady` startup-disable loop, `MaybeReEnableExtension`, `UserMayInstall` (the **Load Unpacked** gate), and `MustRemainDisabled`. Each is located by a `.text`-unique ~24-byte signature (RVA is only a fast path), byte-verified, and idempotent. No call is removed and no control flow is invented — only an existing branch's direction changes, so the binary stays structurally valid.

Details and the porting checklist are in [`mv2-reversing.md`](mv2-reversing.md).

## Building

Requires Visual Studio (2022/2026) or C++ Build Tools with x64 MSVC (`cl.exe`).

```cmd
.\build.bat
```

Produces `chrome-mv2-patch.exe` with an embedded `requireAdministrator` UAC manifest.
The build also stamps the version (defined in `chrome-mv2-patch.cpp`) into the exe's
Properties > Details tab and packages a `chrome-mv2-patch-v<version>.zip` for GitHub
releases. See [`CHANGELOG.md`](CHANGELOG.md) for release notes.

## Usage

Just run it (a UAC prompt appears). Every installed release channel is detected and
listed, and you pick the one to patch:

```
[*] 3 Chrome release channels found:
  1) Stable  151.0.7922.109  [not running] (backup present)
      C:\Program Files\Google\Chrome\Application\151.0.7922.109\chrome.dll
  2) Beta    152.0.7962.4    [RUNNING, 12 process(es)]
      C:\Program Files\Google\Chrome Beta\Application\152.0.7962.4\chrome.dll
  3) Canary  153.0.7997.0    [RUNNING, 8 process(es)]
      C:\Users\me\AppData\Local\Google\Chrome SxS\Application\153.0.7997.0\chrome.dll

[*] Only the channel you pick is modified; the others keep running.

Which channel do you want to patch? [1-3, q to quit]:
```

Closing Chrome first is the clean path. If the channel you picked is still running you
get an explicit warning and a `[y/N]` prompt before anything happens — continuing
**force closes** it and unsaved tabs are lost. Only the processes holding *that*
`chrome.dll` are closed, via the Restart Manager. Stable, Beta, Dev, and Canary each
have their own `chrome.dll`, so patching one never disturbs the others.

```cmd
.\chrome-mv2-patch.exe                          # list channels and pick one
.\chrome-mv2-patch.exe "C:\Path\To\chrome.dll"  # target a channel directly
.\chrome-mv2-patch.exe --restore                # revert from chrome.dll.bak
.\chrome-mv2-patch.exe --yes                    # force close without asking
.\chrome-mv2-patch.exe --quiet                  # no final pause (scripting/CI)
.\chrome-mv2-patch.exe --version                # print version, no elevation
.\chrome-mv2-patch.exe --help                   # usage, no elevation
```

Output is coloured on a VT-capable console and degrades to plain text automatically
when redirected to a file or pipe. Set `NO_COLOR` to disable it; `FORCE_COLOR` keeps
it on through a pipe.

`--quiet` cannot prompt, so with more than one channel installed it needs an explicit
path, and it refuses to force close a running Chrome unless `--yes` is also given.

Flags may be combined. `chrome.dll.bak` is created/refreshed automatically. After writing, every site is re-read and byte-checked, the Security directory is stripped, and the PE `CheckSum` is recalculated.

## Verification

1. Launch Chrome, open `chrome://extensions`, enable **Developer mode**.
2. **Load unpacked** → select an MV2 extension folder (e.g. `uBlock0.chromium`).
3. It loads and runs without "unsupported manifest version" errors.

Or test with the classic MV2 build of [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm) from the Chrome Web Store — after patching it installs and enables again instead of being blocked as an unsupported Manifest V2 extension.

## Porting to a new Chrome version

The patcher relocates automatically across point releases (the signature scan finds a shifted `jg`). A milestone bump can change codegen so the signatures stop matching — the patcher then declines, prints structural candidates, and writes nothing. Re-deriving the seven signatures is a bounded job; the full checklist is in [`mv2-reversing.md`](mv2-reversing.md) §5.

## Donate

If this tool saved you some grief, a tip is appreciated and keeps it maintained across Chrome updates.

- **USDT (TRC20):** TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87
- **USDC (Base):** 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B
- [Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
