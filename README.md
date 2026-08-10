# Chrome Manifest V2 Extension Patcher

A standalone patcher that re-enables Manifest V2 extension support in Chrome by changing a few bytes in the code to skip specific checks. The details in [`mv2-reversing.md`](mv2-reversing.md).

## Usage

```
chrome-mv2 patch          [path]   flip the MV2 gates (default command)
chrome-mv2 restore        [path]   restore the target binary from its .bak
```

Run elevated (Administrator on Windows, `sudo` on Linux). With no path, installed channels are listed so you can pick one — or press `c` at the prompt to type any `chrome.dll` path yourself (handy for a copy kept outside the standard install folders). Options: `-y/--yes` (force-close a running Chrome), `-q/--quiet` (no exit pause, for scripting), `-v/--version`, `-h/--help`.

Both 32-bit (x86) and 64-bit (x64) Chrome for Windows are supported: the `-x86` build patches a 32-bit `chrome.dll`, the plain build a 64-bit one. Each parses its own format and only applies signatures for that architecture.

Chrome-version signatures live in [`signatures.json`](signatures.json), read at runtime from next to the binary (not embedded), so the table can be updated without a rebuild — just ship a new `signatures.json` beside the exe. Derive a new version's entry with `python scripts/derive_milestone.py` (see [`scripts/README.md`](scripts/README.md)).

## Layout

```
cmd/chrome-mv2/        thin main() entry point
internal/app/          engine, PE/ELF image layer, platform glue
signatures.json        the gate signature table (read at runtime, ships beside the binary)
scripts/               cross-platform toolkit: fetch symbols, derive + verify signatures (see scripts/README.md)
mv2-reversing.md       the reverse-engineering write-up (both platforms)
```

## Building

`build.bat` (Windows) builds one binary per platform and a release zip each,
under `build/` — only the Go toolchain is required:

| Output | Target | Patches |
| :--- | :--- | :--- |
| `chrome-mv2.exe` | Windows x64 (`amd64`) | 64-bit `chrome.dll` |
| `chrome-mv2-x86.exe` | Windows x86 (`386`) | 32-bit `chrome.dll` |
| `chrome-mv2` | Linux x64 (`amd64`) | the ELF `chrome` |

(archives: `chrome-mv2-v<ver>-windows-amd64.zip`, `…-windows-386.zip`, `…-linux-amd64.tar.gz`.)
Or directly:

```
go build -o chrome-mv2      ./cmd/chrome-mv2               # host OS
GOOS=linux   GOARCH=amd64 go build -o chrome-mv2-linux   ./cmd/chrome-mv2
GOOS=windows GOARCH=amd64 go build -o chrome-mv2.exe     ./cmd/chrome-mv2
GOOS=windows GOARCH=386   go build -o chrome-mv2-x86.exe ./cmd/chrome-mv2
```

`signatures.json` is read at runtime, so it must sit next to the binary (or in the current directory). `build.bat` places it beside each binary and inside each release zip; a plain `go build` does not, so copy `signatures.json` next to the exe before running it.

The Windows release built by `build.bat` embeds a `requireAdministrator` manifest (`cmd/chrome-mv2/chrome-mv2.exe.manifest`), so it prompts for UAC elevation on launch — the tool needs admin to modify `chrome.dll`. A plain `go build` omits the manifest, which is convenient for unelevated offline testing (`MV2_TEST_NO_ELEVATION=1`).

## Verification

Install [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm) available until the end of August 2026.
Or load it unpacked: enable `Developer mode` on `chrome://extensions`, click `Load unpacked`, and select the `uBlock0.chromium` folder from a [uBlock Origin release](https://github.com/gorhill/uBlock/releases).

## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B  
[Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
