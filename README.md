# Chrome Manifest V2 Extension Patcher

A standalone patcher that re-enables Manifest V2 extension support in Chrome by flipping several `jg` instructions to `jmp` in `chrome.dll`. More technical details are in [`mv2-reversing.md`](mv2-reversing.md).

## Usage

Run `chrome-mv2-patch.exe` as admin.
Use `--help` for more info.

## Building

Requires Visual Studio.  
`.\build.bat`

## Verification

Install [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm).
Or load it unpacked: enable `Developer mode` on `chrome://extensions`, click `Load unpacked`, and select the `uBlock0.chromium` folder from a [uBlock Origin release](https://github.com/gorhill/uBlock/releases).

## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B  
[Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
