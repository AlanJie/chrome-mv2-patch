# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome by patching a few bytes. See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Supported Versions

- ✅ Chrome 151-155
- ✅ Windows x64, x86
- ✅ Linux x64

### Should work. Please check.

- 🧪 Chromium
- 🧪 Windows ARM
- 🧪 Linux ARM
- 🧪 macOS x64, ARM



## Usage

For Windows, use a **locally reviewed copy** of the script. Do not pipe a moving
GitHub branch directly into PowerShell.

```powershell
git clone https://github.com/AlanJie/chrome-mv2-patch.git
cd chrome-mv2-patch
powershell -ExecutionPolicy Bypass -File .\chrome-mv2.ps1
```

The Windows patcher is intentionally offline at runtime. Before creating or
refreshing its clean backup, it requires Windows to validate the target
`chrome.dll` Authenticode signature and requires the leaf signer to be
`Google LLC`. It also refuses partial signature matches and verifies that the
prepared output differs from the Google-signed backup only at the audited MV2
branch bytes plus the PE checksum/security-directory metadata.

### Linux, macOS

The Unix script is still inherited from the upstream legacy architecture and has
not yet received the same provenance hardening as the Windows path. Review and
run a local checkout instead of piping network content into a root shell.

```bash
git clone https://github.com/AlanJie/chrome-mv2-patch.git
cd chrome-mv2-patch
sudo bash chrome-mv2.sh
```

## Testing

Install [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm) from the Chrome Web Store (available until end of August 2026).

Or load it unpacked: turn on Developer mode at `chrome://extensions`, click Load unpacked, and pick the `uBlock0.chromium` folder from a [uBlock Origin release](https://github.com/gorhill/uBlock/releases).

## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B  
[Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
