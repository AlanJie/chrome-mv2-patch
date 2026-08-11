# Chrome MV2 Extension Patcher

Re-enables Manifest V2 extensions in Chrome by patching a few bytes. See [`mv2-reversing.md`](mv2-reversing.md) for details.

## Supported Versions

- ✅ Windows x64
- ✅ Windows x86 (32-bit)
- ✅ Linux x64
- ❌ macOS (not yet supported)
- ❌ ARM (not yet supported)

## Usage

### Windows

Run [`chrome-mv2.ps1`](chrome-mv2.ps1):

```powershell
powershell -ExecutionPolicy Bypass -File chrome-mv2.ps1
```

### Linux

Run [`chrome-mv2.sh`](chrome-mv2.sh):

```bash
chmod +x ./chrome-mv2.sh
sudo ./chrome-mv2.sh
```

## Adding New Chrome Versions

Update the signature tables when a new Chrome version comes out:

- **Windows**: Edit the `$EmbeddedSignatures` block in `chrome-mv2.ps1`, or put a `signatures.json` next to it
- **Linux**: Edit the `EMBEDDED_SIGNATURES` block in `chrome-mv2.sh`, or put a `signatures.json` next to it

Both scripts have signatures built in and will use an external `signatures.json` if present (it overrides the embedded ones).

Use the Python tools in `scripts/` to derive new signatures (see [`scripts/README.md`](scripts/README.md)).

## Files

- `chrome-mv2.ps1` - PowerShell script for Windows
- `chrome-mv2.sh` - Bash script for Linux  
- `signatures.json` - signature database
- `scripts/` - Python tools to derive new signatures
- `mv2-reversing.md` - reverse engineering notes

## Testing

Install [uBlock Origin](https://chromewebstore.google.com/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm) from the Chrome Web Store (available until end of August 2026).

Or load it unpacked: turn on Developer mode at `chrome://extensions`, click Load unpacked, and pick the `uBlock0.chromium` folder from a [uBlock Origin release](https://github.com/gorhill/uBlock/releases).

## Donate

USDT (TRC20): TDAr6Lu2sYtArJYAgUpyfuk6rKNvvyMA87  
USDC (Base): 0x762712dcC8e3E757Cf3FC077AeF0b4EDa8692b7B  
[Boosty](https://boosty.to/sketchystan1)

## License

Released under the [MIT License](LICENSE).
