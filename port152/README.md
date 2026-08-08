# port152 — Chrome 152 signature derivation

Reproducible derivation of the Chrome **152** (`branch-heads/7977`) MV2 gate
signatures used by `kMilestones` in `../chrome-mv2-patch.cpp`. Companion to
`../fetch-chrome-pdb.py`; the full rationale is in `../mv2-reversing.md` §2a/§4.

Inputs (not committed — see `../.gitignore`):
- `../chrome152-stock.dll` — a clean stock 152 `chrome.dll` (copy a channel's
  `chrome.dll.bak`, or fetch stock).
- `../chrome.dll.pdb` — the matching PDB (`python ../fetch-chrome-pdb.py`).

Scripts (run from the repo root, e.g. `python port152/gen_sites.py`):

| Script | What it does |
| :--- | :--- |
| `pe_info.py` | PE parse: image base, `.text` RVA/raw/size, security dir, RSDS key. |
| `resolve_symbols.py` | dbghelp (ctypes) resolves the gate symbols → RVAs; writes `symbols.json`. First PDB parse is slow (~2 min). |
| `disasm_gates.py` | capstone disassembly of each gate; finds `cmp <mv>,2 ; jg`. |
| `analyze.py` | callers, identical-body check, near-jg dump, uniqueness counts. |
| `sweep_all_gates.py` | full-`.text` sweep for **short and near** `jg` gates (ground truth). |
| `gen_sites.py` | emits the `kMilestones` byte arrays and re-verifies each entry's match count. **`ALL SITES VERIFIED: True` is the static check.** |
| `build-test.bat` | builds a throwaway `mv2-test.exe` with `-DMV2_TEST_NO_ELEVATION` for offline patch/verify on a local copy (releases always require admin). |

To re-verify the current 152 table after any change:

```
python port152/gen_sites.py        # must print: ALL SITES VERIFIED: True
```
