import os
import struct
import sys
import urllib.request
from pathlib import Path


def get_cv_info(dll_path: str):
    """Extracts PDB filename and GUID/Age symbol key from PE headers or RSDS scanning."""
    with open(dll_path, "rb") as f:
        data = f.read()

    # --- Method 1: Proper PE Directory Parsing ---
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
            num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
            size_of_opt_header = struct.unpack_from("<H", data, e_lfanew + 20)[0]

            opt_header_offset = e_lfanew + 24
            magic = struct.unpack_from("<H", data, opt_header_offset)[0]

            # Entry 6 = IMAGE_DIRECTORY_ENTRY_DEBUG
            if magic == 0x20B:  # PE32+ (64-bit)
                debug_dir_offset = opt_header_offset + 112 + (6 * 8)
            elif magic == 0x10B:  # PE32 (32-bit)
                debug_dir_offset = opt_header_offset + 96 + (6 * 8)
            else:
                debug_dir_offset = None

            if debug_dir_offset:
                debug_rva, debug_size = struct.unpack_from("<II", data, debug_dir_offset)

                sections_offset = opt_header_offset + size_of_opt_header
                sections = []
                for i in range(num_sections):
                    sec = sections_offset + (i * 40)
                    v_size, v_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sec + 8)
                    sections.append((v_addr, v_size, raw_ptr, raw_size))

                def rva_to_offset(rva):
                    for v_addr, v_size, raw_ptr, _ in sections:
                        if v_addr <= rva < v_addr + v_size:
                            return raw_ptr + (rva - v_addr)
                    return None

                debug_file_offset = rva_to_offset(debug_rva)
                if debug_file_offset:
                    num_entries = debug_size // 28
                    for i in range(num_entries):
                        entry_offset = debug_file_offset + (i * 28)
                        debug_type, data_size, rva, ptr = struct.unpack_from(
                            "<IIII", data, entry_offset + 12
                        )

                        # Type 2 = IMAGE_DEBUG_TYPE_CODEVIEW
                        if debug_type == 2:
                            cv_offset = ptr if ptr != 0 else rva_to_offset(rva)
                            if cv_offset and data[cv_offset : cv_offset + 4] == b"RSDS":
                                return parse_rsds(data, cv_offset)
    except Exception:
        pass  # Fallback to pattern search on parsing failure

    # --- Method 2: Signature Scan Fallback ---
    pos = 0
    while True:
        pos = data.find(b"RSDS", pos)
        if pos == -1:
            break
        try:
            pdb_name, symbol_key = parse_rsds(data, pos)
            if pdb_name.lower().endswith(".pdb"):
                return pdb_name, symbol_key
        except Exception:
            pass
        pos += 4

    raise ValueError("CodeView RSDS debug record not found in DLL")


def parse_rsds(data: bytes, offset: int):
    """Parses RSDS signature block into PDB name and Symbol Key."""
    d1, d2, d3 = struct.unpack_from("<IHH", data, offset + 4)
    d4 = data[offset + 12 : offset + 20]
    age = struct.unpack_from("<I", data, offset + 20)[0]

    pdb_bytes = data[offset + 24 : offset + 260].split(b"\x00")[0]
    pdb_name = Path(pdb_bytes.decode("utf-8", errors="ignore")).name

    guid_str = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"
    age_str = f"{age:X}"

    return pdb_name, f"{guid_str}{age_str}"


def version_key(name: str):
    """Sort key for a Chrome version directory ("151.0.7922.109" -> (151,0,7922,109))."""
    parts = []
    for piece in name.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    return tuple(parts)


# Channel display name -> install directory, relative to an install root. Every
# channel ships its own chrome.dll with its own build ID, so the PDB that matches
# one will not match another.
CHANNELS = [
    ("Stable", Path("Google") / "Chrome"),
    ("Beta", Path("Google") / "Chrome Beta"),
    ("Dev", Path("Google") / "Chrome Dev"),
    ("Canary", Path("Google") / "Chrome SxS"),
]


def install_roots() -> list[Path]:
    """64-bit installs land in Program Files, 32-bit in (x86), user-scope
    installs (always the case for Canary) in Local AppData."""
    roots = []
    for var, fallback in (
        ("ProgramFiles", r"C:\Program Files"),
        ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ("LOCALAPPDATA", None),
    ):
        value = os.environ.get(var) or fallback
        if value:
            roots.append(Path(value))
    return roots


def newest_dll_under(app_dir: Path) -> Path | None:
    """Newest versioned chrome.dll under an Application directory, or one
    sitting directly in it."""
    if app_dir.is_dir():
        version_dirs = sorted(
            (p for p in app_dir.iterdir() if p.is_dir() and (p / "chrome.dll").is_file()),
            key=lambda p: version_key(p.name),
            reverse=True,
        )
        if version_dirs:
            return version_dirs[0] / "chrome.dll"

    direct = app_dir / "chrome.dll"
    return direct if direct.is_file() else None


def find_chrome_installs() -> list[tuple[str, Path]]:
    """Every installed channel, as (channel name, chrome.dll path)."""
    found: list[tuple[str, Path]] = []
    seen: set[str] = set()

    for channel, subdir in CHANNELS:
        for root in install_roots():
            dll = newest_dll_under(root / subdir / "Application")
            if dll is None:
                continue
            key = str(dll).lower()
            if key in seen:
                continue
            seen.add(key)
            found.append((channel, dll))

    return found


def choose_install(installs: list[tuple[str, Path]]) -> Path | None:
    """Ask which channel's chrome.dll to fetch symbols for. Returns None if the
    user quits or stdin is not a terminal."""
    if len(installs) == 1:
        channel, dll = installs[0]
        print(f"Found one Chrome channel: {channel}  {dll.parent.name}")
        print(f"  {dll}")
        return dll

    print(f"\n{len(installs)} Chrome release channels found:")
    for i, (channel, dll) in enumerate(installs, 1):
        print(f"  {i}) {channel:<7} {dll.parent.name}")
        print(f"      {dll}")

    if not sys.stdin.isatty():
        print("\nstdin is not a terminal; pass the chrome.dll path explicitly.")
        return None

    while True:
        try:
            answer = input(f"\nWhich channel's symbols do you want? [1-{len(installs)}, q to quit]: ")
        except EOFError:
            return None

        answer = answer.strip()
        if answer.lower() == "q":
            return None
        if answer.isdigit() and 1 <= int(answer) <= len(installs):
            return installs[int(answer) - 1][1]
        print(f"Enter a number between 1 and {len(installs)}, or q to quit.")


def download_pdb(dll_path: str, output_dir: str = ".") -> bool:
    dll_path = Path(dll_path)
    if not dll_path.is_file():
        print(f"Error: {dll_path} does not exist.")
        return False

    print(f"Extracting debug info from {dll_path.name}...")
    pdb_name, symbol_key = get_cv_info(str(dll_path))

    base_url = "https://chromium-browser-symsrv.commondatastorage.googleapis.com"
    url = f"{base_url}/{pdb_name}/{symbol_key}/{pdb_name}"

    out_path = Path(output_dir) / pdb_name
    print(f"PDB Name:   {pdb_name}")
    print(f"Symbol Key: {symbol_key}")
    print(f"Downloading from: {url}")

    def progress(count, block_size, total_size):
        downloaded = count * block_size
        if total_size > 0:
            percent = downloaded * 100 / total_size
            mb_dl = downloaded / (1024 * 1024)
            mb_total = total_size / (1024 * 1024)
            sys.stdout.write(f"\rProgress: {percent:.1f}% ({mb_dl:.1f}/{mb_total:.1f} MB)")
        else:
            sys.stdout.write(f"\rDownloaded: {downloaded / (1024 * 1024):.1f} MB")
        sys.stdout.flush()

    try:
        urllib.request.urlretrieve(url, out_path, reporthook=progress)
        print(f"\nSaved PDB to: {out_path.resolve()}")
        return True
    except urllib.error.HTTPError as e:
        print(f"\nFailed to download symbol file (HTTP {e.code}). Symbol might not be indexed.")
        return False


def main() -> int:
    args = [a for a in sys.argv[1:]]

    if any(a in ("-h", "--help", "/?") for a in args):
        print(
            "Usage: fetch-chrome-pdb.py [path\\to\\chrome.dll]\n"
            "\n"
            "Downloads the chrome.dll PDB matching a local Chrome install from the\n"
            "Chromium symbol server. With no path, every installed release channel\n"
            "(Stable/Beta/Dev/Canary) is listed so you can pick one.\n"
        )
        return 0

    paths = [a for a in args if not a.startswith("-")]
    if paths:
        chrome_dll_path = Path(paths[0])
    else:
        installs = find_chrome_installs()
        if not installs:
            print("Could not find a Chrome installation with chrome.dll. Pass the DLL path explicitly.")
            return 1
        chrome_dll_path = choose_install(installs)
        if chrome_dll_path is None:
            print("No channel selected.")
            return 0

    return 0 if download_pdb(str(chrome_dll_path)) else 1


if __name__ == "__main__":
    sys.exit(main())