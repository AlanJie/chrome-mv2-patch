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


def find_chrome_dll() -> Path | None:
    """Locate a Chrome installation and return the first chrome.dll found."""
    search_roots = []

    program_files = os.environ.get("ProgramFiles")
    if program_files:
        search_roots.append(Path(program_files) / "Google" / "Chrome" / "Application")

    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if program_files_x86:
        search_roots.append(Path(program_files_x86) / "Google" / "Chrome" / "Application")

    search_roots.extend(
        [
            Path(r"C:\Program Files\Google\Chrome\Application"),
            Path(r"C:\Program Files (x86)\Google\Chrome\Application"),
        ]
    )

    for root in search_roots:
        if not root.exists():
            continue

        version_dirs = sorted(
            [p for p in root.iterdir() if p.is_dir() and (p / "chrome.dll").is_file()],
            key=lambda p: p.name,
            reverse=True,
        )
        if version_dirs:
            return version_dirs[0] / "chrome.dll"

        for dll_path in root.rglob("chrome.dll"):
            if dll_path.is_file():
                return dll_path

    return None


def download_pdb(dll_path: str, output_dir: str = "."):
    dll_path = Path(dll_path)
    if not dll_path.is_file():
        print(f"Error: {dll_path} does not exist.")
        return

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
    except urllib.error.HTTPError as e:
        print(f"\nFailed to download symbol file (HTTP {e.code}). Symbol might not be indexed.")


if __name__ == "__main__":
    chrome_dll_path = None
    if len(sys.argv) > 1:
        chrome_dll_path = Path(sys.argv[1])
    else:
        chrome_dll_path = find_chrome_dll()

    if chrome_dll_path is None:
        print("Could not find a Chrome installation with chrome.dll. Pass the DLL path explicitly.")
        sys.exit(1)

    download_pdb(str(chrome_dll_path))