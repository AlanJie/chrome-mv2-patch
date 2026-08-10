"""Fetch the stock, gate-bearing Chrome binary for MV2 signature derivation.

The rest of the toolkit (`fetch_symbols.py` -> `resolve_symbols.py` / `nm` ->
`derive_milestone.py`) all start from ONE artifact: the browser binary that
carries the inlined `IsExtensionAffected` gates --

    Windows x64    chrome.dll   (PE32+, container "pe")
    Windows x86    chrome.dll   (PE32,  container "pe32")
    Linux  x86-64  chrome       (ELF,   container "elf")

macOS is not a patcher target, so it is intentionally absent.

Google publishes offline installers only for each channel's CURRENT build, so
that is what this fetches by default -- the same consumer binary the patcher
runs against. `--version` falls back to the Chrome for Testing archive for an
older build; CfT is a portable, UNBRANDED build whose codegen can differ from
consumer stable, so a signature table derived from it must be re-verified
against the real install before shipping.

The binary is unwrapped out of the installer and dropped in `_scratch/`
(gitignored) under a clean, arch-tagged name, ready to hand to the next step:

    python scripts/fetch_chrome_binary.py                      # current stable, host arch
    python scripts/fetch_chrome_binary.py --platform linux
    python scripts/fetch_chrome_binary.py --platform win       # 32-bit chrome.dll
    python scripts/fetch_chrome_binary.py --channel beta
    python scripts/fetch_chrome_binary.py --version 152.0.7977.30
    python scripts/fetch_chrome_binary.py --list               # just print current versions

Pure stdlib, but extraction shells out to 7-Zip: the installer nests
(.exe -> updater.7z -> <ver>_chrome_installer.exe -> chrome.7z -> Chrome-bin/,
the beta .msi wraps the same offline .exe, and the .deb holds
data.tar.xz -> ./opt/google/chrome/chrome), so several layers open before the
binary appears.
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO / "_scratch"

CHANNELS = ("stable", "beta")

# The three patcher targets, keyed by the --platform value. Each carries the
# VersionHistory API platform id, the container tag derive_milestone.py stamps,
# the gate binary's filename, and how to recognise the right one on disk:
#   PE optional-header magic 0x20B (PE32+) / 0x10B (PE32) tells x64 from x86,
#   so a 32-bit fetch never grabs a stray 64-bit dll and vice-versa. The Linux
#   ELF is matched by class byte (2 == 64-bit) instead.
PLATFORMS = {
    "win64": {"api": "win64", "container": "pe",   "binary": "chrome.dll", "pe_magic": 0x20B, "tag": "win64",   "suffix": ".dll", "cft": "win64"},
    "win":   {"api": "win",   "container": "pe32", "binary": "chrome.dll", "pe_magic": 0x10B, "tag": "win32",   "suffix": ".dll", "cft": "win32"},
    "linux": {"api": "linux", "container": "elf",  "binary": "chrome",     "pe_magic": None,  "tag": "linux64", "suffix": "",     "cft": "linux64"},
}

# The channel's CURRENT-build offline installers. These URLs always serve the
# version the API reports for the channel, so no version appears in the link.
# Windows stable ships a self-extracting EXE; Windows beta only an enterprise
# MSI; Linux both channels a .deb -- all three carry the full Chrome-bin.
INSTALLERS = {
    "stable": {
        "win64": "https://dl.google.com/chrome/install/standalonesetup64.exe",
        "win":   "https://dl.google.com/chrome/install/standalonesetup.exe",
        "linux": "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
    },
    "beta": {
        "win64": "https://dl.google.com/tag/s/dl/chrome/install/beta/googlechromebetastandaloneenterprise64.msi",
        "win":   "https://dl.google.com/tag/s/dl/chrome/install/beta/googlechromebetastandaloneenterprise.msi",
        "linux": "https://dl.google.com/linux/direct/google-chrome-beta_current_amd64.deb",
    },
}

VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/{platform}"
    "/channels/{channel}/versions/all/releases?filter=endtime=none"
)

# The only official archive of version-pinned builds. It carries Chrome for
# Testing (unbranded), NOT consumer stable, so it is a --version fallback only.
CFT_ENDPOINT = (
    "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
)


def http_get(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(request, timeout=timeout)


def version_key(version):
    """Sort key comparing version parts numerically, so 7922.108 > 7922.99."""
    return tuple(int(part) if part.isdigit() else -1 for part in version.split("."))


def release_version(release):
    name = release.get("name", "")
    if "/versions/" in name:
        return name.split("/versions/")[1].split("/")[0]
    return ""


def current_version(api_platform, channel):
    """Highest version the channel is currently serving for this platform, or ""."""
    url = VERSION_API.format(platform=api_platform, channel=channel)
    try:
        with http_get(url, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as err:
        print(f"  warning: version lookup failed for {api_platform}/{channel}: {err}")
        return ""
    # A channel can serve several releases during a staged rollout, unordered;
    # take the highest version rather than trusting the first entry.
    versions = [
        v for v in (r.get("version") or release_version(r) for r in data.get("releases", [])) if v
    ]
    return max(versions, key=version_key) if versions else ""


def resolve_cft(version, cft_platform):
    """Resolve a pinned version to a CfT download for one platform.

    Returns (resolved_version, url, note) or None. Falls back to the newest
    archived build at or below the requested version when there is no exact one.
    """
    with http_get(CFT_ENDPOINT, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))
    archive = {}
    for entry in data.get("versions", []):
        ver = entry.get("version", "")
        if not ver:
            continue
        archive[ver] = {
            item["platform"]: item["url"]
            for item in entry.get("downloads", {}).get("chrome", [])
            if item.get("platform") and item.get("url")
        }

    if version in archive and archive[version].get(cft_platform):
        return version, archive[version][cft_platform], "exact"

    wanted = version_key(version)
    usable = [
        v for v in archive
        if all(p.isdigit() for p in v.split("."))
        and version_key(v) <= wanted
        and archive[v].get(cft_platform)
    ]
    if not usable:
        return None
    nearest = max(usable, key=version_key)
    return nearest, archive[nearest][cft_platform], f"nearest (<= {version})"


def human_size(num_bytes):
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024 or unit == "GB":
            return f"{num_bytes:.1f}{unit}" if unit != "B" else f"{num_bytes}B"
        num_bytes /= 1024


def _progress(done, total):
    if total > 0:
        sys.stdout.write(f"\r  {done * 100 // total:3d}%  {done >> 20}/{total >> 20} MiB")
    else:
        sys.stdout.write(f"\r  {done >> 20} MiB")
    sys.stdout.flush()


def download(url, dest):
    """Stream a URL to dest, resuming through a .part file. Returns dest or None."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    try:
        with http_get(url, timeout=180) as response:
            total = int(response.headers.get("Content-Length") or 0)
            done = 0
            with open(part, "wb") as handle:
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    handle.write(chunk)
                    done += len(chunk)
                    _progress(done, total)
        print()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as err:
        print(f"\n  download failed: {err}")
        if os.path.exists(part):
            os.remove(part)
        return None
    if total and os.path.getsize(part) != total:
        print(f"  download truncated ({os.path.getsize(part)} of {total} B)")
        os.remove(part)
        return None
    os.replace(part, dest)
    return dest


def find_seven_zip():
    """Locate 7-Zip, which unpacks the EXE/MSI/DEB installer chain."""
    found = shutil.which("7z") or shutil.which("7za")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        "/usr/bin/7z",
        "/usr/bin/7za",
        "/usr/local/bin/7z",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


# --- nested extraction ------------------------------------------------------
# Chrome installers wrap the payload several layers deep, so one 7-Zip pass
# leaves only containers. These rules drive the recursive unwrap; they mirror
# the set the original release fetcher used, minus the macOS pbzx handling.

# Intermediate containers worth opening but not keeping afterwards.
NESTED_SUFFIXES = (".tar.xz", ".tar.gz", ".tar.bz2", ".tar", ".7z", ".cpio", ".xz", ".gz")
NESTED_NAMES = ("payload", "updater.7z", "scripts")
NESTED_PATTERNS = ("_chrome_installer.exe",)

# The MSI stores the offline installer as a stream named
# "Binary.GoogleChromeInstaller" -- no extension, so it is caught by magic
# bytes. Restricted to extensionless files so a real chrome.dll/chrome is never
# mistaken for an archive and unpacked over.
CONTAINER_MAGIC = (
    b"MZ", b"MSCF", b"7z\xbc\xaf\x27\x1c", b"xar!",
    b"\xfd7zXZ", b"\x1f\x8b", b"PK\x03\x04",
)
KNOWN_CONTENT_EXTENSIONS = (
    ".exe", ".dll", ".sys", ".node", ".pak", ".dat", ".bin", ".so", ".dylib",
    ".png", ".jpg", ".svg", ".ico", ".icns", ".json", ".xml", ".txt", ".html",
    ".js", ".css", ".plist", ".strings", ".pb", ".manifest", ".msi", ".nib",
)


def has_container_magic(path):
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return False
    return any(head.startswith(magic) for magic in CONTAINER_MAGIC)


def is_nested_container(path, filename):
    lowered = filename.lower()
    if (
        lowered.endswith(NESTED_SUFFIXES)
        or lowered in NESTED_NAMES
        or any(lowered.endswith(pattern) for pattern in NESTED_PATTERNS)
    ):
        return True
    if os.path.splitext(lowered)[1] not in KNOWN_CONTENT_EXTENSIONS:
        return has_container_magic(path)
    return False


def unpack_nested(root, seven_zip, max_rounds=10):
    """Open container files left behind by the first extraction pass.

    Each round opens one nesting level; the deepest chain (Windows EXE) is four,
    so the cap only stops a pathological archive from looping.
    """
    for _ in range(max_rounds):
        opened = False
        for current_dir, _dirs, files in os.walk(root):
            for filename in files:
                path = os.path.join(current_dir, filename)
                if not is_nested_container(path, filename):
                    continue
                target = os.path.join(current_dir, filename.split(".")[0] + "_contents")
                os.makedirs(target, exist_ok=True)
                subprocess.run(
                    [seven_zip, "x", path, f"-o{target}", "-y"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                # Judge by what landed on disk, not the exit code.
                if any(os.scandir(target)):
                    os.remove(path)
                    opened = True
                else:
                    shutil.rmtree(target, ignore_errors=True)
        if not opened:
            return


def extract(archive_path, workdir, seven_zip):
    """Unpack the installer fully. Returns the extraction root."""
    dest = os.path.join(workdir, "unpacked")
    os.makedirs(dest, exist_ok=True)
    subprocess.run(
        [seven_zip, "x", archive_path, f"-o{dest}", "-y"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    unpack_nested(dest, seven_zip)
    return dest


# --- locating the gate binary ----------------------------------------------
def _pe_optional_magic(path):
    """PE optional-header magic (0x20B PE32+ / 0x10B PE32), or None."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x40)
            if head[:2] != b"MZ" or len(head) < 0x40:
                return None
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            handle.seek(e_lfanew)
            if handle.read(4) != b"PE\x00\x00":
                return None
            handle.seek(e_lfanew + 24)
            return struct.unpack("<H", handle.read(2))[0]
    except (OSError, struct.error):
        return None


def _is_elf64(path):
    try:
        with open(path, "rb") as handle:
            head = handle.read(5)
    except OSError:
        return False
    return head[:4] == b"\x7fELF" and len(head) == 5 and head[4] == 2


def locate_binary(root, spec):
    """Find the gate binary in an unpacked tree, matching name AND architecture.

    A shell-script launcher named `google-chrome` sits beside the Linux ELF, and
    an installer can carry stub DLLs; the magic/arch check skips both. Picks the
    largest match, which is always the real ~200 MB browser binary.
    """
    matches = []
    for current_dir, _dirs, files in os.walk(root):
        for filename in files:
            if filename.lower() != spec["binary"]:
                continue
            path = os.path.join(current_dir, filename)
            if spec["container"] == "elf":
                if _is_elf64(path):
                    matches.append(path)
            elif _pe_optional_magic(path) == spec["pe_magic"]:
                matches.append(path)
    return max(matches, key=os.path.getsize) if matches else None


# ---------------------------------------------------------------------------
def list_current():
    print(f"{'Platform':<10} {'Container':<10} {'Stable':<18} {'Beta':<18}")
    print("-" * 56)
    for key, spec in PLATFORMS.items():
        cells = [current_version(spec["api"], ch) or "-" for ch in CHANNELS]
        print(f"{key:<10} {spec['container']:<10} {cells[0]:<18} {cells[1]:<18}")


def fetch(platform, channel, version, out_dir, keep):
    spec = PLATFORMS[platform]
    seven_zip = find_seven_zip()
    if not seven_zip:
        print("error: 7-Zip not found (install it, or put 7z on PATH).", file=sys.stderr)
        return 1

    latest = current_version(spec["api"], channel)
    if latest:
        print(f"Current {channel} for {platform}: {latest}")

    # Decide the source: the channel's live installer for the current build, or
    # the Chrome for Testing archive for anything older.
    if version and version != latest:
        resolved = resolve_cft(version, spec["cft"])
        if not resolved:
            print(f"error: no Chrome for Testing build at or below {version} for {platform}.", file=sys.stderr)
            return 1
        fetch_version, url, note = resolved
        source = f"Chrome for Testing ({note})"
        print(f"Pinned {version} -> CfT {fetch_version}")
        print("  note: CfT is an UNBRANDED build; re-verify any derived table against the real install.")
    else:
        url = INSTALLERS[channel][platform]
        fetch_version = latest or (version or "current")
        source = f"{channel} installer"

    print(f"Source: {source}\n        {url}")

    workdir = os.path.join(out_dir, "_fetch_tmp")
    if os.path.isdir(workdir):
        shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)

    archive = os.path.join(workdir, os.path.basename(url.split("?")[0]))
    print(f"\nDownloading into {os.path.relpath(workdir)}/ ...")
    if not download(url, archive):
        shutil.rmtree(workdir, ignore_errors=True)
        return 1

    print(f"Extracting {os.path.basename(archive)} ...")
    tree = extract(archive, workdir, seven_zip)
    binary = locate_binary(tree, spec)
    if not binary:
        print(f"error: no {spec['binary']} ({spec['container']}) found in the extracted tree.", file=sys.stderr)
        if not keep:
            shutil.rmtree(workdir, ignore_errors=True)
        return 1

    dest = os.path.join(out_dir, f"chrome-{fetch_version}-{spec['tag']}{spec['suffix']}")
    shutil.copy2(binary, dest)
    size = os.path.getsize(dest)
    if not keep:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\nSaved {spec['container']} binary ({human_size(size)}):")
    print(f"  {os.path.relpath(dest)}")
    print("\nNext:")
    print(f"  python scripts/fetch_symbols.py {os.path.relpath(dest)}")
    if spec["container"] == "elf":
        print("  python scripts/dump_symtab.py _scratch/chrome.debug _scratch/syms.txt")
    else:
        print(f"  python scripts/resolve_symbols.py {os.path.relpath(dest)} --symdir _scratch --json _scratch/syms.json")
    print(f"  python scripts/derive_milestone.py {os.path.relpath(dest)} --symbols _scratch/syms.* --name <ver> --json")
    return 0


def default_platform():
    if sys.platform.startswith("win"):
        return "win64"
    if sys.platform.startswith("linux"):
        return "linux"
    return None  # macOS / other host: force an explicit --platform


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Fetch the stock gate-bearing Chrome binary (chrome.dll / chrome ELF) for MV2 derivation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--platform", choices=sorted(PLATFORMS), default=default_platform(),
        help="which gate binary to fetch (default: this host's)",
    )
    parser.add_argument(
        "--channel", choices=CHANNELS, default="stable",
        help="release channel (default: stable)",
    )
    parser.add_argument(
        "--version", metavar="X.Y.Z.W",
        help="pin a version; falls back to the Chrome for Testing archive when "
             "Google no longer serves that build as an installer",
    )
    parser.add_argument(
        "--out", metavar="DIR", default=str(DEFAULT_OUT),
        help="output directory (default: _scratch/)",
    )
    parser.add_argument(
        "--keep", action="store_true",
        help="keep the downloaded installer and extraction tree (default: remove, leave only the binary)",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="print the current version of every platform/channel and exit",
    )
    args = parser.parse_args(argv)
    if not args.list:
        if args.platform is None:
            parser.error("no default platform for this host; pass --platform win64|win|linux")
        if args.version and not all(p.isdigit() for p in args.version.split(".")):
            parser.error(f"--version expects a dotted numeric version, got {args.version!r}")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.list:
        list_current()
        return 0
    os.makedirs(args.out, exist_ok=True)
    return fetch(args.platform, args.channel, args.version, args.out, args.keep)


if __name__ == "__main__":
    sys.exit(main())
