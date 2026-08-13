"""macOS Mach-O regression tests for chrome-mv2-mac.sh, driven as a black box.

Builds a synthetic universal (fat) fixture in Python and exercises patch /
restore / check, host-aware slice selection, the arm64 --arm64 opt-in gate,
idempotency, decline paths, and backup metadata. The host CPU is pinned per
scenario via MV2_TEST_HOST_ARCH so results are independent of the CI runner's
own architecture. The loose-file target path skips bundle re-signing, so this
runs anywhere (no real Chrome, no codesign).
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _testutil as T

SCRIPT = str(T.REPO / "chrome-mv2-mac.sh")
# Default scenarios run as an Intel (x86_64) host: the x64 slice is the one that
# runs, so it is the default patch target - matching the pre-host-detection tests.
ENV = {"MV2_TEST_NO_ELEVATION": "1", "MV2_TEST_HOST_ARCH": "x86_64"}
ENV_ARM = {"MV2_TEST_NO_ELEVATION": "1", "MV2_TEST_HOST_ARCH": "arm64"}
A = T.Asserter()


def cmd(sub, target, sigs, *extra, env=ENV):
    return T.bash(SCRIPT, sub, target, sigs, *extra, env=env)


def nib(path, off):
    return T.byte_at(path, off) & 0x0F


SIGS = {"milestones": [
    {"name": "t-x64", "container": "macho-x64", "sites": [
        {"name": "gate-x64", "kind": "short", "jgRVA": "0x100000044", "jgOff": 4,
         "expectedMatches": 1, "sig": "837E50027F2F554889E5"}]},
    {"name": "t-arm64", "container": "macho-arm64", "sites": [
        {"name": "gate-arm64", "kind": "bcond", "jgRVA": "0x100000044", "jgOff": 4,
         "expectedMatches": 1, "sig": "1F0900718C000054"}]}]}


def main():
    tmp = Path(tempfile.mkdtemp(prefix="chrome-mv2-macos-tests-"))
    sigs = tmp / "sigs.json"
    sigs.write_text(json.dumps(SIGS))
    target = tmp / "fixture-fat"
    x64_jg, arm_jg = T.make_fat_macho(target)

    A.true(cmd("check", target, sigs).returncode == 0, "check parses the fat fixture")

    # On an x86_64 host the x64 slice is the default target; arm64 is the
    # non-host slice and stays stock WITHOUT --arm64.
    cmd("patch", target, sigs)
    A.eq(T.byte_at(target, x64_jg), 0xEB, "x64 short jg flipped by default (x64 host)")
    A.eq(nib(target, arm_jg), 0x0C, "arm64 left stock (GT) without --arm64")
    A.is_file(f"{target}.bak", "patch creates a backup")
    A.is_file(f"{target}.bak.meta", "patch creates backup metadata")

    # restore, then force BOTH with --arm64 (x64 host + arm64 forced)
    cmd("restore", target, sigs)
    A.eq(T.byte_at(target, x64_jg), 0x7F, "restore recovers x64 stock byte")
    cmd("patch", target, sigs, "--arm64")
    A.eq(T.byte_at(target, x64_jg), 0xEB, "x64 flipped with --arm64")
    A.eq(nib(target, arm_jg), 0x0E, "arm64 b.cond flipped GT(0xC)->AL(0xE) with --arm64")

    # idempotent rerun preserves bytes
    h1 = T.sha256(target)
    cmd("patch", target, sigs, "--arm64")
    A.eq(T.sha256(target), h1, "idempotent patch preserves bytes")

    # full restore -> both slices stock
    cmd("restore", target, sigs)
    A.eq(T.byte_at(target, x64_jg), 0x7F, "restore recovers x64 stock")
    A.eq(nib(target, arm_jg), 0x0C, "restore recovers arm64 stock (GT)")

    # --- host-aware default on Apple Silicon --------------------------------
    # On an arm64 host the arm64 slice is the default target. --yes pre-authorizes
    # the experimental confirmation; the x64 slice is the non-host slice and is
    # left stock even though no --arm64 was passed.
    ahost = tmp / "fixture-armhost"
    ax64_jg, aarm_jg = T.make_fat_macho(ahost)
    cmd("patch", ahost, sigs, "--yes", env=ENV_ARM)
    A.eq(nib(ahost, aarm_jg), 0x0E, "arm64 flipped by default on an arm64 host")
    A.eq(T.byte_at(ahost, ax64_jg), 0x7F, "x64 left stock on an arm64 host (non-host slice)")

    # arm64 host + --quiet WITHOUT --arm64: the experimental slice is declined and
    # x64 is non-host, so nothing is patched and no backup is created.
    aquiet = tmp / "fixture-armquiet"
    T.make_fat_macho(aquiet)
    A.true(cmd("patch", aquiet, sigs, env=ENV_ARM).returncode != 0,
           "arm64 host + --quiet without --arm64 patches nothing")
    A.true(not Path(f"{aquiet}.bak").exists(),
           "declined arm64 (quiet, unconfirmed) creates no backup")

    # refuse to overwrite unrelated modifications
    cmd("patch", target, sigs)
    T.copy(f"{target}.bak", target)
    T.poke(target, 8, 0x99)  # tamper the fat header region
    A.true(cmd("patch", target, sigs).returncode != 0, "patch must refuse unrelated modifications")
    T.copy(f"{target}.bak", target)

    # decline: signature present in neither slice, no backup created
    miss = tmp / "miss.json"
    miss.write_text(json.dumps({"milestones": [{"name": "m", "container": "macho-x64", "sites": [
        {"name": "absent", "kind": "short", "jgRVA": "0x100000044", "jgOff": 4,
         "expectedMatches": 1, "sig": "DEAD7FBEEF11"}]}]}))
    fresh = tmp / "fixture-fresh"
    T.make_fat_macho(fresh)
    A.true(cmd("patch", fresh, miss).returncode != 0, "declined patch fails")
    A.true(not Path(f"{fresh}.bak").exists(), "declined patch must not create a backup")

    # stale backup metadata rejected on restore
    cmd("patch", target, sigs)
    with open(f"{target}.bak.meta", "a") as f:
        f.write("sha256=bad\n")
    A.true(cmd("restore", target, sigs).returncode != 0, "tampered backup metadata should fail restore")

    print(f"macOS tests passed: {A.passed} assertions")


if __name__ == "__main__":
    main()

