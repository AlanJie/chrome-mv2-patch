"""Linux ELF regression tests for chrome-mv2.sh, driven as a black box.

Builds synthetic ELF fixtures in Python and exercises patch / restore / check,
backup + metadata, idempotency, decline paths, and the atomic-write race guard.
Run directly (`python scripts/test_linux.py`) or via `python scripts/run_tests.py`.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _testutil as T

SCRIPT = str(T.REPO / "chrome-mv2.sh")
ENV = {"MV2_TEST_NO_ELEVATION": "1"}
A = T.Asserter()


def patch(target, sigs, *extra):
    return T.bash(SCRIPT, "patch", target, sigs, *extra, env=ENV)


def restore(target, sigs, *extra):
    return T.bash(SCRIPT, "restore", target, sigs, *extra, env=ENV)


def check(target, sigs, *extra):
    return T.bash(SCRIPT, "check", target, sigs, *extra, env=ENV)


FULL_SIG = {"milestones": [{"name": "test-elf", "container": "elf", "sites": [
    {"name": "gate", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4,
     "expectedMatches": 1, "sig": "837E50027F2F554889E5"}]}]}


def main():
    tmp = Path(tempfile.mkdtemp(prefix="chrome-mv2-bash-tests-"))
    target = tmp / "full fixture chrome"
    sigs = tmp / "full signatures.json"
    T.make_elf(target, "837E50027F2F554889E5")
    sigs.write_text(json.dumps(FULL_SIG))

    A.true(patch(target, sigs).returncode == 0, "full synthetic patch should succeed")
    A.eq(T.byte_at(target, 0x144), 0xEB, "full patch should flip short jump")
    A.is_file(f"{target}.bak", "patch should create backup")
    A.is_file(f"{target}.bak.meta", "patch should create backup metadata")

    h1 = T.sha256(target)
    patch(target, sigs)
    A.eq(T.sha256(target), h1, "idempotent patch should preserve bytes")

    restore(target, sigs)
    A.eq(T.byte_at(target, 0x144), 0x7F, "restore should recover stock byte")

    # unrelated modification must be refused and preserved
    T.poke(target, 0x220, 0xA5)
    A.true(patch(target, sigs).returncode != 0, "patch must refuse unrelated modifications")
    A.eq(T.byte_at(target, 0x220), 0xA5, "refused patch must preserve unrelated bytes")
    T.copy(f"{target}.bak", target)

    # stale restore across a different build refuses unless forced
    patch(target, sigs)
    T.poke(target, 0x310, 0x22)
    A.true(restore(target, sigs).returncode != 0, "stale restore should fail closed")
    A.true(restore(target, sigs, "--force-restore").returncode == 0, "forced stale restore should succeed")
    A.eq(T.byte_at(target, 0x144), 0x7F, "forced stale restore should recover backup")

    # partial layout: declined by default, no backup; flips with --allow-partial
    partial = tmp / "partial fixture"
    psig = tmp / "partial signatures.json"
    T.make_elf(partial, "837E50027F2F554889E5", 0x33)
    psig.write_text(json.dumps({"milestones": [{"name": "partial", "container": "elf", "sites": [
        {"name": "present", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
        {"name": "missing", "kind": "short", "jgRVA": "0x00400084", "jgOff": 4, "expectedMatches": 1, "sig": "837A50027F34488B8A28"}]}]}))
    A.true(patch(partial, psig).returncode != 0, "partial layout should be declined")
    A.true(not Path(f"{partial}.bak").exists(), "declined partial must not create a backup")
    A.true(patch(partial, psig, "--allow-partial").returncode == 0, "explicit partial patch should succeed")
    A.eq(T.byte_at(partial, 0x144), 0xEB, "explicit partial patch should flip located gate")
    restore(partial, psig)
    A.eq(T.byte_at(partial, 0x144), 0x7F, "partial-mode backup should remain restorable")

    # ambiguous milestones (two tie): declined even with --allow-partial
    amb = tmp / "ambiguous fixture"
    asig = tmp / "ambiguous signatures.json"
    T.make_elf(amb, "837E50027F2F554889E5", 0x44)
    asig.write_text(json.dumps({"milestones": [
        {"name": "a", "container": "elf", "sites": [
            {"name": "present-a", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
            {"name": "missing-a", "kind": "short", "jgRVA": "0x00400084", "jgOff": 4, "expectedMatches": 1, "sig": "837A50027F34488B8A28"}]},
        {"name": "b", "container": "elf", "sites": [
            {"name": "present-b", "kind": "short", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837E50027F2F554889E5"},
            {"name": "missing-b", "kind": "short", "jgRVA": "0x004000C4", "jgOff": 4, "expectedMatches": 1, "sig": "837B50027F30488B8B28"}]}]}))
    A.true(patch(amb, asig, "--allow-partial").returncode != 0, "ambiguous layouts should be declined")

    # mixed near pair: check must fail
    mixed = tmp / "mixed near fixture"
    msig = tmp / "mixed signatures.json"
    T.make_elf(mixed, "837F50020FE98B000000488B", 0x55)
    msig.write_text(json.dumps({"milestones": [{"name": "near", "container": "elf", "sites": [
        {"name": "near-gate", "kind": "near", "jgRVA": "0x00400044", "jgOff": 4, "expectedMatches": 1, "sig": "837F50020F8F8B000000488B"}]}]}))
    A.true(check(mixed, msig).returncode != 0, "mixed near pair should fail check")

    # corrupt section table: check must fail
    bad = tmp / "bad elf"
    T.copy(f"{target}.bak", bad)
    with open(bad, "r+b") as f:
        f.seek(0x28)
        f.write(b"\xff\xff\xff\x7f\x00\x00\x00\x00")
    A.true(check(bad, sigs).returncode != 0, "out-of-bounds section table should fail")

    # tampered backup metadata: restore must fail
    with open(f"{target}.bak.meta", "a") as f:
        f.write("sha256=bad\n")
    A.true(restore(target, sigs).returncode != 0, "tampered backup metadata should fail restore")

    # atomic-write race guard (white-box via the script's own function)
    rt, rs = tmp / "race target", tmp / "race source"
    rt.write_text("old")
    rs.write_text("new")
    race = ('set -euo pipefail; export MV2_TEST_LIBRARY_ONLY=1; source "$1"; init_colors; '
            'write_target "$2" "$3" "$(printf wrong)"')
    A.true(T.run([T.BASH, "-c", race, "_", T.posix(SCRIPT), T.posix(rt), T.posix(rs)]).returncode != 0,
           "atomic writer should reject a changed target")
    A.eq(rt.read_text(), "old", "race rejection must preserve target bytes")

    print(f"Bash tests passed: {A.passed} assertions")


if __name__ == "__main__":
    main()

