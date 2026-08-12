#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
script="$repo/chrome-mv2.sh"
tmp=$(mktemp -d "/tmp/chrome mv2 bash tests.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
passed=0

ok() { passed=$((passed + 1)); }
fail() { echo "ASSERTION FAILED: $*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "$3 (got '$1', expected '$2')"; ok; }
assert_file() { [[ -f "$1" ]] || fail "$2"; ok; }
assert_fail() { if "$@" >/dev/null 2>&1; then fail "command unexpectedly succeeded: $*"; fi; ok; }

make_elf() {
    local path="$1" sig_hex="$2" build_byte="${3:-11}"
    python3 - "$path" "$sig_hex" "$build_byte" <<'PY'
import struct, sys
path, sig_hex, build_byte = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
buf = bytearray(0x700)
ident = bytearray(b'\x7fELF' + bytes([2,1,1,0]) + bytes(8))
hdr = struct.pack('<16sHHIQQQIHHHHHH', bytes(ident), 2, 62, 1, 0, 0, 0x500, 0, 64, 0, 0, 64, 4, 3)
buf[:64] = hdr
text = 0x100
sig = bytes.fromhex(sig_hex)
buf[text + 0x40:text + 0x40 + len(sig)] = sig
note = struct.pack('<III', 4, 20, 3) + b'GNU\0' + bytes([build_byte]) * 20
buf[0x300:0x300+len(note)] = note
names = b'\0.text\0.note.gnu.build-id\0.shstrtab\0'
buf[0x400:0x400+len(names)] = names
sections = [
    (0,0,0,0,0,0,0,0,0,0),
    (1,1,6,0x400000,0x100,0x100,0,0,16,0),
    (7,7,2,0,0x300,len(note),0,0,4,0),
    (26,3,0,0,0x400,len(names),0,0,1,0),
]
for i, sh in enumerate(sections):
    buf[0x500+i*64:0x500+(i+1)*64] = struct.pack('<IIQQQQIIQQ', *sh)
with open(path, 'wb') as f: f.write(buf)
PY
}

write_full_sigs() {
    local path="$1"
    printf '%s\n' '{"milestones":[{"name":"test-elf","container":"elf","sites":[{"name":"gate","kind":"short","jgRVA":"0x00400044","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5"}]}]}' > "$path"
}

target="$tmp/full fixture chrome"
sigs="$tmp/full signatures.json"
make_elf "$target" 837E50027F2F554889E5
write_full_sigs "$sigs"

MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$target" --signatures "$sigs" --quiet >/dev/null
byte=$(od -A n -t x1 -j $((0x144)) -N 1 "$target" | tr -d ' \n')
assert_eq "$byte" eb 'full patch should flip short jump'
assert_file "$target.bak" 'patch should create backup'
assert_file "$target.bak.meta" 'patch should create backup metadata'
hash1=$(sha256sum "$target" | awk '{print $1}')
MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$target" --signatures "$sigs" --quiet >/dev/null
hash2=$(sha256sum "$target" | awk '{print $1}')
assert_eq "$hash2" "$hash1" 'idempotent patch should preserve bytes'
MV2_TEST_NO_ELEVATION=1 bash "$script" restore "$target" --signatures "$sigs" --quiet >/dev/null
byte=$(od -A n -t x1 -j $((0x144)) -N 1 "$target" | tr -d ' \n')
assert_eq "$byte" 7f 'restore should recover stock byte'

printf '\xa5' | dd of="$target" bs=1 seek=$((0x220)) count=1 conv=notrunc status=none
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$target" --signatures "$sigs" --quiet
byte=$(od -A n -t x1 -j $((0x220)) -N 1 "$target" | tr -d ' \n')
assert_eq "$byte" a5 'refused patch must preserve unrelated modifications'
cp -- "$target.bak" "$target"

MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$target" --signatures "$sigs" --quiet >/dev/null
printf '\x22' | dd of="$target" bs=1 seek=$((0x310)) count=1 conv=notrunc status=none
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" restore "$target" --signatures "$sigs" --quiet
MV2_TEST_NO_ELEVATION=1 bash "$script" restore "$target" --signatures "$sigs" --quiet --force-restore >/dev/null
byte=$(od -A n -t x1 -j $((0x144)) -N 1 "$target" | tr -d ' \n')
assert_eq "$byte" 7f 'forced stale restore should recover backup'

partial="$tmp/partial fixture"
partial_sigs="$tmp/partial signatures.json"
make_elf "$partial" 837E50027F2F554889E5 33
printf '%s\n' '{"milestones":[{"name":"partial","container":"elf","sites":[{"name":"present","kind":"short","jgRVA":"0x00400044","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5"},{"name":"missing","kind":"short","jgRVA":"0x00400084","jgOff":4,"expectedMatches":1,"sig":"837A50027F34488B8A28"}]}]}' > "$partial_sigs"
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$partial" --signatures "$partial_sigs" --quiet
[[ ! -e "$partial.bak" ]] || fail 'declined partial patch must not create a backup'
ok
MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$partial" --signatures "$partial_sigs" --quiet --allow-partial >/dev/null
byte=$(od -A n -t x1 -j $((0x144)) -N 1 "$partial" | tr -d ' \n')
assert_eq "$byte" eb 'explicit partial patch should flip located gate'
MV2_TEST_NO_ELEVATION=1 bash "$script" restore "$partial" --signatures "$partial_sigs" --quiet >/dev/null
byte=$(od -A n -t x1 -j $((0x144)) -N 1 "$partial" | tr -d ' \n')
assert_eq "$byte" 7f 'partial-mode backup should remain restorable'

ambiguous="$tmp/ambiguous fixture"
ambiguous_sigs="$tmp/ambiguous signatures.json"
make_elf "$ambiguous" 837E50027F2F554889E5 44
printf '%s\n' '{"milestones":[{"name":"a","container":"elf","sites":[{"name":"present-a","kind":"short","jgRVA":"0x00400044","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5"},{"name":"missing-a","kind":"short","jgRVA":"0x00400084","jgOff":4,"expectedMatches":1,"sig":"837A50027F34488B8A28"}]},{"name":"b","container":"elf","sites":[{"name":"present-b","kind":"short","jgRVA":"0x00400044","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5"},{"name":"missing-b","kind":"short","jgRVA":"0x004000C4","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B28"}]}]}' > "$ambiguous_sigs"
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" patch "$ambiguous" --signatures "$ambiguous_sigs" --quiet --allow-partial

mixed="$tmp/mixed near fixture"
mixed_sigs="$tmp/mixed signatures.json"
make_elf "$mixed" 837F50020FE98B000000488B 55
printf '%s\n' '{"milestones":[{"name":"near","container":"elf","sites":[{"name":"near-gate","kind":"near","jgRVA":"0x00400044","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8B000000488B"}]}]}' > "$mixed_sigs"
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" check "$mixed" --signatures "$mixed_sigs" --quiet

bad="$tmp/bad elf"
cp "$target.bak" "$bad"
printf '\xff\xff\xff\x7f\x00\x00\x00\x00' | dd of="$bad" bs=1 seek=$((0x28)) count=8 conv=notrunc status=none
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" check "$bad" --signatures "$sigs" --quiet

printf 'sha256=bad\n' >> "$target.bak.meta"
assert_fail env MV2_TEST_NO_ELEVATION=1 bash "$script" restore "$target" --signatures "$sigs" --quiet

race_target="$tmp/race target"
race_source="$tmp/race source"
printf 'old' > "$race_target"
printf 'new' > "$race_source"
assert_fail bash -c 'set -euo pipefail; export MV2_TEST_LIBRARY_ONLY=1; source "$1"; init_colors; write_target "$2" "$3" "$(printf wrong)"' _ "$script" "$race_target" "$race_source"
assert_eq "$(<"$race_target")" old 'race rejection must preserve target bytes'

echo "Bash tests passed: $passed assertions"
