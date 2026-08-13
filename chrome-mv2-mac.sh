#!/usr/bin/env bash
# ============================================================================
# Google Chrome Manifest V2 Patcher - standalone bash script for macOS
#
# Self-contained macOS implementation for the universal (fat) Mach-O
# "Google Chrome Framework" inside Google Chrome.app. Re-enables Manifest V2
# extension support by flipping the inlined IsExtensionAffected manifest-version
# checks in BOTH CPU slices:
#   - x86_64 (Intel): the same x86 cmp/jg flip as Linux/Windows
#       JG_SHORT  0x7F disp8      -> 0xEB disp8       (jmp short, same disp8)
#       JG_NEAR   0x0F 0x8F disp32-> 0x90 0xE9 disp32 (nop ; jmp near, same disp32)
#   - arm64 (Apple Silicon): arm64 has no cmp/jg; the mv>=3 early-out is a
#       cmp w,#2 ; b.gt not_affected, and the flip rewrites ONLY the branch
#       condition GT(0xC) -> AL(0xE), preserving the imm19 displacement so it
#       still targets the same not-affected label (a direction-only edit).
#       B.cond word = 0x54000000 | (imm19<<5) | cond; cond is the low nibble of
#       the little-endian byte0, so one byte changes (b0 = (b0 & 0xF0)|0x0E).
#
# ARCHITECTURE: the framework is a universal (fat) Mach-O, but only ONE slice
# ever executes - the one matching this Mac's CPU. The script detects the host
# CPU (Apple Silicon vs Intel) and by DEFAULT patches only that slice; touching
# the other slice would edit code that never runs. --arm64 forces the arm64
# slice into scope on any host (e.g. an Intel box preparing a build for ASi).
#
# EXPERIMENTAL arm64: macOS publishes no symbols, so the arm64 table is derived
# structurally and is NOT yet runtime-verified. On an Apple Silicon host the
# arm64 slice is the one that runs, so it is patched by default but behind a
# one-time interactive confirmation (pre-authorized by --arm64 or --yes; a
# --quiet run without --arm64 declines it). It declines rather than guesses on
# any layout mismatch.
#
# CODE SIGNING: any byte edit invalidates the Mach-O signature; on Apple Silicon
# an invalid/absent signature is killed on launch. After flipping bytes this
# script ad-hoc re-signs INSIDE-OUT (framework bundle, then the .app) preserving
# entitlements, verifies the signature, and only then atomically replaces the
# target. It uses /usr/bin/codesign, which ships with macOS (NOT the Xcode
# Command Line Tools); a launchable result requires it, and its absence declines.
#
# CARDINAL RULE: never delete or blank a call and never invent control flow -
# only flip the direction of an existing branch to its EXISTING target.
#
# Usage:
#   bash chrome-mv2-mac.sh [patch|restore|check] [path] [--arm64] [--yes] [--quiet]
#
# By default the slice matching this Mac's CPU is patched. On Apple Silicon that
# is the (experimental) arm64 slice, confirmed interactively unless --arm64/--yes.
#
# Requirements: bash 3.2+ (stock macOS), python3 ONLY for --signatures JSON,
#   codesign (at /usr/bin/codesign, built into macOS - no Xcode CLT needed) for
#   patch/restore of a launchable app, plus coreutils present on
#   macOS: od, dd, shasum, stat, grep, mktemp, cp, mv, sync, pgrep.
# ============================================================================

set -euo pipefail

readonly APP_VERSION="1.3.0"

# ============================================================================
# Embedded Mach-O signature tables (pre-tokenized so the default path needs no
# python3/JSON parser - stock macOS ships neither a usable python3 nor jq).
#
# Records, one per line, pipe-delimited:
#   M|<milestone name>|<container>
#   S|<site name>|<kind>|<jgRVA>|<jgOff>|<expectedMatches>|<sig hex>
# container: macho-x64 | macho-arm64
# kind: short (7F->EB) | near (0F8F->90E9) | bcond (arm64 B.cond GT->AL)
# jgRVA: hex RVA of the jg/b.cond opcode in the reference slice (fast-path probe)
# jgOff: byte index of the jump opcode within sig
# sig: hex bytes, jump opcode included at jgOff
#
# Keep in sync with signatures.json (the canonical table). See mv2-reversing.md.
# ============================================================================
readonly EMBEDDED_SIGNATURES='
M|151-macos-x64|macho-x64
S|StandardManagementPolicyProvider::MustRemainDisabled|short|0x01B652F7|3|1|83FA027F5B8B493083F80175494531F683F905740583F90A75
S|ManifestV2Handler::OnExtensionSystemReady|short|0x030822AA|4|1|837950027F2D488B91280200008B423080B90802000000750C
S|ManifestV2Handler::ShouldBlockExtensionEnable|short|0x04727A9D|3|1|83FA027F298B493083F801751783F9050F95C283F90A0F95C0
S|ManifestV2Handler::IsExtensionAffected|short|0x071364A4|4|1|837E50027F2F554889E5488B8E280200008B413080BE080200
S|ManifestV2Handler::ShouldBlockExtensionInstallation|short|0x071364F7|3|1|83FE027F1F83FA01751083F9050F95C283F90A0F95C020D05D
S|ManifestV2Handler::MaybeReEnableExtension|short|0x07136608|4|1|837B50027F30488B8B280200008B413080BB08020000007508
S|StandardManagementPolicyProvider::UserMayInstall|near|0x07B4CFF9|3|1|83FA020F8FA40000008B493083F8010F850F02000083F9050F848F00
E
M|151-macos-arm64|macho-arm64
S|ManifestV2Handler::OnExtensionSystemReady|bcond|0x0178A5E8|4|1|1F090071AC0100542A1541F9483140B929214839C9000037496940B93F050071
S|StandardManagementPolicyProvider::MustRemainDisabled|bcond|0x021EFD80|4|1|5F0900716C040054293140B91F05007181030054140080523F15007160000054
S|ManifestV2Handler::ShouldBlockExtensionEnable|bcond|0x03ED7910|4|1|5F090071CC010054293140B91F050071E10000543F15007124194A7AE0079F1A
S|ManifestV2Handler::IsExtensionAffected|bcond|0x0642852C|4|1|1F090071CC010054291441F9283140B92A204839CA000037296940B93F050071
S|ManifestV2Handler::ShouldBlockExtensionInstallation|bcond|0x06428570|4|1|3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6
S|ManifestV2Handler::MaybeReEnableExtension|bcond|0x064286A8|4|1|1F090071AC010054691641F9283140B96A224839CA000037296940B93F050071
S|StandardManagementPolicyProvider::UserMayInstall|bcond|0x06DB8584|4|1|5F090071EC000054293140B91F050071210F00543F15007124194A7AC1060054
E
'

# Runtime tables (parallel indexed arrays; bash-3.2 safe - no assoc arrays or
# namerefs). ALL_SITES holds every site prefixed with its milestone index so a
# milestone's sites are recovered by filtering, avoiding dynamic array names.
MILESTONE_NAMES=()
MILESTONE_CONTAINERS=()
ALL_SITES=()          # "idx|name|kind|jgRVA|jgOff|expectedMatches|sig"
NUM_MILESTONES=0

# ============================================================================
# Console colour + tags
# ============================================================================
C_RESET="" C_RED="" C_GRN="" C_YEL="" C_CYN="" C_DIM="" C_BOLD=""
TAG_OK="" TAG_ERR="" TAG_INFO="" TAG_WARN="" TAG_SUCCESS="" TAG_WARNING=""

init_colors() {
    local vt=false
    if [[ -t 1 ]]; then vt=true; fi
    if [[ -n "${FORCE_COLOR:-}" ]]; then vt=true; fi
    if [[ -n "${NO_COLOR:-}" ]]; then vt=false; fi
    if $vt; then
        C_RESET=$'\e[0m'  C_RED=$'\e[91m'  C_GRN=$'\e[92m'
        C_YEL=$'\e[93m'   C_CYN=$'\e[96m'  C_DIM=$'\e[90m'  C_BOLD=$'\e[1m'
    fi
    TAG_OK="${C_GRN}[+]${C_RESET}"
    TAG_ERR="${C_RED}[-]${C_RESET}"
    TAG_INFO="${C_CYN}[*]${C_RESET}"
    TAG_WARN="${C_YEL}[!]${C_RESET}"
    TAG_SUCCESS="${C_BOLD}${C_GRN}[SUCCESS]${C_RESET}"
    TAG_WARNING="${C_BOLD}${C_YEL}[WARNING]${C_RESET}"
}

infof()    { echo "${TAG_INFO} $*"; }
okf()      { echo "${TAG_OK} $*"; }
warnf()    { echo "${TAG_WARN} $*"; }
errf()     { echo "${TAG_ERR} $*"; }
successf() { echo "${TAG_SUCCESS} $*"; }
rule()     { echo "${C_CYN}==========================================================${C_RESET}"; }

banner() {
    rule
    echo "${C_BOLD}       Google Chrome Manifest V2 Patcher (macOS)           ${C_RESET}"
    echo "${C_DIM}                    v${APP_VERSION}                       ${C_RESET}"
    rule
}

# ============================================================================
# Binary read helpers - LE/BE integers and hex from a file at an offset, via od.
# ============================================================================
read_u16_le() { local b; b=$(od -A n -t x1 -j "$2" -N 2 "$1" | tr -d ' \n'); echo $(( 16#${b:2:2}${b:0:2} )); }
read_u32_le() { local b; b=$(od -A n -t x1 -j "$2" -N 4 "$1" | tr -d ' \n'); echo $(( 16#${b:6:2}${b:4:2}${b:2:2}${b:0:2} )); }
read_u32_be() { local b; b=$(od -A n -t x1 -j "$2" -N 4 "$1" | tr -d ' \n'); echo $(( 16#${b:0:2}${b:2:2}${b:4:2}${b:6:2} )); }
read_u64_le() { local b; b=$(od -A n -t x1 -j "$2" -N 8 "$1" | tr -d ' \n'); echo $(( 16#${b:14:2}${b:12:2}${b:10:2}${b:8:2}${b:6:2}${b:4:2}${b:2:2}${b:0:2} )); }
read_u64_be() { local b; b=$(od -A n -t x1 -j "$2" -N 8 "$1" | tr -d ' \n'); echo $(( 16#${b:0:2}${b:2:2}${b:4:2}${b:6:2}${b:8:2}${b:10:2}${b:12:2}${b:14:2} )); }
read_bytes_hex() { od -A n -v -t x1 -j "$2" -N "$3" "$1" | tr -d ' \n' | tr 'a-f' 'A-F'; }
read_byte() { local h; h=$(od -A n -t x1 -j "$2" -N 1 "$1" | tr -d ' \n'); echo $(( 16#$h )); }

file_size() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null; }
file_sha256() { shasum -a 256 -- "$1" 2>/dev/null | awk '{print $1}' || sha256sum -- "$1" | awk '{print $1}'; }

range_within_file() {
    local offset="$1" count="$2" size="$3"
    (( offset >= 0 && count >= 0 && offset <= size && count <= size - offset ))
}

# ============================================================================
# Mach-O / fat parser. Populates one entry per CPU slice in parallel arrays.
# section_64.offset is ALREADY the slice-relative file offset, so the absolute
# file offset of __text is slice_base + section.offset (NO vmaddr delta - the
# opposite of ELF). LC_UUID is the build identity (stable across the flip AND
# the ad-hoc re-sign, unlike the whole-file hash).
# ============================================================================
MH_MAGIC_64=4277009103          # 0xFEEDFACF (thin 64-bit, little-endian on disk)
FAT_MAGIC=3405691582            # 0xCAFEBABE (fat, big-endian, 32-bit fat_arch)
FAT_MAGIC_64=3405691583         # 0xCAFEBABF (fat, big-endian, 64-bit fat_arch)
CPU_X86_64=16777223             # 0x01000007
CPU_ARM64=16777228              # 0x0100000C
LC_SEGMENT_64=25                # 0x19
LC_UUID=27                      # 0x1B

SLICE_CONTAINER=()
SLICE_BASE=()
SLICE_SIZE=()
SLICE_TVADDR=()
SLICE_TRAW=()
SLICE_TSIZE=()
SLICE_UUID=()
NUM_SLICES=0

# Parse one thin Mach-O slice at file offset $2; append to SLICE_* on success.
parse_thin_slice() {
    local file="$1" base="$2" declared_size="${3:-0}"
    local fsize; fsize=$(file_size "$file")
    if ! range_within_file "$base" 32 "$fsize"; then return 1; fi
    local magic; magic=$(read_u32_le "$file" "$base")
    if (( magic != MH_MAGIC_64 )); then return 1; fi   # skip 32-bit / foreign slice

    local cputype ncmds container
    cputype=$(read_u32_le "$file" $(( base + 4 )))
    ncmds=$(read_u32_le "$file" $(( base + 16 )))
    if (( cputype == CPU_X86_64 )); then container="macho-x64"
    elif (( cputype == CPU_ARM64 )); then container="macho-arm64"
    else return 1; fi

    local p=$(( base + 32 )) i cmd cmdsize
    local t_addr="" t_off="" t_size="" uuid=""
    for (( i = 0; i < ncmds; i++ )); do
        if ! range_within_file "$p" 8 "$fsize"; then return 1; fi
        cmd=$(read_u32_le "$file" "$p")
        cmdsize=$(read_u32_le "$file" $(( p + 4 )))
        if (( cmdsize < 8 )) || ! range_within_file "$p" "$cmdsize" "$fsize"; then return 1; fi
        if (( cmd == LC_SEGMENT_64 )); then
            local segname7; segname7=$(read_bytes_hex "$file" $(( p + 8 )) 7)
            if [[ "$segname7" == "5F5F5445585400" ]]; then   # "__TEXT\0"
                local nsects; nsects=$(read_u32_le "$file" $(( p + 64 )))
                local sec=$(( p + 72 )) s sname7
                for (( s = 0; s < nsects; s++ )); do
                    sname7=$(read_bytes_hex "$file" "$sec" 7)
                    if [[ "$sname7" == "5F5F7465787400" ]]; then   # "__text\0"
                        t_addr=$(read_u64_le "$file" $(( sec + 32 )))
                        t_size=$(read_u64_le "$file" $(( sec + 40 )))
                        t_off=$(read_u32_le "$file" $(( sec + 48 )))
                    fi
                    sec=$(( sec + 80 ))
                done
            fi
        elif (( cmd == LC_UUID )); then
            uuid=$(read_bytes_hex "$file" $(( p + 8 )) 16)
        fi
        p=$(( p + cmdsize ))
    done

    if [[ -z "$t_addr" ]]; then return 1; fi
    local raw=$(( base + t_off ))
    if ! range_within_file "$raw" "$t_size" "$fsize"; then return 1; fi

    SLICE_CONTAINER+=("$container")
    SLICE_BASE+=("$base")
    SLICE_SIZE+=("$declared_size")
    SLICE_TVADDR+=("$t_addr")
    SLICE_TRAW+=("$raw")
    SLICE_TSIZE+=("$t_size")
    SLICE_UUID+=("$uuid")
    NUM_SLICES=$(( NUM_SLICES + 1 ))
    return 0
}

parse_macho() {
    local file="$1"
    SLICE_CONTAINER=(); SLICE_BASE=(); SLICE_SIZE=()
    SLICE_TVADDR=(); SLICE_TRAW=(); SLICE_TSIZE=(); SLICE_UUID=()
    NUM_SLICES=0

    local fsize; fsize=$(file_size "$file")
    if (( fsize < 32 )); then errf "Not a Mach-O: file too small (${fsize} bytes)."; return 1; fi

    local be le
    be=$(read_u32_be "$file" 0)
    le=$(read_u32_le "$file" 0)

    if (( be == FAT_MAGIC || be == FAT_MAGIC_64 )); then
        local is64=0; (( be == FAT_MAGIC_64 )) && is64=1
        local nfat; nfat=$(read_u32_be "$file" 4)
        if (( nfat < 1 || nfat > 32 )); then errf "Implausible fat arch count (${nfat})."; return 1; fi
        local entry off i soff ssize
        (( is64 )) && entry=32 || entry=20
        off=8
        for (( i = 0; i < nfat; i++ )); do
            if ! range_within_file "$off" "$entry" "$fsize"; then break; fi
            if (( is64 )); then
                soff=$(read_u64_be "$file" $(( off + 8 )))
                ssize=$(read_u64_be "$file" $(( off + 16 )))
            else
                soff=$(read_u32_be "$file" $(( off + 8 )))
                ssize=$(read_u32_be "$file" $(( off + 12 )))
            fi
            off=$(( off + entry ))
            parse_thin_slice "$file" "$soff" "$ssize" || true   # skip slices we do not handle
        done
    elif (( le == MH_MAGIC_64 )); then
        parse_thin_slice "$file" 0 "$fsize" || true
    else
        errf "Not a Mach-O (fat magic 0x$(printf '%08X' "$be"), thin magic 0x$(printf '%08X' "$le"))."
        return 1
    fi

    if (( NUM_SLICES == 0 )); then
        errf "No supported 64-bit Mach-O slice (x86_64 / arm64) found."
        return 1
    fi

    local j desc=""
    for (( j = 0; j < NUM_SLICES; j++ )); do
        desc="${desc}${desc:+, }${SLICE_CONTAINER[$j]} (.text 0x$(printf '%X' "${SLICE_TSIZE[$j]}")B)"
    done
    okf "Mach-O parsed: ${NUM_SLICES} slice(s): ${desc}"
    return 0
}

# ============================================================================
# Signature loading. Default: the pre-tokenized EMBEDDED_SIGNATURES (no python3
# or JSON parser needed). An explicit --signatures FILE, or a signatures.json
# beside the script, is JSON and is tokenized via python3 into the same records.
# ============================================================================
readonly SIGNATURES_FILE="signatures.json"
SIGNATURES_OVERRIDE=""

get_signatures_path() {
    if [[ -n "$SIGNATURES_OVERRIDE" ]]; then
        if [[ ! -f "$SIGNATURES_OVERRIDE" ]]; then return 2; fi
        echo "$SIGNATURES_OVERRIDE"; return 0
    fi
    local script_dir
    script_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    if [[ -f "${script_dir}/${SIGNATURES_FILE}" ]]; then
        echo "${script_dir}/${SIGNATURES_FILE}"; return 0
    fi
    return 1
}

# JSON -> pipe-tokenized records (M|.. / S|..). Validates macho containers and
# short/near/bcond kinds and the stock opcode at jgOff. Requires python3.
json_to_tokens() {
    python3 -c '
import json, re, sys
def clean(v, label):
    if not isinstance(v, str) or not v.strip() or any(c in v for c in "\r\n\t|"):
        raise ValueError(label + " empty or has a reserved character")
    return v
doc = json.load(sys.stdin)
ms = doc.get("milestones")
if not isinstance(ms, list) or not ms:
    raise ValueError("no milestones")
seen = set()
for m in ms:
    name = clean(m.get("name"), "milestone name")
    if name in seen: raise ValueError("duplicate milestone " + name)
    seen.add(name)
    container = m.get("container")
    if container not in ("macho-x64", "macho-arm64"):
        continue  # this script patches only Mach-O; skip pe/pe32/elf tables
    sites = m.get("sites")
    if not isinstance(sites, list) or not sites:
        raise ValueError("milestone %s has no sites" % name)
    print("M|%s|%s" % (name, container))
    sn = set()
    for s in sites:
        snm = clean(s.get("name"), "site name")
        if snm in sn: raise ValueError("dup site %s in %s" % (snm, name))
        sn.add(snm)
        kind = s.get("kind")
        if kind not in ("short", "near", "bcond"):
            raise ValueError("bad kind in %s/%s" % (name, snm))
        rva = s.get("jgRVA")
        if not isinstance(rva, str) or not re.fullmatch(r"0[xX][0-9A-Fa-f]+", rva):
            raise ValueError("bad jgRVA in %s/%s" % (name, snm))
        off = s.get("jgOff"); exp = s.get("expectedMatches"); sig = s.get("sig")
        if not isinstance(off, int) or isinstance(off, bool) or off < 0:
            raise ValueError("bad jgOff in %s/%s" % (name, snm))
        if not isinstance(exp, int) or isinstance(exp, bool) or exp < 1:
            raise ValueError("bad expectedMatches in %s/%s" % (name, snm))
        if not isinstance(sig, str) or not sig or len(sig) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", sig):
            raise ValueError("bad sig in %s/%s" % (name, snm))
        raw = bytes.fromhex(sig)
        need = {"short": 2, "near": 6, "bcond": 4}[kind]
        if off + need > len(raw):
            raise ValueError("jump past sig in %s/%s" % (name, snm))
        if kind == "short" and raw[off] != 0x7F:
            raise ValueError("jgOff not 7F in %s/%s" % (name, snm))
        if kind == "near" and raw[off:off+2] != b"\x0f\x8f":
            raise ValueError("jgOff not 0F8F in %s/%s" % (name, snm))
        if kind == "bcond":
            w = int.from_bytes(raw[off:off+4], "little")
            if (w & 0xFF000010) != 0x54000000 or (w & 0xF) != 0x0C:
                raise ValueError("jgOff not a stock b.gt (GT) in %s/%s" % (name, snm))
        print("S|%s|%s|%s|%d|%d|%s" % (snm, kind, rva, off, exp, sig.upper()))
    print("E")
' 2>&1
}

populate_from_tokens() {
    MILESTONE_NAMES=(); MILESTONE_CONTAINERS=(); ALL_SITES=(); NUM_MILESTONES=0
    local idx=-1 rec f1 f2 f3 f4 f5 f6
    while IFS='|' read -r rec f1 f2 f3 f4 f5 f6; do
        # Strip any trailing CR from every field: a JSON stream tokenized by a
        # Windows python emits CRLF, and a stray \r would corrupt a container or
        # sig comparison. A no-op on the LF embedded tables / on Unix hosts.
        rec="${rec%$'\r'}"; f1="${f1%$'\r'}"; f2="${f2%$'\r'}"
        f3="${f3%$'\r'}"; f4="${f4%$'\r'}"; f5="${f5%$'\r'}"; f6="${f6%$'\r'}"
        case "$rec" in
            M)
                idx=$(( idx + 1 ))
                MILESTONE_NAMES+=("$f1")
                MILESTONE_CONTAINERS+=("$f2")
                ;;
            S)
                # store "idx|name|kind|jgRVA|jgOff|expected|sig"
                ALL_SITES+=("${idx}|${f1}|${f2}|${f3}|${f4}|${f5}|${f6}")
                ;;
        esac
    done
    NUM_MILESTONES=$(( idx + 1 ))
    (( NUM_MILESTONES > 0 ))
}

load_milestones() {
    local sig_path sig_status=0 tokens src_label
    if sig_path=$(get_signatures_path); then
        if [[ ! -r "$sig_path" ]]; then errf "Signature file is not readable: ${sig_path}"; return 1; fi
        if ! command -v python3 >/dev/null 2>&1; then
            errf "An external signatures.json needs python3, which was not found."
            echo "    Remove ${sig_path} to use the built-in tables, or install python3."
            return 1
        fi
        if ! tokens=$(json_to_tokens < "$sig_path"); then
            errf "Failed to parse ${sig_path}:"; printf '    %s\n' "$tokens"; return 1
        fi
        src_label="$sig_path"
    else
        sig_status=$?
        if (( sig_status == 2 )); then
            errf "Signature file does not exist: ${SIGNATURES_OVERRIDE}"; return 1
        fi
        tokens="$EMBEDDED_SIGNATURES"
        src_label="embedded tables"
    fi

    # Feed tokens via a here-string so populate runs in THIS shell (a pipe would
    # run it in a subshell and lose the arrays).
    if ! populate_from_tokens <<< "$tokens"; then
        errf "No usable Mach-O milestones from ${src_label}."
        return 1
    fi
    okf "Loaded ${NUM_MILESTONES} Mach-O milestone(s) from ${src_label}"
    return 0
}

# Sites of milestone index $1 -> "name|kind|jgRVA|jgOff|expected|sig" per line.
sites_of() {
    local want="$1" spec
    for spec in "${ALL_SITES[@]}"; do
        if [[ "${spec%%|*}" == "$want" ]]; then echo "${spec#*|}"; fi
    done
}

# ============================================================================
# Signature matching engine. Exact on every byte except the masked jump:
#   short : jg_off in {7F,EB}; jg_off+1 (disp8) wild
#   near  : jg_off,+1 the pair {0F 8F | 90 E9}; +2..+5 (disp32) wild
#   bcond : the 4-byte LE word at jg_off - opcode 0x54 + bit4=0 fixed, cond in
#           {0xC stock, 0xE patched}, imm19 wild (bit-level, not byte-level)
# ============================================================================
sig_matches_at() {
    local file="$1" file_offset="$2" sig_hex="$3" kind="$4" jg_off="$5"
    local sig_len=$(( ${#sig_hex} / 2 ))
    local actual; actual=$(read_bytes_hex "$file" "$file_offset" "$sig_len")
    local sig_upper; sig_upper=$(echo "$sig_hex" | tr 'a-f' 'A-F')

    if [[ "$kind" == "bcond" ]]; then
        # validate the whole branch word first (little-endian)
        local b0 b1 b2 b3 word cond
        b0=$(( 16#${actual:$(( jg_off*2 )):2} ))
        b1=$(( 16#${actual:$(( (jg_off+1)*2 )):2} ))
        b2=$(( 16#${actual:$(( (jg_off+2)*2 )):2} ))
        b3=$(( 16#${actual:$(( (jg_off+3)*2 )):2} ))
        word=$(( b0 | (b1<<8) | (b2<<16) | (b3<<24) ))
        if (( (word & 0xFF000010) != 0x54000000 )); then return 1; fi
        cond=$(( word & 0xF ))
        if (( cond != 0x0C && cond != 0x0E )); then return 1; fi
    fi

    local i byte_idx sig_byte act_byte act_pair
    for (( i = 0; i < ${#sig_upper}; i += 2 )); do
        byte_idx=$(( i / 2 ))
        sig_byte="${sig_upper:$i:2}"
        act_byte="${actual:$i:2}"
        if [[ "$kind" == "short" ]]; then
            if (( byte_idx == jg_off )); then
                if [[ "$act_byte" != "7F" && "$act_byte" != "EB" ]]; then return 1; fi
                continue
            elif (( byte_idx == jg_off + 1 )); then continue; fi
        elif [[ "$kind" == "near" ]]; then
            if (( byte_idx == jg_off )); then
                act_pair="${actual:$i:4}"
                if [[ "$act_pair" != "0F8F" && "$act_pair" != "90E9" ]]; then return 1; fi
                continue
            elif (( byte_idx >= jg_off + 1 && byte_idx <= jg_off + 5 )); then continue; fi
        else  # bcond: the 4 word bytes are handled above
            if (( byte_idx >= jg_off && byte_idx <= jg_off + 3 )); then continue; fi
        fi
        if [[ "$sig_byte" != "$act_byte" ]]; then return 1; fi
    done
    return 0
}

# Longest fixed (unmasked, grep-safe) run in the signature -> a raw anchor.
BINARY_ANCHOR_HEX=""; BINARY_ANCHOR_OFF=0
build_binary_anchor() {
    local sig; sig=$(echo "$1" | tr 'A-F' 'a-f')
    local kind="$2" jg_off="$3"
    local sig_bytes=$(( ${#sig} / 2 )) mask_len
    case "$kind" in short) mask_len=2 ;; near) mask_len=6 ;; bcond) mask_len=4 ;; esac
    local mask_end=$(( jg_off + mask_len ))
    BINARY_ANCHOR_HEX=""; BINARY_ANCHOR_OFF=0
    local best_len=0 best_start=0 start end byte run_len
    for (( start = 0; start < sig_bytes; start++ )); do
        run_len=0
        for (( end = start; end < sig_bytes; end++ )); do
            if (( end >= jg_off && end < mask_end )); then break; fi
            byte="${sig:$(( end*2 )):2}"
            if [[ "$byte" == "00" || "$byte" == "0a" || "$byte" == "3a" ]]; then break; fi
            run_len=$(( run_len + 1 ))
        done
        if (( run_len > best_len )); then best_len=$run_len; best_start=$start; fi
    done
    if (( best_len >= 4 )); then
        BINARY_ANCHOR_HEX="${sig:$(( best_start*2 )):$(( best_len*2 ))}"
        BINARY_ANCHOR_OFF=$best_start
    fi
}

# find_site_matches <file> <base> <traw> <tvaddr> <tsize> <spec> -> FOUND_OFFSETS, RELOCATED
# spec is "name|kind|jgRVA|jgOff|expectedMatches|sig". FOUND_OFFSETS holds
# ABSOLUTE file offsets of the jump opcode within this slice.
FOUND_OFFSETS=(); RELOCATED=false; FAST_PROBE_ONLY=false
find_site_matches() {
    local file="$1" base="$2" traw="$3" tvaddr="$4" tsize="$5" spec="$6"
    local name kind jg_rva_hex jg_off expected sig_hex
    IFS='|' read -r name kind jg_rva_hex jg_off expected sig_hex <<< "$spec"
    local jg_rva=$(( jg_rva_hex )) sig_len=$(( ${#sig_hex} / 2 ))
    FOUND_OFFSETS=(); RELOCATED=false

    # Fast path: probe the recorded RVA (only when expectedMatches == 1).
    if (( expected == 1 && jg_rva >= tvaddr )); then
        local rva_in_text=$(( jg_rva - tvaddr ))
        if (( rva_in_text < tsize )); then
            local jg_raw=$(( traw + rva_in_text ))
            local sig_start=$(( jg_raw - jg_off ))
            if (( sig_start >= traw && sig_start + sig_len <= traw + tsize )) \
               && sig_matches_at "$file" "$sig_start" "$sig_hex" "$kind" "$jg_off"; then
                FOUND_OFFSETS=("$jg_raw"); RELOCATED=false; return 0
            fi
        fi
    fi
    if $FAST_PROBE_ONLY; then return 0; fi

    # Slow path: one raw fixed-string grep for this site's anchor, verified with
    # the full masked matcher. Mac tables are tiny, so a per-site scan is cheap.
    build_binary_anchor "$sig_hex" "$kind" "$jg_off"
    local anchor_hex="$BINARY_ANCHOR_HEX"
    if [[ -z "$anchor_hex" ]]; then
        errf "Signature has no safe raw scan anchor: ${name}"; return 1
    fi
    local anchor_bin="" ai abyte
    for (( ai = 0; ai < ${#anchor_hex}; ai += 2 )); do
        abyte="${anchor_hex:ai:2}"
        printf -v abyte '%b' "\\x${abyte}"
        anchor_bin+="$abyte"
    done

    local matches=() anchor_pos sig_start jg_file_offset
    while IFS=: read -r anchor_pos _rest; do
        [[ "$anchor_pos" =~ ^[0-9]+$ ]] || continue
        sig_start=$(( anchor_pos - BINARY_ANCHOR_OFF ))
        if (( sig_start < traw || sig_start + sig_len > traw + tsize )); then continue; fi
        if sig_matches_at "$file" "$sig_start" "$sig_hex" "$kind" "$jg_off"; then
            jg_file_offset=$(( sig_start + jg_off ))
            local seen=false m
            for m in "${matches[@]:-}"; do [[ "$m" == "$jg_file_offset" ]] && seen=true; done
            $seen || matches+=("$jg_file_offset")
            if (( ${#matches[@]} > expected + 1 )); then break; fi
        fi
    done < <(LC_ALL=C grep -a -o -b -F -- "$anchor_bin" "$file" 2>/dev/null || true)

    if (( ${#matches[@]} > 0 )); then
        FOUND_OFFSETS=("${matches[@]}"); RELOCATED=true
    fi
    return 0
}

# ============================================================================
# Per-slice milestone probing - pick the best unambiguous milestone for ONE
# slice (mirrors chrome-mv2.sh, but bounded to the slice's own container/.text).
# ============================================================================
BEST_MS_NAME=""; BEST_SATISFIED=0; BEST_TOTAL=0; BEST_FULL=false; BEST_TIES=0
FLIP_NAMES=(); FLIP_KINDS=(); FLIP_OFFSETS=(); FLIP_RELOCATED=()

reset_probe_results() {
    BEST_MS_NAME=""; BEST_SATISFIED=0; BEST_TOTAL=0; BEST_FULL=false; BEST_TIES=0
    FLIP_NAMES=(); FLIP_KINDS=(); FLIP_OFFSETS=(); FLIP_RELOCATED=()
}

probe_slice_pass() {
    local file="$1" base="$2" traw="$3" tvaddr="$4" tsize="$5" container="$6"
    local mi
    for (( mi = 0; mi < NUM_MILESTONES; mi++ )); do
        [[ "${MILESTONE_CONTAINERS[$mi]}" == "$container" ]] || continue
        local ms_name="${MILESTONE_NAMES[$mi]}"
        local satisfied=0 total=0
        local fn=() fk=() fo=() fr=()
        local spec s_name s_kind s_jgrva s_jgoff s_expected s_sig off
        while IFS= read -r spec; do
            [[ -n "$spec" ]] || continue
            total=$(( total + 1 ))
            IFS='|' read -r s_name s_kind s_jgrva s_jgoff s_expected s_sig <<< "$spec"
            find_site_matches "$file" "$base" "$traw" "$tvaddr" "$tsize" "$spec"
            if (( ${#FOUND_OFFSETS[@]} == s_expected )); then
                satisfied=$(( satisfied + 1 ))
                for off in "${FOUND_OFFSETS[@]}"; do
                    fn+=("$s_name"); fk+=("$s_kind"); fo+=("$off"); fr+=("$RELOCATED")
                done
            fi
        done < <(sites_of "$mi")

        if (( satisfied > BEST_SATISFIED )); then
            BEST_MS_NAME="$ms_name"; BEST_SATISFIED=$satisfied; BEST_TOTAL=$total
            FLIP_NAMES=("${fn[@]:-}"); FLIP_KINDS=("${fk[@]:-}")
            FLIP_OFFSETS=("${fo[@]:-}"); FLIP_RELOCATED=("${fr[@]:-}")
            BEST_TIES=1
            (( satisfied == total )) && break
        elif (( satisfied == BEST_SATISFIED && satisfied > 0 )); then
            BEST_TIES=$(( BEST_TIES + 1 ))
        fi
    done
    if (( BEST_SATISFIED == BEST_TOTAL && BEST_TOTAL > 0 )); then BEST_FULL=true; else BEST_FULL=false; fi
}

probe_slice() {
    local idx="$1" file="$2"
    local base="${SLICE_BASE[$idx]}" traw="${SLICE_TRAW[$idx]}"
    local tvaddr="${SLICE_TVADDR[$idx]}" tsize="${SLICE_TSIZE[$idx]}"
    local container="${SLICE_CONTAINER[$idx]}"
    reset_probe_results
    FAST_PROBE_ONLY=true
    probe_slice_pass "$file" "$base" "$traw" "$tvaddr" "$tsize" "$container"
    FAST_PROBE_ONLY=false
    if $BEST_FULL; then return 0; fi
    reset_probe_results
    probe_slice_pass "$file" "$base" "$traw" "$tvaddr" "$tsize" "$container"
    return 0
}

# ============================================================================
# Flip engine (operates on the FLIP_* set filled by probe_slice, in a work file).
#   short : 0x7F      -> 0xEB
#   near  : 0F 8F     -> 90 E9
#   bcond : B.cond word byte0 low nibble GT(0xC) -> AL(0xE); ONLY that nibble
#           changes (b0 = (b0 & 0xF0) | 0x0E), preserving opcode and imm19.
# ============================================================================
SLICE_FLIPS=0; SLICE_ALREADY=0
apply_flips_slice() {
    local file="$1" applied=0 already=0 i name kind offset cur o0 o1 nib newb
    SLICE_FLIPS=0; SLICE_ALREADY=0
    for (( i = 0; i < ${#FLIP_OFFSETS[@]}; i++ )); do
        name="${FLIP_NAMES[$i]}"; kind="${FLIP_KINDS[$i]}"; offset="${FLIP_OFFSETS[$i]}"
        if [[ "$kind" == "short" ]]; then
            cur=$(read_byte "$file" "$offset")
            if (( cur == 0xEB )); then already=$(( already + 1 )); continue; fi
            if (( cur != 0x7F )); then
                warnf "    ${BEST_MS_NAME}: ${name} unexpected 0x$(printf '%X' "$cur") (want 7F) - skipping."
                continue
            fi
            printf '\xEB' | dd of="$file" bs=1 seek="$offset" count=1 conv=notrunc 2>/dev/null
            applied=$(( applied + 1 ))
        elif [[ "$kind" == "near" ]]; then
            o0=$(read_byte "$file" "$offset"); o1=$(read_byte "$file" $(( offset + 1 )))
            if (( o0 == 0x90 && o1 == 0xE9 )); then already=$(( already + 1 )); continue; fi
            if ! (( o0 == 0x0F && o1 == 0x8F )); then
                warnf "    ${BEST_MS_NAME}: ${name} unexpected 0x$(printf '%X' "$o0") 0x$(printf '%X' "$o1") (want 0F 8F) - skipping."
                continue
            fi
            printf '\x90\xE9' | dd of="$file" bs=1 seek="$offset" count=2 conv=notrunc 2>/dev/null
            applied=$(( applied + 1 ))
        else  # bcond
            cur=$(read_byte "$file" "$offset")   # little-endian byte0 holds the condition
            nib=$(( cur & 0x0F ))
            if (( nib == 0x0E )); then already=$(( already + 1 )); continue; fi
            if (( nib != 0x0C )); then
                warnf "    ${BEST_MS_NAME}: ${name} b.cond nibble 0x$(printf '%X' "$nib") (want C=GT) - skipping."
                continue
            fi
            newb=$(( (cur & 0xF0) | 0x0E ))
            printf "\\x$(printf '%02X' "$newb")" | dd of="$file" bs=1 seek="$offset" count=1 conv=notrunc 2>/dev/null
            applied=$(( applied + 1 ))
        fi
        local suffix=""; [[ "${FLIP_RELOCATED[$i]}" == "true" ]] && suffix="  (RELOCATED)"
        okf "    ${BEST_MS_NAME}: ${name} flipped${suffix}"
    done
    SLICE_FLIPS=$applied; SLICE_ALREADY=$already
}

STATE_STOCK=0; STATE_PATCHED=0
classify_flip_states_slice() {
    local file="$1" i kind offset o0 o1 nib
    STATE_STOCK=0; STATE_PATCHED=0
    for (( i = 0; i < ${#FLIP_OFFSETS[@]}; i++ )); do
        kind="${FLIP_KINDS[$i]}"; offset="${FLIP_OFFSETS[$i]}"
        o0=$(read_byte "$file" "$offset")
        if [[ "$kind" == "short" ]]; then
            if (( o0 == 0x7F )); then STATE_STOCK=$(( STATE_STOCK + 1 ))
            elif (( o0 == 0xEB )); then STATE_PATCHED=$(( STATE_PATCHED + 1 ))
            else return 1; fi
        elif [[ "$kind" == "near" ]]; then
            o1=$(read_byte "$file" $(( offset + 1 )))
            if (( o0 == 0x0F && o1 == 0x8F )); then STATE_STOCK=$(( STATE_STOCK + 1 ))
            elif (( o0 == 0x90 && o1 == 0xE9 )); then STATE_PATCHED=$(( STATE_PATCHED + 1 ))
            else return 1; fi
        else
            nib=$(( o0 & 0x0F ))
            if (( nib == 0x0C )); then STATE_STOCK=$(( STATE_STOCK + 1 ))
            elif (( nib == 0x0E )); then STATE_PATCHED=$(( STATE_PATCHED + 1 ))
            else return 1; fi
        fi
    done
}

# ============================================================================
# Identity + backup. Identity is keyed on the per-slice LC_UUIDs (stable across
# the flip AND the ad-hoc re-sign); the whole-file sha256 is an integrity check
# only. The backup is the ORIGINAL Google-signed framework file - re-signing is
# lossy, so restore copies these exact bytes back (no re-sign needed).
# ============================================================================
IDENTITY_UUIDS=""
compute_identity() {
    # requires parse_macho() to have populated SLICE_* for $1
    local file="$1" i pairs=""
    for (( i = 0; i < NUM_SLICES; i++ )); do
        pairs="${pairs}${pairs:+,}${SLICE_CONTAINER[$i]}:${SLICE_UUID[$i]}"
    done
    IDENTITY_UUIDS="$pairs"
}

WRITE_TMP=""
# Atomic in-directory replace, preserving mode; optional expected-hash re-check
# closes the inspect/write race.
write_target() {
    local target="$1" source="$2" expected_hash="${3:-}"
    local dir; dir=$(dirname "$target")
    local tmp; tmp=$(mktemp "${dir}/.chrome-mv2-XXXXXX"); WRITE_TMP="$tmp"
    if [[ -e "$target" ]]; then cp -p -- "$target" "$tmp"; fi
    cp -- "$source" "$tmp"
    local shash thash chash
    shash=$(file_sha256 "$source"); thash=$(file_sha256 "$tmp")
    if [[ "$shash" != "$thash" ]]; then rm -f -- "$tmp"; WRITE_TMP=""; errf "Temp-file verification failed for ${target}."; return 1; fi
    if [[ -n "$expected_hash" ]]; then
        chash=$(file_sha256 "$target")
        if [[ "$chash" != "$expected_hash" ]]; then rm -f -- "$tmp"; WRITE_TMP=""; errf "Target changed after inspection; refusing to overwrite."; return 1; fi
    fi
    mv -f -- "$tmp" "$target"; WRITE_TMP=""
    sync 2>/dev/null || true
}

backup_meta_path() { printf '%s.meta\n' "$1"; }

save_backup_snapshot() {
    local target="$1" backup="$2" source="$3" identity="$4"
    local prev=""; [[ -f "$backup" ]] && prev=$(file_sha256 "$backup")
    write_target "$backup" "$source" "$prev" || return 1
    local meta size hash
    meta=$(backup_meta_path "$backup"); size=$(file_size "$backup"); hash=$(file_sha256 "$backup")
    printf 'schema=1\ncontainer=macho\nidentity=%s\nsize=%s\nsha256=%s\n' "$identity" "$size" "$hash" > "${meta}.tmp"
    mv -f -- "${meta}.tmp" "$meta"
}

BACKUP_IDENTITY=""; BACKUP_SIZE=0; BACKUP_HASH=""; BACKUP_LEGACY=false
validate_backup_snapshot() {
    local backup="$1" meta
    [[ -f "$backup" ]] || return 1
    parse_macho "$backup" >/dev/null || return 1
    compute_identity "$backup"; BACKUP_IDENTITY="$IDENTITY_UUIDS"
    BACKUP_SIZE=$(file_size "$backup"); BACKUP_HASH=$(file_sha256 "$backup")
    [[ -n "$BACKUP_IDENTITY" ]] || return 1
    meta=$(backup_meta_path "$backup")
    BACKUP_LEGACY=false
    if [[ ! -f "$meta" ]]; then BACKUP_LEGACY=true; return 0; fi
    local schema="" container="" identity="" size="" sha256="" key value extra
    while IFS='=' read -r key value extra; do
        [[ -z "$extra" ]] || return 1
        case "$key" in
            schema) schema="$value" ;; container) container="$value" ;;
            identity) identity="$value" ;; size) size="$value" ;; sha256) sha256="$value" ;;
            *) return 1 ;;
        esac
    done < "$meta"
    [[ "$schema" == 1 && "$container" == macho && "$identity" == "$BACKUP_IDENTITY" \
       && "$size" == "$BACKUP_SIZE" && "$sha256" == "$BACKUP_HASH" ]]
}

# ============================================================================
# Code signing. Any edit invalidates the Mach-O signature; on Apple Silicon the
# kernel refuses to launch an invalid/absent signature. A bare-Mach-O sign is
# NOT enough (bundle seals go stale; library validation rejects an ad-hoc
# framework under Google's Team-ID executable). So re-sign INSIDE-OUT and ad-hoc
# (framework bundle, then the .app), preserving entitlements/flags, then verify.
# ============================================================================
have_codesign() { command -v codesign >/dev/null 2>&1; }

resign_inside_out() {
    local framework_bundle="$1" app_path="$2"
    if [[ -z "$framework_bundle" || ! -d "$framework_bundle" ]]; then
        errf "Framework bundle not found for re-signing: ${framework_bundle}"; return 1
    fi
    infof "Ad-hoc re-signing (inside-out): framework, then app ..."
    # Framework first. --preserve-metadata keeps JIT entitlements (allow-jit,
    # allow-unsigned-executable-memory) and the hardened-runtime flag; dropping
    # them crashes V8/renderers.
    if ! codesign --force --sign - --preserve-metadata=entitlements,flags,requirements "$framework_bundle" 2>/dev/null; then
        # Some framework versions have no entitlements to preserve; retry plain.
        codesign --force --sign - "$framework_bundle" || { errf "codesign failed on the framework bundle."; return 1; }
    fi
    if [[ -n "$app_path" && -d "$app_path" ]]; then
        if ! codesign --force --sign - --preserve-metadata=entitlements,flags,requirements "$app_path" 2>/dev/null; then
            # Fallback: whole-tree ad-hoc re-seal (deprecated --deep, but correct
            # for making every nested component ad-hoc so library validation passes).
            codesign --force --deep --sign - "$app_path" || { errf "codesign failed on the app bundle."; return 1; }
        fi
    fi
    return 0
}

verify_signature() {
    local app_path="$1"
    if [[ -n "$app_path" && -d "$app_path" ]]; then
        codesign --verify --deep --strict "$app_path" 2>/dev/null
        return $?
    fi
    return 0
}

# ============================================================================
# macOS platform glue - .app discovery, framework resolution, process handling.
# ============================================================================
APP_PATH=""; FRAMEWORK_BUNDLE=""; TARGET_FILE=""

app_version() {
    local app="$1" plist="$1/Contents/Info.plist"
    [[ -f "$plist" ]] || { echo ""; return; }
    if command -v defaults >/dev/null 2>&1; then
        defaults read "${app}/Contents/Info" CFBundleShortVersionString 2>/dev/null && return
    fi
    if command -v plutil >/dev/null 2>&1; then
        plutil -extract CFBundleShortVersionString raw -o - "$plist" 2>/dev/null && return
    fi
    echo ""
}

# From a .app dir, set FRAMEWORK_BUNDLE + TARGET_FILE (the real versioned Mach-O).
resolve_framework_from_app() {
    local app="$1" fw=""
    local d
    for d in "$app"/Contents/Frameworks/*Framework.framework; do
        [[ -d "$d" ]] && { fw="$d"; break; }
    done
    [[ -n "$fw" ]] || return 1
    FRAMEWORK_BUNDLE="$fw"
    local base; base=$(basename "$fw" .framework)
    local versions="$fw/Versions" v vdir=""
    if [[ -d "$versions" ]]; then
        for v in "$versions"/*; do
            [[ -d "$v" && ! -L "$v" ]] || continue
            [[ "$(basename "$v")" == "Current" ]] && continue
            vdir="$v"   # last real version dir; installs keep exactly one
        done
    fi
    if [[ -n "$vdir" && -f "$vdir/$base" ]]; then
        TARGET_FILE="$vdir/$base"
    elif [[ -f "$versions/Current/$base" ]]; then
        TARGET_FILE="$versions/Current/$base"    # follow the symlink if no real dir found
    else
        return 1
    fi
    return 0
}

# Normalize any user-supplied path to APP_PATH/FRAMEWORK_BUNDLE/TARGET_FILE.
resolve_target() {
    local path="$1"
    APP_PATH=""; FRAMEWORK_BUNDLE=""; TARGET_FILE=""
    if [[ -d "$path" && "$path" == *.app ]]; then
        APP_PATH="$path"
        resolve_framework_from_app "$path" || { errf "No Chrome framework inside ${path}"; return 1; }
    elif [[ -d "$path" && "$path" == *.framework ]]; then
        FRAMEWORK_BUNDLE="$path"
        local base; base=$(basename "$path" .framework)
        if [[ -f "$path/Versions/Current/$base" ]]; then TARGET_FILE="$path/Versions/Current/$base"
        else errf "No versioned binary in ${path}"; return 1; fi
    elif [[ -f "$path" ]]; then
        TARGET_FILE="$path"        # a loose Mach-O (offline scratch copy): no bundle re-seal
    else
        errf "Path is not a .app, .framework, or Mach-O file: ${path}"; return 1
    fi
    return 0
}

CHROME_APPS=("Google Chrome.app" "Google Chrome Beta.app" "Google Chrome Dev.app" "Google Chrome Canary.app")
CHROME_LABELS=("Stable" "Beta" "Dev" "Canary")
INSTALLS_LABELS=(); INSTALLS_APPS=(); INSTALLS_VERSIONS=(); INSTALLS_RUNNING=()

enumerate_installs() {
    INSTALLS_LABELS=(); INSTALLS_APPS=(); INSTALLS_VERSIONS=(); INSTALLS_RUNNING=()
    local roots=("/Applications" "$HOME/Applications") root i app ver running
    for root in "${roots[@]}"; do
        for (( i = 0; i < ${#CHROME_APPS[@]}; i++ )); do
            app="$root/${CHROME_APPS[$i]}"
            [[ -d "$app" ]] || continue
            ver=$(app_version "$app")
            running=false
            if command -v pgrep >/dev/null 2>&1 && pgrep -f "$app/Contents/MacOS/" >/dev/null 2>&1; then running=true; fi
            INSTALLS_LABELS+=("${CHROME_LABELS[$i]}"); INSTALLS_APPS+=("$app")
            INSTALLS_VERSIONS+=("$ver"); INSTALLS_RUNNING+=("$running")
        done
    done
}

proc_holders_app() {
    local app="$1"
    if command -v pgrep >/dev/null 2>&1; then pgrep -f "$app/Contents/MacOS/" 2>/dev/null | wc -l | tr -d ' '; else echo 0; fi
}

quit_chrome() {
    local app="$1" assume_yes="$2"
    (( $(proc_holders_app "$app") == 0 )) && return 0
    if ! $assume_yes && ! $QUIET; then
        echo -n "${C_BOLD}Chrome ($(basename "$app")) is running; quit it to patch cleanly? [y/N]: ${C_RESET}"
        local line; read -r line || return 1
        case "$line" in y|Y) ;; *) infof "Cancelled - nothing changed."; return 1 ;; esac
    fi
    # Graceful quit, then force. All helpers map the framework, so quit them too.
    command -v osascript >/dev/null 2>&1 && osascript -e "quit app \"$app\"" 2>/dev/null || true
    local i
    for (( i = 0; i < 20; i++ )); do (( $(proc_holders_app "$app") == 0 )) && return 0; sleep 0.25; done
    command -v pkill >/dev/null 2>&1 && pkill -f "$app/Contents/MacOS/" 2>/dev/null || true
    for (( i = 0; i < 20; i++ )); do (( $(proc_holders_app "$app") == 0 )) && return 0; sleep 0.25; done
    errf "Chrome processes still hold the framework; close it manually and retry."; return 1
}

# ============================================================================
# Orchestration
# ============================================================================
WORK_FILE=""
QUIET=false
ALLOW_ARM64=false

# The Mach-O container matching this Mac's CPU - the ONLY slice that executes.
# Detection order: an explicit test override, then the hardware bit (correct even
# under Rosetta, where uname -m reports x86_64 on Apple Silicon), then uname -m.
HOST_CONTAINER=""
detect_host_container() {
    case "${MV2_TEST_HOST_ARCH:-}" in
        arm64|aarch64)  HOST_CONTAINER="macho-arm64"; return ;;
        x86_64|amd64|x64) HOST_CONTAINER="macho-x64"; return ;;
    esac
    if command -v sysctl >/dev/null 2>&1 \
       && [[ "$(sysctl -n hw.optional.arm64 2>/dev/null)" == "1" ]]; then
        HOST_CONTAINER="macho-arm64"; return
    fi
    case "$(uname -m 2>/dev/null || echo)" in
        arm64|aarch64) HOST_CONTAINER="macho-arm64" ;;
        *)             HOST_CONTAINER="macho-x64" ;;
    esac
}

# Human label for the host container, for console output.
host_arch_label() {
    case "$HOST_CONTAINER" in
        macho-arm64) echo "Apple Silicon (arm64)" ;;
        *)           echo "Intel (x86_64)" ;;
    esac
}

# Should this slice be patched? Sets SKIP_REASON on decline. Uses BEST_* (already
# probed) and HOST_CONTAINER. By default only the host slice is eligible; --arm64
# forces the arm64 slice on any host. $1=container $2=allow_partial
slice_decision() {
    local container="$1" allow_partial="$2"
    SKIP_REASON=""
    if (( BEST_SATISFIED == 0 )); then SKIP_REASON="no known layout matched"; return 1; fi
    if ! $BEST_FULL && (( BEST_TIES > 1 )); then SKIP_REASON="ambiguous (${BEST_TIES} milestones tied)"; return 1; fi
    if [[ "$container" == "macho-arm64" ]]; then
        if [[ "$HOST_CONTAINER" != "macho-arm64" ]] && ! $ALLOW_ARM64; then
            SKIP_REASON="the arm64 slice does not run on this $(host_arch_label) Mac; pass --arm64 to patch it anyway"; return 1
        fi
    else  # macho-x64
        if [[ "$HOST_CONTAINER" != "macho-x64" ]]; then
            SKIP_REASON="the x86_64 slice does not run on this $(host_arch_label) Mac"; return 1
        fi
    fi
    if ! $BEST_FULL && ! $allow_partial; then
        SKIP_REASON="only ${BEST_SATISFIED}/${BEST_TOTAL} sites; needs --allow-partial"; return 1
    fi
    return 0
}

do_check() {
    local target="$1"
    parse_macho "$target" || return 1
    compute_identity "$target"
    okf "Mach-O identity (per-slice UUID): ${IDENTITY_UUIDS}"
    okf "Size=$(file_size "$target"), SHA-256=$(file_sha256 "$target")"
    local idx
    for (( idx = 0; idx < NUM_SLICES; idx++ )); do
        local c="${SLICE_CONTAINER[$idx]}"
        probe_slice "$idx" "$target"
        if (( BEST_SATISFIED == 0 )); then
            warnf "  ${c}: no known MV2 layout matched."
        elif ! $BEST_FULL && (( BEST_TIES > 1 )); then
            warnf "  ${c}: ${BEST_TIES} milestones tied at ${BEST_SATISFIED}; ambiguous."
        else
            if classify_flip_states_slice "$target"; then
                local state="stock"
                if (( STATE_PATCHED > 0 && STATE_STOCK == 0 )); then state="patched"
                elif (( STATE_PATCHED > 0 && STATE_STOCK > 0 )); then state="mixed"; fi
                okf "  ${c}: Chrome ${BEST_MS_NAME}, ${BEST_SATISFIED}/${BEST_TOTAL} sites, state=${state}."
            else
                warnf "  ${c}: located gates contain invalid bytes."
            fi
        fi
    done
    local backup="${target}.bak"
    if [[ -f "$backup" ]]; then
        if validate_backup_snapshot "$backup"; then okf "Backup: verified (metadata=$(! $BACKUP_LEGACY && echo true || echo false))."
        else warnf "Backup: invalid."; fi
    else infof "Backup: absent."; fi
    return 0
}

do_restore() {
    local target="$1" app_path="$2" assume_yes="$3" force_restore="$4"
    local backup="${target}.bak"
    infof "Restore mode requested..."
    [[ -f "$backup" ]] || { errf "Backup ${backup} does not exist."; return 1; }
    validate_backup_snapshot "$backup" || { errf "Backup or metadata failed validation."; return 1; }

    parse_macho "$target" >/dev/null || return 1
    compute_identity "$target"; local target_id="$IDENTITY_UUIDS"
    local target_hash; target_hash=$(file_sha256 "$target")
    if [[ "$target_id" != "$BACKUP_IDENTITY" ]] && ! $force_restore; then
        errf "Backup belongs to a different Chrome build; refusing to downgrade."
        echo "    Use --force-restore only if restoring that older build is intentional."; return 1
    fi
    if [[ "$target_hash" == "$BACKUP_HASH" ]]; then successf "Target already matches the backup; nothing to do."; return 0; fi

    if [[ -n "$app_path" ]]; then quit_chrome "$app_path" "$assume_yes" || return 1; fi
    write_target "$target" "$backup" "$target_hash" || return 1
    if [[ "$(file_sha256 "$target")" != "$BACKUP_HASH" ]]; then errf "Post-restore SHA-256 mismatch."; return 1; fi
    # The backup is Google's original signed binary, so no re-sign is needed; but
    # the bundle seals were replaced during patch, so re-establish them cleanly.
    if [[ -n "$app_path" ]] && have_codesign; then
        resign_inside_out "$FRAMEWORK_BUNDLE" "$app_path" || warnf "Re-seal after restore failed; run: codesign --force --deep --sign - \"$app_path\""
    fi
    successf "Original framework restored from backup."
    return 0
}

# Confirm the experimental arm64 slice when it is in scope only because it is the
# host slice (i.e. NOT forced with --arm64). Returns 0 to proceed, 1 to skip.
# --arm64 or --yes pre-authorize (no prompt); --quiet without --arm64 declines.
# $1 = assume_yes ("true"/"false").
confirm_experimental_arm64() {
    local assume_yes="$1"
    if $ALLOW_ARM64; then return 0; fi
    if $assume_yes; then return 0; fi
    if $QUIET; then return 1; fi
    echo -n "${C_BOLD}The arm64 slice is EXPERIMENTAL and runtime-unverified. Patch it? [y/N]: ${C_RESET}"
    local line; read -r line || return 1
    case "$line" in y|Y) return 0 ;; *) return 1 ;; esac
}

do_patch() {
    local target="$1" app_path="$2" assume_yes="$3" allow_partial="$4"
    local size; size=$(file_size "$target")
    (( size > 0 )) || { errf "Target file is empty."; return 1; }
    okf "Target: ${target} (${size} bytes)."
    parse_macho "$target" || return 1
    compute_identity "$target"; local target_id="$IDENTITY_UUIDS"
    local target_hash; target_hash=$(file_sha256 "$target")

    # Decide which slices we will patch (probe each against the live target).
    local idx to_patch=() ic=() any=false default_declined=false
    for (( idx = 0; idx < NUM_SLICES; idx++ )); do
        local c="${SLICE_CONTAINER[$idx]}"
        probe_slice "$idx" "$target"
        if slice_decision "$c" "$allow_partial"; then
            if [[ "$c" == "macho-arm64" ]] && ! $ALLOW_ARM64; then
                # In scope because it is the host slice - confirm the experimental patch.
                if ! confirm_experimental_arm64 "$assume_yes"; then
                    warnf "  ${c}: skipped (experimental arm64 patch not confirmed; pass --arm64 to force)."
                    continue
                fi
            fi
            to_patch+=("$idx"); ic+=("$c"); any=true
            infof "  ${c}: will patch (Chrome ${BEST_MS_NAME}, ${BEST_SATISFIED}/${BEST_TOTAL} sites)."
            [[ "$c" == "macho-arm64" ]] && warnf "  ${c}: EXPERIMENTAL, runtime-unverified - test the launched app."
        else
            warnf "  ${c}: skipped (${SKIP_REASON})."
            [[ "$c" == "macho-x64" ]] && default_declined=true
        fi
    done
    if ! $any; then errf "No slice matched a known, permitted MV2 layout; nothing was modified."; return 1; fi

    local backup="${target}.bak"
    if [[ ! -f "$backup" ]]; then
        infof "Creating initial backup: ${backup}"
        save_backup_snapshot "$target" "$backup" "$target" "$target_id" || return 1
        validate_backup_snapshot "$backup" || { errf "Initial backup verification failed."; return 1; }
    else
        validate_backup_snapshot "$backup" || { errf "Backup/metadata failed validation; refusing to overwrite it."; return 1; }
        if [[ "$target_id" != "$BACKUP_IDENTITY" ]]; then
            infof "Chrome update detected (UUID changed) - refreshing backup."
            save_backup_snapshot "$target" "$backup" "$target" "$target_id" || return 1
            validate_backup_snapshot "$backup" || { errf "Updated backup verification failed."; return 1; }
        elif $BACKUP_LEGACY; then
            save_backup_snapshot "$target" "$backup" "$backup" "$BACKUP_IDENTITY" || return 1
        fi
    fi

    # Build the patched image from the clean backup, per slice.
    local work; work=$(mktemp "${TMPDIR:-/tmp}/chrome-mv2-work.XXXXXX"); WORK_FILE="$work"
    cp -- "$backup" "$work"
    parse_macho "$work" >/dev/null || { rm -f -- "$work"; WORK_FILE=""; return 1; }
    local k
    for k in "${to_patch[@]}"; do
        probe_slice "$k" "$work"
        apply_flips_slice "$work"
    done

    # Verify the prepared slices are fully flipped.
    parse_macho "$work" >/dev/null || { rm -f -- "$work"; WORK_FILE=""; return 1; }
    for k in "${to_patch[@]}"; do
        probe_slice "$k" "$work"
        classify_flip_states_slice "$work" || { errf "Prepared output has invalid gate bytes."; rm -f -- "$work"; WORK_FILE=""; return 1; }
        if (( STATE_STOCK != 0 )); then errf "Prepared ${SLICE_CONTAINER[$k]} slice is not fully flipped."; rm -f -- "$work"; WORK_FILE=""; return 1; fi
    done

    local prepared_hash; prepared_hash=$(file_sha256 "$work")
    if [[ "$prepared_hash" == "$target_hash" ]]; then rm -f -- "$work"; WORK_FILE=""; successf "Target already fully patched for the selected slices."; return 0; fi
    if [[ "$target_hash" != "$BACKUP_HASH" ]]; then
        errf "Target has changes unrelated to this patch; refusing to overwrite them."
        echo "    Reinstall Chrome or inspect the framework before retrying."; rm -f -- "$work"; WORK_FILE=""; return 1
    fi

    if [[ -n "$app_path" ]]; then quit_chrome "$app_path" "$assume_yes" || { rm -f -- "$work"; WORK_FILE=""; return 1; }; fi
    write_target "$target" "$work" "$target_hash" || { rm -f -- "$work"; WORK_FILE=""; return 1; }
    rm -f -- "$work"; WORK_FILE=""

    # Re-sign the now-modified bundle inside-out, then verify. On any failure,
    # roll the framework back to the pristine backup so the app still launches.
    if [[ -n "$app_path" ]]; then
        if have_codesign; then
            if ! resign_inside_out "$FRAMEWORK_BUNDLE" "$app_path" || ! verify_signature "$app_path"; then
                errf "Re-sign/verify failed; rolling framework back to stock."
                write_target "$target" "$backup" "" || true
                have_codesign && resign_inside_out "$FRAMEWORK_BUNDLE" "$app_path" >/dev/null 2>&1 || true
                return 1
            fi
            okf "Ad-hoc signature verified (codesign --verify --deep --strict)."
        else
            errf "codesign not found at /usr/bin/codesign (unexpected - it ships with macOS)."
            echo "    The framework is patched but UNSIGNED and will not launch on Apple Silicon."
            echo "    Restore stock with:  bash $0 restore \"$app_path\""
            echo "    or, once codesign is available:  codesign --force --deep --sign - \"$app_path\""
            return 1
        fi
    fi

    rule
    successf "Manifest V2 re-enabled for: ${ic[*]}"
    [[ -n "$app_path" ]] && echo "          Relaunch Chrome. Revert with: bash $0 restore \"$app_path\""
    for k in "${to_patch[@]}"; do
        [[ "${SLICE_CONTAINER[$k]}" == "macho-arm64" ]] && echo "          NOTE: the arm64 slice is experimental - confirm MV2 works and report back."
    done
    rule
    return 0
}

CHOSEN_INDEX=-1
choose_install() {
    local count=${#INSTALLS_APPS[@]} i
    if (( count == 0 )); then
        warnf "No installed Google Chrome.app was found under /Applications or ~/Applications."
        echo "    Pass a path explicitly: bash $0 patch \"/path/to/Google Chrome.app\""
        return 1
    fi
    echo ""; echo "${TAG_INFO} ${count} Chrome install(s) found:"
    for (( i = 0; i < count; i++ )); do
        echo -n "  ${C_BOLD}$(( i + 1 ))${C_RESET}) ${C_CYN}${INSTALLS_LABELS[$i]}${C_RESET}"
        [[ -n "${INSTALLS_VERSIONS[$i]}" ]] && echo -n "  ${INSTALLS_VERSIONS[$i]}"
        ${INSTALLS_RUNNING[$i]} && echo -n "  ${C_YEL}[running]${C_RESET}" || echo -n "  ${C_GRN}[not running]${C_RESET}"
        echo ""; echo "      ${C_DIM}${INSTALLS_APPS[$i]}${C_RESET}"
    done
    while true; do
        echo -n "${C_BOLD}Which install? [1-${count}, q=quit]: ${C_RESET}"
        local line; read -r line || return 1
        [[ "$line" == q || "$line" == Q ]] && return 1
        if [[ "$line" =~ ^[0-9]+$ ]] && (( line >= 1 && line <= count )); then CHOSEN_INDEX=$(( line - 1 )); return 0; fi
        errf "Enter a number between 1 and ${count}, or q."
    done
}

print_usage() {
    cat <<EOF
Usage: bash chrome-mv2-mac.sh [command] [path] [options]

Re-enables Manifest V2 in Google Chrome on macOS by flipping the inlined
IsExtensionAffected checks. The framework is a universal (fat) Mach-O; only the
slice matching this Mac's CPU runs, so by default only that slice is patched.

Commands:
  patch                  Flip the MV2 gates (default if omitted).
  restore                Restore the framework from its verified .bak.
  check                  Read-only per-slice layout/patch/backup diagnostics.

Arguments:
  path                   A Google Chrome.app, a *.framework, or the framework
                         Mach-O file. If omitted, installed apps are listed.

Options:
      --arm64            Force the arm64 slice on any host (EXPERIMENTAL,
                         unverified). Also skips the arm64 confirmation on an
                         Apple Silicon Mac, where arm64 is the default slice.
  -y, --yes              Quit a running Chrome, and confirm the experimental
                         arm64 patch, without asking.
  -q, --quiet            Do not prompt (for scripting).
      --allow-partial    Developer override: write an incomplete milestone.
      --force-restore    Restore a backup from a different Chrome build.
      --signatures PATH  Use this external signature JSON (needs python3).
  -v, --version          Print the tool version and exit.
  -h, --help             Show this help and exit.

Environment:
  MV2_TEST_NO_ELEVATION  Skip the write-permission check (tests only).
  MV2_TEST_HOST_ARCH     Force the detected host CPU (arm64/x86_64; tests only).
  NO_COLOR / FORCE_COLOR Disable / force ANSI colour.
EOF
}

cleanup() {
    local rc=$?      # preserve the real exit status; the trap must not mask it
    local t
    for t in "${WORK_FILE:-}" "${WRITE_TMP:-}"; do
        [[ -n "$t" && -f "$t" ]] && rm -f -- "$t"
    done
    return "$rc"
}
trap cleanup EXIT

main() {
    init_colors
    local cmd="patch" target_path="" assume_yes=false allow_partial=false force_restore=false
    QUIET=false; ALLOW_ARM64=false
    local positional=()
    while (( $# > 0 )); do
        case "$1" in
            --arm64) ALLOW_ARM64=true ;;
            --yes|-y) assume_yes=true ;;
            --quiet|-q) QUIET=true ;;
            --allow-partial) allow_partial=true ;;
            --force-restore) force_restore=true ;;
            --signatures) (( $# >= 2 )) || { errf "--signatures needs a path."; exit 2; }; SIGNATURES_OVERRIDE="$2"; shift ;;
            --) shift; while (( $# > 0 )); do positional+=("$1"); shift; done; break ;;
            --version|-v) echo "chrome-mv2-patch ${APP_VERSION}"; exit 0 ;;
            --help|-h) print_usage; exit 0 ;;
            -*) errf "Unknown option: $1"; print_usage; exit 2 ;;
            *) positional+=("$1") ;;
        esac
        shift
    done
    if (( ${#positional[@]} >= 1 )); then
        case "${positional[0]}" in
            patch|restore|check) cmd="${positional[0]}"; (( ${#positional[@]} >= 2 )) && target_path="${positional[1]}" ;;
            *) target_path="${positional[0]}" ;;
        esac
    fi
    (( ${#positional[@]} <= 2 )) || { errf "Too many positional arguments."; print_usage; exit 2; }

    load_milestones || exit 1
    banner
    detect_host_container
    infof "Host CPU: $(host_arch_label); default target slice: ${HOST_CONTAINER#macho-}."

    local tool
    for tool in od dd grep head mktemp cp mv awk; do
        command -v "$tool" >/dev/null 2>&1 || { errf "Required tool '${tool}' not found."; exit 1; }
    done
    command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 || { errf "Need shasum or sha256sum."; exit 1; }

    if [[ -n "$target_path" ]]; then
        [[ -e "$target_path" ]] || { errf "Path does not exist: ${target_path}"; exit 1; }
        resolve_target "$target_path" || exit 1
    else
        infof "Scanning for installed Google Chrome..."
        enumerate_installs
        if $QUIET; then
            (( ${#INSTALLS_APPS[@]} == 1 )) || { errf "Need exactly one install for --quiet; pass a path."; exit 1; }
            CHOSEN_INDEX=0
        else
            choose_install || exit 0
        fi
        APP_PATH="${INSTALLS_APPS[$CHOSEN_INDEX]}"
        resolve_framework_from_app "$APP_PATH" || { errf "No Chrome framework inside ${APP_PATH}"; exit 1; }
    fi

    okf "Framework binary: ${TARGET_FILE}"
    if [[ -n "$APP_PATH" ]]; then
        okf "App bundle: ${APP_PATH}"
    elif [[ "$cmd" != "check" ]]; then
        warnf "No .app resolved: bundle re-signing will be skipped (offline/scratch mode)."
    fi

    if [[ "$cmd" != "check" && -z "${MV2_TEST_NO_ELEVATION:-}" ]]; then
        local dir; dir=$(dirname "$TARGET_FILE")
        if [[ ! -w "$TARGET_FILE" || ! -w "$dir" ]]; then
            errf "Write access is required for ${TARGET_FILE} and its directory."
            echo "    Take ownership of the app, or copy it somewhere writable and patch that."
            exit 1
        fi
    fi

    case "$cmd" in
        restore) do_restore "$TARGET_FILE" "$APP_PATH" "$assume_yes" "$force_restore" ;;
        patch)   do_patch   "$TARGET_FILE" "$APP_PATH" "$assume_yes" "$allow_partial" ;;
        check)   do_check   "$TARGET_FILE" ;;
    esac
}

if [[ -z "${MV2_TEST_LIBRARY_ONLY:-}" ]]; then
    main "$@"
fi

















