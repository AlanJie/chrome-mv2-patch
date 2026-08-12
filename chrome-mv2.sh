#!/usr/bin/env bash
# ============================================================================
# Google Chrome Manifest V2 Patcher — standalone bash script for Linux
#
# Self-contained single-file port of the Go patcher (ELF path only).
# Re-enables Manifest V2 extension support in Google Chrome by flipping the
# inlined IsExtensionAffected manifest-version checks.
#
# Same milestone engine, same match/decline semantics, same .bak handling.
#
# SELF-CONTAINED: the Linux signature tables are EMBEDDED in this file
# ($EMBEDDED_SIGNATURES below), so the script needs no signatures.json and no
# other file to run. If a signatures.json IS present next to the script (or in
# the current directory) it takes precedence, so the tables can still be
# updated without editing the script.
#
# BACKUP SAFETY: uses pure-bash ELF build-id parser to detect Chrome updates.
# Build-id survives patching, so the script can distinguish:
#   - Same build-id = already patched → work from backup (prevents corruption)
#   - Different build-id = Chrome updated → refresh backup to new version
# This ensures the backup always contains clean stock bytes, never patched bytes.
#
# HOW IT PATCHES: for each gate, first probe the RVA recorded in the table -
# cheap, and exact for the build the table was derived from. On a miss, scan
# the whole .text section for the gate's byte signature; that is what relocates
# a gate cleanly across point releases. A site counts as located only when its
# signature matches EXACTLY expectedMatches times: a different count means the
# layout moved, so the site is declined rather than guessed at. The milestone
# with the most located sites wins; one that locates none is declined outright.
# Then flip the gates and write the patched binary.
#
# CARDINAL RULE: never delete or blank a call and never invent control flow -
# only flip the direction of an existing branch to its EXISTING target.
#
#   JG_SHORT  0x7F disp8       -> 0xEB disp8        (jmp short, same disp8)
#   JG_NEAR   0x0F 0x8F disp32 -> 0x90 0xE9 disp32  (nop ; jmp near, same disp32)
#
# Usage:
#   sudo bash chrome-mv2.sh [patch|restore] [path] [--yes] [--quiet]
#
# Requirements: bash 4+, dd, od, grep, head, mktemp, mv, chmod, sync
#               (all coreutils/POSIX - no xxd/vim needed)
# ============================================================================

set -euo pipefail

readonly APP_VERSION="1.2.0"

# ============================================================================
# Embedded ELF signature tables (151-linux & 152-linux).
# Self-contained: the Linux signature tables are EMBEDDED in this file, so the
# script needs no signatures.json to run. If a signatures.json IS present next
# to the script (or in the current directory) it takes precedence, so the tables
# can still be updated without editing the script.
#
# Format: pipe-delimited fields per site, semicolon-delimited sites per
# milestone.  Fields: name|kind|jgRVA|jgOff|expectedMatches|sig
#
# kind: "short" = 7F disp8 → EB disp8;  "near" = 0F 8F disp32 → 90 E9 disp32
# jgRVA: hex RVA of the jg opcode in the reference build (fast-path probe)
# jgOff: byte index of jg opcode within sig
# sig: hex bytes, jg opcode included at jgOff
# ============================================================================

# Embedded signature tables
readonly EMBEDDED_SIGNATURES='
{
  "milestones": [
    {"name":"151-linux","container":"elf","sites":[{"name":"MV2DeprecationImpactChecker::IsExtensionAffected (shared predicate)","kind":"short","jgRVA":"0x067D9F14","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x098D3CC7","jgOff":3,"expectedMatches":1,"sig":"83FE027F1F83FA01751083F9050F95C283F90A0F95C020D05D"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x098D3D0D","jgOff":3,"expectedMatches":1,"sig":"83FA027F298B493083F801751783F9050F95C283F90A0F95C0"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, near jg)","kind":"near","jgRVA":"0x0A3224A3","jgOff":3,"expectedMatches":1,"sig":"83FA020F8FBE0000008B493083F8010F856402000083F9050F84A900"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined)","kind":"short","jgRVA":"0x05E5DB24","jgOff":3,"expectedMatches":1,"sig":"83FA027F7A8B493083F80175684531F683F905740583F90A75"}]},
    {"name":"152-linux","container":"elf","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x0985B449","jgOff":3,"expectedMatches":1,"sig":"83FF027F1D83FE087718B90A0100000FA3F1730E83FA050F95"},{"name":"ManifestV2Handler::IsExtensionAffected / ShouldBlockExtensionEnable (shared body)","kind":"short","jgRVA":"0x0985B0F4","jgOff":4,"expectedMatches":1,"sig":"837E50027F2F554889E5488B8E280200008B413080BE080200"},{"name":"ManifestV2Handler::MaybeReEnableExtension (inlined)","kind":"short","jgRVA":"0x0985B238","jgOff":4,"expectedMatches":1,"sig":"837B50027F30488B8B280200008B413080BB08020000007508"},{"name":"StandardManagementPolicyProvider::UserMayInstall (inlined, near jg)","kind":"near","jgRVA":"0x0A256BAA","jgOff":4,"expectedMatches":1,"sig":"837B50020F8FD1000000488B8B280200008B413080BB080200000075"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x0599A69A","jgOff":4,"expectedMatches":1,"sig":"837E50020F8F8E000000498B8E280200008B41304180BE0802000000"}]}
  ]
}
'

# Runtime variables populated by load_milestones (from external JSON or embedded)
MILESTONE_NAMES=()
MILESTONE_CONTAINERS=()
declare -a MILESTONE_SITES  # Array of arrays (one per milestone)
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
        C_YEL=$'\e[93m'   C_CYN=$'\e[96m'  C_DIM=$'\e[90m'
        C_BOLD=$'\e[1m'
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
    echo "${C_BOLD}        Google Chrome Manifest V2 Patcher (bash)            ${C_RESET}"
    echo "${C_DIM}                    v${APP_VERSION}                       ${C_RESET}"
    rule
}

# ============================================================================
# Signature loading - load from external signatures.json or embedded tables
# ============================================================================

readonly SIGNATURES_FILE="signatures.json"

# Check for external signatures.json: script directory first, then cwd
get_signatures_path() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "$0")")
    
    # Check next to script
    if [[ -f "${script_dir}/${SIGNATURES_FILE}" ]]; then
        echo "${script_dir}/${SIGNATURES_FILE}"
        return 0
    fi
    
    # Check in cwd
    if [[ -f "${SIGNATURES_FILE}" ]]; then
        echo "${SIGNATURES_FILE}"
        return 0
    fi
    
    # Not found
    return 1
}

# Minimal JSON field readers for the fixed signatures schema.  These avoid jq
# and GNU grep -P while still accepting normal pretty-printed JSON whitespace.
json_string_field() {
    local text="$1" key="$2"
    local re="\"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
    if [[ "$text" =~ $re ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

json_number_field() {
    local text="$1" key="$2"
    local re="\"${key}\"[[:space:]]*:[[:space:]]*([0-9]+)"
    if [[ "$text" =~ $re ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    fi
}

# Parse JSON and populate MILESTONE_* arrays without jq or another JSON tool.
load_milestones() {
    local json_data=""
    local src_label=""
    
    # Try external file first
    local sig_path
    if sig_path=$(get_signatures_path); then
        if [[ -r "$sig_path" ]]; then
            json_data=$(cat "$sig_path")
            src_label="$sig_path"
        fi
    fi
    
    # Fall back to embedded
    if [[ -z "$json_data" ]]; then
        json_data="$EMBEDDED_SIGNATURES"
        src_label="embedded tables"
    fi

    # The external document is intentionally human-readable and therefore
    # spans many lines, while the tiny embedded document uses one object per
    # line.  The parser below is deliberately dependency-free and operates on
    # one milestone object at a time, so normalize line endings/whitespace
    # boundaries before extracting objects.
    json_data="${json_data//$'\r'/}"
    json_data="${json_data//$'\n'/}"
    
    # Parse the constrained signatures schema manually (no jq dependency).
    MILESTONE_NAMES=()
    MILESTONE_CONTAINERS=()
    NUM_MILESTONES=0

    local milestone_idx=0
    local remaining="$json_data"
    local milestone_re='(\{[[:space:]]*"name"[[:space:]]*:[[:space:]]*"[^"]+"[[:space:]]*,[[:space:]]*"container"[[:space:]]*:[[:space:]]*"[^"]+"[[:space:]]*,[[:space:]]*"sites"[[:space:]]*:[[:space:]]*\[[^]]*\][[:space:]]*\})'

    while [[ "$remaining" =~ $milestone_re ]]; do
        local ms_line="${BASH_REMATCH[1]}"
        remaining="${remaining#*"${BASH_REMATCH[0]}"}"

        # Extract name
        local name
        name=$(json_string_field "$ms_line" "name")

        # Extract container
        local container
        container=$(json_string_field "$ms_line" "container")

        if [[ -z "$name" || -z "$container" ]]; then
            continue
        fi

        MILESTONE_NAMES+=("$name")
        MILESTONE_CONTAINERS+=("$container")

        # Parse sites array for this milestone
        local sites_json=""
        local sites_re='"sites"[[:space:]]*:[[:space:]]*\[([^]]*)\]'
        if [[ "$ms_line" =~ $sites_re ]]; then
            sites_json="${BASH_REMATCH[1]}"
        fi

        # Create a variable name for this milestone's sites
        local sites_var="MILESTONE_${milestone_idx}_SITES"
        declare -g -a "$sites_var"

        # Parse each site
        local site_specs=()
        local site_re='(\{[^{}]*\})'
        while [[ "$sites_json" =~ $site_re ]]; do
            local site_obj="${BASH_REMATCH[1]}"
            sites_json="${sites_json#*"${BASH_REMATCH[0]}"}"

            local s_name s_kind s_jgrva s_jgoff s_expected s_sig
            s_name=$(json_string_field "$site_obj" "name")
            s_kind=$(json_string_field "$site_obj" "kind")
            s_jgrva=$(json_string_field "$site_obj" "jgRVA")
            s_jgoff=$(json_number_field "$site_obj" "jgOff")
            s_expected=$(json_number_field "$site_obj" "expectedMatches")
            s_sig=$(json_string_field "$site_obj" "sig")

            if [[ -n "$s_name" && -n "$s_kind" && -n "$s_jgrva" ]]; then
                local spec="${s_name}|${s_kind}|${s_jgrva}|${s_jgoff}|${s_expected}|${s_sig}"
                site_specs+=("$spec")
            fi
        done

        # Assign sites to the milestone variable
        eval "${sites_var}=(\"\${site_specs[@]}\")"

        ((milestone_idx++)) || true
    done

    NUM_MILESTONES=$milestone_idx
    
    if (( NUM_MILESTONES == 0 )); then
        errf "Failed to parse signature data from ${src_label}"
        return 1
    fi
    
    okf "Loaded ${NUM_MILESTONES} milestone(s) from ${src_label}"
    return 0
}

# ============================================================================
# Binary read helpers — read LE integers from a file at a given offset.
# Uses od to read raw bytes and assemble them in little-endian order.
# ============================================================================

# read_u16_le <file> <offset> → prints decimal value
read_u16_le() {
    local file="$1" offset="$2"
    local bytes
    bytes=$(od -A n -t x1 -j "$offset" -N 2 "$file" | tr -d ' \n')
    echo $(( 16#${bytes:2:2}${bytes:0:2} ))
}

# read_u32_le <file> <offset> → prints decimal value
read_u32_le() {
    local file="$1" offset="$2"
    local bytes
    bytes=$(od -A n -t x1 -j "$offset" -N 4 "$file" | tr -d ' \n')
    echo $(( 16#${bytes:6:2}${bytes:4:2}${bytes:2:2}${bytes:0:2} ))
}

# read_u64_le <file> <offset> → prints decimal value
read_u64_le() {
    local file="$1" offset="$2"
    local bytes
    bytes=$(od -A n -t x1 -j "$offset" -N 8 "$file" | tr -d ' \n')
    # bash arithmetic can handle 64-bit on 64-bit systems
    echo $(( 16#${bytes:14:2}${bytes:12:2}${bytes:10:2}${bytes:8:2}${bytes:6:2}${bytes:4:2}${bytes:2:2}${bytes:0:2} ))
}

# read_bytes_hex <file> <offset> <count> → prints uppercase hex string (no spaces)
# od is coreutils/POSIX and -j seeks directly, so no xxd and no per-byte dd.
read_bytes_hex() {
    local file="$1" offset="$2" count="$3"
    od -A n -v -t x1 -j "$offset" -N "$count" "$file" | tr -d ' \n' | tr 'a-f' 'A-F'
}

# read_byte <file> <offset> → prints decimal value of one byte
read_byte() {
    local file="$1" offset="$2"
    local hex
    hex=$(od -A n -t x1 -j "$offset" -N 1 "$file" | tr -d ' \n')
    echo $(( 16#$hex ))
}

# ============================================================================
# ELF64 parser — locate .text section (vaddr, file offset, size).
# Returns via global variables: TEXT_VADDR, TEXT_RAW, TEXT_SIZE
# ============================================================================

TEXT_VADDR=0
TEXT_RAW=0
TEXT_SIZE=0

# ============================================================================
# ELF build-id extractor — reads GNU build-id from .note.gnu.build-id section.
# Returns build-id as hex string, or empty string if not found.
# ============================================================================

get_elf_build_id() {
    local file="$1"
    local fsize
    fsize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)

    if (( fsize < 64 )); then
        echo ""
        return 1
    fi

    # Verify ELF magic and 64-bit little-endian
    local magic
    magic=$(read_bytes_hex "$file" 0 4)
    if [[ "$magic" != "7F454C46" ]]; then
        echo ""
        return 1
    fi

    local ei_class ei_data
    ei_class=$(read_byte "$file" 4)
    ei_data=$(read_byte "$file" 5)
    if (( ei_class != 2 || ei_data != 1 )); then
        echo ""
        return 1
    fi

    # Read section header table info
    local shoff shentsize shnum shstrndx
    shoff=$(read_u64_le "$file" $((0x28)))
    shentsize=$(read_u16_le "$file" $((0x3A)))
    shnum=$(read_u16_le "$file" $((0x3C)))
    shstrndx=$(read_u16_le "$file" $((0x3E)))

    if (( shoff == 0 || shnum == 0 )); then
        echo ""
        return 1
    fi

    # Locate .shstrtab for section name resolution
    local strhdr_off str_off str_size
    strhdr_off=$(( shoff + shstrndx * shentsize ))
    str_off=$(read_u64_le "$file" $(( strhdr_off + 0x18 )))
    str_size=$(read_u64_le "$file" $(( strhdr_off + 0x20 )))

    # Find .note.gnu.build-id section
    local i sh_off name_off sec_name sec_off sec_size
    for (( i = 0; i < shnum; i++ )); do
        sh_off=$(( shoff + i * shentsize ))
        name_off=$(read_u32_le "$file" "$sh_off")

        # Read section name (NUL-terminated string)
        sec_name=$(dd if="$file" bs=1 skip=$(( str_off + name_off )) count=32 2>/dev/null | tr '\0' '\n' | head -1)

        if [[ "$sec_name" == ".note.gnu.build-id" ]]; then
            sec_off=$(read_u64_le "$file" $(( sh_off + 0x18 )))
            sec_size=$(read_u64_le "$file" $(( sh_off + 0x20 )))

            if (( sec_size < 16 )); then
                echo ""
                return 1
            fi

            # Parse ELF note structure:
            # struct Elf64_Nhdr { uint32 namesz; uint32 descsz; uint32 type; }
            # followed by: name (namesz bytes, padded to 4), desc (descsz bytes)
            local namesz descsz note_type
            namesz=$(read_u32_le "$file" "$sec_off")
            descsz=$(read_u32_le "$file" $(( sec_off + 4 )))
            note_type=$(read_u32_le "$file" $(( sec_off + 8 )))

            # NT_GNU_BUILD_ID = 3
            if (( note_type == 3 && descsz > 0 && descsz <= 64 )); then
                # name starts at offset 12, desc starts after name (padded to 4-byte boundary)
                local name_padded
                name_padded=$(( (namesz + 3) / 4 * 4 ))
                local desc_off
                desc_off=$(( sec_off + 12 + name_padded ))

                # Read build-id (desc field) as hex
                local build_id
                build_id=$(read_bytes_hex "$file" "$desc_off" "$descsz")
                echo "$build_id"
                return 0
            fi
            break
        fi
    done

    echo ""
    return 1
}

parse_elf() {
    local file="$1"
    local fsize
    fsize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)

    if (( fsize < 64 )); then
        errf "Not a valid ELF: file too small (${fsize} bytes)."
        return 1
    fi

    # Check ELF magic: 7F 45 4C 46
    local magic
    magic=$(read_bytes_hex "$file" 0 4)
    if [[ "$magic" != "7F454C46" ]]; then
        errf "Not an ELF file (magic: ${magic})."
        return 1
    fi

    # Check 64-bit (class = 2) and little-endian (data = 1)
    local ei_class ei_data
    ei_class=$(read_byte "$file" 4)
    ei_data=$(read_byte "$file" 5)
    if (( ei_class != 2 )); then
        errf "Not a 64-bit ELF (EI_CLASS=${ei_class})."
        return 1
    fi
    if (( ei_data != 1 )); then
        errf "Not a little-endian ELF (EI_DATA=${ei_data})."
        return 1
    fi

    # Section header table offset, entry size, count, and shstrtab index
    local shoff shentsize shnum shstrndx
    shoff=$(read_u64_le "$file" $((0x28)))
    shentsize=$(read_u16_le "$file" $((0x3A)))
    shnum=$(read_u16_le "$file" $((0x3C)))
    shstrndx=$(read_u16_le "$file" $((0x3E)))

    if (( shoff == 0 || shnum == 0 )); then
        errf "ELF has no section table (fully stripped?)."
        return 1
    fi

    # Locate .shstrtab to resolve section names
    local strhdr_off str_off str_size
    strhdr_off=$(( shoff + shstrndx * shentsize ))
    str_off=$(read_u64_le "$file" $(( strhdr_off + 0x18 )))
    str_size=$(read_u64_le "$file" $(( strhdr_off + 0x20 )))

    # Iterate sections to find .text
    local i sh_off name_off sec_name
    TEXT_VADDR=0; TEXT_RAW=0; TEXT_SIZE=0
    for (( i = 0; i < shnum; i++ )); do
        sh_off=$(( shoff + i * shentsize ))
        name_off=$(read_u32_le "$file" "$sh_off")

        # Read section name from .shstrtab (NUL-terminated)
        sec_name=$(dd if="$file" bs=1 skip=$(( str_off + name_off )) count=16 2>/dev/null | tr '\0' '\n' | head -1)

        if [[ "$sec_name" == ".text" ]]; then
            TEXT_VADDR=$(read_u64_le "$file" $(( sh_off + 0x10 )))
            TEXT_RAW=$(read_u64_le "$file" $(( sh_off + 0x18 )))
            TEXT_SIZE=$(read_u64_le "$file" $(( sh_off + 0x20 )))
            break
        fi
    done

    if (( TEXT_SIZE == 0 )); then
        errf "Could not locate .text section."
        return 1
    fi

    okf "ELF64 parsed: .text vaddr=0x$(printf '%X' $TEXT_VADDR) offset=0x$(printf '%X' $TEXT_RAW) size=0x$(printf '%X' $TEXT_SIZE) ($(( TEXT_SIZE / 1024 / 1024 )) MiB)"
    return 0
}

# ============================================================================
# Signature matching engine
#
# For each site, first try the fast path (probe the known RVA), then use one
# raw-byte fixed-anchor scan shared by every unresolved signature.  A site is
# accepted only when the match count equals expectedMatches exactly.
# ============================================================================

# The raw backend is available on the grep implementations shipped by the
# mainstream Linux distributions.  It is deliberately feature-tested instead
# of assuming GNU grep or requiring another package.
init_scan_backend() {
    # -f with multiple binary patterns is the feature the fast path needs.
    # A newline terminates a grep pattern, so an anchor itself must not contain
    # newline (enforced by build_binary_anchor).
    local probe_patterns
    probe_patterns=$(mktemp /tmp/chrome-mv2-probe.XXXXXX)
    printf 'x\ny\n' > "$probe_patterns"
    local ok=false
    if printf 'xy' | LC_ALL=C grep -a -o -b -F -f "$probe_patterns" >/dev/null 2>&1; then ok=true; fi
    rm -f -- "$probe_patterns"
    if ! $ok; then
        errf "This grep does not support the required raw fixed-string options (-a -o -b -F -f)."
        echo "    Installations from mainstream Linux distributions include a compatible grep."
        return 1
    fi
}

    # Build the longest exact anchor that can safely be passed as a shell/grep
    # match. NUL cannot be stored in a Bash variable, while newline and colon
    # terminate or split grep's byte-offset output record, so split exact runs
    # around all three bytes.
BINARY_ANCHOR_HEX=""
BINARY_ANCHOR_OFF=0
build_binary_anchor() {
    local sig="${1,,}" kind="$2" jg_off="$3"
    local sig_bytes=$(( ${#sig} / 2 )) mask_len=2
    [[ "$kind" == "near" ]] && mask_len=6
    local mask_end=$(( jg_off + mask_len ))

    BINARY_ANCHOR_HEX=""
    BINARY_ANCHOR_OFF=0
    local best_len=0 best_start=0 start end byte run_len
    for (( start = 0; start < sig_bytes; start++ )); do
        run_len=0
        for (( end = start; end < sig_bytes; end++ )); do
            if (( end >= jg_off && end < mask_end )); then break; fi
            byte="${sig:$(( end * 2 )):2}"
            if [[ "$byte" == "00" || "$byte" == "0a" || "$byte" == "3a" ]]; then break; fi
            (( run_len += 1 )) || true
        done
        if (( run_len > best_len )); then
            best_len=$run_len
            best_start=$start
        fi
    done

    # A tiny anchor creates too many candidates and defeats the purpose of the
    # raw backend. Signature tables must provide at least one safe 4-byte run.
    if (( best_len >= 4 )); then
        BINARY_ANCHOR_HEX="${sig:$(( best_start * 2 )):$(( best_len * 2 ))}"
        BINARY_ANCHOR_OFF=$best_start
    fi
}

# sig_matches_at <file> <file_offset> <sig_hex> <kind> <jg_off> → 0 if matches
sig_matches_at() {
    local file="$1" file_offset="$2" sig_hex="$3" kind="$4" jg_off="$5"
    local sig_len=$(( ${#sig_hex} / 2 ))
    local actual
    actual=$(read_bytes_hex "$file" "$file_offset" "$sig_len")

    local sig_upper="${sig_hex^^}"

    # Compare byte by byte, masking the jg opcode and displacement
    local i byte_idx
    for (( i = 0; i < ${#sig_upper}; i += 2 )); do
        byte_idx=$(( i / 2 ))
        local sig_byte="${sig_upper:$i:2}"
        local act_byte="${actual:$i:2}"

        if [[ "$kind" == "short" ]]; then
            if (( byte_idx == jg_off )); then
                # jg opcode: accept 7F (stock) or EB (flipped)
                if [[ "$act_byte" != "7F" && "$act_byte" != "EB" ]]; then return 1; fi
                continue
            elif (( byte_idx == jg_off + 1 )); then
                # disp8: wildcard
                continue
            fi
        else  # near
            if (( byte_idx == jg_off )); then
                # The two opcode bytes are a pair: accept only stock 0F 8F or
                # already-flipped 90 E9, never a mixed pair.
                local act_pair="${actual:$i:4}"
                if [[ "$act_pair" != "0F8F" && "$act_pair" != "90E9" ]]; then return 1; fi
                continue
            elif (( byte_idx == jg_off + 1 )); then
                continue
            elif (( byte_idx >= jg_off + 2 && byte_idx <= jg_off + 5 )); then
                # disp32: wildcard
                continue
            fi
        fi

        # Exact match required
        if [[ "$sig_byte" != "$act_byte" ]]; then return 1; fi
    done
    return 0
}

# Results from the one-pass raw scan, keyed by kind|jgOff|signature.  The scan
# is lazy: an exact recorded-RVA build never pays for it.
declare -A GLOBAL_SCAN_DONE=()
declare -A GLOBAL_SCAN_MATCHES=()
GLOBAL_SCAN_SOURCE=""
GLOBAL_SCAN_TEXT_RAW=-1
GLOBAL_SCAN_TEXT_SIZE=-1
SCAN_PATTERNS_FILE=""

prepare_global_raw_scan() {
    local file="$1"
    if [[ "$GLOBAL_SCAN_SOURCE" == "$file" && $GLOBAL_SCAN_TEXT_RAW -eq $TEXT_RAW && $GLOBAL_SCAN_TEXT_SIZE -eq $TEXT_SIZE ]]; then
        return 0
    fi

    GLOBAL_SCAN_DONE=()
    GLOBAL_SCAN_MATCHES=()
    GLOBAL_SCAN_SOURCE="$file"
    GLOBAL_SCAN_TEXT_RAW=$TEXT_RAW
    GLOBAL_SCAN_TEXT_SIZE=$TEXT_SIZE

    # Bash read applies the current locale while decoding grep's raw-byte
    # output.  Invalid UTF-8 bytes can otherwise make it stop after the first
    # match.  Keep both grep and the reader in the byte-oriented C locale.
    local LC_ALL=C

    local patterns_file
    patterns_file=$(mktemp /tmp/chrome-mv2-patterns.XXXXXX)
    SCAN_PATTERNS_FILE="$patterns_file"

    local -A anchor_seen=()
    local -A anchor_to_keys=()
    local -A key_anchor_off=()
    local mi site_spec name kind jg_rva_hex jg_off expected_matches sig_hex
    local key anchor_hex anchor_bin ai abyte

    for (( mi = 0; mi < NUM_MILESTONES; mi++ )); do
        [[ "${MILESTONE_CONTAINERS[$mi]}" == "elf" ]] || continue
        local sites_var="MILESTONE_${mi}_SITES[@]"
        local sites=("${!sites_var}")
        for site_spec in "${sites[@]}"; do
            IFS='|' read -r name kind jg_rva_hex jg_off expected_matches sig_hex <<< "$site_spec"
            sig_hex="${sig_hex^^}"
            key="${kind}|${jg_off}|${sig_hex}"
            [[ -n "${GLOBAL_SCAN_DONE[$key]+x}" ]] && continue

            build_binary_anchor "$sig_hex" "$kind" "$jg_off"
            anchor_hex="$BINARY_ANCHOR_HEX"
            if [[ -z "$anchor_hex" ]]; then
                errf "Signature has no safe raw scan anchor: ${name}"
                rm -f -- "$patterns_file"
                SCAN_PATTERNS_FILE=""
                return 1
            fi

            anchor_bin=""
            for (( ai = 0; ai < ${#anchor_hex}; ai += 2 )); do
                abyte="${anchor_hex:ai:2}"
                printf -v abyte '%b' "\\x${abyte}"
                anchor_bin+="$abyte"
            done

            GLOBAL_SCAN_DONE["$key"]=1
            GLOBAL_SCAN_MATCHES["$key"]=""
            key_anchor_off["$key"]=$BINARY_ANCHOR_OFF
            if [[ -z "${anchor_seen[$anchor_bin]+x}" ]]; then
                anchor_seen["$anchor_bin"]=1
                printf '%s\n' "$anchor_bin" >> "$patterns_file"
            fi
            if [[ -n "${anchor_to_keys[$anchor_bin]-}" ]]; then
                anchor_to_keys["$anchor_bin"]+=" $key"
            else
                anchor_to_keys["$anchor_bin"]="$key"
            fi
        done
    done

    if [[ ! -s "$patterns_file" ]]; then
        rm -f -- "$patterns_file"
        SCAN_PATTERNS_FILE=""
        return 0
    fi

    infof "Scanning raw signature candidates in one fixed-string pass..."
    local anchor_pos keys sig_start sig_end jg_file_offset existing
    while IFS=: read -r anchor_pos anchor_bin; do
        [[ "$anchor_pos" =~ ^[0-9]+$ ]] || continue
        keys="${anchor_to_keys[$anchor_bin]-}"
        [[ -n "$keys" ]] || continue
        for key in $keys; do
            IFS='|' read -r kind jg_off sig_hex <<< "$key"
            sig_start=$(( anchor_pos - key_anchor_off[$key] ))
            sig_end=$(( sig_start + ${#sig_hex} / 2 ))
            if (( sig_start < TEXT_RAW || sig_end > TEXT_RAW + TEXT_SIZE )); then continue; fi
            if sig_matches_at "$file" "$sig_start" "$sig_hex" "$kind" "$jg_off"; then
                jg_file_offset=$(( sig_start + jg_off ))
                existing=" ${GLOBAL_SCAN_MATCHES[$key]-} "
                if [[ "$existing" != *" $jg_file_offset "* ]]; then
                    if [[ -n "${GLOBAL_SCAN_MATCHES[$key]}" ]]; then
                        GLOBAL_SCAN_MATCHES["$key"]+=" $jg_file_offset"
                    else
                        GLOBAL_SCAN_MATCHES["$key"]="$jg_file_offset"
                    fi
                fi
            fi
        done
    done < <(LC_ALL=C grep -a -o -b -F -f "$patterns_file" -- "$file" 2>/dev/null || true)

    rm -f -- "$patterns_file"
    SCAN_PATTERNS_FILE=""
}

# find_site_matches <file> <site_spec> → sets FOUND_OFFSETS array and RELOCATED flag
# site_spec is "name|kind|jgRVA|jgOff|expectedMatches|sig"
FOUND_OFFSETS=()
RELOCATED=false
FAST_PROBE_ONLY=false

find_site_matches() {
    local file="$1"
    local name kind jg_rva_hex jg_off expected_matches sig_hex
    IFS='|' read -r name kind jg_rva_hex jg_off expected_matches sig_hex <<< "$2"

    local jg_rva=$(( jg_rva_hex ))
    local sig_len=$(( ${#sig_hex} / 2 ))

    FOUND_OFFSETS=()
    RELOCATED=false

    # Fast path: probe the known RVA (only when expectedMatches == 1)
    if (( expected_matches == 1 && jg_rva >= TEXT_VADDR )); then
        local rva_in_text=$(( jg_rva - TEXT_VADDR ))
        if (( rva_in_text < TEXT_SIZE )); then
            local jg_raw=$(( TEXT_RAW + rva_in_text ))
            local sig_start=$(( jg_raw - jg_off ))
            if (( sig_start >= TEXT_RAW && sig_start + sig_len <= TEXT_RAW + TEXT_SIZE )) && sig_matches_at "$file" "$sig_start" "$sig_hex" "$kind" "$jg_off"; then
                FOUND_OFFSETS=("$jg_raw")
                RELOCATED=false
                return 0
            fi
        fi
    fi

    if $FAST_PROBE_ONLY; then
        return 0
    fi

    # Slow path: one global raw fixed-string pass is shared by every unresolved
    # site and milestone.  The full masked verifier remains authoritative.
    local matches=()
    local scan_key="${kind}|${jg_off}|${sig_hex^^}"
    prepare_global_raw_scan "$file" || return 1
    if [[ -n "${GLOBAL_SCAN_MATCHES[$scan_key]-}" ]]; then
        read -r -a matches <<< "${GLOBAL_SCAN_MATCHES[$scan_key]}"
        if (( ${#matches[@]} > expected_matches + 1 )); then
            matches=("${matches[@]:0:$(( expected_matches + 1 ))}")
        fi
    fi

    if (( ${#matches[@]} > 0 )); then
        FOUND_OFFSETS=("${matches[@]}")
        RELOCATED=true
    fi
    return 0
}

# ============================================================================
# Milestone probing — find the best-matching milestone
# ============================================================================

# Results set by probe_milestones:
BEST_MS_INDEX=-1
BEST_MS_NAME=""
BEST_SATISFIED=0
BEST_TOTAL=0
BEST_FULL=false
# Arrays for the best milestone's flips:
FLIP_NAMES=()
FLIP_KINDS=()
FLIP_OFFSETS=()
FLIP_RELOCATED=()

reset_probe_results() {
    BEST_MS_INDEX=-1
    BEST_MS_NAME=""
    BEST_SATISFIED=0
    BEST_TOTAL=0
    BEST_FULL=false
    FLIP_NAMES=()
    FLIP_KINDS=()
    FLIP_OFFSETS=()
    FLIP_RELOCATED=()
}

probe_milestones_pass() {
    local file="$1"

    local mi
    for (( mi = 0; mi < NUM_MILESTONES; mi++ )); do
        local ms_container="${MILESTONE_CONTAINERS[$mi]}"
        # Only probe ELF milestones
        if [[ "$ms_container" != "elf" ]]; then continue; fi

        local ms_name="${MILESTONE_NAMES[$mi]}"
        local sites_var="MILESTONE_${mi}_SITES[@]"
        local sites=("${!sites_var}")
        local satisfied=0
        local flip_names_tmp=() flip_kinds_tmp=() flip_offsets_tmp=() flip_relocated_tmp=()

        local site_spec
        for site_spec in "${sites[@]}"; do
            local s_name s_kind s_jgrva s_jgoff s_expected s_sig
            IFS='|' read -r s_name s_kind s_jgrva s_jgoff s_expected s_sig <<< "$site_spec"

            find_site_matches "$file" "$site_spec"

            if (( ${#FOUND_OFFSETS[@]} == s_expected )); then
                (( satisfied++ )) || true
                local off
                for off in "${FOUND_OFFSETS[@]}"; do
                    flip_names_tmp+=("$s_name")
                    flip_kinds_tmp+=("$s_kind")
                    flip_offsets_tmp+=("$off")
                    flip_relocated_tmp+=("$RELOCATED")
                done
            fi
        done

        if (( satisfied > BEST_SATISFIED )); then
            BEST_MS_INDEX=$mi
            BEST_MS_NAME="$ms_name"
            BEST_SATISFIED=$satisfied
            BEST_TOTAL=${#sites[@]}
            FLIP_NAMES=("${flip_names_tmp[@]}")
            FLIP_KINDS=("${flip_kinds_tmp[@]}")
            FLIP_OFFSETS=("${flip_offsets_tmp[@]}")
            FLIP_RELOCATED=("${flip_relocated_tmp[@]}")

            # Short-circuit: if this milestone satisfied every site, no other
            # milestone can beat it — skip the rest (avoids the expensive hex
            # dump for the remaining milestones).
            if (( satisfied == ${#sites[@]} )); then break; fi
        fi
    done

    if (( BEST_SATISFIED == BEST_TOTAL && BEST_TOTAL > 0 )); then
        BEST_FULL=true
    else
        BEST_FULL=false
    fi
}

probe_milestones() {
    local file="$1"

    # First probe every milestone only at its recorded RVAs.  This prevents an
    # older table from triggering a full scan before a newer exact-build table
    # has had a chance to win immediately.
    reset_probe_results
    FAST_PROBE_ONLY=true
    probe_milestones_pass "$file"
    FAST_PROBE_ONLY=false
    if $BEST_FULL; then
        return 0
    fi

    # At least one site moved (or has expectedMatches > 1).  Run the normal
    # pass; its first miss lazily performs one shared raw scan for all tables.
    reset_probe_results
    probe_milestones_pass "$file"
}

# ============================================================================
# Flip engine — apply the jg → jmp flips
# ============================================================================

PATCH_STATUS=0   # 0=declined, 1=flips applied, 2=all already applied
PATCH_FLIPS=0
WRITTEN_RVAS=()
WRITTEN_BYTES=()

apply_flips() {
    local file="$1"
    local applied=0 already=0
    local i

    PATCH_STATUS=0
    PATCH_FLIPS=0
    WRITTEN_RVAS=()
    WRITTEN_BYTES=()

    infof "Chrome ${BEST_MS_NAME} MV2 layout detected (${BEST_SATISFIED}/${BEST_TOTAL} inlined IsExtensionAffected sites, ${#FLIP_OFFSETS[@]} jg flip(s))."

    for (( i = 0; i < ${#FLIP_OFFSETS[@]}; i++ )); do
        local name="${FLIP_NAMES[$i]}"
        local kind="${FLIP_KINDS[$i]}"
        local offset="${FLIP_OFFSETS[$i]}"
        local relocated="${FLIP_RELOCATED[$i]}"
        local rva=$(( TEXT_VADDR + (offset - TEXT_RAW) ))
        local rva_hex
        rva_hex=$(printf '0x%X' "$rva")

        if [[ "$kind" == "short" ]]; then
            local cur
            cur=$(read_byte "$file" "$offset")

            if (( cur == 0xEB )); then
                echo "    [i] ${BEST_MS_NAME}: ${name} jg->jmp at RVA ${rva_hex} already applied (no change)."
                (( already++ )) || true
                WRITTEN_RVAS+=("$rva")
                WRITTEN_BYTES+=("EB")
                continue
            fi
            if (( cur != 0x7F )); then
                echo "    ${TAG_WARN} ${BEST_MS_NAME}: ${name} unexpected byte 0x$(printf '%X' $cur) at RVA ${rva_hex} (expected 0x7F) - skipping this site."
                continue
            fi

            # Write the flip: 0x7F → 0xEB
            printf '\xEB' | dd of="$file" bs=1 seek="$offset" count=1 conv=notrunc 2>/dev/null
            (( applied++ )) || true
            (( PATCH_FLIPS++ )) || true
            WRITTEN_RVAS+=("$rva")
            WRITTEN_BYTES+=("EB")

        else  # near: 0F 8F → 90 E9
            local o0 o1
            o0=$(read_byte "$file" "$offset")
            o1=$(read_byte "$file" $(( offset + 1 )))

            if (( o0 == 0x90 && o1 == 0xE9 )); then
                echo "    [i] ${BEST_MS_NAME}: ${name} jg->jmp at RVA ${rva_hex} already applied (no change)."
                (( already++ )) || true
                WRITTEN_RVAS+=("$rva")
                WRITTEN_BYTES+=("90E9")
                continue
            fi
            if ! (( o0 == 0x0F && o1 == 0x8F )); then
                echo "    ${TAG_WARN} ${BEST_MS_NAME}: ${name} unexpected bytes 0x$(printf '%X' $o0) 0x$(printf '%X' $o1) at RVA ${rva_hex} (expected 0F 8F) - skipping this site."
                continue
            fi

            # Write the flip: 0F 8F → 90 E9
            printf '\x90\xE9' | dd of="$file" bs=1 seek="$offset" count=2 conv=notrunc 2>/dev/null
            (( applied++ )) || true
            (( PATCH_FLIPS++ )) || true
            WRITTEN_RVAS+=("$rva")
            WRITTEN_BYTES+=("90E9")
        fi

        local suffix=""
        if [[ "$relocated" == "true" ]]; then
            suffix="  (RELOCATED - point-release layout)"
        fi
        echo "    ${TAG_OK} ${BEST_MS_NAME}: ${name} jg->jmp at RVA ${rva_hex}${suffix}"
    done

    (( PATCH_FLIPS += already )) || true

    if ! $BEST_FULL; then
        echo "    ${TAG_WARN} Chrome ${BEST_MS_NAME}: $(( BEST_TOTAL - BEST_SATISFIED )) site(s) not found - this Chrome build may have shifted them."
        echo "          MV2 re-enable is PARTIAL and may still be blocked; please report the version."
    fi

    if (( applied > 0 )); then
        PATCH_STATUS=1
    else
        PATCH_STATUS=2
    fi
}

# ============================================================================
# Report-only candidate scanner — structural scan for cmp r/m32,2 ; jg
# ============================================================================

report_layout_candidates() {
    local file="$1"
    if (( TEXT_SIZE < 8 )); then return; fi

    infof "Scanning .text for the IsExtensionAffected skeleton (cmp r/m32,2 ; jg short ; ... ; type/location check)..."

    local total=0 shown=0
    local max_display=20
    local marker
    printf -v marker '%b' '\x02\x7f'

    # Search raw bytes for the immediate/opcode pair 02 7F, then validate the
    # cmp encoding before it and the type/location check after it.
    local LC_ALL=C
    while IFS=: read -r marker_pos _match; do
        [[ "$marker_pos" =~ ^[0-9]+$ ]] || continue
        if (( marker_pos < TEXT_RAW + 2 || marker_pos + 2 > TEXT_RAW + TEXT_SIZE )); then continue; fi

        local valid=false cmp_back=0 ctx
        ctx=$(read_bytes_hex "$file" $(( marker_pos - 2 )) 2)
        # reg form: 83 F8..FF 02 7F
        if [[ "$ctx" =~ ^83F[89A-F]$ ]]; then
            valid=true
            cmp_back=2
        fi
        # disp8 form: 83 78..7F disp8 02 7F
        if ! $valid && (( marker_pos >= TEXT_RAW + 3 )); then
            ctx=$(read_bytes_hex "$file" $(( marker_pos - 3 )) 3)
            if [[ "$ctx" =~ ^837[89A-F][[:xdigit:]]{2}$ ]]; then
                valid=true
                cmp_back=3
            fi
        fi

        if ! $valid; then continue; fi

        # Follow-up check within ~40 bytes after the jg
        local follow_start=$(( marker_pos + 2 ))
        local follow_count=40
        if (( follow_start + follow_count > TEXT_RAW + TEXT_SIZE )); then
            follow_count=$(( TEXT_RAW + TEXT_SIZE - follow_start ))
        fi
        local follow_region=""
        if (( follow_count > 0 )); then
            follow_region=$(read_bytes_hex "$file" "$follow_start" "$follow_count")
        fi

        local has_follow=false
        # cmp reg, 1 or cmp reg, 5
        if [[ "$follow_region" =~ 83F[89A-F]0[15] ]]; then has_follow=true; fi
        # cmp byte [reg+disp32], 0
        if ! $has_follow && [[ "$follow_region" =~ 80B[89A-F][[:xdigit:]]{8}00 ]]; then has_follow=true; fi

        if ! $has_follow; then continue; fi

        (( total++ )) || true
        if (( shown < max_display )); then
            local rva=$(( TEXT_VADDR + marker_pos - TEXT_RAW - cmp_back ))
            printf "    [candidate] RVA 0x%X\n" "$rva"
            (( shown++ )) || true
        fi
    done < <(LC_ALL=C grep -a -o -b -F -- "$marker" "$file" 2>/dev/null || true)

    local extra=""
    if (( total > shown )); then extra=" ($((total - shown)) not shown)"; fi
    infof "Skeleton scan found ${total} candidate site(s)${extra}. None were modified - verify each against mv2-reversing.md before hand-patching."
}

# ============================================================================
# Linux platform glue
# ============================================================================

# Chrome install channels on Linux
LINUX_CHANNELS=("Stable" "Beta" "Dev")
LINUX_DIRS=("/opt/google/chrome" "/opt/google/chrome-beta" "/opt/google/chrome-unstable")

# Get Chrome version from binary
chrome_version() {
    local bin="$1"
    local ver
    ver=$("$bin" --version 2>/dev/null | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    echo "$ver"
}

# Count processes holding the binary open
proc_holders() {
    local bin="$1"
    local want
    want=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
    local count=0
    local pid_dir
    for pid_dir in /proc/[0-9]*/exe; do
        local target
        target=$(readlink "$pid_dir" 2>/dev/null || true)
        if [[ -z "$target" ]]; then continue; fi
        # A replaced binary shows up as "<path> (deleted)"
        if [[ "$target" == "$want" || "$target" == "$bin" || "$target" == "${want} (deleted)" || "$target" == "${bin} (deleted)" ]]; then
            (( count++ )) || true
        fi
    done
    echo "$count"
}

# Kill processes holding the binary
kill_chrome_processes() {
    local bin="$1"
    local want
    want=$(readlink -f "$bin" 2>/dev/null || echo "$bin")
    local pid_dir
    for pid_dir in /proc/[0-9]*/exe; do
        local target pid
        target=$(readlink "$pid_dir" 2>/dev/null || true)
        if [[ -z "$target" ]]; then continue; fi
        if [[ "$target" == "$want" || "$target" == "$bin" || "$target" == "${want} (deleted)" || "$target" == "${bin} (deleted)" ]]; then
            pid="${pid_dir#/proc/}"
            pid="${pid%%/*}"
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Wait up to 5 seconds for them to die
    local i
    for (( i = 0; i < 20; i++ )); do
        if (( $(proc_holders "$bin") == 0 )); then return 0; fi
        sleep 0.25
    done
    # Still running — the rename will still succeed (old inode stays mapped)
    return 0
}

# Atomic write: temp file + sync + rename (sidesteps ETXTBSY)
write_target() {
    local target="$1" source="$2"
    local dir mode
    dir=$(dirname "$target")
    mode=$(stat -c%a "$target" 2>/dev/null || echo "755")

    local tmp
    tmp=$(mktemp "${dir}/.chrome-mv2-XXXXXX")

    cp "$source" "$tmp"
    sync "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$target"
}

# ============================================================================
# Install discovery
# ============================================================================

INSTALLS_CHANNELS=()
INSTALLS_PATHS=()
INSTALLS_VERSIONS=()
INSTALLS_RUNNING=()
INSTALLS_HOLDERS=()
INSTALLS_BACKUPS=()

enumerate_installs() {
    INSTALLS_CHANNELS=()
    INSTALLS_PATHS=()
    INSTALLS_VERSIONS=()
    INSTALLS_RUNNING=()
    INSTALLS_HOLDERS=()
    INSTALLS_BACKUPS=()

    local i
    for (( i = 0; i < ${#LINUX_CHANNELS[@]}; i++ )); do
        local bin="${LINUX_DIRS[$i]}/chrome"
        if [[ ! -f "$bin" ]]; then continue; fi

        local ver holders has_backup running
        ver=$(chrome_version "$bin")
        holders=$(proc_holders "$bin")
        if (( holders > 0 )); then running=true; else running=false; fi
        if [[ -f "${bin}.bak" ]]; then has_backup=true; else has_backup=false; fi

        INSTALLS_CHANNELS+=("${LINUX_CHANNELS[$i]}")
        INSTALLS_PATHS+=("$bin")
        INSTALLS_VERSIONS+=("$ver")
        INSTALLS_RUNNING+=("$running")
        INSTALLS_HOLDERS+=("$holders")
        INSTALLS_BACKUPS+=("$has_backup")
    done
}

print_install_row() {
    local idx="$1" i="$2"
    echo -n "  ${C_BOLD}${idx})${C_RESET} ${C_CYN}${INSTALLS_CHANNELS[$i]}${C_RESET}"
    if [[ -n "${INSTALLS_VERSIONS[$i]}" ]]; then
        echo -n "  ${INSTALLS_VERSIONS[$i]}"
    fi
    if ${INSTALLS_RUNNING[$i]}; then
        echo -n "  ${C_YEL}[RUNNING, ${INSTALLS_HOLDERS[$i]} process(es)]${C_RESET}"
    else
        echo -n "  ${C_GRN}[not running]${C_RESET}"
    fi
    if ${INSTALLS_BACKUPS[$i]}; then
        echo -n " ${C_DIM}(backup present)${C_RESET}"
    fi
    echo ""
    echo "      ${C_DIM}${INSTALLS_PATHS[$i]}${C_RESET}"
}

# ============================================================================
# Interactive UI
# ============================================================================

read_custom_path() {
    while true; do
        echo -n "${C_BOLD}Enter the full path to chrome binary, blank to cancel: ${C_RESET}"
        local line
        read -r line || return 1
        line=$(echo "$line" | xargs)  # Trim whitespace and quotes
        
        if [[ -z "$line" ]]; then
            return 1
        fi
        
        if [[ ! -f "$line" ]]; then
            errf "No file at that path. Try again, or leave blank to cancel."
            continue
        fi
        
        # Set the custom path and return success
        CHOSEN_CUSTOM_PATH="$line"
        return 0
    done
}

choose_install() {
    local count=${#INSTALLS_CHANNELS[@]}
    if (( count == 0 )); then
        warnf "No installed Chrome channel was found."
        echo ""
        if read_custom_path; then
            TARGET_FILE="$CHOSEN_CUSTOM_PATH"
            return 0
        fi
        infof "No path entered - nothing was changed."
        return 1
    fi

    if (( count == 1 )); then
        okf "One Chrome channel found:"
        print_install_row 1 0
    else
        echo ""
        echo "${TAG_INFO} ${count} Chrome release channels found:"
        local j
        for (( j = 0; j < count; j++ )); do
            print_install_row $(( j + 1 )) "$j"
        done
        echo ""
        echo "${TAG_INFO} Only the channel you pick is modified; the others keep running."
    fi

    while true; do
        if (( count == 1 )); then
            echo -n "${C_BOLD}Patch this channel? [Enter=yes, r=restore, c=custom path, q=quit]: ${C_RESET}"
        else
            echo -n "${C_BOLD}Which channel do you want to patch? [1-${count}, r=restore, c=custom path, q=quit]: ${C_RESET}"
        fi
        local line
        read -r line || return 1

        if [[ "$line" == "q" || "$line" == "Q" ]]; then
            return 1
        fi
        if [[ "$line" == "c" || "$line" == "C" ]]; then
            if read_custom_path; then
                TARGET_FILE="$CHOSEN_CUSTOM_PATH"
                return 0
            fi
            continue
        fi
        if [[ "$line" == "r" || "$line" == "R" ]]; then
            cmd="restore"
            if (( count == 1 )); then
                CHOSEN_INDEX=0
                return 0
            fi
            # Show restore-specific prompt for multiple channels
            echo ""
            echo "${TAG_INFO} Restore mode selected. Choose which channel to restore from backup:"
            while true; do
                echo -n "${C_BOLD}Which channel do you want to restore? [1-${count}, c=custom path, q=cancel]: ${C_RESET}"
                local restore_line
                read -r restore_line || return 1
                
                if [[ "$restore_line" == "q" || "$restore_line" == "Q" ]]; then
                    infof "Restore cancelled."
                    return 1
                fi
                if [[ "$restore_line" == "c" || "$restore_line" == "C" ]]; then
                    if read_custom_path; then
                        TARGET_FILE="$CHOSEN_CUSTOM_PATH"
                        return 0
                    fi
                    continue
                fi
                if [[ "$restore_line" =~ ^[0-9]+$ ]] && (( restore_line >= 1 && restore_line <= count )); then
                    CHOSEN_INDEX=$(( restore_line - 1 ))
                    return 0
                fi
                errf "Enter a number between 1 and ${count}, c for custom path, or q to cancel."
            done
        fi
        if (( count == 1 )) && [[ -z "$line" ]]; then
            CHOSEN_INDEX=0
            return 0
        fi
        if [[ "$line" =~ ^[0-9]+$ ]] && (( line >= 1 && line <= count )); then
            CHOSEN_INDEX=$(( line - 1 ))
            return 0
        fi
        if (( count == 1 )); then
            errf "Press Enter to accept, r to restore, c for custom path, or q to quit."
        else
            errf "Enter a number between 1 and ${count}, r to restore, c for custom path, or q to quit."
        fi
    done
}

confirm_force_close() {
    local channel="$1" holders="$2"
    echo ""
    echo "${C_BOLD}${C_YEL}  !! WARNING: Chrome ${channel} is running !!${C_RESET}"
    echo "     Close it now to patch cleanly. If you continue, its ${holders} process(es)"
    echo "     will be FORCE CLOSED and any unsaved tabs or downloads are lost."

    while true; do
        echo -n "${C_BOLD}Force close Chrome ${channel} and patch? [y/N]: ${C_RESET}"
        local line
        read -r line || return 1
        case "$line" in
            y|Y) return 0 ;;
            ""|n|N) infof "Cancelled - nothing was changed."; return 1 ;;
        esac
    done
}

# ============================================================================
# Orchestration — patch / restore flows
# ============================================================================

TARGET_FILE=""
CHOSEN_INDEX=-1
CHOSEN_CUSTOM_PATH=""

do_patch() {
    local target="$1" assume_yes="$2"
    local holders
    holders=$(proc_holders "$target")

    if (( holders > 0 )); then
        if $assume_yes; then
            warnf "Chrome is running and will be force closed (--yes)."
            kill_chrome_processes "$target"
        elif $QUIET; then
            errf "Chrome is running (${holders} process(es))."
            echo "    Close it, or pass --yes to force close it."
            return 1
        else
            confirm_force_close "$(basename "$(dirname "$target")")" "$holders" || return 1
            kill_chrome_processes "$target"
        fi
    fi

    # Read the target
    local fsize
    fsize=$(stat -c%s "$target" 2>/dev/null || stat -f%z "$target" 2>/dev/null)
    if (( fsize == 0 )); then
        errf "Error: the target file is empty."
        return 1
    fi
    okf "Target: ${target} (${fsize} bytes)."

    # Parse ELF
    parse_elf "$target" || return 1

    # Backup management
    local backup="${target}.bak"
    local work_file
    work_file=$(mktemp /tmp/chrome-mv2-work.XXXXXX)

    if [[ ! -f "$backup" ]]; then
        infof "Creating initial backup copy: ${backup} ..."
        cp "$target" "$backup"
        cp "$target" "$work_file"
        okf "Initial backup created successfully."
    else
        # Use ELF build-id to detect Chrome updates. Build-id is in the
        # .note.gnu.build-id section and survives patching, so we can distinguish:
        #   - Same build-id = same Chrome version → work from backup (safe)
        #   - Different build-id = Chrome updated → refresh backup
        local target_id backup_id
        target_id=$(get_elf_build_id "$target")
        backup_id=$(get_elf_build_id "$backup")
        
        if [[ -z "$target_id" ]]; then
            errf "Error: could not extract build-id from ${target}."
            echo "    The file may be corrupted or not a valid ELF binary."
            rm -f "$work_file"
            return 1
        fi
        if [[ -z "$backup_id" ]]; then
            warnf "Warning: could not extract build-id from backup - recreating it."
            cp "$target" "$backup"
            backup_id="$target_id"
        fi
        
        if [[ "$target_id" != "$backup_id" ]]; then
            infof "Chrome update detected (build-id changed) - refreshing backup ${backup} ..."
            okf "  Old build-id: ${backup_id:0:16}..."
            okf "  New build-id: ${target_id:0:16}..."
            cp "$target" "$backup"
            cp "$target" "$work_file"
            okf "Backup updated to new version."
        else
            infof "Same Chrome build detected - working from existing backup to preserve clean stock..."
            cp "$backup" "$work_file"
        fi
    fi

    # Probe milestones
    infof "Starting MV2 patching (ManifestV2Handler architecture, ELF target)..."
    infof "Probing for a known Chrome layout (${NUM_MILESTONES} milestone table(s))..."

    if ! probe_milestones "$work_file"; then
        rm -f "$work_file"
        return 1
    fi

    if (( BEST_SATISFIED == 0 )); then
        report_layout_candidates "$work_file"
        warnf "No known MV2 layout matched this binary."
        echo "    Chrome likely shifted its layout (new milestone or different codegen)."
        echo "    Nothing was modified. See 'Porting to a new Chrome version' in the"
        echo "    mv2-reversing.md notes."
        rm -f "$work_file"
        return 1
    fi

    # Apply flips to the work file
    apply_flips "$work_file"

    local msg
    if (( PATCH_STATUS == 1 )); then
        msg="applied."
    else
        msg="all sites already patched (no change needed)."
    fi
    infof "Chrome ${BEST_MS_NAME} ${msg}"

    # ELF finalize is a no-op (no security directory, no checksum)
    okf "ELF: no post-flip fixups needed."

    # Write the patched file atomically
    write_target "$target" "$work_file"
    rm -f "$work_file"

    # Report outcome
    rule
    if $BEST_FULL; then
        successf "Binary successfully patched!"
        echo "          Manifest V2 extension support re-enabled (Chrome ${BEST_MS_NAME} layout)."
    else
        echo "${TAG_WARNING} Binary was PARTIALLY patched (Chrome ${BEST_MS_NAME} layout, ${BEST_SATISFIED}/${BEST_TOTAL} gates)."
        echo "          The flips found were written, but"
        echo "          $((BEST_TOTAL - BEST_SATISFIED)) gate(s) were not located, so MV2 may STILL be blocked."
        echo "          Please report the exact version. Revert with: sudo bash $0 restore"
    fi
    rule
    return 0
}

do_restore() {
    local target="$1" assume_yes="$2"
    local backup="${target}.bak"

    infof "Restore mode requested..."
    if [[ ! -f "$backup" ]]; then
        errf "Error: backup file ${backup} does not exist."
        return 1
    fi

    local holders
    holders=$(proc_holders "$target")
    if (( holders > 0 )); then
        if $assume_yes; then
            warnf "Chrome is running and will be force closed (--yes)."
            kill_chrome_processes "$target"
        elif $QUIET; then
            errf "Chrome is running (${holders} process(es))."
            echo "    Close it, or pass --yes to force close it."
            return 1
        else
            confirm_force_close "$(basename "$(dirname "$target")")" "$holders" || return 1
            kill_chrome_processes "$target"
        fi
    fi

    write_target "$target" "$backup"
    successf "Original binary successfully restored from backup!"
    return 0
}

print_usage() {
    cat <<'EOF'
Usage: sudo bash chrome-mv2.sh [command] [path] [options]

Re-enables Manifest V2 extension support in Google Chrome by flipping the
inlined IsExtensionAffected manifest-version checks (Linux ELF only).

Commands:
  patch                  Flip the MV2 gates (default if omitted).
  restore                Restore the target binary from its .bak.

Arguments:
  path                   Full path to target chrome binary. If omitted, installed
                         channels are listed to pick from. Can also specify a custom
                         path to patch a non-standard Chrome installation.

Options:
  -y, --yes              Force close a running Chrome without asking.
  -q, --quiet            Do not pause for interactive prompts (for scripting).
  -v, --version          Print the tool version and exit.
  -h, --help             Show this help and exit.

Examples:
  sudo bash chrome-mv2.sh
  sudo bash chrome-mv2.sh patch /opt/google/chrome/chrome --yes
  sudo bash chrome-mv2.sh restore
  sudo bash chrome-mv2.sh patch /custom/path/to/chrome

Environment:
  MV2_TEST_NO_ELEVATION  If set, skip the root check (for testing on copies).
  NO_COLOR               Disable ANSI colour output.
  FORCE_COLOR            Force ANSI colour output.
EOF
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup() {
    if [[ -n "${SCAN_PATTERNS_FILE:-}" && -f "${SCAN_PATTERNS_FILE:-}" ]]; then
        rm -f "$SCAN_PATTERNS_FILE"
    fi
}
trap cleanup EXIT

# ============================================================================
# Entry point
# ============================================================================

main() {
    init_colors

    # Load signature tables (external or embedded)
    load_milestones || exit 1

    # Parse arguments - match PS1 parameter order: [command] [path] [options]
    local cmd="patch"
    local target_path=""
    local assume_yes=false
    QUIET=false
    
    local positional_args=()

    while (( $# > 0 )); do
        case "$1" in
            --yes|-y)
                assume_yes=true ;;
            --quiet|-q)
                QUIET=true ;;
            --version|-v)
                echo "chrome-mv2-patch ${APP_VERSION}"
                exit 0 ;;
            --help|-h)
                print_usage
                exit 0 ;;
            -*)
                errf "Unknown option: $1"
                print_usage
                exit 2 ;;
            *)
                positional_args+=("$1") ;;
        esac
        shift
    done
    
    # Process positional arguments (match PS1: Position 0 = command, Position 1 = path)
    if (( ${#positional_args[@]} >= 1 )); then
        case "${positional_args[0]}" in
            patch|restore)
                cmd="${positional_args[0]}"
                if (( ${#positional_args[@]} >= 2 )); then
                    target_path="${positional_args[1]}"
                fi
                ;;
            *)
                # Not a command, treat as path (for backward compat: "script.sh /path/to/chrome")
                target_path="${positional_args[0]}"
                ;;
        esac
    fi

    banner

    # Check for required tools (all coreutils/POSIX - present on any Linux)
    local tool
    for tool in dd od grep head mktemp stat; do
        if ! command -v "$tool" &>/dev/null; then
            errf "Required tool '${tool}' not found."
            exit 1
        fi
    done
    init_scan_backend || exit 1

    # Root check
    if [[ "$(id -u)" -ne 0 && -z "${MV2_TEST_NO_ELEVATION:-}" ]]; then
        errf "root privileges are REQUIRED to modify /opt/google/chrome/chrome."
        echo "    Re-run with sudo."
        exit 1
    fi

    # Resolve target
    if [[ -n "$target_path" ]]; then
        if [[ ! -f "$target_path" ]]; then
            errf "Error: the given path does not exist: ${target_path}"
            exit 1
        fi
        TARGET_FILE="$target_path"
    else
        infof "Scanning for installed Chrome release channels..."
        enumerate_installs

        if $QUIET; then
            if (( ${#INSTALLS_CHANNELS[@]} == 0 )); then
                errf "Error: no installed Chrome channel was found."
                echo "    Pass the path explicitly, e.g. sudo bash $0 patch /path/to/chrome"
                exit 1
            fi
            if (( ${#INSTALLS_CHANNELS[@]} > 1 )); then
                errf "${#INSTALLS_CHANNELS[@]} channels are installed and --quiet cannot prompt."
                local j
                for (( j = 0; j < ${#INSTALLS_CHANNELS[@]}; j++ )); do
                    print_install_row $(( j + 1 )) "$j"
                done
                echo "    Re-run with the path of the channel you want."
                exit 1
            fi
            CHOSEN_INDEX=0
        else
            choose_install || exit 0
        fi

        TARGET_FILE="${INSTALLS_PATHS[$CHOSEN_INDEX]}"
    fi

    okf "Target channel: ${C_CYN}$(basename "$(dirname "$TARGET_FILE")")${C_RESET}"
    okf "Target file: ${TARGET_FILE}"

    # Dispatch
    case "$cmd" in
        restore)
            do_restore "$TARGET_FILE" "$assume_yes"
            ;;
        patch)
            do_patch "$TARGET_FILE" "$assume_yes"
            ;;
    esac
}

main "$@"
