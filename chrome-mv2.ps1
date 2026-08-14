<#
.SYNOPSIS
    Google Chrome Manifest V2 Patcher - single-file, self-contained PowerShell
    port for Windows (chrome.dll only; x64, x86, and arm64).

.DESCRIPTION
    Re-enables Manifest V2 extension support in Google Chrome by flipping the
    inlined IsExtensionAffected manifest-version checks. Same milestone engine,
    same match/decline semantics, same .bak handling. Handles x64/x86 (PE, PE32)
    and Windows-on-ARM (PE32+ arm64, machine 0xAA64).

    Self-contained: the Windows signature tables are EMBEDDED in this file
    ($EmbeddedSignatures below), so the script needs no signatures.json and no
    other file to run. A signatures.json installed next to the script takes
    precedence; another file must be selected explicitly with -Signatures.
    Being self-contained is also what lets
    it run straight from a URL (see the irm|iex example).

    HOW IT PATCHES: for each gate, first probe the RVA recorded in the table -
    cheap, and exact for the build the table was derived from. On a miss, scan
    the whole .text section for the gate's byte signature; that is what relocates
    a gate cleanly across point releases. A site counts as located only when its
    signature matches EXACTLY expectedMatches times: a different count means the
    layout moved, so the site is declined rather than guessed at. The milestone
    with the most located sites wins; one that locates none is declined outright.
    Then flip the gates, clear the Authenticode directory and recompute the PE
    checksum.

    CARDINAL RULE: never delete or blank a call and never invent control flow -
    only flip the direction of an existing branch to its EXISTING target.

      JG_SHORT  0x7F disp8       -> 0xEB disp8        (jmp short, same disp8)
      JG_NEAR   0x0F 0x8F disp32 -> 0x90 0xE9 disp32  (nop ; jmp near, same disp32)
      BCOND     arm64 b.gt (cond GT 0xC) -> b.al (cond AL 0xE), imm19 preserved
                (the low nibble of the B.cond word's byte0; one byte changes)

    PERFORMANCE NOTE - why this file is shaped the way it is:
    chrome.dll is ~285 MB. A per-byte loop in PowerShell is ~1000x slower than a
    compiled scan, so every hot loop lives in inline C# compiled via Add-Type.
    That compile is lazy - paid once per run, by the first operation that needs
    it (a full .text scan or a checksum pass). Trying to beat the scan with
    [Array]::IndexOf as a native memchr does NOT work: the signatures' first byte
    0x83 occurs ~3,000,000 times in .text (once per 84 bytes) and each candidate
    costs a ~36 us PowerShell-to-.NET round trip - ~109 s per signature versus a
    ~4.5 s compiled full-section scan. The remaining cost is the ~285 MB file
    being read/copied/written a few times; see the README for which passes are
    structural and which could be traded against safety.

    FILE MAP, top to bottom: parameters -> embedded signature tables -> console
    output -> inline C# hot loops -> signature loading + validation -> PE image
    layer -> patching engine -> Windows host glue (file locks, elevation) ->
    install discovery -> interactive prompts -> orchestration -> entry point.

    .PARAMETER Command
    patch (default), restore, or check. Check is read-only and never elevates.

.PARAMETER Path
    Target chrome.dll. Omitted: installed channels are listed to pick from.

.PARAMETER Yes
    Force close a running Chrome without asking.

    .PARAMETER Quiet
    Do not pause on error ('Press any key to exit') (for scripting).

    .PARAMETER AllowPartial
    Developer-only override which permits writing a milestone when only some of
    its sites were located. The safe default is to decline partial layouts.

    .PARAMETER ForceRestore
    Restore even when the backup identity does not match the installed binary.

    .PARAMETER Signatures
    Explicit external signatures.json path. External data is never loaded from
    the current directory implicitly.

.EXAMPLE
    .\chrome-mv2.ps1
.EXAMPLE
    .\chrome-mv2.ps1 patch "C:\Program Files\Google\Chrome\Application\151.0.7922.109\chrome.dll" -Yes
.EXAMPLE
    .\chrome-mv2.ps1 restore
.EXAMPLE
    # Run directly from a URL (self-elevates via UAC; keep the window open):
    powershell -ExecutionPolicy Bypass -c "irm https://example.com/chrome-mv2.ps1 | iex"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('patch', 'restore', 'check')]
    [string]$Command = 'patch',

    [Parameter(Position = 1)]
    [string]$Path,

    [Alias('y')]
    [switch]$Yes,

    [Alias('q')]
    [switch]$Quiet,

    [switch]$AllowPartial,

    [switch]$ForceRestore,

    [string]$Signatures,

    [Alias('v')]
    [switch]$Version,

    # Internal: set on the elevated relaunch so a failed elevation cannot loop.
    [switch]$Relaunched
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppVersion      = '1.4.0'
$SignaturesFile  = 'signatures.json'
$script:CsLoaded = $false

# Embedded Windows signature tables - see the .DESCRIPTION note. An external
# signatures.json next to the script overrides this if present.
#
# Schema. Per milestone: name (label used in output), container ("pe" = PE32+/x64,
# "pe32" = PE32/x86, "pe-arm64" = PE32+/arm64 - milestones whose container does
# not match the target are skipped), sites[]. Per site:
#   name            label used in output
#   kind            "short" (7F disp8), "near" (0F 8F disp32), or "bcond"
#                   (arm64 B.cond GT->AL, low nibble of the 4-byte branch word)
#   jgRVA           RVA of the jg / b.cond opcode byte in the build this entry was
#                   derived from - a shortcut to try first, NOT a requirement
#   jgOff           index of that opcode byte within sig
#   expectedMatches how many times sig must occur in .text; >1 means one shared
#                   body the linker folded, and every copy gets flipped
#   sig             hex bytes, jg / b.cond opcode included at jgOff
$EmbeddedSignatures = @'
{
  "milestones": [
    {"name":"151","container":"pe","sites":[{"name":"IsExtensionAffected","kind":"short","jgRVA":"0x083012E4","jgOff":4,"expectedMatches":1,"sig":"837A50027F34488B8A280200008B413080BA08020000007508"},{"name":"ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x08301323","jgOff":3,"expectedMatches":1,"sig":"83FA027F234183F80175114183F9050F95C14183F90A"},{"name":"ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x03291F6B","jgOff":7,"expectedMatches":1,"sig":"8B41684183F8027F288B493083F801751683F9050F95C2"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x01618C4C","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x08301436","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x08E736BA","jgOff":6,"expectedMatches":1,"sig":"8B416883FA027F3B8B493083F8010F851A01000083F905742A"},{"name":"MustRemainDisabled (inlined)","kind":"short","jgRVA":"0x016448AA","jgOff":6,"expectedMatches":1,"sig":"8B416883FA027F788B493083F801756631FF83F905740583F9"}]},
    {"name":"152","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x082D26F5","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F805"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x03348754","jgOff":4,"expectedMatches":2,"sig":"837A50027F34488B8A280200008B413080BA080200000075"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x0124109C","jgOff":4,"expectedMatches":1,"sig":"837950027F2D488B91280200008B423080B90802000000750C"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x082D24D6","jgOff":4,"expectedMatches":1,"sig":"837E50027F2D488B8E280200008B413080BE08020000007508"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x08DDC241","jgOff":4,"expectedMatches":1,"sig":"837F50027F4E488B8F280200008B413080BF0802000000750C"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x015A8D31","jgOff":4,"expectedMatches":1,"sig":"837F50020F8F8B000000488B8F280200008B413080BF080200000075"}]},
    {"name":"151-x86","container":"pe32","sites":[{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x00B20DB9","jgOff":4,"expectedMatches":1,"sig":"837928027F2C8B91640100008B421880B95401000000750C8B"},{"name":"MustRemainDisabled (inlined)","kind":"short","jgRVA":"0x0111E3EC","jgOff":3,"expectedMatches":1,"sig":"83FA027F728B491883F801756031DB83F905740583F90A752B"},{"name":"ShouldBlockExtensionEnable","kind":"short","jgRVA":"0x029E11BE","jgOff":3,"expectedMatches":1,"sig":"83FA027F2B8B491883F801751983F9050F95C283F90A0F95C0"},{"name":"IsExtensionAffected","kind":"short","jgRVA":"0x07022F9A","jgOff":4,"expectedMatches":1,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"ShouldBlockExtensionInstallation","kind":"short","jgRVA":"0x07022FE7","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B450C83F80175158B451083F8050F95C183F8"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x0702310D","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x079D46E7","jgOff":3,"expectedMatches":1,"sig":"83FA027F338B491883F8010F85FD00000083F905742283F90A"}]},
    {"name":"152-x86","container":"pe32","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate; covers install thunk)","kind":"short","jgRVA":"0x06FB7547","jgOff":4,"expectedMatches":1,"sig":"837D08027F278B4D0C31C083F908771FBA0A0100000FA3CA73"},{"name":"ShouldBlockExtensionEnable / IsExtensionAffected (shared body)","kind":"short","jgRVA":"0x0299ED6A","jgOff":4,"expectedMatches":2,"sig":"837A28027F368B8A640100008B411880BA540100000075088B"},{"name":"OnExtensionSystemReady startup loop","kind":"short","jgRVA":"0x00A580A6","jgOff":4,"expectedMatches":1,"sig":"837928027F2C8B91640100008B421880B95401000000750C8B"},{"name":"MaybeReEnableExtension","kind":"short","jgRVA":"0x06FB736D","jgOff":4,"expectedMatches":1,"sig":"837E28027F248B8E640100008B411880BE540100000075088B"},{"name":"UserMayInstall (inlined)","kind":"short","jgRVA":"0x0791012F","jgOff":4,"expectedMatches":1,"sig":"837F28027F458B8F640100008B411880BF5401000000750C8B"},{"name":"MustRemainDisabled (inlined, near jg)","kind":"near","jgRVA":"0x010851A8","jgOff":4,"expectedMatches":1,"sig":"837B28020F8F840000008B8B640100008B411880BB54010000007508"}]},
    {"name":"151-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x01058388","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled","kind":"bcond","jgRVA":"0x0125352C","jgOff":4,"expectedMatches":1,"sig":"5F0900716C050054293140B91F050071810400543F150071F4031F2A60000054"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable","kind":"bcond","jgRVA":"0x02C0729C","jgOff":4,"expectedMatches":1,"sig":"5F090071CC010054293140B91F050071E10000543F15007124194A7AE0079F1A"},{"name":"MV2DeprecationImpactChecker::IsExtensionAffected","kind":"bcond","jgRVA":"0x02C07334","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionInstallation","kind":"bcond","jgRVA":"0x07836B6C","jgOff":4,"expectedMatches":1,"sig":"3F0800716C0100545F040071A10000547F14007164184A7AE0079F1AC0035FD6"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x07836C94","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::UserMayInstall","kind":"bcond","jgRVA":"0x082F94F8","jgOff":4,"expectedMatches":1,"sig":"5F090071EC010054293140B91F050071610700543F150071400100543F290071"}]},
    {"name":"152-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x01014CBC","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x013591BC","jgOff":4,"expectedMatches":2,"sig":"1F090071EC050054891641F98A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable / ManifestV2Handler::IsExtensionAffected (shared body)","kind":"bcond","jgRVA":"0x02C1FD9C","jgOff":4,"expectedMatches":2,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x07702AEC","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839283140B98A000037296940B93F050071"}]}
  ]
}
'@

# ============================================================================
# Console colour + tags. $script:C holds the escape sequences (all empty strings
# when colour is off), so every caller can interpolate them unconditionally.
# ============================================================================

$script:C = @{}

# Decides once whether to emit ANSI colour, then builds $C and the [+]/[!] tags.
# Must run before any output: the tags are empty until it does.
function Initialize-Colors {
    $vt = $false
    if ($Host.UI.SupportsVirtualTerminal) { $vt = $true }
    # PS7 on a real console always handles VT; redirected output should not.
    if (-not [Console]::IsOutputRedirected -and $PSVersionTable.PSVersion.Major -ge 6) { $vt = $true }
    if ($env:FORCE_COLOR) { $vt = $true }
    if ($env:NO_COLOR)    { $vt = $false }   # checked last so it always wins

    if ($vt) {
        $e = [char]27
        $script:C = @{
            Reset = "$e[0m"; Red = "$e[91m"; Grn = "$e[92m"
            Yel   = "$e[93m"; Cyn = "$e[96m"; Dim = "$e[90m"; Bold = "$e[1m"
        }
    } else {
        $script:C = @{ Reset=''; Red=''; Grn=''; Yel=''; Cyn=''; Dim=''; Bold='' }
    }

    $script:TagOK      = "$($C.Grn)[+]$($C.Reset)"
    $script:TagErr     = "$($C.Red)[-]$($C.Reset)"
    $script:TagInfo    = "$($C.Cyn)[*]$($C.Reset)"
    $script:TagWarn    = "$($C.Yel)[!]$($C.Reset)"
    $script:TagSuccess = "$($C.Bold)$($C.Grn)[SUCCESS]$($C.Reset)"
    $script:TagWarning = "$($C.Bold)$($C.Yel)[WARNING]$($C.Reset)"
}

function Write-Info    { param([string]$m) Write-Host "$script:TagInfo $m" }
function Write-Ok      { param([string]$m) Write-Host "$script:TagOK $m" }
function Write-Warn    { param([string]$m) Write-Host "$script:TagWarn $m" }
function Write-Err     { param([string]$m) Write-Host "$script:TagErr $m" }
function Write-Success { param([string]$m) Write-Host "$script:TagSuccess $m" }
function Write-Rule    { Write-Host "$($C.Cyn)==========================================================$($C.Reset)" }

function Write-Banner {
    Write-Rule
    Write-Host "$($C.Bold)     Google Chrome Manifest V2 Patcher (PowerShell)        $($C.Reset)"
    Write-Host "$($C.Dim)                    v$AppVersion                       $($C.Reset)"
    Write-Rule
}

# "7F 34 EB" - byte dumps for the candidate listing.
function Format-HexUpper {
    param([byte[]]$Bytes)
    ($Bytes | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
}

# ============================================================================
# Lazy native helpers (scan hot loop + PE checksum)
#
# Compiled ONLY when a full .text scan or a checksum pass is actually required.
# The signature match and the checksum must stay byte-for-byte exact, so both hot
# loops live in inline C#. Add-Type cannot redefine a type in the same session,
# hence the $script:CsLoaded guard.
# ============================================================================

function Initialize-NativeHelpers {
    if ($script:CsLoaded) { return }
    Write-Info 'Compiling native helpers (full .text scan / PE checksum)...'
    $sw = [Diagnostics.Stopwatch]::StartNew()

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;

public static class Mv2Native
{
    public const int KindShort = 0;
    public const int KindNear  = 1;
    public const int KindBcond = 2;

    // Signature match at one position. Exact match on every byte
    // except the jump opcode and its displacement, which are masked per encoding:
    //   short: [jgOff] in {7F,EB}; [jgOff+1] disp8 wild
    //   near : opcode pair is exactly {0F 8F,90 E9}; [jgOff+2..+5] wild
    //   bcond: the 4-byte LE arm64 B.cond word at [jgOff] - opcode 0x54 + bit4=0
    //          fixed, cond nibble in {0xC stock GT, 0xE patched AL}, imm19 wild
    public static bool SigMatchesAt(byte[] buf, long start, byte[] sig, int jgOff, int kind)
    {
        if (start < 0 || start + sig.Length > buf.LongLength) return false;
        if (kind == KindBcond)
        {
            // Validate the whole branch word once (little-endian) before the byte loop.
            long w0 = start + jgOff;
            uint word = (uint)(buf[w0] | (buf[w0 + 1] << 8) | (buf[w0 + 2] << 16) | (buf[w0 + 3] << 24));
            if ((word & 0xFF000010u) != 0x54000000u) return false;
            uint cond = word & 0xFu;
            if (cond != 0x0Cu && cond != 0x0Eu) return false;
        }
        for (int k = 0; k < sig.Length; k++)
        {
            byte p = buf[start + k];
            if (kind == KindShort)
            {
                if (k == jgOff)          { if (p != 0x7F && p != 0xEB) return false; }
                else if (k == jgOff + 1) { /* disp8 wildcard */ }
                else if (p != sig[k])    { return false; }
            }
            else if (kind == KindNear)
            {
                if (k == jgOff)
                {
                    byte p1 = buf[start + jgOff + 1];
                    if (!((p == 0x0F && p1 == 0x8F) || (p == 0x90 && p1 == 0xE9))) return false;
                }
                else if (k == jgOff + 1)                   { /* pair checked above */ }
                else if (k >= jgOff + 2 && k <= jgOff + 5) { /* disp32 wildcard */ }
                else if (p != sig[k])                      { return false; }
            }
            else // KindBcond: the 4 branch-word bytes were validated above
            {
                if (k >= jgOff && k <= jgOff + 3) { /* branch word, wild imm19 */ }
                else if (p != sig[k])            { return false; }
            }
        }
        return true;
    }

    // Full .text scan, used when the recorded RVA missed. Returns file offsets of
    // each jg opcode byte matched. Stops once we exceed expectedMatches: that is
    // already enough for the caller to reject the site as ambiguous.
    public static long[] Scan(byte[] buf, long textRaw, long textSize,
                              byte[] sig, int jgOff, int kind, int expectedMatches)
    {
        var found = new List<long>();
        long textEnd = textRaw + textSize;
        long limit = Math.Min(textEnd, buf.LongLength);
        byte first = sig[0];
        for (long r = textRaw; r + sig.Length <= limit; r++)
        {
            if (buf[r] != first) continue;              // fast filter on first byte
            if (!SigMatchesAt(buf, r, sig, jgOff, kind)) continue;
            found.Add(r + jgOff);
            if (found.Count > expectedMatches) break;
        }
        return found.ToArray();
    }

    // PE checksum: 16-bit ones-complement-style sum over the whole file
    // (skipping the CheckSum field) plus the file size.
    public static uint PeChecksum(byte[] data, long checksumOffset)
    {
        ulong checksum = 0;
        long dwords = data.LongLength / 4;
        long skip = checksumOffset / 4;
        for (long i = 0; i < dwords; i++)
        {
            if (i == skip) continue;
            checksum += BitConverter.ToUInt32(data, (int)(i * 4));
            if (checksum > 0xFFFFFFFF) checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
        int rem = (int)(data.LongLength % 4);
        if (rem != 0)
        {
            uint last = 0; int shift = 0;
            for (int k = 0; k < rem; k++) { last |= (uint)data[dwords * 4 + k] << shift; shift += 8; }
            checksum += last;
            if (checksum > 0xFFFFFFFF) checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
        while ((checksum >> 16) != 0) checksum = (checksum & 0xFFFF) + (checksum >> 16);
        return (uint)(checksum + (ulong)data.LongLength);
    }

    // Report-only structural scan for the decline path. Never writes.
    public static long[] SkeletonScan(byte[] buf, long textRaw, long textSize)
    {
        var hits = new List<long>();
        long tsize = Math.Min(textSize, buf.LongLength - textRaw);
        for (long i = 2; i + 2 < tsize; i++)
        {
            if (buf[textRaw + i] != 0x02 || buf[textRaw + i + 1] != 0x7F) continue;

            long cmpStart;
            if (buf[textRaw + i - 2] == 0x83 && (buf[textRaw + i - 1] & 0xF8) == 0xF8)
                cmpStart = i - 2;                                    // 83 F8..FF 02
            else if (i >= 3 && buf[textRaw + i - 3] == 0x83 && (buf[textRaw + i - 2] & 0xF8) == 0x78)
                cmpStart = i - 3;                                    // 83 78..7F disp8 02
            else continue;

            bool follow = false;
            long end = Math.Min(i + 2 + 40, tsize);
            for (long j = i + 2; j + 2 < end; j++)
            {
                byte b0 = buf[textRaw + j], b1 = buf[textRaw + j + 1], b2 = buf[textRaw + j + 2];
                if (b0 == 0x83 && (b1 & 0xF8) == 0xF8 && (b2 == 0x01 || b2 == 0x05)) { follow = true; break; }
                if (b0 == 0x80 && (b1 & 0xF8) == 0xB8 && j + 6 < end && buf[textRaw + j + 6] == 0x00) { follow = true; break; }
            }
            if (follow) hits.Add(cmpStart);
        }
        return hits.ToArray();
    }
}
'@
    $sw.Stop()
    $script:CsLoaded = $true
    Write-Ok ('Native helpers ready ({0:N1} s).' -f $sw.Elapsed.TotalSeconds)
}

# ============================================================================
# Signature loading. The milestone tables are embedded in this
# file ($EmbeddedSignatures); an external signatures.json overrides them if
# present, so new data can be shipped without editing the script. Another path
# must be supplied explicitly with -Signatures.
# ============================================================================

# An explicit -Signatures path wins, followed by signatures.json beside the
# script. $null means neither exists, so the embedded tables are used.
function Get-SignaturesPath {
    if ($Signatures) {
        if (-not (Test-Path -LiteralPath $Signatures -PathType Leaf)) {
            throw "signature file does not exist: $Signatures"
        }
        return (Resolve-Path -LiteralPath $Signatures).Path
    }

    # A file installed beside the script is part of the tool distribution and
    # may override the embedded tables. Never trust an admin's current directory
    # implicitly: an unrelated signatures.json there must have no effect.
    if ($PSScriptRoot) {
        $besideScript = Join-Path $PSScriptRoot $SignaturesFile
        if (Test-Path -LiteralPath $besideScript -PathType Leaf) { return $besideScript }
    }
    return $null
}

# Reads and parses the active signature document (external file if present,
# otherwise the embedded copy).
function Read-SignatureJson {
    $path = Get-SignaturesPath
    if ($path) {
        try   { $raw = Get-Content -LiteralPath $path -Raw }
        catch { throw "reading ${path}: $_" }
        $srcLabel = $path
    } else {
        $raw = $EmbeddedSignatures
        $srcLabel = 'embedded tables'
    }
    try   { return ($raw | ConvertFrom-Json) }
    catch { throw "parsing ${srcLabel}: $_" }
}

# "7F34EB" -> [byte[]](0x7F, 0x34, 0xEB). The leading comma on the return is
# required: PowerShell would otherwise unroll a 1-byte array into a scalar.
function ConvertFrom-HexString {
    param([string]$Hex)
    if ($Hex.Length % 2 -ne 0) { throw "odd-length hex string" }
    $out = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $out.Length; $i++) {
        $out[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$out
}

# Reads and strictly validates the signature tables:
# the sig must carry the stock jg opcode at jgOff, near jgs need 6 bytes, and
# expectedMatches must be >= 1. Anything off is a hard error, never a guess.
# Kind is normalised to the int the C# helper expects (0 = short, 1 = near).
function Import-Milestones {
    $doc = Read-SignatureJson

    if ($null -eq $doc.milestones -or @($doc.milestones).Count -eq 0) {
        throw 'signature document contains no milestones'
    }

    $out = @()
    $milestoneNames = @{}
    foreach ($rm in $doc.milestones) {
        $msName = [string]$rm.name
        $container = [string]$rm.container
        if ([string]::IsNullOrWhiteSpace($msName) -or $msName -match '[\r\n|]') {
            throw 'milestone name is empty or contains a reserved character'
        }
        if ($milestoneNames.ContainsKey($msName)) { throw "duplicate milestone name '$msName'" }
        $milestoneNames[$msName] = $true
        if ($container -notin 'pe', 'pe32', 'pe-arm64', 'elf', 'elf-arm64', 'macho-x64', 'macho-arm64') {
            throw "milestone $msName has unsupported container '$container'"
        }
        # This script patches only Windows PE (x64 'pe', x86 'pe32', arm64
        # 'pe-arm64'). A shared signatures.json may also carry the Linux (elf,
        # elf-arm64) and macOS (macho-x64/macho-arm64) tables, so skip any non-PE
        # milestone rather than validate a kind this engine does not implement.
        if ($container -notin 'pe', 'pe32', 'pe-arm64') { continue }
        if ($null -eq $rm.sites -or @($rm.sites).Count -eq 0) {
            throw "milestone $msName contains no sites"
        }

        $sites = @()
        $siteNames = @{}
        foreach ($rs in $rm.sites) {
            $siteName = [string]$rs.name
            if ([string]::IsNullOrWhiteSpace($siteName) -or $siteName -match '[\r\n|]') {
                throw "milestone $msName has an invalid site name"
            }
            if ($siteNames.ContainsKey($siteName)) { throw "milestone $msName has duplicate site '$siteName'" }
            $siteNames[$siteName] = $true
            switch ($rs.kind) {
                'short' { $kind = 0 }      # Mv2Native.KindShort
                'near'  { $kind = 1 }      # Mv2Native.KindNear
                'bcond' { $kind = 2 }      # Mv2Native.KindBcond (arm64 B.cond GT->AL)
                default { throw "milestone $($rm.name) site '$($rs.name)': unknown kind '$($rs.kind)'" }
            }
            # A bcond site must sit in an arm64 PE; short/near are x86/x64 only.
            if ($kind -eq 2 -and $container -ne 'pe-arm64') {
                throw "milestone $msName site '$siteName': 'bcond' kind is only valid in a pe-arm64 milestone"
            }
            if ($kind -ne 2 -and $container -eq 'pe-arm64') {
                throw "milestone $msName site '$siteName': pe-arm64 milestones use the 'bcond' kind, not '$($rs.kind)'"
            }

            $sigText = [string]$rs.sig
            if ([string]::IsNullOrWhiteSpace($sigText) -or $sigText -notmatch '^[0-9A-Fa-f]+$') {
                throw "milestone $msName site '$siteName': sig must be non-empty hexadecimal bytes"
            }
            $sig = ConvertFrom-HexString $sigText
            $jgOff = [int]$rs.jgOff
            if ($jgOff -lt 0 -or $jgOff -ge $sig.Length) {
                throw "milestone $($rm.name) site '$($rs.name)': jgOff $jgOff out of range (sig len $($sig.Length))"
            }
            $op = $sig[$jgOff]
            if (($kind -eq 0 -and $op -ne 0x7F) -or ($kind -eq 1 -and $op -ne 0x0F)) {
                throw ("milestone $($rm.name) site '$($rs.name)': jgOff points at 0x{0:X2}, not a $($rs.kind) jg opcode" -f $op)
            }
            if ($kind -eq 1 -and ($jgOff + 5) -ge $sig.Length) {
                throw "milestone $($rm.name) site '$($rs.name)': near jg needs 6 bytes but sig ends early"
            }
            if ($kind -eq 0 -and ($jgOff + 1) -ge $sig.Length) {
                throw "milestone $msName site '$siteName': short jg needs 2 bytes but sig ends early"
            }
            if ($kind -eq 1 -and $sig[$jgOff + 1] -ne 0x8F) {
                throw ("milestone $msName site '$siteName': near jg second opcode is 0x{0:X2}, expected 0x8F" -f $sig[$jgOff + 1])
            }
            if ($kind -eq 2) {
                if (($jgOff + 3) -ge $sig.Length) {
                    throw "milestone $msName site '$siteName': bcond needs 4 bytes but sig ends early"
                }
                # Stock B.cond word (little-endian) must be a GT branch: 0x54.......C.
                $w = [uint32]$sig[$jgOff] -bor ([uint32]$sig[$jgOff + 1] -shl 8) -bor `
                     ([uint32]$sig[$jgOff + 2] -shl 16) -bor ([uint32]$sig[$jgOff + 3] -shl 24)
                if (($w -band 0xFF00001F) -ne 0x5400000C) {
                    throw ("milestone $msName site '$siteName': jgOff is not a stock b.gt (GT) B.cond word (0x{0:X8})" -f $w)
                }
            }
            $expected = [int]$rs.expectedMatches
            if ($expected -lt 1) {
                throw "milestone $($rm.name) site '$($rs.name)': expectedMatches must be >= 1"
            }

            $sites += [pscustomobject]@{
                Name            = $siteName
                Kind            = $kind
                JgRVA           = [uint32]([Convert]::ToUInt32($rs.jgRVA, 16))
                Sig             = $sig
                JgOff           = $jgOff
                ExpectedMatches = $expected
            }
        }
        $out += [pscustomobject]@{ Name = $msName; Container = $container; Sites = $sites }
    }
    return $out
}

# ============================================================================
# Image layer - PE only. chrome.dll is a PE; this Windows-only
# script does not handle the Linux ELF 'chrome'.
# ============================================================================

# Entry point of the image layer: sniff the container and hand off. Only 'MZ' is
# accepted, so a mistyped path to some other file fails here, before any write.
function Open-Image {
    param([byte[]]$Buf)

    if ($Buf.Length -ge 2 -and $Buf[0] -eq 0x4D -and $Buf[1] -eq 0x5A) { return Open-PeImage $Buf }
    throw "unrecognized executable (not a PE 'MZ' - this tool patches chrome.dll only)"
}

# Validates a PE32 or PE32+ and records only bounds-checked
# offsets, so every later read/write is safe.
function Open-PeImage {
    param([byte[]]$Buf)

    if ($Buf.Length -lt 64) { throw "not a valid PE: file too small" }
    $eLfanew = [BitConverter]::ToUInt32($Buf, 0x3C)

    if (($eLfanew + 24) -gt $Buf.Length) { throw "not a valid PE: truncated NT headers" }
    if ($Buf[$eLfanew] -ne 0x50 -or $Buf[$eLfanew+1] -ne 0x45 -or
        $Buf[$eLfanew+2] -ne 0 -or $Buf[$eLfanew+3] -ne 0) { throw "not a valid PE: bad NT signature" }

    $numSections  = [BitConverter]::ToUInt16($Buf, $eLfanew + 6)
    $sizeOfOptHdr = [BitConverter]::ToUInt16($Buf, $eLfanew + 20)
    $optOff       = [int64]$eLfanew + 24
    if (($optOff + $sizeOfOptHdr) -gt $Buf.Length) { throw "not a valid PE: optional header out of bounds" }

    $magic = [BitConverter]::ToUInt16($Buf, $optOff)
    switch ($magic) {
        0x20B   { $fixedLen = 112; $is32 = $false }   # PE32+ (x86-64)
        0x10B   { $fixedLen = 96;  $is32 = $true  }   # PE32  (x86)
        default { throw ("not a valid PE: unsupported optional header magic 0x{0:X}" -f $magic) }
    }
    if ($sizeOfOptHdr -lt ($fixedLen + 5 * 8)) {
        throw "not a valid PE: optional header too small for data directories"
    }

    $secOff = $optOff + $sizeOfOptHdr
    if (($secOff + [int64]$numSections * 40) -gt $Buf.Length) { throw "not a valid PE: section table out of bounds" }

    $textRVA = 0; $textRaw = 0; $textSize = 0
    for ($i = 0; $i -lt $numSections; $i++) {
        $sh = $secOff + $i * 40
        $name = [Text.Encoding]::ASCII.GetString($Buf, $sh, 8).TrimEnd([char]0)
        if ($name -eq '.text') {
            $textRVA  = [BitConverter]::ToUInt32($Buf, $sh + 12)
            $textSize = [BitConverter]::ToUInt32($Buf, $sh + 16)   # SizeOfRawData
            $textRaw  = [BitConverter]::ToUInt32($Buf, $sh + 20)
            break
        }
    }
    if ($textSize -eq 0) { throw "could not locate .text section" }
    if ([int64]$textRaw -lt 0 -or [int64]$textRaw + [int64]$textSize -gt $Buf.LongLength) {
        throw "not a valid PE: .text raw data is out of bounds"
    }

    # PE32+ carries both x64 (machine 0x8664) and Windows-on-ARM arm64 (0xAA64);
    # the machine field splits them so an arm64 dll matches only pe-arm64
    # milestones (the arm64 'bcond' flip) and never the x64 'pe' jg tables.
    $machine = [BitConverter]::ToUInt16($Buf, $eLfanew + 4)
    $format  = if ($is32) { 'pe32' } elseif ($machine -eq 0xAA64) { 'pe-arm64' } else { 'pe' }

    return [pscustomobject]@{
        Format     = $format                               # matches a milestone's "container"
        TextRVA    = $textRVA
        TextRaw    = $textRaw
        TextSize   = $textSize
        ChecksumAt = $optOff + 64                          # same offset in PE32 and PE32+
        SecDirAt   = $optOff + $fixedLen + 4 * 8           # data directory [4] = Security
        NtHeaderAt = [int64]$eLfanew
        Machine    = $machine
        TimeStamp  = [BitConverter]::ToUInt32($Buf, $eLfanew + 8)
        Is32       = $is32
    }
}

# A non-zero Security Directory means an untouched, signed stock chrome.dll
# (this tool zeroes it when patching).
function Test-LikelyStock {
    param($Img, [byte[]]$Buf)
    $va = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt)
    $sz = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt + 4)
    return ($va -ne 0 -and $sz -ne 0)
}

# Clears the Authenticode Security Directory and writes the recomputed checksum
# (the finalize step).
function Complete-Image {
    param($Img, [byte[]]$Buf)

    $va = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt)
    $sz = [BitConverter]::ToUInt32($Buf, $Img.SecDirAt + 4)
    if ($va -ne 0 -or $sz -ne 0) {
        Write-Ok ('Clearing Security Directory (RVA: 0x{0:X}, Size: 0x{1:X})' -f $va, $sz)
        [Array]::Clear($Buf, $Img.SecDirAt, 8)
    }

    Initialize-NativeHelpers
    $sum = [Mv2Native]::PeChecksum($Buf, $Img.ChecksumAt)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$sum), 0, $Buf, $Img.ChecksumAt, 4)
    Write-Ok ('Recalculated PE CheckSum: 0x{0:X}' -f $sum)
}

function Get-ByteHash {
    param([byte[]]$Buf)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Buf))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PeIdentity {
    param([byte[]]$Buf, $Img)
    return [pscustomobject]@{
        Format    = [string]$Img.Format
        Machine   = [uint16]$Img.Machine
        TimeStamp = [uint32]$Img.TimeStamp
        Length    = [int64]$Buf.LongLength
        SHA256    = Get-ByteHash $Buf
    }
}

function Test-SameBuildIdentity {
    param($A, $B)
    return ($A.Format -eq $B.Format -and [uint16]$A.Machine -eq [uint16]$B.Machine -and
        [uint32]$A.TimeStamp -eq [uint32]$B.TimeStamp -and [int64]$A.Length -eq [int64]$B.Length)
}

function Write-AtomicFile {
    param(
        [string]$TargetPath,
        [byte[]]$Buf,
        [string]$ExpectedCurrentHash = '',
        [string]$PreserveMetadataFrom = ''
    )

    $full = [IO.Path]::GetFullPath($TargetPath)
    $dir = [IO.Path]::GetDirectoryName($full)
    if (-not $dir) { $dir = (Get-Location).Path }
    $tmp = Join-Path $dir ('.chrome-mv2-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $old = Join-Path $dir ('.chrome-mv2-' + [Guid]::NewGuid().ToString('N') + '.old')

    try {
        $fs = New-Object IO.FileStream($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None, 1048576, [IO.FileOptions]::WriteThrough)
        try {
            $fs.Write($Buf, 0, $Buf.Length)
            $fs.Flush($true)
        } finally { $fs.Dispose() }

        $written = [IO.File]::ReadAllBytes($tmp)
        if ($written.LongLength -ne $Buf.LongLength -or (Get-ByteHash $written) -ne (Get-ByteHash $Buf)) {
            throw "temporary-file verification failed for $TargetPath"
        }

        if ($PreserveMetadataFrom -and (Test-Path -LiteralPath $PreserveMetadataFrom -PathType Leaf)) {
            try { [IO.File]::SetAttributes($tmp, [IO.File]::GetAttributes($PreserveMetadataFrom)) } catch { }
            try { Set-Acl -LiteralPath $tmp -AclObject (Get-Acl -LiteralPath $PreserveMetadataFrom) } catch { }
        }

        if ($ExpectedCurrentHash) {
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'target disappeared before replacement' }
            $now = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($now -ne $ExpectedCurrentHash.ToLowerInvariant()) {
                throw 'target changed after it was inspected; refusing to overwrite it'
            }
        }

        if (Test-Path -LiteralPath $full -PathType Leaf) {
            [IO.File]::Replace($tmp, $full, $old, $true)
            Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue
        } else {
            [IO.File]::Move($tmp, $full)
        }
    } finally {
        if (Test-Path -LiteralPath $tmp -PathType Leaf) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        # If replacement succeeded but cleanup was interrupted, the .old file is
        # a recoverable copy of the previous target; remove it on normal unwind.
        if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old -Force -ErrorAction SilentlyContinue }
    }
}

function Get-BackupMetadataPath { param([string]$BackupPath) return "$BackupPath.json" }

# Delete a backup and its metadata sidecar. Called after a successful restore:
# the installed DLL is now the verified original, so the backup has served its
# purpose. A later 'patch' recreates it from the restored stock DLL.
function Remove-BackupFiles {
    param([string]$BackupPath)
    foreach ($p in @($BackupPath, (Get-BackupMetadataPath $BackupPath))) {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop }
            catch { Write-Warn "Could not remove backup file ${p}: $_" }
        }
    }
}

function Save-BackupSnapshot {
    param([string]$TargetPath, [string]$BackupPath, [byte[]]$Buf, $Identity)

    Write-AtomicFile -TargetPath $BackupPath -Buf $Buf -PreserveMetadataFrom $TargetPath
    $meta = [ordered]@{
        Schema = 1; Format = $Identity.Format; Machine = $Identity.Machine
        TimeStamp = $Identity.TimeStamp; Length = $Identity.Length; SHA256 = $Identity.SHA256
    }
    $json = ($meta | ConvertTo-Json -Compress) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    Write-AtomicFile -TargetPath (Get-BackupMetadataPath $BackupPath) -Buf $bytes
}

function Read-ValidatedBackup {
    param([string]$BackupPath)

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { throw "backup does not exist: $BackupPath" }
    $buf = [IO.File]::ReadAllBytes($BackupPath)
    if ($buf.Length -eq 0) { throw 'backup is empty' }
    $img = Open-Image $buf
    $identity = Get-PeIdentity -Buf $buf -Img $img
    $metaPath = Get-BackupMetadataPath $BackupPath
    $legacy = -not (Test-Path -LiteralPath $metaPath -PathType Leaf)
    if (-not $legacy) {
        try { $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json }
        catch { throw "invalid backup metadata ${metaPath}: $_" }
        if ([int]$meta.Schema -ne 1 -or $meta.Format -ne $identity.Format -or
            [uint16]$meta.Machine -ne $identity.Machine -or [uint32]$meta.TimeStamp -ne $identity.TimeStamp -or
            [int64]$meta.Length -ne $identity.Length -or ([string]$meta.SHA256).ToLowerInvariant() -ne $identity.SHA256) {
            throw 'backup metadata/hash does not match the backup file'
        }
    }
    return [pscustomobject]@{ Buf = $buf; Img = $img; Identity = $identity; Legacy = $legacy }
}

# ============================================================================
# Patching engine
# ============================================================================

# Pure-PowerShell signature match at ONE known offset - the recorded-RVA check in
# Find-AffectedJgSites, so the per-byte cost is irrelevant. It is what keeps an
# unmoved build off the compiled full-section scan.
#
# Mirrors Mv2Native.SigMatchesAt exactly (keep the two in sync): the opcode byte
# matches the stock jg OR the already-flipped form, and the displacement is
# wildcarded. Accepting the flipped form is what makes a re-run idempotent
# instead of "no known layout matched".
function Test-SigAt {
    param([byte[]]$Buf, [int64]$Start, [byte[]]$Sig, [int]$JgOff, [int]$Kind)

    if ($Start -lt 0 -or ($Start + $Sig.Length) -gt $Buf.LongLength) { return $false }
    if ($Kind -eq 2) {
        # arm64 B.cond word (little-endian) at JgOff: 0x54 opcode + bit4=0 fixed,
        # cond nibble in {0xC stock GT, 0xE patched AL}, imm19 wild.
        $w = [uint32]$Buf[$Start + $JgOff] -bor ([uint32]$Buf[$Start + $JgOff + 1] -shl 8) -bor `
             ([uint32]$Buf[$Start + $JgOff + 2] -shl 16) -bor ([uint32]$Buf[$Start + $JgOff + 3] -shl 24)
        if (($w -band 0xFF000010) -ne 0x54000000) { return $false }
        $cond = $w -band 0xF
        if ($cond -ne 0x0C -and $cond -ne 0x0E) { return $false }
    }
    for ($k = 0; $k -lt $Sig.Length; $k++) {
        $p = $Buf[$Start + $k]
        if ($Kind -eq 0) {
            if     ($k -eq $JgOff)     { if ($p -ne 0x7F -and $p -ne 0xEB) { return $false } }
            elseif ($k -eq $JgOff + 1) { }                       # disp8 wildcard
            elseif ($p -ne $Sig[$k])   { return $false }
        } elseif ($Kind -eq 1) {
            if ($k -eq $JgOff) {
                $p1 = $Buf[$Start + $JgOff + 1]
                if (-not (($p -eq 0x0F -and $p1 -eq 0x8F) -or ($p -eq 0x90 -and $p1 -eq 0xE9))) { return $false }
            }
            elseif ($k -eq $JgOff + 1) { }                         # pair checked above
            elseif ($k -ge $JgOff + 2 -and $k -le $JgOff + 5) { } # disp32 wildcard
            elseif ($p -ne $Sig[$k])   { return $false }
        } else {                                                   # bcond
            if ($k -ge $JgOff -and $k -le $JgOff + 3) { }         # branch word validated above
            elseif ($p -ne $Sig[$k])   { return $false }
        }
    }
    return $true
}

# Locates the jg gate for one site. First it checks the recorded RVA in pure
# PowerShell; only a miss falls through to the compiled full-section scan.
# Returns Found (file offsets of each jg opcode byte) and Relocated ($true when
# the hit came from the scan, i.e. this build moved the gate - reported to the
# user and a hint that the table's jgRVA is worth refreshing).
function Find-AffectedJgSites {
    param([byte[]]$Buf, $Img, $Site)

    $textRVA = [int64]$Img.TextRVA; $textRaw = [int64]$Img.TextRaw; $textSize = [int64]$Img.TextSize

    # Shortcut only when the site is expected to be unique - a shared-body site
    # (expectedMatches > 1) must always scan so it finds every copy.
    if ($Site.ExpectedMatches -eq 1 -and
        $Site.JgRVA -ge $textRVA -and ($Site.JgRVA - $textRVA) -lt $textSize) {
        $jgRaw = $textRaw + ($Site.JgRVA - $textRVA)
        $sigStart = $jgRaw - $Site.JgOff
        if ($sigStart -ge 0 -and (Test-SigAt -Buf $Buf -Start $sigStart -Sig $Site.Sig -JgOff $Site.JgOff -Kind $Site.Kind)) {
            return [pscustomobject]@{ Found = @([int64]$jgRaw); Relocated = $false }
        }
    }

    if ($textSize -lt $Site.Sig.Length) {
        return [pscustomobject]@{ Found = @(); Relocated = $false }
    }

    Initialize-NativeHelpers
    $hits = [Mv2Native]::Scan($Buf, $textRaw, $textSize, $Site.Sig, $Site.JgOff, $Site.Kind, $Site.ExpectedMatches)
    return [pscustomobject]@{
        Found     = @($hits)
        Relocated = ($hits.Count -gt 0)
    }
}

# Picks the winning milestone and applies its flips to $Buf in place. A site is
# "satisfied" only when its signature matches EXACTLY expectedMatches times; a
# wrong count means the layout changed and the site is declined, never guessed.
# The milestone with the most satisfied sites wins.
#
# Returns:
#   Status     0 = nothing matched, caller declines; 1 = bytes were flipped;
#              2 = every located site was already patched (buffer unchanged)
#   Milestone  winning table's name, for output
#   Located    satisfied sites, out of Total sites in that milestone
#   Full       Located -eq Total; a partial patch may still leave MV2 blocked
#   Flips      sites now in the patched state, already-applied ones included
#   Written    @{ RVA; Bytes } per patched site for record-keeping
#   Relocated  at least one gate was found by scan, not at its recorded RVA
function Invoke-PatchMilestones {
    param(
        [byte[]]$Buf,
        $Img,
        [array]$Milestones,
        [bool]$AllowPartial = $false,
        [bool]$Apply = $true
    )

    $best = $null
    $bestCount = 0
    foreach ($ms in $Milestones) {
        $flips = @(); $satisfied = 0
        foreach ($s in $ms.Sites) {
            $r = Find-AffectedJgSites -Buf $Buf -Img $Img -Site $s
            if ($r.Found.Count -eq $s.ExpectedMatches) {
                $satisfied++
                foreach ($jgRaw in $r.Found) {
                    $flips += [pscustomobject]@{ Site = $s; JgRaw = $jgRaw; Relocated = $r.Relocated }
                }
            }
        }
        if ($null -eq $best -or $satisfied -gt $best.Satisfied) {
            $best = [pscustomobject]@{ Ms = $ms; Flips = $flips; Satisfied = $satisfied }
            $bestCount = 1
        } elseif ($satisfied -eq $best.Satisfied -and $satisfied -gt 0) {
            $bestCount++
        }
        # Early exit: a milestone that satisfies EVERY site is the definitive
        # match - no other milestone can beat 100%. Stop here so we do not scan
        # .text again for the remaining milestone(s). On a relocated point
        # release every site is a full-.text scan, so skipping the losing
        # milestone's whole site set is the single biggest time saving here.
        if ($best.Satisfied -eq $best.Ms.Sites.Count) { break }
    }

    $res = [pscustomobject]@{
        Status = 0; Milestone = ''; Located = 0; Total = 0; Flips = 0
        Full = $false; Written = @(); Relocated = $false; Reason = ''
        Stock = 0; Already = 0
    }
    if ($null -eq $best -or $best.Satisfied -eq 0) { return $res }

    $res.Milestone = $best.Ms.Name
    $res.Located   = $best.Satisfied
    $res.Total     = $best.Ms.Sites.Count
    $res.Full      = ($best.Satisfied -eq $best.Ms.Sites.Count)

    if (-not $res.Full -and $bestCount -gt 1) {
        $res.Reason = "$bestCount milestones tied at $($best.Satisfied) located site(s); layout is ambiguous"
        Write-Warn $res.Reason
        return $res
    }
    if (-not $res.Full -and -not $AllowPartial) {
        $res.Reason = "only $($res.Located)/$($res.Total) sites matched; partial writes require -AllowPartial"
        Write-Warn $res.Reason
        return $res
    }

    Write-Info ("Chrome {0} MV2 layout detected ({1}/{2} inlined IsExtensionAffected sites, {3} jg flip(s))." -f `
        $best.Ms.Name, $res.Located, $res.Total, $best.Flips.Count)

    # Three cases per site: already flipped (counted, nothing written), stock jg
    # (flip it), anything else (left alone with a warning - never guess).
    $applied = 0; $already = 0
    foreach ($f in $best.Flips) {
        $jgRVA = [uint32]($Img.TextRVA + ($f.JgRaw - $Img.TextRaw))
        $ms    = $best.Ms.Name
        if ($f.Relocated) { $res.Relocated = $true }

        if ($f.Site.Kind -eq 0) {
            $cur = $Buf[$f.JgRaw]
            if ($cur -eq 0xEB) {
                Write-Host ("    [i] {0}: {1} jg->jmp at RVA 0x{2:X} already applied (no change)." -f $ms, $f.Site.Name, $jgRVA)
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0xEB) }
                continue
            }
            if ($cur -ne 0x7F) {
                Write-Host ("    {0} {1}: {2} unexpected byte 0x{3:X} at RVA 0x{4:X} (expected 0x7F) - skipping this site." -f `
                    $script:TagWarn, $ms, $f.Site.Name, $cur, $jgRVA)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = 0xEB }          # jg -> jmp short
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0xEB) }
        } elseif ($f.Site.Kind -eq 1) {
            $o0 = $Buf[$f.JgRaw]; $o1 = $Buf[$f.JgRaw + 1]
            if ($o0 -eq 0x90 -and $o1 -eq 0xE9) {
                Write-Host ("    [i] {0}: {1} jg->jmp at RVA 0x{2:X} already applied (no change)." -f $ms, $f.Site.Name, $jgRVA)
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0x90, 0xE9) }
                continue
            }
            if (-not ($o0 -eq 0x0F -and $o1 -eq 0x8F)) {
                Write-Host ("    {0} {1}: {2} unexpected bytes 0x{3:X} 0x{4:X} at RVA 0x{5:X} (expected 0F 8F) - skipping this site." -f `
                    $script:TagWarn, $ms, $f.Site.Name, $o0, $o1, $jgRVA)
                continue
            }
            $res.Stock++
            if ($Apply) {
                $Buf[$f.JgRaw]     = 0x90      # nop
                $Buf[$f.JgRaw + 1] = 0xE9      # jmp near (keeps the disp32)
            }
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0x90, 0xE9) }
        } else {
            # bcond (arm64): the branch's cond nibble is the low nibble of byte0.
            # Flip GT (0xC) -> AL (0xE); imm19 and everything else are preserved,
            # so a valid branch to its existing target simply becomes unconditional.
            $cur     = $Buf[$f.JgRaw]
            $cond    = $cur -band 0x0F
            $patched = [byte](($cur -band 0xF0) -bor 0x0E)
            if ($cond -eq 0x0E) {
                Write-Host ("    [i] {0}: {1} b.gt->b.al at RVA 0x{2:X} already applied (no change)." -f $ms, $f.Site.Name, $jgRVA)
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@($patched) }
                continue
            }
            if ($cond -ne 0x0C) {
                Write-Host ("    {0} {1}: {2} unexpected b.cond 0x{3:X} at RVA 0x{4:X} (expected GT nibble 0xC) - skipping this site." -f `
                    $script:TagWarn, $ms, $f.Site.Name, $cur, $jgRVA)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = $patched }      # b.gt -> b.al (cond GT->AL)
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@($patched) }
        }

        $suffix = if ($f.Relocated) { '  (RELOCATED - point-release layout)' } else { '' }
        $verb = if ($f.Site.Kind -eq 2) { 'b.gt->b.al' } else { 'jg->jmp' }
        if ($Apply) {
            Write-Host ("    {0} {1}: {2} {3} at RVA 0x{4:X}{5}" -f $script:TagOK, $ms, $f.Site.Name, $verb, $jgRVA, $suffix)
        } else {
            $stockWord = if ($f.Site.Kind -eq 2) { 'stock b.gt' } else { 'stock jg' }
            Write-Host ("    {0} {1}: {2} {3} at RVA 0x{4:X}{5}" -f $script:TagOK, $ms, $f.Site.Name, $stockWord, $jgRVA, $suffix)
        }
    }
    $res.Flips += $already   # count already-applied sites toward the flip total

    if (-not $res.Full) {
        Write-Host ("    {0} Chrome {1}: {2} site(s) not found - this Chrome build may have shifted them. MV2 re-enable is PARTIAL and may still be blocked; please report the version." -f `
            $script:TagWarn, $best.Ms.Name, ($res.Total - $res.Located))
    }

    $res.Status = if ($applied -gt 0) { 1 } else { 2 }
    return $res
}

function Test-PatchOutput {
    param([byte[]]$Buf, $Img, $Patch)
    foreach ($w in $Patch.Written) {
        $off = [int64]$Img.TextRaw + ([int64]$w.RVA - [int64]$Img.TextRVA)
        if ($off -lt 0 -or $off + $w.Bytes.Length -gt $Buf.LongLength) { return $false }
        for ($i = 0; $i -lt $w.Bytes.Length; $i++) {
            if ($Buf[$off + $i] -ne $w.Bytes[$i]) { return $false }
        }
    }
    return ($Patch.Written.Count -gt 0)
}

function Get-CleanStockLayout {
    param([byte[]]$Buf, $Img, [array]$Milestones, [bool]$AllowPartialLayout = $false)
    $copy = [byte[]]$Buf.Clone()
    # This is a validation probe (no write). Suppress the per-site "stock jg at
    # RVA ..." host output (stream 6) - callers print their own one-line summary.
    $probe = Invoke-PatchMilestones -Buf $copy -Img $Img -Milestones $Milestones `
        -AllowPartial $AllowPartialLayout -Apply $false 6>$null
    $clean = ($probe.Status -ne 0 -and $probe.Stock -gt 0 -and $probe.Already -eq 0 -and
        ($probe.Full -or $AllowPartialLayout) -and -not $probe.Reason)
    return [pscustomobject]@{ Clean = $clean; Probe = $probe }
}

# Report-only structural scan for the decline path. Never writes anything: it
# prints up to 20 cmp/jg skeletons that LOOK like a gate, as a starting point for
# deriving a new milestone by hand. Heuristic, so expect false positives.
function Show-LayoutCandidates {
    param([byte[]]$Buf, $Img)

    if ($Img.TextSize -lt 8) { return }
    Write-Info 'Scanning .text for the IsExtensionAffected skeleton (cmp r/m32,2 ; jg short ; ... ; type/location check)...'
    Initialize-NativeHelpers

    $hits = [Mv2Native]::SkeletonScan($Buf, [int64]$Img.TextRaw, [int64]$Img.TextSize)
    $maxDisplay = 20
    $shown = 0
    foreach ($cmpStart in $hits) {
        if ($shown -ge $maxDisplay) { break }
        $rva = [uint32]($Img.TextRVA + $cmpStart)
        $len = [Math]::Min(24, $Img.TextSize - $cmpStart)
        $slice = [byte[]]::new($len)
        [Array]::Copy($Buf, $Img.TextRaw + $cmpStart, $slice, 0, $len)
        Write-Host ("    [candidate] RVA 0x{0:X}: {1}" -f $rva, (Format-HexUpper $slice))
        $shown++
    }
    $extra = if ($hits.Count -gt $shown) { " ($($hits.Count - $shown) not shown)" } else { '' }
    Write-Info ("Skeleton scan found {0} candidate site(s){1}. None were modified - verify each against mv2-reversing.md 'Porting to a new Chrome version' before hand-patching." -f $hits.Count, $extra)
}

# ============================================================================
# Windows host glue: who has chrome.dll open, and are we admin.
# ============================================================================

# Restart Manager (rstrtmgr) + CreateFileW P/Invoke. Loaded on demand, and only
# once - the ('Mv2Win32' -as [type]) probe is the guard, since Add-Type cannot
# redefine a type in the same session.
function Initialize-Win32 {
    if ('Mv2Win32' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class Mv2Win32
{
    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

    const int CCH_RM_MAX_APP_NAME = 255;
    const int CCH_RM_MAX_SVC_NAME = 63;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, IntPtr rgApplications, uint nServices, string[] rgsServiceNames);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint pSessionHandle);

    // Returns "pid|starttime|appname" for each process holding the file, so the
    // caller can validate the PID has not been recycled before terminating it.
    public static string[] GetFileHolders(string path)
    {
        uint session; var key = Guid.NewGuid().ToString();
        var results = new List<string>();
        if (RmStartSession(out session, 0, key) != 0) return results.ToArray();
        try
        {
            if (RmRegisterResources(session, 1, new[] { path }, 0, IntPtr.Zero, 0, null) != 0)
                return results.ToArray();

            uint needed = 0, got = 0, reason = 0;
            RmGetList(session, out needed, ref got, null, ref reason);
            if (needed == 0) return results.ToArray();

            var info = new RM_PROCESS_INFO[needed];
            got = needed;
            if (RmGetList(session, out needed, ref got, info, ref reason) != 0)
                return results.ToArray();

            for (int i = 0; i < got; i++)
            {
                ulong ft = ((ulong)(uint)info[i].Process.ProcessStartTime.dwHighDateTime << 32)
                         | (uint)info[i].Process.ProcessStartTime.dwLowDateTime;
                results.Add(info[i].Process.dwProcessId + "|" + ft + "|" + info[i].strAppName);
            }
        }
        finally { RmEndSession(session); }
        return results.ToArray();
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint OPEN_EXISTING = 3, FILE_ATTRIBUTE_NORMAL = 0x80;
    const int ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33;

    // Open for write with no sharing; a sharing/lock violation means a running
    // process has it mapped. Any other failure is a permissions problem.
    public static bool IsFileLocked(string path)
    {
        IntPtr h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h != new IntPtr(-1)) { CloseHandle(h); return false; }
        int err = Marshal.GetLastWin32Error();
        return err == ERROR_SHARING_VIOLATION || err == ERROR_LOCK_VIOLATION;
    }
}
'@
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ElevationHint {
    return "Administrator privileges are REQUIRED to modify chrome.dll in Program Files!`n    Re-run from an elevated terminal (right-click PowerShell -> Run as administrator)."
}

function Get-QuotedArg {
    param([string]$s)
    # CommandLineToArgvW rules: wrap in quotes if empty or containing whitespace
    # or a quote, escaping embedded quotes as \". Adequate for switches and
    # Windows file paths (no trailing-backslash / embedded-quote cases here).
    if ($s -eq '' -or $s -match '[\s"]') { return '"' + ($s -replace '"', '\"') + '"' }
    return $s
}

<#
Re-launches this script elevated via Start-Process -Verb RunAs, which raises the
UAC consent dialog (a compiled exe would get the same effect from a
requireAdministrator manifest). Returns the elevated child's
exit code, or $null when elevation was declined/impossible so the caller can
fall back to the plain "you need admin" message.

There are TWO launch shapes to handle:

  * FILE mode - the normal case: the script is a file on disk ($PSCommandPath is
    set). Relaunch with -File <script> and the same bound parameters, plus
    -Relaunched as the loop guard.

  * REPLAY mode - `irm https://.../chrome-mv2.ps1 | iex`: there is NO script file
    ($PSCommandPath is empty and the body is not visible to itself), so -File is
    impossible. Instead replay the process's own command line
    ([Environment]::GetCommandLineArgs()) verbatim under RunAs, so the elevated
    child re-fetches and re-runs exactly the same one-liner. The loop guard is
    injected in-band by prefixing the -Command/-EncodedCommand payload with
    `$env:MV2_RELAUNCHED='1';` - env vars are NOT reliably inherited across the
    UAC boundary, so the marker has to live inside the replayed command itself.

Details common to both:
  * Arguments are quoted so a path with spaces ("C:\Program Files\...") stays one
    argument instead of splitting.
  * -WorkingDirectory is pinned to the current directory (an elevated process
    otherwise starts in system32), so a relative target path still resolves.
  * -Wait -PassThru is required for $p.ExitCode to be populated.

NOTE: file mode forwards parameters explicitly - a new user-facing switch has to
be added to the $argv list below or it is silently dropped on the elevated run.
#>
function Invoke-SelfElevate {
    param([string]$ResolvedTargetPath)
    # Prefer the current host (pwsh vs powershell.exe) so PS7 stays on PS7.
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' } }

    $fileMode = $PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)

    if ($fileMode) {
        $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-QuotedArg $PSCommandPath), $Command)
        if ($ResolvedTargetPath)  { $argv += (Get-QuotedArg $ResolvedTargetPath) }
        if ($Yes)   { $argv += '-Yes' }
        if ($Quiet) { $argv += '-Quiet' }
        if ($AllowPartial) { $argv += '-AllowPartial' }
        if ($ForceRestore) { $argv += '-ForceRestore' }
        if ($Signatures) { $argv += '-Signatures'; $argv += (Get-QuotedArg ([IO.Path]::GetFullPath($Signatures))) }
        $argv += '-Relaunched'
        $argString = $argv -join ' '
    } else {
        # REPLAY mode: rebuild from this process's own argv, injecting the guard
        # into the -Command / -EncodedCommand payload.
        $raw = [Environment]::GetCommandLineArgs()
        $targetB64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ResolvedTargetPath))
        $marker = "`$env:MV2_RELAUNCHED='1'; `$env:MV2_TARGET_B64='$targetB64'; "
        $rebuilt = New-Object System.Collections.Generic.List[string]
        $injected = $false
        for ($i = 1; $i -lt $raw.Count; $i++) {
            $tok = $raw[$i]
            if (-not $injected -and $tok -match '^-(c|Command)$' -and ($i + 1) -lt $raw.Count) {
                $rebuilt.Add($tok)
                $rebuilt.Add((Get-QuotedArg ($marker + $raw[$i + 1])))
                $i++; $injected = $true; continue
            }
            if (-not $injected -and $tok -match '^-(e|ec|EncodedCommand)$' -and ($i + 1) -lt $raw.Count) {
                $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($raw[$i + 1]))
                $reenc   = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($marker + $decoded))
                $rebuilt.Add($tok); $rebuilt.Add($reenc)
                $i++; $injected = $true; continue
            }
            $rebuilt.Add((Get-QuotedArg $tok))
        }
        if (-not $injected) {
            # No command payload to guard - refuse rather than risk a UAC loop.
            Write-Warn 'Cannot self-elevate this invocation; re-run from an elevated terminal.'
            return $null
        }
        $argString = $rebuilt -join ' '
    }

    Write-Info 'Requesting Administrator privileges (a UAC prompt will appear)...'
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argString -Verb RunAs `
                           -WorkingDirectory (Get-Location).Path -Wait -PassThru -ErrorAction Stop
        return $p.ExitCode
    } catch {
        # 1223 = ERROR_CANCELLED: the user dismissed the UAC dialog.
        Write-Warn 'Elevation was declined - nothing was changed.'
        return $null
    }
}

function Test-TargetLocked {
    param([string]$TargetPath)
    Initialize-Win32
    return [Mv2Win32]::IsFileLocked($TargetPath)
}

# Unpacks the "pid|starttime|appname" rows from Mv2Win32.GetFileHolders. Empty
# when nothing holds the file (or Restart Manager refused the query).
function Get-FileHolders {
    param([string]$TargetPath)
    Initialize-Win32
    $out = @()
    foreach ($row in [Mv2Win32]::GetFileHolders($TargetPath)) {
        $parts = $row -split '\|', 3
        $out += [pscustomobject]@{
            Pid = [int]$parts[0]; StartTime = [uint64]$parts[1]; AppName = $parts[2]
        }
    }
    return $out
}

# Force-closes only the processes holding this file, validating each PID still
# refers to the process RM saw (PIDs recycle) before killing it.
function Close-FileHolders {
    param([string]$TargetPath)

    $holders = @(Get-FileHolders -TargetPath $TargetPath)
    if ($holders.Count -gt 0) {
        Write-Warn "Force-closing $($holders.Count) process(es) that hold this target."
    }
    foreach ($h in $holders) {
        try {
            $p = Get-Process -Id $h.Pid -ErrorAction Stop
            if ($h.StartTime -ne 0) {
                $seen = [uint64]$p.StartTime.ToFileTime()
                if ($seen -ne $h.StartTime) { continue }   # recycled PID - not our process
            }
            $name = if ($h.AppName) { $h.AppName } else { 'process' }
            $p.Kill()
            $p.WaitForExit(5000) | Out-Null
            Write-Host "    $script:TagOK Closed $name (PID $($h.Pid))."
        } catch { }
    }

    # Chrome tears down asynchronously; re-check the file itself.
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Test-TargetLocked -TargetPath $TargetPath)) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

# Performs a fresh lock/holder check and obtains consent in the same operation.
# A process which starts after this returns is handled by the atomic replace
# failing; it is never killed without going through this consent gate.
function Request-TargetUnlock {
    param($Target, [bool]$AssumeYes)

    $holders = @(Get-FileHolders -TargetPath $Target.Path)
    $locked = Test-TargetLocked -TargetPath $Target.Path
    if ($holders.Count -eq 0 -and -not $locked) { return $true }

    $current = [pscustomobject]@{
        Channel = $Target.Channel; Path = $Target.Path; Running = $true
        Holders = $holders.Count
    }
    if ($AssumeYes) {
        Write-Warn "Chrome $($Target.Channel) is running and will be force closed (-Yes)."
    } elseif ($Quiet) {
        Write-Err "Chrome $($Target.Channel) is running ($($holders.Count) detected holder(s))."
        Write-Host '    Close it, or pass -Yes to force close it.'
        return $false
    } elseif (-not (Confirm-ForceClose $current)) {
        return $false
    }

    if (Close-FileHolders -TargetPath $Target.Path) {
        Write-Ok 'This channel is closed; other Chrome channels were left running.'
        return $true
    }
    return $false
}

function Test-TargetDirectoryWritable {
    param([string]$TargetPath)
    $dir = Split-Path -Parent ([IO.Path]::GetFullPath($TargetPath))
    $probe = Join-Path $dir ('.chrome-mv2-write-probe-' + [Guid]::NewGuid().ToString('N'))
    try {
        $fs = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $fs.Dispose()
        return $true
    } catch {
        return $false
    } finally {
        if (Test-Path -LiteralPath $probe -PathType Leaf) { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
    }
}

# Writes the patched image in place. The file was unlocked first, so a straight
# overwrite is safe (Chrome reopens chrome.dll on next launch).
function Write-Target {
    param([string]$TargetPath, [byte[]]$Buf, [string]$ExpectedCurrentHash = '')
    Write-AtomicFile -TargetPath $TargetPath -Buf $Buf -ExpectedCurrentHash $ExpectedCurrentHash -PreserveMetadataFrom $TargetPath
}

# ============================================================================
# Install discovery: find each channel's chrome.dll without touching the registry
# (the install roots and per-channel subdirectory names are fixed).
# ============================================================================

$WinChannels = @(
    @{ Name = 'Stable'; Subdir = 'Google\Chrome' }
    @{ Name = 'Beta';   Subdir = 'Google\Chrome Beta' }
    @{ Name = 'Dev';    Subdir = 'Google\Chrome Dev' }
    @{ Name = 'Canary'; Subdir = 'Google\Chrome SxS' }   # SxS = Canary's side-by-side dir
)

# True for a Chrome version directory name like "151.0.7922.109" (>= 3 numeric
# parts). Used to label the target and to skip non-version subdirectories.
function Test-LooksLikeVersion {
    param([string]$Name)
    $parts = $Name -split '\.'
    if ($parts.Count -lt 3) { return $false }
    foreach ($p in $parts) { if ($p -eq '' -or $p -notmatch '^\d+$') { return $false } }
    return $true
}

# Numeric version compare over up to 4 parts, so "151.0.7922.99" sorts below
# "151.0.7922.109" (a plain string compare would not).
function Compare-Version {
    param([string]$A, [string]$B)   # returns $true if A < B
    $pa = @($A -split '\.' | ForEach-Object { [int]($_ -replace '\D', '0') })
    $pb = @($B -split '\.' | ForEach-Object { [int]($_ -replace '\D', '0') })
    for ($i = 0; $i -lt 4; $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($x -ne $y) { return ($x -lt $y) }
    }
    return $false
}

function Get-BackupPath { param([string]$Target) return "$Target.bak" }

# Returns the chrome.dll under the highest-numbered version subdirectory, or one
# sitting directly in the Application dir.
function Find-DllUnderApplication {
    param([string]$AppDir)
    if (Test-Path -LiteralPath $AppDir -PathType Container) {
        $best = ''
        foreach ($d in Get-ChildItem -LiteralPath $AppDir -Directory -ErrorAction SilentlyContinue) {
            if ($best -eq '' -or (Compare-Version $best $d.Name)) {
                if (Test-Path -LiteralPath (Join-Path $d.FullName 'chrome.dll') -PathType Leaf) { $best = $d.Name }
            }
        }
        if ($best -ne '') { return (Join-Path (Join-Path $AppDir $best) 'chrome.dll') }
    }
    $direct = Join-Path $AppDir 'chrome.dll'
    if (Test-Path -LiteralPath $direct -PathType Leaf) { return $direct }
    return ''
}

# One target's display/decision facts: channel, version, whether it is running,
# and whether a .bak already exists.
function Get-InstallDetails {
    param([string]$TargetPath, [string]$Channel)

    $parent = Split-Path -Leaf (Split-Path -Parent $TargetPath)
    $version = if (Test-LooksLikeVersion $parent) { $parent } else { '' }

    $holders = @()
    try { $holders = @(Get-FileHolders -TargetPath $TargetPath) } catch { }
    $running = ($holders.Count -gt 0)
    if (-not $running) { try { $running = Test-TargetLocked -TargetPath $TargetPath } catch { } }

    if (-not $Channel) {
        $lower = $TargetPath.ToLower()
        foreach ($ch in $WinChannels) {
            if ($lower.Contains($ch.Subdir.ToLower())) { $Channel = $ch.Name; break }
        }
        if (-not $Channel) { $Channel = 'Unknown' }
    }

    return [pscustomobject]@{
        Channel   = $Channel
        Path      = $TargetPath
        Version   = $version
        Running   = $running
        Holders   = $holders.Count
        HasBackup = (Test-Path -LiteralPath (Get-BackupPath $TargetPath) -PathType Leaf)
    }
}

# Every installed channel across the machine-wide and per-user install roots,
# deduplicated by path (a channel can appear under more than one root).
function Get-ChromeInstalls {
    $found = @(); $seen = @{}

    $roots = @()
    foreach ($v in 'ProgramFiles', 'ProgramFiles(x86)', 'LOCALAPPDATA') {
        $val = [Environment]::GetEnvironmentVariable($v)
        if ($val) { $roots += $val }
    }
    foreach ($ch in $WinChannels) {
        foreach ($root in $roots) {
            $dll = Find-DllUnderApplication (Join-Path (Join-Path $root $ch.Subdir) 'Application')
            if ($dll -eq '') { continue }
            $key = $dll.ToLower()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $found += Get-InstallDetails -TargetPath $dll -Channel $ch.Name
        }
    }
    # A chrome.dll dropped next to the script stays supported for offline use.
    if ($found.Count -eq 0 -and (Test-Path './chrome.dll' -PathType Leaf)) {
        $found += Get-InstallDetails -TargetPath './chrome.dll' -Channel 'Local file'
    }
    return $found
}

# ============================================================================
# Interactive prompts. All of these are skipped under -Quiet, which never reads
# from stdin - see Confirm-CloseConsent and Resolve-Target.
# ============================================================================

# One numbered line per channel: "3) Beta 152.0.7444.20 [RUNNING, 8 process(es)]".
function Show-InstallRow {
    param([int]$Index, $Inst)
    $line = "  $($C.Bold)$Index)$($C.Reset) $($C.Cyn)$($Inst.Channel)$($C.Reset)"
    if ($Inst.Version) { $line += "  $($Inst.Version)" }
    if ($Inst.Running) {
        $line += "  $($C.Yel)[RUNNING"
        if ($Inst.Holders -gt 0) { $line += ", $($Inst.Holders) process(es)" }
        $line += "]$($C.Reset)"
    } else {
        $line += "  $($C.Grn)[not running]$($C.Reset)"
    }
    if ($Inst.HasBackup) { $line += " $($C.Dim)(backup present)$($C.Reset)" }
    Write-Host $line
    Write-Host "      $($C.Dim)$($Inst.Path)$($C.Reset)"
}

# Prompts for a chrome.dll path until one exists, or $null if the user gives up.
# The Trim chain strips the quotes that copying a path from Explorer adds.
function Read-CustomPath {
    while ($true) {
        Write-Host "$($C.Bold)"
        $line = Read-Host 'Enter the full path to chrome.dll, blank to cancel'
        Write-Host "$($C.Reset)" -NoNewline
        $p = $line.Trim().Trim('"').Trim("'").Trim()
        if ($p -eq '') { return $null }
        if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
            Write-Err 'No file at that path. Try again, or leave blank to cancel.'
            continue
        }
        return (Get-InstallDetails -TargetPath $p -Channel '')
    }
}

# Lists the channels and returns the chosen one, or $null on quit. With exactly
# one install, Enter accepts it; otherwise a number is required.
function Select-Install {
    param([array]$Installs)

    if ($Installs.Count -eq 1) {
        Write-Ok 'One Chrome channel found:'
        Show-InstallRow 1 $Installs[0]
    } else {
        Write-Host "`n$script:TagInfo $($Installs.Count) Chrome release channels found:"
        for ($i = 0; $i -lt $Installs.Count; $i++) { Show-InstallRow ($i + 1) $Installs[$i] }
        Write-Host "`n$script:TagInfo Only the channel you pick is modified; the others keep running."
    }

    # 'check' is read-only and must never turn into a write, so it neither offers
    # nor honors the restore switch; only 'patch' may divert to restore. The verb
    # keeps the prompt honest for whichever command is actually running.
    $verb = switch ($script:Command) { 'check' { 'Check' } 'restore' { 'Restore' } default { 'Patch' } }
    $verbLower = $verb.ToLower()
    $allowRestore = ($script:Command -eq 'patch')

    while ($true) {
        $restoreOpt = if ($allowRestore) { 'r=restore, ' } else { '' }
        $prompt = if ($Installs.Count -eq 1) {
            "$verb this channel? [Enter=yes, ${restoreOpt}c=custom path, q=quit]"
        } else {
            "Which channel do you want to ${verbLower}? [1-$($Installs.Count), ${restoreOpt}c=custom path, q=quit]"
        }
        $line = (Read-Host "`n$prompt").Trim()

        if ($line -in 'q', 'Q') { return $null }
        if ($allowRestore -and $line -in 'r', 'R') {
            $script:Command = 'restore'
            if ($Installs.Count -eq 1) { return $Installs[0] }
            # Show restore-specific prompt for multiple channels
            Write-Host "`n$script:TagInfo Restore mode selected. Choose which channel to restore from backup:"
            while ($true) {
                $restoreLine = (Read-Host "`nWhich channel do you want to restore? [1-$($Installs.Count), q=cancel]").Trim()
                if ($restoreLine -in 'q', 'Q') { 
                    Write-Info 'Restore cancelled.'
                    return $null 
                }
                $rn = 0
                if ([int]::TryParse($restoreLine, [ref]$rn) -and $rn -ge 1 -and $rn -le $Installs.Count) {
                    return $Installs[$rn - 1]
                }
                Write-Err "Enter a number between 1 and $($Installs.Count), or q to cancel."
            }
        }
        if ($line -in 'c', 'C') {
            $pick = Read-CustomPath
            if ($pick) { return $pick }
            continue
        }
        if ($Installs.Count -eq 1 -and $line -eq '') { return $Installs[0] }
        $n = 0
        if ([int]::TryParse($line, [ref]$n) -and $n -ge 1 -and $n -le $Installs.Count) {
            return $Installs[$n - 1]
        }
        $restoreHint = if ($allowRestore) { 'r to restore, ' } else { '' }
        if ($Installs.Count -eq 1) {
            Write-Err "Press Enter to accept, ${restoreHint}c for a custom path, or q to quit."
        } else {
            Write-Err "Enter a number between 1 and $($Installs.Count), ${restoreHint}c for a custom path, or q to quit."
        }
    }
}

function Confirm-ForceClose {
    param($Inst)
    Write-Host "`n$($C.Bold)$($C.Yel)  !! WARNING: Chrome $($Inst.Channel) is running !!$($C.Reset)"
    Write-Host "     Close it now to patch cleanly. If you continue, its $($Inst.Holders) process(es)"
    Write-Host '     will be FORCE CLOSED and any unsaved tabs or downloads are lost.'
    Write-Host "     $($C.Dim)Other Chrome channels are unaffected either way.$($C.Reset)"

    while ($true) {
        $line = (Read-Host "`nForce close Chrome $($Inst.Channel) and patch? [y/N]").Trim()
        if ($line -in 'y', 'Y') { return $true }
        if ($line -eq '' -or $line -in 'n', 'N') { Write-Info 'Cancelled - nothing was changed.'; return $false }
    }
}

# ============================================================================
# Orchestration
# ============================================================================

# Decides which file to work on: an explicit path wins; otherwise discovery, then
# a prompt. Non-interactive (-Quiet) auto-picks only when exactly one channel is
# installed, so an unattended run can never patch a channel nobody chose.
function Resolve-Target {
    param([string]$TargetPath, [bool]$Interactive)

    if ($TargetPath) {
        if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
            Write-Err 'Error: the given path does not exist.'
            return $null
        }
        return (Get-InstallDetails -TargetPath $TargetPath -Channel '')
    }

    Write-Info 'Scanning for installed Chrome release channels...'
    $installs = @(Get-ChromeInstalls)

    if ($installs.Count -eq 0) {
        if (-not $Interactive) {
            Write-Err 'Error: no installed Chrome channel was found.'
            Write-Host '    Pass the path explicitly, e.g. .\chrome-mv2.ps1 patch C:\path\to\chrome.dll'
            return $null
        }
        Write-Warn 'No installed Chrome channel was found.'
        $pick = Read-CustomPath
        if ($pick) { return $pick }
        Write-Info 'No path entered - nothing was changed.'
        return $null
    }
    if (-not $Interactive -and $installs.Count -gt 1) {
        Write-Err "$($installs.Count) channels are installed and -Quiet cannot prompt."
        for ($i = 0; $i -lt $installs.Count; $i++) { Show-InstallRow ($i + 1) $installs[$i] }
        Write-Host '    Re-run with the path of the channel you want.'
        return $null
    }
    if (-not $Interactive) { return $installs[0] }

    $picked = Select-Install $installs
    if (-not $picked) { Write-Info 'No channel selected - nothing was changed.'; return $null }
    return $picked
}

# patch: consent -> unlock -> read -> backup policy -> flip gates -> finalize ->
# write. Returns a process exit code (0 = patched, 1 = nothing written).
function Invoke-Patch {
    param($Target, [bool]$AssumeYes)

    $buf = [IO.File]::ReadAllBytes($Target.Path)
    if ($buf.Length -eq 0) { Write-Err 'Error: the target file is empty.'; return 1 }
    Write-Ok "Loaded $($buf.Length) bytes from $($Target.Path)."

    $img = Open-Image $buf
    $targetIdentity = Get-PeIdentity -Buf $buf -Img $img
    $targetHash = $targetIdentity.SHA256

    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $img.Format })
    Write-Info "Starting MV2 patching (ManifestV2Handler architecture, $($img.Format.ToUpper()) target)..."
    if ($milestones.Count -eq 0) {
        Write-Warn "No $($img.Format.ToUpper()) milestone signatures are known yet - declining (nothing modified)."
        Show-LayoutCandidates -Buf $buf -Img $img
        return 1
    }

    # Backups are accepted only when they parse as clean stock and describe the
    # same PE build. A patched/unsigned target can never become a new baseline.
    $backupPath = Get-BackupPath $Target.Path
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        if (-not (Test-LikelyStock -Img $img -Buf $buf)) {
            Write-Err 'No clean backup exists and the target is not a signed stock Chrome DLL.'
            Write-Host '    Restore/reinstall Chrome first; refusing to save patched bytes as the baseline.'
            return 1
        }
        $stockLayout = Get-CleanStockLayout -Buf $buf -Img $img -Milestones $milestones `
            -AllowPartialLayout $AllowPartial.IsPresent
        if (-not $stockLayout.Clean) {
            Write-Err 'No clean backup exists and the target is not a recognized stock layout.'
            return 1
        }
        Write-Info "Creating initial backup copy: $backupPath ..."
        Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $buf -Identity $targetIdentity
        $backup = Read-ValidatedBackup $backupPath
        Write-Ok 'Initial backup created and verified.'
    } else {
        try {
            $backup = Read-ValidatedBackup $backupPath
        } catch {
            Write-Err "Backup validation failed: $_"
            return 1
        }
        if (-not (Test-LikelyStock -Img $backup.Img -Buf $backup.Buf)) {
            Write-Err 'The backup does not look like signed stock Chrome; refusing to use it.'
            return 1
        }
        $backupLayout = Get-CleanStockLayout -Buf $backup.Buf -Img $backup.Img -Milestones $milestones `
            -AllowPartialLayout $AllowPartial.IsPresent
        if (-not $backupLayout.Clean) {
            Write-Err 'The backup is not a recognized clean stock layout.'
            return 1
        }

        if (-not (Test-SameBuildIdentity -A $targetIdentity -B $backup.Identity)) {
            if (-not (Test-LikelyStock -Img $img -Buf $buf)) {
                Write-Err 'Chrome changed builds, but the current target is not verifiable stock.'
                Write-Host '    Reinstall/update Chrome to recreate a clean target before patching.'
                return 1
            }
            $newStockLayout = Get-CleanStockLayout -Buf $buf -Img $img -Milestones $milestones `
                -AllowPartialLayout $AllowPartial.IsPresent
            if (-not $newStockLayout.Clean) {
                Write-Err 'The updated target is signed but does not match a complete known stock layout.'
                return 1
            }
            Write-Info 'Chrome update detected - replacing the backup with the new signed stock build...'
            Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $buf -Identity $targetIdentity
            $backup = Read-ValidatedBackup $backupPath
            Write-Ok 'Backup updated and verified.'
        } elseif ($backup.Legacy) {
            Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $backup.Buf -Identity $backup.Identity
            Write-Ok 'Legacy backup validated and metadata added.'
        }
    }

    $buf = [byte[]]$backup.Buf.Clone()
    $img = Open-Image $buf

    Write-Info "Probing for a known Chrome layout ($($milestones.Count) milestone table(s))..."
    $patch = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones `
        -AllowPartial $AllowPartial.IsPresent -Apply $true
    if ($patch.Status -eq 0) {
        Show-LayoutCandidates -Buf $buf -Img $img
        Write-Warn 'No known MV2 layout matched this binary.'
        Write-Host '    Chrome likely shifted its layout (new milestone or different codegen).'
        Write-Host '    Nothing was modified. See "Porting to a new Chrome version" in the'
        Write-Host '    mv2-reversing.md notes and add a milestone to signatures.json (next to the script).'
        return 1
    }

    $msg = if ($patch.Status -eq 1) { 'applied.' } else { 'all sites already patched (no change needed).' }
    Write-Info "Chrome $($patch.Milestone) $msg"

    Complete-Image -Img $img -Buf $buf
    if (-not (Test-PatchOutput -Buf $buf -Img $img -Patch $patch)) {
        Write-Err 'Internal verification failed: prepared output does not contain every selected patch.'
        return 1
    }

    $preparedHash = Get-ByteHash $buf
    if ($preparedHash -eq $targetHash) {
        Write-Success 'Target is already fully patched; no write was needed.'
        return 0
    }
    if ($targetHash -ne $backup.Identity.SHA256) {
        Write-Err 'Target contains changes unrelated to this patch; refusing to overwrite them.'
        Write-Host '    Restore/reinstall Chrome or inspect the binary manually before retrying.'
        return 1
    }

    if (-not (Request-TargetUnlock -Target $Target -AssumeYes $AssumeYes)) {
        Write-Err 'Target is still locked; nothing was written.'
        return 1
    }
    Write-Target -TargetPath $Target.Path -Buf $buf -ExpectedCurrentHash $targetHash
    $afterHash = (Get-FileHash -LiteralPath $Target.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($afterHash -ne $preparedHash) { throw 'post-write SHA-256 verification failed' }

    Write-Rule
    if ($patch.Full) {
        Write-Success 'Binary successfully patched!'
        Write-Host "          Manifest V2 extension support re-enabled (Chrome $($patch.Milestone) layout)."
    } else {
        Write-Host "$script:TagWarning Binary was PARTIALLY patched (Chrome $($patch.Milestone) layout, $($patch.Located)/$($patch.Total) gates)."
        Write-Host '          The flips found were written, but'
        Write-Host "          $($patch.Total - $patch.Located) gate(s) were not located, so MV2 may STILL be blocked."
        Write-Host '          Please report the exact version. Revert with: .\chrome-mv2.ps1 restore'
    }
    Write-Rule
    return 0
}

# restore: validates backup metadata, stock layout, and build identity before an
# atomic replacement. A cross-build restore requires the explicit force switch.
function Invoke-Restore {
    param($Target, [bool]$AssumeYes)

    Write-Info 'Restore mode requested...'
    $backupPath = Get-BackupPath $Target.Path
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        Write-Err "Error: backup file $backupPath does not exist."
        return 1
    }
    try { $backup = Read-ValidatedBackup $backupPath }
    catch { Write-Err "Backup validation failed: $_"; return 1 }
    if (-not (Test-LikelyStock -Img $backup.Img -Buf $backup.Buf)) {
        Write-Err 'Backup is not verifiable signed stock Chrome; refusing to restore it.'
        return 1
    }
    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $backup.Img.Format })
    $backupLayout = Get-CleanStockLayout -Buf $backup.Buf -Img $backup.Img -Milestones $milestones -AllowPartialLayout $true
    if (-not $backupLayout.Clean) {
        Write-Err 'Backup is not a recognized clean stock layout.'
        return 1
    }
    Write-Ok ("Backup verified: clean stock Chrome {0} ({1}/{2} MV2 gate sites intact)." -f `
        $backupLayout.Probe.Milestone, $backupLayout.Probe.Located, $backupLayout.Probe.Total)

    $current = [IO.File]::ReadAllBytes($Target.Path)
    $currentImg = Open-Image $current
    $currentIdentity = Get-PeIdentity -Buf $current -Img $currentImg
    if (-not (Test-SameBuildIdentity -A $currentIdentity -B $backup.Identity) -and -not $ForceRestore) {
        Write-Err 'Backup belongs to a different Chrome build; refusing to downgrade the installed DLL.'
        Write-Host '    Use -ForceRestore only if restoring that older build is intentional.'
        return 1
    }
    if (-not (Test-SameBuildIdentity -A $currentIdentity -B $backup.Identity)) {
        Write-Warn 'Forcing restore from a different Chrome build (-ForceRestore).'
    }
    if ($currentIdentity.SHA256 -eq $backup.Identity.SHA256) {
        Write-Success 'Target already matches the verified backup; no write was needed.'
        Remove-BackupFiles $backupPath
        Write-Info 'Backup removed; the installed DLL is the original stock build.'
        return 0
    }
    if (-not (Request-TargetUnlock -Target $Target -AssumeYes $AssumeYes)) {
        Write-Err 'Target is still locked; nothing was written.'
        return 1
    }
    Write-Target -TargetPath $Target.Path -Buf $backup.Buf -ExpectedCurrentHash $currentIdentity.SHA256
    $afterHash = (Get-FileHash -LiteralPath $Target.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($afterHash -ne $backup.Identity.SHA256) { throw 'post-restore SHA-256 verification failed' }
    Write-Success 'Original binary successfully restored from backup!'
    Remove-BackupFiles $backupPath
    Write-Info 'Backup removed; the installed DLL is the original stock build.'
    return 0
}

function Invoke-Check {
    param($Target)
    $buf = [IO.File]::ReadAllBytes($Target.Path)
    if ($buf.Length -eq 0) { Write-Err 'Error: the target file is empty.'; return 1 }
    $img = Open-Image $buf
    $identity = Get-PeIdentity -Buf $buf -Img $img
    Write-Ok ("PE identity: {0}, machine=0x{1:X4}, timestamp=0x{2:X8}, size={3}, SHA-256={4}" -f `
        $identity.Format, $identity.Machine, $identity.TimeStamp, $identity.Length, $identity.SHA256)

    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $img.Format })
    $probe = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones -AllowPartial $true -Apply $false
    if ($probe.Status -eq 0) {
        Write-Warn $(if ($probe.Reason) { $probe.Reason } else { 'No known complete MV2 layout matched.' })
    } else {
        $state = if ($probe.Stock -gt 0 -and $probe.Already -gt 0) { 'mixed' } elseif ($probe.Stock -gt 0) { 'stock' } else { 'patched' }
        Write-Ok "Layout: Chrome $($probe.Milestone), $($probe.Located)/$($probe.Total) sites, state=$state."
    }

    $backupPath = Get-BackupPath $Target.Path
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
        try {
            $backup = Read-ValidatedBackup $backupPath
            $same = Test-SameBuildIdentity -A $identity -B $backup.Identity
            Write-Ok "Backup: verified, same build=$same, metadata=$(-not $backup.Legacy)."
        } catch { Write-Warn "Backup: invalid ($_)." }
    } else { Write-Info 'Backup: absent.' }

    # Exit-code contract (kept in step with chrome-mv2.sh): 0 = a complete,
    # internally consistent layout was recognized, whether stock or patched;
    # non-zero = no complete layout matched, or it was mixed/partial. This is
    # deliberately NOT a patched-vs-stock detector - read the printed
    # state=stock|patched|mixed line for that distinction.
    return $(if ($probe.Full) { 0 } else { 1 })
}

# ============================================================================
# Entry point
# ============================================================================

# Version/banner -> elevation -> target selection -> command dispatch. Returns
# the process exit code; MV2_TEST_NO_ELEVATION=1 bypasses the admin gate so an
# unelevated run can be tested against a scratch copy of a chrome.dll.
function Invoke-Main {
    Initialize-Colors

    if ($Version) { Write-Host "chrome-mv2-patch (PowerShell) $AppVersion"; return 0 }

    Write-Banner

    $effectivePath = $Path
    if (-not $effectivePath -and $env:MV2_TARGET_B64) {
        try { $effectivePath = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:MV2_TARGET_B64)) }
        catch { Write-Err 'Invalid elevated target marker.'; return 1 }
    }

    # Resolve before elevation. Read-only checks never need admin, and an
    # offline/user-owned copy should not cause a UAC prompt merely because the
    # normal Program Files installation does.
    $target = Resolve-Target -TargetPath $effectivePath -Interactive (-not $Quiet)
    if (-not $target) { return 1 }

    Write-Host "$script:TagOK Target channel: $($C.Cyn)$($target.Channel)$($C.Reset)"
    Write-Host "$script:TagOK Target file: $($target.Path)"
    if ($target.Version) { Write-Host "$script:TagOK Chrome version detected: $($target.Version)" }

    if ($Command -eq 'check') { return (Invoke-Check -Target $target) }

    $needsElevation = -not (Test-TargetDirectoryWritable -TargetPath $target.Path)
    if ($needsElevation -and -not (Test-Elevated) -and -not $env:MV2_TEST_NO_ELEVATION) {
        # Loop guard: -Relaunched (file mode) or the MV2_RELAUNCHED env marker
        # (replay/irm|iex mode) means we ALREADY tried to elevate. If we are
        # still not admin, report and stop instead of spawning again.
        $alreadyTried = $Relaunched -or $env:MV2_RELAUNCHED
        if (-not $alreadyTried) {
            $childCode = Invoke-SelfElevate -ResolvedTargetPath ([IO.Path]::GetFullPath($target.Path))
            if ($null -ne $childCode) {
                # The elevated child ran in its own window and already paused on
                # any error of its own, so don't pause again here.
                $script:SuppressPause = $true
                return $childCode
            }
            return 1
        }
        Write-Host "$script:TagWarn $(Get-ElevationHint)"
        return 1
    }

    if ($Command -eq 'restore') { return (Invoke-Restore -Target $target -AssumeYes $Yes.IsPresent) }
    return (Invoke-Patch -Target $target -AssumeYes $Yes.IsPresent)
}

# Set true when an elevated child ran: it owns its window and its own error pause.
$script:SuppressPause = $false

if ($env:MV2_TEST_LIBRARY_ONLY) { return }

$exitCode = Invoke-Main

# On failure, hold a double-clicked window open so the error stays visible. Skip
# in -Quiet (scripting), when an elevated child already paused on its own error,
# and when input is redirected (piped/automation) so an unattended run never hangs.
if ($exitCode -ne 0 -and -not $Quiet -and -not $script:SuppressPause -and -not [Console]::IsInputRedirected) {
    Write-Host ''
    Write-Host 'Press any key to exit...' -NoNewline
    try { [void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') }
    catch { Read-Host | Out-Null }
    Write-Host ''
}
exit $exitCode
