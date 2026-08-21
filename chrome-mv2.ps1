<#
.SYNOPSIS
    Chrome / Chromium Manifest V2 Patcher - single-file, self-contained PowerShell
    port for Windows (chrome.dll only; x64, x86, and arm64).

.DESCRIPTION
    Re-enables Manifest V2 extension support in Google Chrome or Chromium (both
    ship chrome.dll) by flipping the inlined IsExtensionAffected manifest-version
    checks. Same milestone engine, same match/decline semantics, same .bak
    handling. Handles x64/x86 (PE, PE32) and Windows-on-ARM (PE32+ arm64, machine
    0xAA64).

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

$AppVersion      = '1.5.1'
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
    {"name":"152-win-arm64","container":"pe-arm64","sites":[{"name":"ManifestV2Handler::OnExtensionSystemReady","kind":"bcond","jgRVA":"0x01014CBC","jgOff":4,"expectedMatches":1,"sig":"3F0900718C010054091541F90A214839283140B98A000037296940B93F050071"},{"name":"StandardManagementPolicyProvider::MustRemainDisabled / StandardManagementPolicyProvider::UserMayInstall (shared body)","kind":"bcond","jgRVA":"0x013591BC","jgOff":4,"expectedMatches":2,"sig":"1F090071EC050054891641F98A224839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::ShouldBlockExtensionEnable / ManifestV2Handler::IsExtensionAffected (shared body)","kind":"bcond","jgRVA":"0x02C1FD9C","jgOff":4,"expectedMatches":2,"sig":"1F0900710C020054291441F92A204839283140B98A000037296940B93F050071"},{"name":"ManifestV2Handler::MaybeReEnableExtension","kind":"bcond","jgRVA":"0x07702AEC","jgOff":4,"expectedMatches":1,"sig":"1F0900710C020054691641F96A224839283140B98A000037296940B93F050071"}]},
    {"name":"152-chromium","container":"pe","sites":[{"name":"manifest_v2_util::IsExtensionAffected (free predicate)","kind":"short","jgRVA":"0x04723915","jgOff":3,"expectedMatches":1,"sig":"83F9027F1F83FA08771AB90A0100000FA3D173104183F8050F"}]}
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
    Write-Host "$($C.Bold)             Chrome MV2 Patcher (PowerShell)              $($C.Reset)"
    Write-Host "$($C.Dim)                          v$AppVersion                          $($C.Reset)"
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
    Write-Info 'Getting ready...'
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
    Write-Ok 'Ready.'
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
    throw "That doesn't look like a Chrome file (this tool only works on chrome.dll)."
}

# Validates a PE32 or PE32+ and records only bounds-checked
# offsets, so every later read/write is safe.
function Open-PeImage {
    param([byte[]]$Buf)

    if ($Buf.Length -lt 64) { throw "not a valid Chrome file: file too small" }
    $eLfanew = [BitConverter]::ToUInt32($Buf, 0x3C)

    if (($eLfanew + 24) -gt $Buf.Length) { throw "not a valid Chrome file: truncated NT headers" }
    if ($Buf[$eLfanew] -ne 0x50 -or $Buf[$eLfanew+1] -ne 0x45 -or
        $Buf[$eLfanew+2] -ne 0 -or $Buf[$eLfanew+3] -ne 0) { throw "not a valid Chrome file: bad NT signature" }

    $numSections  = [BitConverter]::ToUInt16($Buf, $eLfanew + 6)
    $sizeOfOptHdr = [BitConverter]::ToUInt16($Buf, $eLfanew + 20)
    $optOff       = [int64]$eLfanew + 24
    if (($optOff + $sizeOfOptHdr) -gt $Buf.Length) { throw "not a valid Chrome file: optional header out of bounds" }

    $magic = [BitConverter]::ToUInt16($Buf, $optOff)
    switch ($magic) {
        0x20B   { $fixedLen = 112; $is32 = $false }   # PE32+ (x86-64)
        0x10B   { $fixedLen = 96;  $is32 = $true  }   # PE32  (x86)
        default { throw ("not a valid Chrome file: unsupported optional header magic 0x{0:X}" -f $magic) }
    }
    if ($sizeOfOptHdr -lt ($fixedLen + 5 * 8)) {
        throw "not a valid Chrome file: optional header too small for data directories"
    }

    $secOff = $optOff + $sizeOfOptHdr
    if (($secOff + [int64]$numSections * 40) -gt $Buf.Length) { throw "not a valid Chrome file: section table out of bounds" }

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
    if ($textSize -eq 0) { throw "not a valid Chrome file: missing code section" }
    if ([int64]$textRaw -lt 0 -or [int64]$textRaw + [int64]$textSize -gt $Buf.LongLength) {
        throw "not a valid Chrome file: .text raw data is out of bounds"
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
        [Array]::Clear($Buf, $Img.SecDirAt, 8)
    }

    Initialize-NativeHelpers
    $sum = [Mv2Native]::PeChecksum($Buf, $Img.ChecksumAt)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$sum), 0, $Buf, $Img.ChecksumAt, 4)
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
        [string]$PreserveMetadataFrom = '',
        # Caller-supplied SHA-256 of $Buf. When set, the read-back verification
        # compares against it instead of re-hashing the 285 MB $Buf a second time
        # (the caller has usually just computed this hash).
        [string]$KnownBufHash = ''
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
        $bufHash = if ($KnownBufHash) { $KnownBufHash } else { Get-ByteHash $Buf }
        if ($written.LongLength -ne $Buf.LongLength -or (Get-ByteHash $written) -ne $bufHash) {
            throw "Couldn't write to $TargetPath safely - nothing was changed."
        }

        if ($PreserveMetadataFrom -and (Test-Path -LiteralPath $PreserveMetadataFrom -PathType Leaf)) {
            try { [IO.File]::SetAttributes($tmp, [IO.File]::GetAttributes($PreserveMetadataFrom)) } catch { }
            try { Set-Acl -LiteralPath $tmp -AclObject (Get-Acl -LiteralPath $PreserveMetadataFrom) } catch { }
        }

        if ($ExpectedCurrentHash) {
            if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'The file went missing before we could update it.' }
            $now = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($now -ne $ExpectedCurrentHash.ToLowerInvariant()) {
                throw 'Chrome changed while we were working - nothing was changed. Try again.'
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
            catch { Write-Warn "Couldn't delete a backup file: ${p}" }
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

    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { throw "No backup found at: $BackupPath" }
    $buf = [IO.File]::ReadAllBytes($BackupPath)
    if ($buf.Length -eq 0) { throw 'The backup file is empty.' }
    $img = Open-Image $buf
    $identity = Get-PeIdentity -Buf $buf -Img $img
    $metaPath = Get-BackupMetadataPath $BackupPath
    $legacy = -not (Test-Path -LiteralPath $metaPath -PathType Leaf)
    if (-not $legacy) {
        try { $meta = Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json }
        catch { throw "The backup's info file looks wrong: ${metaPath}" }
        if ([int]$meta.Schema -ne 1 -or $meta.Format -ne $identity.Format -or
            [uint16]$meta.Machine -ne $identity.Machine -or [uint32]$meta.TimeStamp -ne $identity.TimeStamp -or
            [int64]$meta.Length -ne $identity.Length -or ([string]$meta.SHA256).ToLowerInvariant() -ne $identity.SHA256) {
            throw "The backup doesn't match its saved info - it may be damaged."
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

    # Ranking: a milestone whose EVERY site matched (full) always beats a partial
    # one, regardless of raw satisfied count; among full matches the one with MORE
    # sites wins (most specific), so a Chrome build's multi-site table is chosen
    # over a coexisting single-site Chromium table (same container tag) and vice-
    # versa. Among partials the most-satisfied wins. A genuine equal-rank collision
    # (two fulls of the same size, or two equal partials) bumps $bestCount and the
    # caller declines when $bestCount > 1.
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
        if ($satisfied -eq 0) { continue }
        $total    = $ms.Sites.Count
        $candFull = ($satisfied -eq $total)
        $bestFull = ($null -ne $best -and $best.Satisfied -eq $best.Ms.Sites.Count)

        $take = $false; $tie = $false
        if ($null -eq $best) {
            $take = $true                                  # first candidate
        } elseif ($candFull -and -not $bestFull) {
            $take = $true                                  # full beats partial
        } elseif ($candFull -and $bestFull -and $total -gt $best.Ms.Sites.Count) {
            $take = $true                                  # more specific full
        } elseif (-not $candFull -and -not $bestFull -and $satisfied -gt $best.Satisfied) {
            $take = $true                                  # more of a partial matched
        } elseif (($candFull -and $bestFull -and $total -eq $best.Ms.Sites.Count) -or
                  (-not $candFull -and -not $bestFull -and $satisfied -eq $best.Satisfied)) {
            $tie = $true                                   # genuine equal-rank collision
        }

        if ($take) {
            $best = [pscustomobject]@{ Ms = $ms; Flips = $flips; Satisfied = $satisfied }
            $bestCount = 1
        } elseif ($tie) {
            $bestCount++
        }
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

    if ($bestCount -gt 1) {
        $res.Reason = "$bestCount possible Chrome versions tied - can't tell which one this is"
        Write-Warn $res.Reason
        return $res
    }
    if (-not $res.Full -and -not $AllowPartial) {
        $res.Reason = "only $($res.Located) of $($res.Total) changes matched; a partial patch needs -AllowPartial"
        Write-Warn $res.Reason
        return $res
    }

    Write-Info ("Found Chrome {0}. Applying {1} change(s)..." -f $best.Ms.Name, $best.Flips.Count)

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
                Write-Host '    [i] One change was already applied.'
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0xEB) }
                continue
            }
            if ($cur -ne 0x7F) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = 0xEB }          # jg -> jmp short
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0xEB) }
        } elseif ($f.Site.Kind -eq 1) {
            $o0 = $Buf[$f.JgRaw]; $o1 = $Buf[$f.JgRaw + 1]
            if ($o0 -eq 0x90 -and $o1 -eq 0xE9) {
                Write-Host '    [i] One change was already applied.'
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@(0x90, 0xE9) }
                continue
            }
            if (-not ($o0 -eq 0x0F -and $o1 -eq 0x8F)) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
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
                Write-Host '    [i] One change was already applied.'
                $already++; $res.Already++
                $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@($patched) }
                continue
            }
            if ($cond -ne 0x0C) {
                Write-Host ("    {0} Skipped one change - it didn't look the way we expected." -f $script:TagWarn)
                continue
            }
            $res.Stock++
            if ($Apply) { $Buf[$f.JgRaw] = $patched }      # b.gt -> b.al (cond GT->AL)
            $applied++; $res.Flips++
            $res.Written += [pscustomobject]@{ RVA = $jgRVA; Bytes = [byte[]]@($patched) }
        }

        if ($Apply) {
            Write-Host ("    {0} Change {1} of {2} applied." -f $script:TagOK, $applied, $best.Flips.Count)
        } else {
            Write-Host ("    {0} Change {1} of {2} found." -f $script:TagOK, $applied, $best.Flips.Count)
        }
    }
    $res.Flips += $already   # count already-applied sites toward the flip total

    if (-not $res.Full) {
        Write-Host ("    {0} {1} change(s) couldn't be found for Chrome {2}, so this may not fully work. Please report this Chrome version." -f `
            $script:TagWarn, ($res.Total - $res.Located), $best.Ms.Name)
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
    # A read-only validation probe: Invoke-PatchMilestones with -Apply $false
    # never writes to $Buf, so it is passed through directly (no defensive clone
    # of the 285 MB buffer). Suppress the per-site "stock jg at RVA ..." host
    # output (stream 6) - callers print their own one-line summary.
    $probe = Invoke-PatchMilestones -Buf $Buf -Img $Img -Milestones $Milestones `
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
    Write-Info "This Chrome version isn't recognized yet. Looking for clues to help add support..."
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
    Write-Info ("Found {0} possible spot(s){1}. Nothing was changed - please share this and your Chrome version with the developer." -f $hits.Count, $extra)
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
    return "This needs administrator access to change Chrome.`n    Right-click PowerShell and choose 'Run as administrator', then try again."
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
Recovers this file's own source text, needed when there is no script file to
point -File at (`irm ... | iex`). $PSCommandPath is empty there, but every
function in the file was compiled from ONE scriptblock spanning the whole file,
so that scriptblock's AST hands the text back verbatim.

Returns $null when the text cannot be trusted - notably when the body arrived in
fragments (pasted into a console chunk by chunk), where the AST covers only the
fragment that happened to define the function. Both ends of the file must be
present for the copy to count as whole.
#>
function Get-SelfSourceText {
    $src = $null
    try { $src = ${function:Invoke-SelfElevate}.Ast.Extent.StartScriptPosition.GetFullScript() }
    catch { return $null }
    if (-not $src) { return $null }
    # A fragment can still parse, and a whole file can still be broken, so check
    # both: the two ends of the file must be there AND the text must parse. If
    # either anchor below is ever edited away, the elevation test in
    # scripts/test_windows.py fails rather than this silently refusing.
    if ($src -notmatch '(?m)^function Invoke-Main\b') { return $null }
    if ($src -notmatch '(?m)^exit \$exitCode\s*$') { return $null }
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count) { return $null }
    return $src
}

<#
Stages the recovered source in a private temp directory so the elevated child has
a real file to run. Returns $null when the source could not be recovered.

The staged copy is then held open on a READ handle (FileAccess Read, FileShare
Read) for as long as the child runs. That combination lets the child open it for
reading while denying write and delete to everything else, so the file cannot be
swapped in the window between UAC consent and the elevated child loading it.
Holding a WRITE handle instead would break the child: its own read open asks for
a share mode that excludes writers, which our write access would violate.
#>
function New-SelfStage {
    $src = Get-SelfSourceText
    if (-not $src) { return $null }

    $dir  = Join-Path ([IO.Path]::GetTempPath()) ('chrome-mv2-' + [Guid]::NewGuid().ToString('N'))
    $path = Join-Path $dir 'chrome-mv2.ps1'
    try {
        [void][IO.Directory]::CreateDirectory($dir)
        # BOM so the child reads it as UTF-8 whatever the host's default is.
        [IO.File]::WriteAllText($path, $src, (New-Object Text.UTF8Encoding($true)))
        $handle = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        return @{ Path = $path; Dir = $dir; Handle = $handle }
    } catch {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        return $null
    }
}

function Remove-SelfStage {
    param($Stage)
    if (-not $Stage) { return }
    try { $Stage.Handle.Dispose() } catch { }
    Remove-Item -LiteralPath $Stage.Dir -Recurse -Force -ErrorAction SilentlyContinue
}

<#
Re-launches this script elevated via Start-Process -Verb RunAs, which raises the
UAC consent dialog (a compiled exe would get the same effect from a
requireAdministrator manifest). Returns the elevated child's
exit code, or $null when elevation was declined/impossible so the caller can
fall back to the plain "you need admin" message.

The child is ALWAYS started as -File <script>, so there is one relaunch shape to
reason about. Normally the script already is a file on disk ($PSCommandPath is
set) and is used as-is; under `irm https://.../chrome-mv2.ps1 | iex` there is no
file, so the source is staged to a temp one first (see New-SelfStage).

Earlier versions instead replayed the process's own command line under RunAs,
which meant parsing powershell.exe's argv to find the -Command payload and
prefixing an `$env:MV2_RELAUNCHED='1';` guard into it. That only ever worked for
a literal `-Command`/`-EncodedCommand` token: the documented one-liner
`powershell "irm ...|iex"` puts the command in the implicit positional slot with
no switch to find, and an abbreviation the host does accept (-Com, -Comm) missed
too. Both failed with "cannot ask for administrator access this way".

Staging removes that whole class of bug: the loop guard and the target are
ordinary parameters (-Relaunched, positional path), so nothing has to survive the
UAC boundary in-band - and env vars would NOT survive it. It also means the
elevated run is the very code that just ran, instead of a second download.

Details:
  * Arguments are quoted so a path with spaces ("C:\Program Files\...") stays one
    argument instead of splitting.
  * -WorkingDirectory is pinned to the current directory (an elevated process
    otherwise starts in system32), so a relative target path still resolves.
  * -Wait -PassThru is required for $p.ExitCode to be populated.

NOTE: parameters are forwarded explicitly - a new user-facing switch has to be
added to the $argv list below or it is silently dropped on the elevated run.
#>
function Invoke-SelfElevate {
    param([string]$ResolvedTargetPath)
    # Prefer the current host (pwsh vs powershell.exe) so PS7 stays on PS7.
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh.exe' } else { 'powershell.exe' } }

    $scriptPath = $PSCommandPath
    $stage = $null
    if (-not ($scriptPath -and (Test-Path -LiteralPath $scriptPath -PathType Leaf))) {
        $stage = New-SelfStage
        if (-not $stage) {
            # Nothing runnable to hand the elevated child - refuse rather than
            # risk a UAC loop.
            Write-Warn 'Cannot ask for administrator access this way; re-run from an admin terminal.'
            return $null
        }
        $scriptPath = $stage.Path
    }

    try {
        $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Get-QuotedArg $scriptPath), $Command)
        if ($ResolvedTargetPath)  { $argv += (Get-QuotedArg $ResolvedTargetPath) }
        if ($Yes)   { $argv += '-Yes' }
        if ($Quiet) { $argv += '-Quiet' }
        if ($AllowPartial) { $argv += '-AllowPartial' }
        if ($ForceRestore) { $argv += '-ForceRestore' }
        if ($Signatures) { $argv += '-Signatures'; $argv += (Get-QuotedArg ([IO.Path]::GetFullPath($Signatures))) }
        $argv += '-Relaunched'

        Write-Info 'Asking for administrator access (you''ll see a Windows prompt)...'
        try {
            $p = Start-Process -FilePath $exe -ArgumentList ($argv -join ' ') -Verb RunAs `
                               -WorkingDirectory (Get-Location).Path -Wait -PassThru -ErrorAction Stop
            return $p.ExitCode
        } catch {
            # 1223 = ERROR_CANCELLED: the user dismissed the UAC dialog.
            Write-Warn 'Admin access was declined - nothing was changed.'
            return $null
        }
    } finally {
        Remove-SelfStage $stage
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
        Write-Warn "Closing $($holders.Count) Chrome process(es)..."
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
            Write-Host "    $script:TagOK Closed $name."
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
        Write-Warn "Chrome $($Target.Channel) is open and will be closed (-Yes)."
    } elseif ($Quiet) {
        Write-Err "Chrome $($Target.Channel) is open."
        Write-Host '    Close it, or add -Yes to close it automatically.'
        return $false
    } elseif (-not (Confirm-ForceClose $current)) {
        return $false
    }

    if (Close-FileHolders -TargetPath $Target.Path) {
        Write-Ok 'Chrome is closed. Your other Chrome channels are still running.'
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
    param([string]$TargetPath, [byte[]]$Buf, [string]$ExpectedCurrentHash = '', [string]$KnownBufHash = '')
    Write-AtomicFile -TargetPath $TargetPath -Buf $Buf -ExpectedCurrentHash $ExpectedCurrentHash -PreserveMetadataFrom $TargetPath -KnownBufHash $KnownBufHash
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
    @{ Name = 'Chromium'; Subdir = 'Chromium' }          # open-source Chromium keeps the chrome.dll name
)

# The channel label for a target we were handed as a bare path: an explicit
# -Path, a typed custom path, or the elevated relaunch, which forwards only the
# resolved path. Matched on whole path segments, because a plain substring test
# reads "Google\Chrome Beta" as Stable - "Google\Chrome" is a prefix of it - and
# so mislabels every non-Stable channel once elevation re-derives the label.
function Get-ChannelFromPath {
    param([string]$TargetPath)
    $hay = '\' + ($TargetPath -replace '/', '\').Trim('\').ToLower() + '\'
    foreach ($ch in $WinChannels) {
        if ($hay.Contains('\' + $ch.Subdir.ToLower() + '\')) { return $ch.Name }
    }
    return 'Unknown'
}

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
# Cheap patched/stock probe for the install list. Reads ONLY the PE header (not
# the ~285 MB body) and inspects the Authenticode Security Directory: a stock,
# signed chrome.dll has one; patching zeroes it (see Complete-Image). Returns
# 'patched', 'not patched', or '' (unknown / not a PE). This is a fast list hint,
# not the authoritative gate probe that 'check'/'patch' run.
function Get-PatchStateQuick {
    param([string]$Path)
    try {
        $hdr = [byte[]]::new(8192)
        $fs = [IO.File]::OpenRead($Path)
        try { $n = $fs.Read($hdr, 0, $hdr.Length) } finally { $fs.Dispose() }
        if ($n -lt 64 -or $hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) { return '' }
        $eLfanew = [BitConverter]::ToUInt32($hdr, 0x3C)
        if ($eLfanew + 24 -gt $n) { return '' }
        if ($hdr[$eLfanew] -ne 0x50 -or $hdr[$eLfanew + 1] -ne 0x45) { return '' }
        $optOff = [int]$eLfanew + 24
        $magic = [BitConverter]::ToUInt16($hdr, $optOff)
        $fixedLen = if ($magic -eq 0x20B) { 112 } elseif ($magic -eq 0x10B) { 96 } else { return '' }
        $secDirAt = $optOff + $fixedLen + 4 * 8      # data directory [4] = Security
        if ($secDirAt + 8 -gt $n) { return '' }
        $va = [BitConverter]::ToUInt32($hdr, $secDirAt)
        $sz = [BitConverter]::ToUInt32($hdr, $secDirAt + 4)
        if ($va -ne 0 -and $sz -ne 0) { return 'not patched' } else { return 'patched' }
    } catch { return '' }
}

function Get-InstallDetails {
    param([string]$TargetPath, [string]$Channel)

    $parent = Split-Path -Leaf (Split-Path -Parent $TargetPath)
    $version = if (Test-LooksLikeVersion $parent) { $parent } else { '' }

    $holders = @()
    try { $holders = @(Get-FileHolders -TargetPath $TargetPath) } catch { }
    $running = ($holders.Count -gt 0)
    if (-not $running) { try { $running = Test-TargetLocked -TargetPath $TargetPath } catch { } }

    if (-not $Channel) { $Channel = Get-ChannelFromPath $TargetPath }

    return [pscustomobject]@{
        Channel   = $Channel
        Path      = $TargetPath
        Version   = $version
        Running   = $running
        Holders   = $holders.Count
        HasBackup = (Test-Path -LiteralPath (Get-BackupPath $TargetPath) -PathType Leaf)
        State     = (Get-PatchStateQuick $TargetPath)
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
        $line += "  $($C.Yel)[open]$($C.Reset)"
    } else {
        $line += "  $($C.Grn)[closed]$($C.Reset)"
    }
    if ($Inst.PSObject.Properties['State']) {
        if     ($Inst.State -eq 'patched')     { $line += "  $($C.Grn)[patched]$($C.Reset)" }
        elseif ($Inst.State -eq 'not patched') { $line += "  $($C.Dim)[not patched]$($C.Reset)" }
    }
    if ($Inst.HasBackup) { $line += " $($C.Dim)(backup saved)$($C.Reset)" }
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
        Write-Ok 'Found one Chrome:'
        Show-InstallRow 1 $Installs[0]
    } else {
        Write-Host "`n$script:TagInfo Found $($Installs.Count) Chrome versions:"
        for ($i = 0; $i -lt $Installs.Count; $i++) { Show-InstallRow ($i + 1) $Installs[$i] }
        Write-Host "`n$script:TagInfo Only the one you pick is changed; the others are left alone."
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
            "$verb this Chrome? [Enter=yes, ${restoreOpt}c=custom path, q=quit]"
        } else {
            "Which Chrome do you want to ${verbLower}? [1-$($Installs.Count), ${restoreOpt}c=custom path, q=quit]"
        }
        $line = (Read-Host "`n$prompt").Trim()

        if ($line -in 'q', 'Q') { return $null }
        if ($allowRestore -and $line -in 'r', 'R') {
            $script:Command = 'restore'
            if ($Installs.Count -eq 1) { return $Installs[0] }
            # Show restore-specific prompt for multiple channels
            Write-Host "`n$script:TagInfo Restore selected. Which Chrome do you want to restore?"
            while ($true) {
                $restoreLine = (Read-Host "`nWhich Chrome do you want to restore? [1-$($Installs.Count), q=cancel]").Trim()
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
    Write-Host "`n$($C.Bold)$($C.Yel)  Chrome $($Inst.Channel) is open.$($C.Reset)"
    Write-Host '     I need to close it to make the change. Any unsaved tabs will be lost.'
    Write-Host "     $($C.Dim)Your other Chrome versions won't be touched.$($C.Reset)"

    while ($true) {
        $line = (Read-Host "`nClose Chrome $($Inst.Channel) and continue? [y/N]").Trim()
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
            Write-Err "That path doesn't exist."
            return $null
        }
        return (Get-InstallDetails -TargetPath $TargetPath -Channel '')
    }

    Write-Info 'Looking for Chrome or Chromium...'
    $installs = @(Get-ChromeInstalls)

    if ($installs.Count -eq 0) {
        if (-not $Interactive) {
            Write-Err "Couldn't find Chrome on this computer."
            Write-Host '    Give the path to chrome.dll, e.g. .\chrome-mv2.ps1 patch C:\path\to\chrome.dll'
            return $null
        }
        Write-Warn "Couldn't find Chrome on this computer."
        $pick = Read-CustomPath
        if ($pick) { return $pick }
        Write-Info 'No path entered - nothing was changed.'
        return $null
    }
    if (-not $Interactive -and $installs.Count -gt 1) {
        Write-Err "Found $($installs.Count) Chrome versions, and -Quiet can't ask which one."
        for ($i = 0; $i -lt $installs.Count; $i++) { Show-InstallRow ($i + 1) $installs[$i] }
        Write-Host '    Re-run with the path of the one you want.'
        return $null
    }
    if (-not $Interactive) { return $installs[0] }

    $picked = Select-Install $installs
    if (-not $picked) { Write-Info 'Nothing selected - nothing was changed.'; return $null }
    return $picked
}

# patch: consent -> unlock -> read -> backup policy -> flip gates -> finalize ->
# write. Returns a process exit code (0 = patched, 1 = nothing written).
function Invoke-Patch {
    param($Target, [bool]$AssumeYes)

    $buf = [IO.File]::ReadAllBytes($Target.Path)
    if ($buf.Length -eq 0) { Write-Err 'That file is empty.'; return 1 }
    Write-Ok "Read Chrome from $($Target.Path)."

    $img = Open-Image $buf
    $targetIdentity = Get-PeIdentity -Buf $buf -Img $img
    $targetHash = $targetIdentity.SHA256

    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $img.Format })
    Write-Info 'Getting Chrome ready...'
    if ($milestones.Count -eq 0) {
        Write-Warn "This kind of Chrome isn't supported yet - nothing was changed."
        Show-LayoutCandidates -Buf $buf -Img $img
        return 1
    }

    # Backups are accepted only when they parse as clean stock and describe the
    # same PE build. A patched/unsigned target can never become a new baseline.
    $backupPath = Get-BackupPath $Target.Path
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        if (-not (Test-LikelyStock -Img $img -Buf $buf)) {
            Write-Err "There's no backup yet, and this Chrome has already been changed."
            Write-Host '    Reinstall Chrome first so we can save a clean backup.'
            return 1
        }
        $stockLayout = Get-CleanStockLayout -Buf $buf -Img $img -Milestones $milestones `
            -AllowPartialLayout $AllowPartial.IsPresent
        if (-not $stockLayout.Clean) {
            Write-Err "There's no backup yet, and this doesn't look like an untouched Chrome."
            return 1
        }
        Write-Info 'Saving a backup...'
        Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $buf -Identity $targetIdentity
        $backup = Read-ValidatedBackup $backupPath
        Write-Ok 'Backup saved.'
    } else {
        try {
            $backup = Read-ValidatedBackup $backupPath
        } catch {
            Write-Err "The backup couldn't be verified: $_"
            return 1
        }
        if (-not (Test-LikelyStock -Img $backup.Img -Buf $backup.Buf)) {
            Write-Err "The backup doesn't look like an original Chrome, so I won't use it."
            return 1
        }
        $backupLayout = Get-CleanStockLayout -Buf $backup.Buf -Img $backup.Img -Milestones $milestones `
            -AllowPartialLayout $AllowPartial.IsPresent
        if (-not $backupLayout.Clean) {
            Write-Err "The backup doesn't look like an untouched Chrome."
            return 1
        }

        if (-not (Test-SameBuildIdentity -A $targetIdentity -B $backup.Identity)) {
            if (-not (Test-LikelyStock -Img $img -Buf $buf)) {
                Write-Err "Chrome was updated, but this copy has already been changed."
                Write-Host '    Reinstall or update Chrome so we can start from a clean copy.'
                return 1
            }
            $newStockLayout = Get-CleanStockLayout -Buf $buf -Img $img -Milestones $milestones `
                -AllowPartialLayout $AllowPartial.IsPresent
            if (-not $newStockLayout.Clean) {
                Write-Err "This updated Chrome isn't fully supported yet."
                return 1
            }
            Write-Info 'Chrome was updated - saving a fresh backup...'
            Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $buf -Identity $targetIdentity
            $backup = Read-ValidatedBackup $backupPath
            Write-Ok 'Backup updated.'
        } elseif ($backup.Legacy) {
            Save-BackupSnapshot -TargetPath $Target.Path -BackupPath $backupPath -Buf $backup.Buf -Identity $backup.Identity
            Write-Ok 'Backup checked and updated.'
        }
    }

    $buf = [byte[]]$backup.Buf.Clone()
    $img = Open-Image $buf

    Write-Info 'Checking your Chrome version...'
    $patch = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones `
        -AllowPartial $AllowPartial.IsPresent -Apply $true
    if ($patch.Status -eq 0) {
        Show-LayoutCandidates -Buf $buf -Img $img
        Write-Warn "This Chrome version isn't recognized."
        Write-Host '    Nothing was changed. It may be too new - please report your Chrome version.'
        return 1
    }

    $msg = if ($patch.Status -eq 1) { 'patched.' } else { 'was already patched (no change needed).' }
    Write-Info "Chrome $($patch.Milestone) $msg"

    Complete-Image -Img $img -Buf $buf
    if (-not (Test-PatchOutput -Buf $buf -Img $img -Patch $patch)) {
        Write-Err 'Something went wrong while preparing the change - nothing was changed.'
        return 1
    }

    $preparedHash = Get-ByteHash $buf
    if ($preparedHash -eq $targetHash) {
        Write-Success 'Already done - no change was needed.'
        return 0
    }
    if ($targetHash -ne $backup.Identity.SHA256) {
        Write-Err "This Chrome has other changes we didn't make, so we won't overwrite it."
        Write-Host '    Reinstall Chrome, or check the file yourself, then try again.'
        return 1
    }

    if (-not (Request-TargetUnlock -Target $Target -AssumeYes $AssumeYes)) {
        Write-Err 'Chrome is still open - close it and try again.'
        return 1
    }
    # Write-AtomicFile reads the written bytes back and verifies them against
    # $preparedHash before the atomic Replace, so the target already equals the
    # prepared image on success - no post-write re-read/re-hash is needed.
    Write-Target -TargetPath $Target.Path -Buf $buf -ExpectedCurrentHash $targetHash -KnownBufHash $preparedHash

    Write-Rule
    if ($patch.Full) {
        Write-Success 'Done. Manifest V2 re-enabled.'
        Write-Host "          Your older extensions will work again (Chrome $($patch.Milestone)). Restart Chrome."
    } else {
        Write-Host "$script:TagWarning Only part of the change was applied (Chrome $($patch.Milestone), $($patch.Located)/$($patch.Total))."
        Write-Host "          $($patch.Total - $patch.Located) part(s) couldn't be found, so this may not fully work."
        Write-Host '          Please report your Chrome version. To undo: .\chrome-mv2.ps1 restore'
    }
    Write-Rule
    return 0
}

# restore: validates backup metadata, stock layout, and build identity before an
# atomic replacement. A cross-build restore requires the explicit force switch.
function Invoke-Restore {
    param($Target, [bool]$AssumeYes)

    Write-Info 'Restoring the original Chrome...'
    $backupPath = Get-BackupPath $Target.Path
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
        Write-Err "No backup found, so there's nothing to restore."
        return 1
    }
    try { $backup = Read-ValidatedBackup $backupPath }
    catch { Write-Err "The backup couldn't be verified: $_"; return 1 }
    if (-not (Test-LikelyStock -Img $backup.Img -Buf $backup.Buf)) {
        Write-Err "The backup doesn't look like an original Chrome, so I won't use it."
        return 1
    }
    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $backup.Img.Format })
    $backupLayout = Get-CleanStockLayout -Buf $backup.Buf -Img $backup.Img -Milestones $milestones -AllowPartialLayout $true
    if (-not $backupLayout.Clean) {
        Write-Err "The backup doesn't look like an untouched Chrome."
        return 1
    }
    Write-Ok ("Backup looks good (Chrome {0})." -f $backupLayout.Probe.Milestone)

    $current = [IO.File]::ReadAllBytes($Target.Path)
    $currentImg = Open-Image $current
    $currentIdentity = Get-PeIdentity -Buf $current -Img $currentImg
    if (-not (Test-SameBuildIdentity -A $currentIdentity -B $backup.Identity) -and -not $ForceRestore) {
        Write-Err "This backup is from a different Chrome version, so I won't use it."
        Write-Host '    Add -ForceRestore only if you really mean to go back to that version.'
        return 1
    }
    if (-not (Test-SameBuildIdentity -A $currentIdentity -B $backup.Identity)) {
        Write-Warn 'Restoring a different Chrome version (-ForceRestore).'
    }
    if ($currentIdentity.SHA256 -eq $backup.Identity.SHA256) {
        Write-Success 'Chrome is already the original - nothing to undo.'
        Remove-BackupFiles $backupPath
        Write-Info 'Backup removed - Chrome is back to normal.'
        return 0
    }
    if (-not (Request-TargetUnlock -Target $Target -AssumeYes $AssumeYes)) {
        Write-Err 'Chrome is still open - close it and try again.'
        return 1
    }
    # As in Invoke-Patch: Write-AtomicFile verifies the read-back against the
    # backup's known hash before the atomic Replace, so no post-write re-read.
    Write-Target -TargetPath $Target.Path -Buf $backup.Buf -ExpectedCurrentHash $currentIdentity.SHA256 -KnownBufHash $backup.Identity.SHA256
    Write-Success 'Done. Your original Chrome is back.'
    Remove-BackupFiles $backupPath
    Write-Info 'Backup removed - Chrome is back to normal.'
    return 0
}

function Invoke-Check {
    param($Target)
    $buf = [IO.File]::ReadAllBytes($Target.Path)
    if ($buf.Length -eq 0) { Write-Err 'That file is empty.'; return 1 }
    $img = Open-Image $buf
    $identity = Get-PeIdentity -Buf $buf -Img $img

    $milestones = @(Import-Milestones | Where-Object { $_.Container -eq $img.Format })
    $probe = Invoke-PatchMilestones -Buf $buf -Img $img -Milestones $milestones -AllowPartial $true -Apply $false 6>$null
    if ($probe.Status -eq 0) {
        if ($probe.Reason -match 'tied') { Write-Warn "Couldn't tell which Chrome version this is." }
        else { Write-Warn "This Chrome version isn't recognized yet." }
    } else {
        $state = if ($probe.Stock -gt 0 -and $probe.Already -gt 0) { 'partly patched' } elseif ($probe.Stock -gt 0) { 'not patched yet' } else { 'already patched' }
        Write-Ok "This is Chrome $($probe.Milestone) - $state."
    }

    $backupPath = Get-BackupPath $Target.Path
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
        try {
            $backup = Read-ValidatedBackup $backupPath
            Write-Ok 'A backup is saved.'
        } catch { Write-Warn 'A backup exists but looks damaged.' }
    } else { Write-Info 'No backup saved yet.' }

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

    # Resolve before elevation. Read-only checks never need admin, and an
    # offline/user-owned copy should not cause a UAC prompt merely because the
    # normal Program Files installation does.
    $target = Resolve-Target -TargetPath $Path -Interactive (-not $Quiet)
    if (-not $target) { return 1 }

    Write-Host "$script:TagOK Chrome: $($C.Cyn)$($target.Channel)$($C.Reset)"
    Write-Host "$script:TagOK File: $($target.Path)"
    if ($target.Version) { Write-Host "$script:TagOK Version: $($target.Version)" }

    if ($Command -eq 'check') { return (Invoke-Check -Target $target) }

    $needsElevation = -not (Test-TargetDirectoryWritable -TargetPath $target.Path)
    if ($needsElevation -and -not (Test-Elevated) -and -not $env:MV2_TEST_NO_ELEVATION) {
        # Loop guard: -Relaunched means we ALREADY tried to elevate. If we are
        # still not admin, report and stop instead of spawning again.
        if (-not $Relaunched) {
            $childCode = Invoke-SelfElevate -ResolvedTargetPath ([IO.Path]::GetFullPath($target.Path))
            if ($null -ne $childCode) {
                # The child did the work in its own window and held it open until
                # the user dismissed it, so don't pause again here - but do say how
                # it went, or this window's last line is still "asking for
                # administrator access" as if nothing had happened.
                $script:SuppressPause = $true
                if ($childCode -eq 0) { Write-Ok 'Finished with administrator access.' }
                else { Write-Err 'The run with administrator access did not succeed.' }
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

<#
Whether to hold the window open before exiting.

Two cases need it. A failure must not vanish with the window. And the elevated
child needs it on ANY outcome, success included: that window was opened by
Start-Process rather than by the user, and the child cannot write into the
parent's window, so a successful patch would otherwise flash past and leave
nothing on screen to read.

Never pause when the caller asked for silence (-Quiet, scripting), when an
elevated child has already done the pausing, or when input is redirected
(piped/automation) - an unattended run must not hang waiting for a key.
#>
function Test-ShouldPause {
    param(
        [int]$ExitCode,
        [bool]$IsElevatedChild,
        [bool]$QuietMode,
        [bool]$ChildAlreadyPaused,
        [bool]$InputRedirected
    )
    if ($QuietMode -or $ChildAlreadyPaused -or $InputRedirected) { return $false }
    return (($ExitCode -ne 0) -or $IsElevatedChild)
}

# Set true when an elevated child ran: it owns its window and its own pause.
$script:SuppressPause = $false

if ($env:MV2_TEST_LIBRARY_ONLY) { return }

$exitCode = Invoke-Main

if (Test-ShouldPause -ExitCode $exitCode -IsElevatedChild $Relaunched.IsPresent `
                     -QuietMode $Quiet.IsPresent -ChildAlreadyPaused $script:SuppressPause `
                     -InputRedirected ([Console]::IsInputRedirected)) {
    Write-Host ''
    Write-Host 'Press any key to exit...' -NoNewline
    try { [void]$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') }
    catch { Read-Host | Out-Null }
    Write-Host ''
}
exit $exitCode
