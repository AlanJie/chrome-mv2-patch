$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$env:MV2_TEST_LIBRARY_ONLY = '1'
. (Join-Path $repo 'chrome-mv2.ps1')
Remove-Item Env:MV2_TEST_LIBRARY_ONLY -ErrorAction SilentlyContinue
Initialize-Colors
$script:Quiet = $true

$passed = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:passed++
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw $Message
}

function New-TestPe {
    param(
        [string]$Path,
        [byte[]]$Signature,
        [int]$SignatureOffset = 0x40,
        [uint32]$TimeStamp = 0x12345678,
        [bool]$Signed = $true
    )
    $buf = [byte[]]::new(0x800)
    $buf[0] = 0x4D; $buf[1] = 0x5A
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x80), 0, $buf, 0x3C, 4)
    $nt = 0x80
    $buf[$nt] = 0x50; $buf[$nt + 1] = 0x45
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x8664), 0, $buf, $nt + 4, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]1), 0, $buf, $nt + 6, 2)
    [Array]::Copy([BitConverter]::GetBytes($TimeStamp), 0, $buf, $nt + 8, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0xF0), 0, $buf, $nt + 20, 2)
    $opt = $nt + 24
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x20B), 0, $buf, $opt, 2)
    [Array]::Copy([BitConverter]::GetBytes([uint32]16), 0, $buf, $opt + 108, 4)
    if ($Signed) {
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x700), 0, $buf, $opt + 144, 4)
        [Array]::Copy([BitConverter]::GetBytes([uint32]0x20), 0, $buf, $opt + 148, 4)
    }
    $section = $opt + 0xF0
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('.text'), 0, $buf, $section, 5)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x200), 0, $buf, $section + 8, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $buf, $section + 12, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x200), 0, $buf, $section + 16, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x400), 0, $buf, $section + 20, 4)
    [Array]::Copy($Signature, 0, $buf, 0x400 + $SignatureOffset, $Signature.Length)
    [IO.File]::WriteAllBytes($Path, $buf)
}

function Write-Signatures {
    param([string]$Path, [array]$Milestones)
    @{ milestones = $Milestones } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding utf8
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('chrome mv2 ps tests ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $near = [byte[]]@(0x83,0x7F,0x50,0x02,0x0F,0x8F,0x8B,0,0,0,0x48,0x8B)
    $pePath = Join-Path $temp 'near fixture.dll'
    New-TestPe -Path $pePath -Signature $near
    $buf = [IO.File]::ReadAllBytes($pePath)
    $start = 0x440
    Assert-True (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1) 'stock near pair should match'
    $buf[$start + 4] = 0x90; $buf[$start + 5] = 0xE9
    Assert-True (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1) 'patched near pair should match'
    $buf[$start + 4] = 0x0F; $buf[$start + 5] = 0xE9
    Assert-True (-not (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1)) 'mixed 0F E9 pair must not match'
    $buf[$start + 4] = 0x90; $buf[$start + 5] = 0x8F
    Assert-True (-not (Test-SigAt -Buf $buf -Start $start -Sig $near -JgOff 4 -Kind 1)) 'mixed 90 8F pair must not match'
    Initialize-NativeHelpers
    Assert-True (-not [Mv2Native]::SigMatchesAt($buf, $start, $near, 4, 1)) 'compiled matcher must reject mixed near pairs'

    $sig = [byte[]]@(0x83,0x7E,0x50,0x02,0x7F,0x2F,0x55,0x48,0x89,0xE5)
    $target = Join-Path $temp 'full fixture.dll'
    $sigPath = Join-Path $temp 'full signatures.json'
    New-TestPe -Path $target -Signature $sig
    Write-Signatures -Path $sigPath -Milestones @(
        @{ name='test-pe'; container='pe'; sites=@(
            @{ name='gate'; kind='short'; jgRVA='0x00001044'; jgOff=4; expectedMatches=1; sig='837E50027F2F554889E5' }
        ) }
    )
    $script:Signatures = $sigPath
    $script:AllowPartial = [switch]$false
    $script:ForceRestore = [switch]$false
    $targetObj = [pscustomobject]@{ Path=$target; Channel='Test'; Running=$false; Holders=0 }

    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 0) 'full synthetic PE patch should succeed'
    Assert-True (([IO.File]::ReadAllBytes($target))[0x444] -eq 0xEB) 'patch should flip the short jump'
    Assert-True (Test-Path -LiteralPath "$target.bak") 'patch should create a backup'
    Assert-True (Test-Path -LiteralPath "$target.bak.json") 'patch should create backup metadata'
    $patchedHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 0) 'idempotent re-patch should succeed'
    Assert-True ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $patchedHash) 'idempotent re-patch should not rewrite different bytes'
    Assert-True ((Invoke-Restore -Target $targetObj -AssumeYes $true) -eq 0) 'verified restore should succeed'
    Assert-True (([IO.File]::ReadAllBytes($target))[0x444] -eq 0x7F) 'restore should recover stock byte'

    $unrelated = [IO.File]::ReadAllBytes($target)
    $unrelated[0x620] = 0xA5
    [IO.File]::WriteAllBytes($target, $unrelated)
    Assert-True ((Invoke-Patch -Target $targetObj -AssumeYes $true) -eq 1) 'patch should refuse unrelated target modifications'
    Assert-True (([IO.File]::ReadAllBytes($target))[0x620] -eq 0xA5) 'refused patch must preserve unrelated modifications'
    Copy-Item -LiteralPath "$target.bak" -Destination $target -Force

    $other = Join-Path $temp 'different build.dll'
    New-TestPe -Path $other -Signature $sig -TimeStamp 0x22345678
    Copy-Item -LiteralPath $other -Destination $target -Force
    Assert-True ((Invoke-Restore -Target $targetObj -AssumeYes $true) -eq 1) 'stale restore should fail closed'
    Assert-True (([BitConverter]::ToUInt32([IO.File]::ReadAllBytes($target), 0x88)) -eq 0x22345678) 'failed stale restore must leave target untouched'

    $raceTarget = Join-Path $temp 'race target.bin'
    $raceSource = Join-Path $temp 'race source.bin'
    [IO.File]::WriteAllBytes($raceTarget, [byte[]]@(1,2,3))
    [IO.File]::WriteAllBytes($raceSource, [byte[]]@(9,8,7))
    Assert-Throws { Write-AtomicFile -TargetPath $raceTarget -Buf ([IO.File]::ReadAllBytes($raceSource)) -ExpectedCurrentHash ('0' * 64) } 'atomic writer should reject a changed target'
    Assert-True ((Get-ByteHash ([IO.File]::ReadAllBytes($raceTarget))) -eq (Get-ByteHash ([byte[]]@(1,2,3)))) 'race rejection must preserve target bytes'

    $truncated = [IO.File]::ReadAllBytes($pePath)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000), 0, $truncated, 0x80 + 24 + 0xF0 + 16, 4)
    Assert-Throws { Open-Image $truncated | Out-Null } 'out-of-bounds .text must be rejected'

    $partialBuf = [IO.File]::ReadAllBytes($pePath)
    $partialImg = Open-Image $partialBuf
    $partialMilestones = @(
        [pscustomobject]@{ Name='partial'; Container='pe'; Sites=@(
            [pscustomobject]@{ Name='present'; Kind=1; JgRVA=[uint32]0x1044; Sig=$near; JgOff=4; ExpectedMatches=1 },
            [pscustomobject]@{ Name='missing'; Kind=0; JgRVA=[uint32]0x1084; Sig=$sig; JgOff=4; ExpectedMatches=1 }
        ) }
    )
    $declined = Invoke-PatchMilestones -Buf $partialBuf -Img $partialImg -Milestones $partialMilestones -Apply $true
    Assert-True ($declined.Status -eq 0 -and $declined.Reason -match 'partial') 'partial layout should be declined by default'

    $ambiguous = @(
        [pscustomobject]@{ Name='a'; Container='pe'; Sites=$partialMilestones[0].Sites },
        [pscustomobject]@{ Name='b'; Container='pe'; Sites=$partialMilestones[0].Sites }
    )
    $ambiguousResult = Invoke-PatchMilestones -Buf ([IO.File]::ReadAllBytes($pePath)) -Img $partialImg -Milestones $ambiguous -AllowPartial $true -Apply $true
    Assert-True ($ambiguousResult.Status -eq 0 -and $ambiguousResult.Reason -match 'tied') 'ambiguous partial layouts should be declined'

    Write-Host "PowerShell tests passed: $passed assertions"
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
