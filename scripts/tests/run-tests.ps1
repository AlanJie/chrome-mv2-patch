$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'test-powershell.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$windowsBashTest = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'test-bash.sh'))
$bashTest = '/mnt/' + $windowsBashTest.Substring(0, 1).ToLowerInvariant() + $windowsBashTest.Substring(2).Replace('\', '/')
& bash $bashTest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$windowsBashScript = [IO.Path]::GetFullPath((Join-Path $repo 'chrome-mv2.sh'))
$bashScript = '/mnt/' + $windowsBashScript.Substring(0, 1).ToLowerInvariant() + $windowsBashScript.Substring(2).Replace('\', '/')
& bash -n $bashScript
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$tokens = $null; $errors = $null
[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'chrome-mv2.ps1'), [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count) {
    $errors | ForEach-Object { Write-Error ("{0}:{1}: {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message) }
    exit 1
}

Write-Host 'All tests passed.'
