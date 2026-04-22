#Requires -Version 5.1
<#
.SYNOPSIS
    Produce a directory of fixture files, each carrying a different
    pathological Zone.Identifier stream.  Pair with MotwFinder to see
    which variants your detector handles and which ones Windows/SmartScreen
    treats as "marked" vs "unmarked".

.EXAMPLE
    .\New-TamperedFixtures.ps1 -OutputDir C:\motw-tamper
    # Then run:
    .\Find-Motw.ps1 -Path C:\motw-tamper
    .\Find-SuspiciousMotw.ps1 -Path C:\motw-tamper
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$OutputDir,
    [string[]]$Variants
)

Import-Module (Join-Path $PSScriptRoot 'psm/ZoneIdTampering.psm1') -Force

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

$list = Get-ZoneIdTamperingVariants
if ($Variants) {
    $list = $list | Where-Object Name -in $Variants
    if (-not $list) { throw "None of the requested variants match: $($Variants -join ', ')" }
}

$manifest = @()
foreach ($v in $list) {
    $safe = ($v.Name -replace '[^A-Za-z0-9]','').ToLowerInvariant()
    $path = Join-Path $OutputDir "tampered-$safe.txt"
    $r = New-TamperedFixtureFile -Path $path -Variant $v.Name
    $manifest += [pscustomobject]@{
        File             = $r.Path
        Variant          = $v.Name
        Description      = $v.Description
        ParseExpectation = $v.ParseExpectation
    }
    Write-Host "  $($v.Name) -> $($r.Path)"
}

$mfPath = Join-Path $OutputDir 'tampered.manifest.json'
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $mfPath -Encoding utf8
Write-Host ""
Write-Host "Wrote $($manifest.Count) fixture(s) and $mfPath" -ForegroundColor Green
