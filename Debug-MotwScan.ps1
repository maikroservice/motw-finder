#Requires -Version 5.1
<#
.SYNOPSIS
    Per-file diagnostic for Test-MotwPropagation.ps1. For each entry in an
    expected.json manifest, prints:
      * the path the scanner would look at
      * whether that path exists
      * the raw Zone.Identifier stream bytes (if any)
      * what Get-FileMotw parses out
    Plus a cross-check against every file in the drop dir so we can see
    whether the browser renamed a drop (marker.txt -> marker (1).txt etc.)

.EXAMPLE
    .\Debug-MotwScan.ps1 -DropDir "$env:USERPROFILE\Downloads" -ExpectedManifest .\expected.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$DropDir,
    [Parameter(Mandatory, Position = 1)][string]$ExpectedManifest
)

Import-Module (Join-Path $PSScriptRoot 'psm/MotwFinder.psm1') -Force

if (-not (Test-Path -LiteralPath $ExpectedManifest)) {
    throw "Expected manifest not found: $ExpectedManifest"
}
if (-not (Test-Path -LiteralPath $DropDir)) {
    throw "Drop directory not found: $DropDir"
}

$expected = Get-Content -LiteralPath $ExpectedManifest -Raw | ConvertFrom-Json
if ($expected -isnot [array]) { $expected = @($expected) }

Write-Host ''
Write-Host ('=== Per-expected-entry diagnostic ({0} entries) ===' -f $expected.Count) -ForegroundColor Cyan

foreach ($exp in $expected) {
    $path = Join-Path $DropDir $exp.FileName
    Write-Host ''
    Write-Host ('-- {0}' -f $exp.FileName) -ForegroundColor White
    Write-Host ('   Expected path : {0}' -f $path)
    $exists = Test-Path -LiteralPath $path
    Write-Host ('   Exists        : {0}' -f $exists) -ForegroundColor ($(if ($exists) { 'Green' } else { 'Yellow' }))

    if ($exists) {
        Write-Host '   Raw stream    :'
        $raw = $null
        try {
            $raw = Get-Content -LiteralPath $path -Stream 'Zone.Identifier' -Raw -ErrorAction Stop
        } catch {
            Write-Host ('     <no Zone.Identifier stream: {0}>' -f $_.Exception.Message) -ForegroundColor Yellow
        }
        if ($raw) {
            foreach ($line in ($raw -split "`r?`n")) {
                if ($line) { Write-Host ('     | ' + $line) }
            }
            Write-Host ('   Raw length    : {0} chars' -f $raw.Length)
        }

        Write-Host '   Get-FileMotw  :'
        $motw = Get-FileMotw -Path $path
        if ($null -eq $motw) {
            Write-Host '     <null — no parsed MOTW>' -ForegroundColor Red
        } else {
            Write-Host ('     ZoneId      : {0} ({1})' -f $motw.ZoneId, $motw.ZoneName)
            Write-Host ('     HostUrl     : {0}' -f $motw.HostUrl)
            Write-Host ('     ReferrerUrl : {0}' -f $motw.ReferrerUrl)
        }
    } else {
        # Show candidate files the browser may have renamed to
        $stem = [System.IO.Path]::GetFileNameWithoutExtension($exp.FileName)
        $ext  = [System.IO.Path]::GetExtension($exp.FileName)
        $pattern = "$stem*$ext"
        $candidates = Get-ChildItem -LiteralPath $DropDir -Filter $pattern -File -ErrorAction SilentlyContinue |
                      Where-Object Name -ne $exp.FileName
        if ($candidates) {
            Write-Host '   Candidate renames in drop dir (browser name-collision?):' -ForegroundColor Yellow
            foreach ($c in $candidates) {
                Write-Host ('     - {0}' -f $c.Name)
            }
        }
    }
}

Write-Host ''
Write-Host '=== Everything in DropDir that has MOTW ===' -ForegroundColor Cyan
$allMarked = Get-ChildItem -LiteralPath $DropDir -File -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        $m = Get-FileMotw -Path $_.FullName
        if ($m) {
            [pscustomobject]@{
                Name     = $_.Name
                ZoneName = $m.ZoneName
                HostUrl  = $m.HostUrl
            }
        }
    }
if ($allMarked) {
    $allMarked | Format-Table -AutoSize
    Write-Host ('{0} marked file(s) under {1}' -f @($allMarked).Count, $DropDir)
} else {
    Write-Host ('No MOTW-marked files found anywhere under {0}' -f $DropDir) -ForegroundColor Yellow
}
