#Requires -Version 5.1
<#
.SYNOPSIS
    Scan a drop folder against an expected-MOTW manifest.  Reports whether
    every payload got MOTW (outer) and how propagation fared through each
    container via every extractor available on the host (inner).

.EXAMPLE
    .\Test-MotwPropagation.ps1 -DropDir "$env:USERPROFILE\Downloads" -ExpectedManifest .\expected.json

.EXAMPLE
    .\Test-MotwPropagation.ps1 -DropDir C:\drops -ExpectedManifest .\expected.json -Format Json |
        Out-File results.json -Encoding utf8
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$DropDir,
    [Parameter(Mandatory, Position = 1)][string]$ExpectedManifest,
    [string[]]$Extractors,
    [ValidateSet('Summary','Table','Grouped','Csv','Json')][string]$Format = 'Summary'
)

Import-Module (Join-Path $PSScriptRoot 'PropagationScanner.psm1') -Force

$params = @{ DropDir = $DropDir; ExpectedManifest = $ExpectedManifest }
if ($PSBoundParameters.ContainsKey('Extractors')) { $params.Extractors = $Extractors }

$results = Invoke-MotwPropagationScan @params

function Write-Summary {
    param($Rows)

    $outer = @($Rows | Where-Object Section -eq 'outer')
    $inner = @($Rows | Where-Object Section -eq 'inner')

    $by = @{}
    foreach ($s in 'PASS','FAIL','MISSING','ERROR','SKIP') { $by[$s] = 0 }
    foreach ($r in $Rows) { if ($by.ContainsKey($r.Status)) { $by[$r.Status] += 1 } }

    $color = 'Green'
    if ($by['FAIL'] -gt 0 -or $by['ERROR'] -gt 0) { $color = 'Red' }
    elseif ($by['MISSING'] -gt 0)                { $color = 'Yellow' }

    Write-Host ''
    Write-Host '=== MOTW propagation summary ===' -ForegroundColor Cyan
    Write-Host ("Total rows: {0}  (outer: {1}, inner: {2})" -f $Rows.Count, $outer.Count, $inner.Count)
    Write-Host ("  PASS    : {0}" -f $by['PASS'])    -ForegroundColor Green
    Write-Host ("  FAIL    : {0}" -f $by['FAIL'])    -ForegroundColor Red
    Write-Host ("  MISSING : {0}" -f $by['MISSING']) -ForegroundColor Yellow
    Write-Host ("  ERROR   : {0}" -f $by['ERROR'])   -ForegroundColor Magenta
    Write-Host ("  SKIP    : {0}" -f $by['SKIP'])    -ForegroundColor DarkGray

    if ($outer.Count -gt 0) {
        $withMotw = @($outer | Where-Object ActualMotw)
        Write-Host ''
        Write-Host ("Outer drops carrying MOTW: {0}/{1}" -f $withMotw.Count, $outer.Count) -ForegroundColor $color

        $zoneCounts = $outer | Where-Object ActualMotw |
                      Group-Object ZoneName -NoElement |
                      Sort-Object Count -Descending
        foreach ($z in $zoneCounts) {
            Write-Host ("  Zone {0,-12} : {1}" -f $z.Name, $z.Count)
        }

        $hosts = @($outer | Where-Object { $_.HostUrl } |
                           Select-Object -ExpandProperty HostUrl -Unique)
        if ($hosts.Count -gt 0) {
            Write-Host ''
            Write-Host ("Distinct outer HostUrl values ({0}):" -f $hosts.Count)
            foreach ($h in $hosts) { Write-Host "  $h" }
        }
    }

    if ($inner.Count -gt 0) {
        Write-Host ''
        Write-Host '=== Inner (container) propagation by extractor ===' -ForegroundColor Cyan
        $inner | Group-Object Extractor | ForEach-Object {
            $ext   = $_.Name
            $pass  = @($_.Group | Where-Object Status -eq 'PASS').Count
            $fail  = @($_.Group | Where-Object Status -eq 'FAIL').Count
            $total = $_.Group.Count
            $c = if ($fail -gt 0) { 'Red' } else { 'Green' }
            Write-Host ("  {0,-18} {1}/{2} PASS, {3} FAIL" -f $ext, $pass, $total, $fail) -ForegroundColor $c
        }
    }

    $failing = @($Rows | Where-Object { $_.Status -in 'FAIL','MISSING','ERROR' })
    if ($failing.Count -gt 0) {
        Write-Host ''
        Write-Host '=== Rows needing attention ===' -ForegroundColor Yellow
        $failing | Format-Table Status, Section, Extractor, FileName, ExpectMotw, ActualMotw, ZoneName, Reason -AutoSize -Wrap
    }
}

switch ($Format) {
    'Summary' { Write-Summary -Rows $results }
    'Table'   {
        $results | Format-Table Section, Status, Extractor, FileName, ZoneName, HostUrl, ExpectMotw, ActualMotw, Reason -AutoSize -Wrap
    }
    'Grouped' {
        $statusColors = @{ PASS='Green'; FAIL='Red'; MISSING='Yellow'; SKIP='Cyan'; ERROR='Magenta' }
        foreach ($status in 'FAIL','ERROR','MISSING','SKIP','PASS') {
            $group = @($results | Where-Object Status -eq $status)
            if ($group.Count -eq 0) { continue }
            Write-Host ''
            Write-Host ("=== {0} ({1}) ===" -f $status, $group.Count) -ForegroundColor $statusColors[$status]
            $group | Format-Table Section, Extractor, FileName, ZoneName, HostUrl, ExpectMotw, ActualMotw, Reason -AutoSize -Wrap
        }
    }
    'Csv'  { $results | ConvertTo-Csv -NoTypeInformation }
    'Json' { $results | ConvertTo-Json -Depth 4 }
}

$failed = @($results | Where-Object Status -eq 'FAIL')
if ($failed.Count -gt 0) { exit 1 }
