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
    [ValidateSet('Table','Grouped','Csv','Json')][string]$Format = 'Table'
)

Import-Module (Join-Path $PSScriptRoot 'PropagationScanner.psm1') -Force

$params = @{ DropDir = $DropDir; ExpectedManifest = $ExpectedManifest }
if ($PSBoundParameters.ContainsKey('Extractors')) { $params.Extractors = $Extractors }

$results = Invoke-MotwPropagationScan @params

switch ($Format) {
    'Table' {
        $results | Format-Table Section, Status, Extractor, FileName, ExpectMotw, ActualMotw, Reason -AutoSize -Wrap
    }
    'Grouped' {
        $statusColors = @{ PASS = 'Green'; FAIL = 'Red'; MISSING = 'Yellow'; SKIP = 'Cyan'; ERROR = 'Magenta' }
        foreach ($status in 'FAIL','MISSING','ERROR','SKIP','PASS') {
            $group = @($results | Where-Object Status -eq $status)
            if ($group.Count -eq 0) { continue }
            Write-Host ""
            Write-Host "=== $status ($($group.Count)) ===" -ForegroundColor $statusColors[$status]
            $group | Format-Table Section, Extractor, FileName, ExpectMotw, ActualMotw, Reason -AutoSize -Wrap
        }
    }
    'Csv'  { $results | ConvertTo-Csv -NoTypeInformation }
    'Json' { $results | ConvertTo-Json -Depth 4 }
}

$failed = @($results | Where-Object Status -eq 'FAIL')
if ($failed.Count -gt 0) { exit 1 }
