#Requires -Version 5.1
<#
.SYNOPSIS
    Hunt for files whose Mark-of-the-Web looks like it came from (or enables) an attack chain.

.DESCRIPTION
    Wraps Find-SuspiciousMotw and groups findings by severity. Rules include:
      - DangerousExtensionFromInternet  (High)   — ZoneId=3 + .lnk/.hta/.wsf/.chm/.js/...
      - SuspiciousOrigin                (Medium) — HostUrl/ReferrerUrl matches known-abused infra
      - UnparseableZoneIdentifier       (Medium) — stream exists but won't parse (tampering)
      - MissingProvenance               (Info)   — Internet zone with empty HostUrl/ReferrerUrl

.EXAMPLE
    .\Find-SuspiciousMotw.ps1 -Path C:\Users\$env:USERNAME\Downloads

.EXAMPLE
    .\Find-SuspiciousMotw.ps1 -Path C:\ -Since (Get-Date).AddDays(-14) -Format Json |
        Out-File findings.json -Encoding utf8
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Path,
    [datetime]$Since,
    [ValidateSet('Table', 'Grouped', 'Csv', 'Json')][string]$Format = 'Grouped',
    [ValidateSet('High', 'Medium', 'Info')][string]$MinSeverity = 'Info'
)

Import-Module (Join-Path $PSScriptRoot 'MotwFinder.psm1') -Force

$params = @{ Path = $Path }
if ($PSBoundParameters.ContainsKey('Since')) { $params.Since = $Since }

$order = @{ High = 3; Medium = 2; Info = 1 }
$threshold = $order[$MinSeverity]

$findings = Find-SuspiciousMotw @params | Where-Object { $order[$_.Severity] -ge $threshold }

switch ($Format) {
    'Table' {
        $findings | Sort-Object @{e={$order[$_.Severity]};desc=$true}, Path |
            Format-Table Severity, Rule, Path, HostUrl, Reason -AutoSize -Wrap
    }
    'Grouped' {
        foreach ($sev in 'High', 'Medium', 'Info') {
            $group = @($findings | Where-Object Severity -eq $sev)
            if ($group.Count -eq 0) { continue }
            Write-Host ""
            Write-Host "=== $sev ($($group.Count)) ===" -ForegroundColor (
                @{ High = 'Red'; Medium = 'Yellow'; Info = 'Cyan' }[$sev]
            )
            $group | Format-List Path, Rule, Reason, ZoneName, HostUrl, ReferrerUrl, LastWriteTime
        }
    }
    'Csv'  { $findings | ConvertTo-Csv -NoTypeInformation }
    'Json' { $findings | ConvertTo-Json -Depth 4 }
}
