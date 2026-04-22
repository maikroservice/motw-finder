#Requires -Version 5.1
<#
.SYNOPSIS
    List files under a path that carry a Mark-of-the-Web (NTFS Zone.Identifier ADS).

.EXAMPLE
    .\Find-Motw.ps1 -Path C:\Users\$env:USERNAME\Downloads

.EXAMPLE
    # Only files modified in the last 7 days (e.g. since the recent Windows update)
    .\Find-Motw.ps1 -Path C:\Users\$env:USERNAME\Downloads -Since (Get-Date).AddDays(-7)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Path,
    [datetime]$Since,
    [ValidateSet('Table', 'List', 'Csv', 'Json')][string]$Format = 'Table'
)

Import-Module (Join-Path $PSScriptRoot 'MotwFinder.psm1') -Force

$params = @{ Path = $Path }
if ($PSBoundParameters.ContainsKey('Since')) { $params.Since = $Since }

$results = Find-Motw @params

switch ($Format) {
    'Table' { $results | Format-Table Path, ZoneName, HostUrl, LastWriteTime -AutoSize }
    'List'  { $results | Format-List }
    'Csv'   { $results | ConvertTo-Csv -NoTypeInformation }
    'Json'  { $results | ConvertTo-Json -Depth 3 }
}
