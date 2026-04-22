#Requires -Version 5.1
<#
.SYNOPSIS
    Measure whether `git clone` bypasses MOTW, and compare against a
    browser-downloaded ZIP of the same tree.

.DESCRIPTION
    The clone path should produce zero Zone.Identifier streams -- that's
    the evergreen bypass.  The download-archive path should produce MOTW
    on the outer ZIP; inner propagation depends on the extractor.

.EXAMPLE
    # Offline: build a local fixture repo and scan its clone.
    .\Test-GitMotwPropagation.ps1 -BuildFixtureRepo -WorkDir C:\git-test

.EXAMPLE
    # Compare clone vs. downloaded ZIP.
    .\Test-GitMotwPropagation.ps1 `
        -Source https://github.com/owner/repo.git `
        -DownloadedArchive "$env:USERPROFILE\Downloads\repo-main.zip" `
        -WorkDir C:\git-test
#>
[CmdletBinding(DefaultParameterSetName = 'Source')]
param(
    [Parameter(ParameterSetName = 'Source', Mandatory)][string]$Source,
    [Parameter(ParameterSetName = 'Fixture', Mandatory)][switch]$BuildFixtureRepo,
    [Parameter(Mandatory)][string]$WorkDir,
    [string]$DownloadedArchive,
    [string[]]$Extractors,
    [ValidateSet('Table','Grouped','Csv','Json')][string]$Format = 'Grouped'
)

Import-Module (Join-Path $PSScriptRoot 'psm/GitHarness.psm1') -Force

if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -Path $WorkDir -ItemType Directory | Out-Null
}

if ($PSCmdlet.ParameterSetName -eq 'Fixture') {
    $fixture = Join-Path $WorkDir 'fixture'
    $Source = New-GitMotwFixtureRepo -Path $fixture
    Write-Host "Built fixture bare repo at $Source" -ForegroundColor Cyan
}

$params = @{ Source = $Source; WorkDir = $WorkDir }
if ($PSBoundParameters.ContainsKey('DownloadedArchive')) { $params.DownloadedArchive = $DownloadedArchive }
if ($PSBoundParameters.ContainsKey('Extractors'))        { $params.Extractors        = $Extractors }

$rows = Test-GitMotwPropagation @params

switch ($Format) {
    'Table'   { $rows | Format-Table Delivery, Path, HasMotw, HostUrl -AutoSize }
    'Grouped' {
        foreach ($d in ($rows.Delivery | Sort-Object -Unique)) {
            $group = @($rows | Where-Object Delivery -eq $d)
            $marked = @($group | Where-Object HasMotw)
            $totalMarked = $marked.Count
            Write-Host ""
            $color = if ($d -like 'git-clone*' -and $totalMarked -eq 0) { 'Green' }
                     elseif ($d -like 'download-archive:outer' -and $totalMarked -gt 0) { 'Green' }
                     else { 'Yellow' }
            Write-Host "=== $d ($totalMarked/$($group.Count) marked) ===" -ForegroundColor $color
            $group | Format-Table Path, HasMotw, ZoneName, HostUrl -AutoSize
        }
    }
    'Csv'  { $rows | ConvertTo-Csv -NoTypeInformation }
    'Json' { $rows | ConvertTo-Json -Depth 4 }
}
