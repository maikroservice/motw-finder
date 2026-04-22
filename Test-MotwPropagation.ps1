#Requires -Version 5.1
<#
.SYNOPSIS
    For every file under a path, report whether it carries Mark-of-the-Web.

.DESCRIPTION
    HOW MOTW DETECTION WORKS:

      Windows attaches Mark-of-the-Web as an NTFS Alternate Data Stream
      named "Zone.Identifier" on the file itself.  Concretely, for
      C:\Downloads\foo.exe, MOTW lives at the pseudo-path
      "C:\Downloads\foo.exe:Zone.Identifier" and contains INI-style
      text, e.g.

          [ZoneTransfer]
          ZoneId=3
          HostUrl=https://example.com/foo.exe
          ReferrerUrl=https://example.com/

      This script reads that stream via:

          Get-Content -LiteralPath <file> -Stream 'Zone.Identifier' -Raw

      Decision logic for each file:
        * Stream read succeeds AND the content parses as a [ZoneTransfer]
          section with a valid integer ZoneId  ->  HasMotw = True.
          The parsed ZoneName / HostUrl / ReferrerUrl are shown.
        * Stream does not exist (Get-Content raises
          ItemNotFoundException)                ->  HasMotw = False.
        * Stream exists but is empty / malformed ->  HasMotw = False.
          (Use Find-SuspiciousMotw.ps1 if you want "stream present but
          unparseable" called out as its own finding.)

.EXAMPLE
    .\Test-MotwPropagation.ps1 -Path "$env:USERPROFILE\Downloads"

.EXAMPLE
    .\Test-MotwPropagation.ps1 -Path ..\..\files-motw -Recurse -Format Csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Path,
    [switch]$Recurse,
    [switch]$HideMethodBanner,
    [ValidateSet('Table','Csv','Json')][string]$Format = 'Table'
)

Import-Module (Join-Path $PSScriptRoot 'psm/MotwFinder.psm1') -Force

$Path = (Resolve-Path -LiteralPath $Path).ProviderPath
if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Path is not a directory: $Path"
}

if (-not $HideMethodBanner -and $Format -eq 'Table') {
    Write-Host ''
    Write-Host 'How MOTW detection works:' -ForegroundColor Cyan
    Write-Host '  MOTW lives in an NTFS Alternate Data Stream named "Zone.Identifier" on the'
    Write-Host '  file itself (e.g. C:\path\foo.exe:Zone.Identifier). This script reads it with:'
    Write-Host ''
    Write-Host '    Get-Content -LiteralPath <file> -Stream "Zone.Identifier" -Raw'
    Write-Host ''
    Write-Host '  Stream present + parses as [ZoneTransfer] with integer ZoneId  ->  HasMotw = True'
    Write-Host '  Stream missing (ItemNotFoundException) or unparseable           ->  HasMotw = False'
    Write-Host ''
}

$files = if ($Recurse) {
    Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Get-ChildItem -LiteralPath $Path -File -Force -ErrorAction SilentlyContinue
}

$results = foreach ($f in $files) {
    $motw = Get-FileMotw -Path $f.FullName
    [pscustomobject]@{
        FileName    = $f.Name
        HasMotw     = [bool]$motw
        ZoneName    = if ($motw) { $motw.ZoneName }    else { $null }
        HostUrl     = if ($motw) { $motw.HostUrl }     else { $null }
        ReferrerUrl = if ($motw) { $motw.ReferrerUrl } else { $null }
        Path        = $f.FullName
    }
}

switch ($Format) {
    'Table' {
        $results |
            Sort-Object @{ Expression = { -not $_.HasMotw } }, FileName |
            Format-Table FileName, HasMotw, ZoneName, HostUrl -AutoSize

        $total  = @($results).Count
        $marked = @($results | Where-Object HasMotw).Count
        Write-Host ''
        Write-Host ("{0} file(s) total: {1} with MOTW, {2} without." -f $total, $marked, ($total - $marked)) -ForegroundColor Cyan
    }
    'Csv'  { $results | ConvertTo-Csv -NoTypeInformation }
    'Json' { $results | ConvertTo-Json -Depth 4 }
}
