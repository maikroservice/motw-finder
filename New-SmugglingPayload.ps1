#Requires -Version 7.0
<#
.SYNOPSIS
    Generate the HTML-smuggling test page + expected-MOTW manifest.

.EXAMPLE
    .\New-SmugglingPayload.ps1 -OutputDir C:\motw-test
    # -> C:\motw-test\smuggle.html  (open in each browser you want to test)
    # -> C:\motw-test\expected.json (consumed by Test-MotwPropagation.ps1)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$OutputDir,
    [string]$HtmlName     = 'smuggle.html',
    [string]$ManifestName = 'expected.json'
)

Import-Module (Join-Path $PSScriptRoot 'SmugglingHarness.psm1') -Force

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

Write-Host "Building payloads..." -ForegroundColor Cyan
$manifest = Get-DefaultPayloadManifest
Write-Host "  $($manifest.Count) payload(s) built." -ForegroundColor Cyan

Write-Host "Encrypting and assembling HTML..." -ForegroundColor Cyan
$bundle = New-SmugglingHtmlBundle -Items $manifest

$htmlPath = Join-Path $OutputDir $HtmlName
$mfPath   = Join-Path $OutputDir $ManifestName

Set-Content -LiteralPath $htmlPath -Value $bundle.Html -Encoding utf8
$bundle.Expected | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $mfPath -Encoding utf8

Write-Host ""
Write-Host "Wrote:" -ForegroundColor Green
Write-Host "  HTML:     $htmlPath"
Write-Host "  Expected: $mfPath"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Open the HTML in each browser you want to exercise (Chrome/Edge/Firefox)."
Write-Host "  2. Click 'Drop ... test payloads'."
Write-Host "  3. Run Test-MotwPropagation.ps1 -DropDir <Downloads> -ExpectedManifest $mfPath"
