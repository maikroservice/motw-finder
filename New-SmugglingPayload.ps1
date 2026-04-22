#Requires -Version 5.1
<#
.SYNOPSIS
    Generate the HTML-smuggling test page + expected-MOTW manifest.

.DESCRIPTION
    Default cipher mode is CbcHmac (AES-256-CBC + HMAC-SHA256), which
    works on Windows PowerShell 5.1 and PowerShell 7+.  Gcm mode requires
    PS 7+ (.NET 5+) and is kept for realism with modern HTML-smuggling
    samples.

.EXAMPLE
    .\New-SmugglingPayload.ps1 -OutputDir C:\motw-test
    # -> C:\motw-test\smuggle.html  (open in each browser you want to test)
    # -> C:\motw-test\expected.json (consumed by Test-MotwPropagation.ps1)

.EXAMPLE
    .\New-SmugglingPayload.ps1 -OutputDir C:\motw-test -CipherMode Gcm
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$OutputDir,
    [string]$HtmlName     = 'smuggle.html',
    [string]$ManifestName = 'expected.json',
    [ValidateSet('CbcHmac','Gcm')][string]$CipherMode = 'CbcHmac'
)

Import-Module (Join-Path $PSScriptRoot 'SmugglingHarness.psm1') -Force

if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

Write-Host "Building payloads..." -ForegroundColor Cyan
$manifest = Get-DefaultPayloadManifest
Write-Host "  $($manifest.Count) payload(s) built." -ForegroundColor Cyan

Write-Host "Encrypting ($CipherMode) and assembling HTML..." -ForegroundColor Cyan
$bundle = New-SmugglingHtmlBundle -Items $manifest -CipherMode $CipherMode

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
