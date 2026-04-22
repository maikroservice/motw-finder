Set-StrictMode -Version Latest

<#
HTML-smuggling test harness.  Takes benign marker payloads from
PayloadBuilders, encrypts each with AES-GCM, and inlines them into the
smuggling-template.html.  Opening the emitted HTML in a browser triggers
`<a download>` drops of every payload — the reproduction of canonical
HTML-smuggling delivery against known-benign content so MOTW behaviour
can be measured end-to-end.

Requires PowerShell 7+ (uses System.Security.Cryptography.AesGcm).
#>

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PayloadBuilders.psm1') -Force

$script:DefaultTemplate = Join-Path $PSScriptRoot 'smuggling-template.html'

function Test-AesGcmAvailable {
    [CmdletBinding()] param()
    try {
        [System.Security.Cryptography.AesGcm] | Out-Null
        return $true
    } catch { return $false }
}

function Invoke-AesGcmEncrypt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Nonce,
        [Parameter(Mandatory)][byte[]]$Plaintext
    )
    if (-not (Test-AesGcmAvailable)) {
        throw 'System.Security.Cryptography.AesGcm not available. Run this on PowerShell 7+ (.NET 5+).'
    }
    $ct  = [byte[]]::new($Plaintext.Length)
    $tag = [byte[]]::new(16)
    $gcm = [System.Security.Cryptography.AesGcm]::new($Key)
    try { $gcm.Encrypt($Nonce, $Plaintext, $ct, $tag) } finally { $gcm.Dispose() }
    # WebCrypto AES-GCM decrypt expects ciphertext || tag
    $out = [byte[]]::new($ct.Length + $tag.Length)
    [Buffer]::BlockCopy($ct, 0, $out, 0, $ct.Length)
    [Buffer]::BlockCopy($tag, 0, $out, $ct.Length, $tag.Length)
    return $out
}

function Invoke-AesGcmDecrypt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Nonce,
        [Parameter(Mandatory)][byte[]]$CiphertextWithTag
    )
    if (-not (Test-AesGcmAvailable)) {
        throw 'System.Security.Cryptography.AesGcm not available.'
    }
    $tagLen = 16
    $ctLen  = $CiphertextWithTag.Length - $tagLen
    $ct  = [byte[]]::new($ctLen)
    $tag = [byte[]]::new($tagLen)
    [Buffer]::BlockCopy($CiphertextWithTag, 0, $ct, 0, $ctLen)
    [Buffer]::BlockCopy($CiphertextWithTag, $ctLen, $tag, 0, $tagLen)
    $plain = [byte[]]::new($ctLen)
    $gcm = [System.Security.Cryptography.AesGcm]::new($Key)
    try { $gcm.Decrypt($Nonce, $ct, $tag, $plain) } finally { $gcm.Dispose() }
    return $plain
}

function Get-DefaultPayloadManifest {
    <#
    .SYNOPSIS
        The built-in payload set (Tier 1 + some Tier 3 script types).
        Each entry knows its expected MOTW outcome on a fully-patched
        current Windows so Test-MotwPropagation can pass/fail against it.
    #>
    [CmdletBinding()] param()

    $items = @()

    # A. Baselines
    $items += @{ Builder = { New-MarkerFileBytes -Extension '.txt' };                     Mime = 'text/plain';                                                           ExpectMotw = $true;  Expected = @{} }
    $items += @{ Builder = { New-MarkerFileBytes -Extension '.pdf' -Comment 'pdf-stub' }; Mime = 'application/pdf';                                                      ExpectMotw = $true;  Expected = @{} }
    $items += @{ Builder = { New-MarkerHtaBytes };                                        Mime = 'application/hta';                                                      ExpectMotw = $true;  Expected = @{} }

    # Office
    $items += @{ Builder = { New-OoxmlContainerBytes -Kind docx }; Mime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'; ExpectMotw = $true; Expected = @{} }
    $items += @{ Builder = { New-OoxmlContainerBytes -Kind docm }; Mime = 'application/vnd.ms-word.document.macroEnabled.12';                         ExpectMotw = $true; Expected = @{} }
    $items += @{ Builder = { New-OoxmlContainerBytes -Kind xlsm }; Mime = 'application/vnd.ms-excel.sheet.macroEnabled.12';                           ExpectMotw = $true; Expected = @{} }

    # F. Script / loader types (marker files with dangerous extensions)
    foreach ($ext in '.lnk','.hta','.js','.vbs','.wsf','.ps1','.bat','.cmd','.scr','.chm','.cpl','.msc','.settingcontent-ms','.url') {
        $e = $ext
        $items += @{
            Builder = [scriptblock]::Create("New-MarkerFileBytes -Extension '$e'")
            Mime    = 'application/octet-stream'
            ExpectMotw = $true
            Expected = @{}
        }
    }

    # B / C. Containers with an inner marker.lnk — exercises extractor propagation
    $innerLnk   = (New-MarkerFileBytes -Extension '.lnk' -Comment 'inner')
    $innerItems = @(@{ Name = $innerLnk.FileName; Bytes = $innerLnk.Bytes })

    $items += @{
        Builder = [scriptblock]::Create(@"
New-ZipContainerBytes -Items @(@{ Name = '$($innerLnk.FileName)'; Bytes = [Convert]::FromBase64String('$([Convert]::ToBase64String($innerLnk.Bytes))') }) -ArchiveName 'container.zip'
"@)
        Mime       = 'application/zip'
        ExpectMotw = $true
        Expected   = @{ InnerFiles = @(@{ Path = $innerLnk.FileName; ExpectMotw = $false; Reason = '7-Zip <22.00 / Explorer built-in vary on propagation; compare with fixed versions' }) }
    }

    if (Test-ExternalTool @('7z','7z.exe','7zz')) {
        $items += @{
            Builder = [scriptblock]::Create(@"
New-PasswordZipContainerBytes -Items @(@{ Name = '$($innerLnk.FileName)'; Bytes = [Convert]::FromBase64String('$([Convert]::ToBase64String($innerLnk.Bytes))') }) -Password 'motwtest' -ArchiveName 'container-pw.zip'
"@)
            Mime       = 'application/zip'
            ExpectMotw = $true
            Expected   = @{ InnerFiles = @(@{ Path = $innerLnk.FileName; ExpectMotw = $false; Reason = 'Password-protected ZIPs historically strip MOTW on extraction' }) }
        }
    }

    if (Test-ExternalTool @('genisoimage','mkisofs','xorriso','oscdimg.exe','oscdimg')) {
        $items += @{
            Builder = [scriptblock]::Create(@"
New-IsoContainerBytes -Items @(@{ Name = '$($innerLnk.FileName)'; Bytes = [Convert]::FromBase64String('$([Convert]::ToBase64String($innerLnk.Bytes))') }) -ArchiveName 'container.iso'
"@)
            Mime       = 'application/x-iso9660-image'
            ExpectMotw = $true
            Expected   = @{ InnerFiles = @(@{ Path = $innerLnk.FileName; ExpectMotw = $true; Reason = 'Post-CVE-2022-41091 Windows should propagate MOTW on mount' }) }
        }

        $items += @{
            Builder = [scriptblock]::Create(@"
New-IsoContainerBytes -Items @(@{ Name = '$($innerLnk.FileName)'; Bytes = [Convert]::FromBase64String('$([Convert]::ToBase64String($innerLnk.Bytes))') }) -ArchiveName 'container.img'
"@)
            Mime       = 'application/octet-stream'
            ExpectMotw = $true
            Expected   = @{ InnerFiles = @(@{ Path = $innerLnk.FileName; ExpectMotw = $true; Reason = 'IMG handled same as ISO post-patch' }) }
        }
    }

    # Materialise each builder.
    $materialised = @()
    foreach ($i in $items) {
        $p = & $i.Builder
        $materialised += [pscustomobject]@{
            FileName   = $p.FileName
            Bytes      = $p.Bytes
            Mime       = $i.Mime
            ExpectMotw = $i.ExpectMotw
            Expected   = $i.Expected
        }
    }
    $materialised
}

function New-SmugglingHtmlBundle {
    <#
    .SYNOPSIS
        Build the smuggling HTML + expected-MOTW manifest from materialised items.
    .PARAMETER Items
        Objects with FileName, Bytes, Mime, ExpectMotw, Expected.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [string]$TemplatePath = $script:DefaultTemplate
    )
    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        throw "Template not found: $TemplatePath"
    }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $key = [byte[]]::new(32); $rng.GetBytes($key)

    $blobs = New-Object System.Collections.Generic.List[object]
    foreach ($item in $Items) {
        $iv = [byte[]]::new(12); $rng.GetBytes($iv)
        $ct = Invoke-AesGcmEncrypt -Key $key -Nonce $iv -Plaintext $item.Bytes
        $blobs.Add([pscustomobject]@{
            n  = $item.FileName
            m  = $item.Mime
            iv = [Convert]::ToBase64String($iv)
            c  = [Convert]::ToBase64String($ct)
        })
    }

    $blobJson  = ConvertTo-Json -InputObject $blobs -Compress -Depth 4
    $keyB64Lit = '"' + [Convert]::ToBase64String($key) + '"'

    $html = Get-Content -LiteralPath $TemplatePath -Raw
    $html = $html.Replace('{{COUNT}}', [string]$Items.Count)
    $html = $html.Replace('/*__PAYLOAD_JSON__*/', $blobJson)
    $html = $html.Replace('/*__KEY_B64__*/', $keyB64Lit)

    $expected = foreach ($item in $Items) {
        [pscustomobject]@{
            FileName   = $item.FileName
            Mime       = $item.Mime
            SizeBytes  = $item.Bytes.Length
            ExpectMotw = [bool]$item.ExpectMotw
            Expected   = $item.Expected
        }
    }

    [pscustomobject]@{
        Html     = $html
        KeyB64   = [Convert]::ToBase64String($key)
        Expected = @($expected)
    }
}

Export-ModuleMember -Function `
    Test-AesGcmAvailable, `
    Invoke-AesGcmEncrypt, `
    Invoke-AesGcmDecrypt, `
    Get-DefaultPayloadManifest, `
    New-SmugglingHtmlBundle
