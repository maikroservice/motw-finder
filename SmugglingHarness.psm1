Set-StrictMode -Version Latest

<#
HTML-smuggling test harness.  Takes benign marker payloads from
PayloadBuilders, encrypts each with an authenticated-encryption scheme,
and inlines them into smuggling-template.html.  Opening the emitted
HTML in a browser triggers `<a download>` drops of every payload -- the
reproduction of canonical HTML-smuggling delivery against known-benign
content so MOTW behaviour can be measured end-to-end.

Ciphers:
  * CbcHmac  (default)  AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC.
                        Works on Windows PowerShell 5.1 and PowerShell 7+.
                        This is also a very common shape in real 2020-2023
                        HTML-smuggling samples, so it makes for realistic
                        detection test data.
  * Gcm                 AES-256-GCM via System.Security.Cryptography.AesGcm.
                        Requires PowerShell 7+ (.NET 5+).  More modern
                        samples use this; kept as an option for realism.

Both modes round-trip in PowerShell and via WebCrypto on the browser
side.
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

# ---------- AES-CBC + HMAC-SHA256 (Encrypt-then-MAC) ----------

function Invoke-AesCbcEncrypt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$Plaintext
    )
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = $Key
        $aes.IV      = $InitVector
        $enc = $aes.CreateEncryptor()
        try {
            return ,$enc.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
        } finally { $enc.Dispose() }
    } finally { $aes.Dispose() }
}

function Invoke-AesCbcDecrypt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$Ciphertext
    )
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key     = $Key
        $aes.IV      = $InitVector
        $dec = $aes.CreateDecryptor()
        try {
            return ,$dec.TransformFinalBlock($Ciphertext, 0, $Ciphertext.Length)
        } finally { $dec.Dispose() }
    } finally { $aes.Dispose() }
}

function Invoke-HmacSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][byte[]]$Data
    )
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    try { return ,$hmac.ComputeHash($Data) }
    finally { $hmac.Dispose() }
}

function Test-HmacConstantTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$A,
        [Parameter(Mandatory)][byte[]]$B
    )
    if ($A.Length -ne $B.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) {
        $diff = $diff -bor ($A[$i] -bxor $B[$i])
    }
    return ($diff -eq 0)
}

function Invoke-AesCbcHmacEncrypt {
    <#
    .SYNOPSIS
        Encrypt-then-MAC.  HMAC covers IV || ciphertext so the verifier
        can confirm the IV hasn't been swapped either.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$AesKey,
        [Parameter(Mandatory)][byte[]]$MacKey,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$Plaintext
    )
    $ct = Invoke-AesCbcEncrypt -Key $AesKey -InitVector $InitVector -Plaintext $Plaintext
    $macInput = [byte[]]::new($InitVector.Length + $ct.Length)
    [Buffer]::BlockCopy($InitVector, 0, $macInput, 0, $InitVector.Length)
    [Buffer]::BlockCopy($ct, 0, $macInput, $InitVector.Length, $ct.Length)
    $tag = Invoke-HmacSha256 -Key $MacKey -Data $macInput
    [pscustomobject]@{ Ciphertext = $ct; Tag = $tag }
}

function Invoke-AesCbcHmacDecrypt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$AesKey,
        [Parameter(Mandatory)][byte[]]$MacKey,
        [Parameter(Mandatory)][byte[]]$InitVector,
        [Parameter(Mandatory)][byte[]]$Ciphertext,
        [Parameter(Mandatory)][byte[]]$Tag
    )
    $macInput = [byte[]]::new($InitVector.Length + $Ciphertext.Length)
    [Buffer]::BlockCopy($InitVector, 0, $macInput, 0, $InitVector.Length)
    [Buffer]::BlockCopy($Ciphertext, 0, $macInput, $InitVector.Length, $Ciphertext.Length)
    $computed = Invoke-HmacSha256 -Key $MacKey -Data $macInput
    if (-not (Test-HmacConstantTime -A $computed -B $Tag)) {
        throw 'HMAC verification failed -- ciphertext/IV was tampered or keys mismatch.'
    }
    Invoke-AesCbcDecrypt -Key $AesKey -InitVector $InitVector -Ciphertext $Ciphertext
}

# ---------- AES-GCM (optional, PS7+ only) ----------

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
    return ,$out
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
    return ,$plain
}

# ---------- Default payload manifest ----------

function Get-DefaultPayloadManifest {
    <#
    .SYNOPSIS
        The built-in payload set (Tier 1 + some Tier 3 script types).
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

    # B / C. Containers with an inner marker.lnk -- exercises extractor propagation
    $innerLnk   = (New-MarkerFileBytes -Extension '.lnk' -Comment 'inner')
    $innerB64   = [Convert]::ToBase64String($innerLnk.Bytes)
    $innerName  = $innerLnk.FileName

    $items += @{
        Builder = [scriptblock]::Create(@"
New-ZipContainerBytes -Items @(@{ Name = '$innerName'; Bytes = [Convert]::FromBase64String('$innerB64') }) -ArchiveName 'container.zip'
"@)
        Mime       = 'application/zip'
        ExpectMotw = $true
        Expected   = @{ InnerFiles = @(@{ Path = $innerName; ExpectMotw = $false; Reason = '7-Zip <22.00 / Explorer built-in vary on propagation' }) }
    }

    if (Test-ExternalTool @('7z','7z.exe','7zz')) {
        $items += @{
            Builder = [scriptblock]::Create(@"
New-PasswordZipContainerBytes -Items @(@{ Name = '$innerName'; Bytes = [Convert]::FromBase64String('$innerB64') }) -Password 'motwtest' -ArchiveName 'container-pw.zip'
"@)
            Mime       = 'application/zip'
            ExpectMotw = $true
            Expected   = @{ InnerFiles = @(@{ Path = $innerName; ExpectMotw = $false; Reason = 'Password-protected ZIPs historically strip MOTW on extraction' }) }
        }
    }

    if (Test-ExternalTool @('genisoimage','mkisofs','xorriso','oscdimg.exe','oscdimg')) {
        $items += @{
            Builder = [scriptblock]::Create(@"
New-IsoContainerBytes -Items @(@{ Name = '$innerName'; Bytes = [Convert]::FromBase64String('$innerB64') }) -ArchiveName 'container.iso'
"@)
            Mime       = 'application/x-iso9660-image'
            ExpectMotw = $true
            Expected   = @{ InnerFiles = @(@{ Path = $innerName; ExpectMotw = $true; Reason = 'Post-CVE-2022-41091 Windows should propagate MOTW on mount' }) }
        }

        $items += @{
            Builder = [scriptblock]::Create(@"
New-IsoContainerBytes -Items @(@{ Name = '$innerName'; Bytes = [Convert]::FromBase64String('$innerB64') }) -ArchiveName 'container.img'
"@)
            Mime       = 'application/octet-stream'
            ExpectMotw = $true
            Expected   = @{ InnerFiles = @(@{ Path = $innerName; ExpectMotw = $true; Reason = 'IMG handled same as ISO post-patch' }) }
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

# ---------- Bundle assembler ----------

function New-SmugglingHtmlBundle {
    <#
    .SYNOPSIS
        Build the smuggling HTML + expected-MOTW manifest from materialised items.
    .PARAMETER CipherMode
        CbcHmac (default, works on PS 5.1+) or Gcm (requires PS 7+).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Items,
        [string]$TemplatePath = $script:DefaultTemplate,
        [ValidateSet('CbcHmac','Gcm')][string]$CipherMode = 'CbcHmac'
    )
    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        throw "Template not found: $TemplatePath"
    }
    if ($CipherMode -eq 'Gcm' -and -not (Test-AesGcmAvailable)) {
        throw "CipherMode 'Gcm' requires PowerShell 7+ (.NET 5+). Use 'CbcHmac' for PS 5.1."
    }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $aesKey = [byte[]]::new(32); $rng.GetBytes($aesKey)
        $macKey = $null
        $ivLen  = 16
        if ($CipherMode -eq 'CbcHmac') {
            $macKey = [byte[]]::new(32); $rng.GetBytes($macKey)
            $ivLen = 16
        } else {
            $ivLen = 12   # AES-GCM nonce
        }

        $blobs = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Items) {
            $iv = [byte[]]::new($ivLen); $rng.GetBytes($iv)
            if ($CipherMode -eq 'CbcHmac') {
                $r = Invoke-AesCbcHmacEncrypt -AesKey $aesKey -MacKey $macKey -InitVector $iv -Plaintext $item.Bytes
                $blobs.Add([pscustomobject]@{
                    n  = $item.FileName
                    m  = $item.Mime
                    iv = [Convert]::ToBase64String($iv)
                    c  = [Convert]::ToBase64String($r.Ciphertext)
                    t  = [Convert]::ToBase64String($r.Tag)
                })
            } else {
                $ct = Invoke-AesGcmEncrypt -Key $aesKey -Nonce $iv -Plaintext $item.Bytes
                $blobs.Add([pscustomobject]@{
                    n  = $item.FileName
                    m  = $item.Mime
                    iv = [Convert]::ToBase64String($iv)
                    c  = [Convert]::ToBase64String($ct)
                })
            }
        }
    } finally {
        $rng.Dispose()
    }

    $blobJson   = ConvertTo-Json -InputObject $blobs -Compress -Depth 4
    $modeMarker = if ($CipherMode -eq 'CbcHmac') { "'cbc-hmac'" } else { "'gcm'" }
    $aesKeyLit  = '"' + [Convert]::ToBase64String($aesKey) + '"'
    $macKeyLit  = if ($null -ne $macKey) { '"' + [Convert]::ToBase64String($macKey) + '"' } else { 'null' }

    $html = Get-Content -LiteralPath $TemplatePath -Raw
    $html = $html.Replace('{{COUNT}}',              [string]$Items.Count)
    $html = $html.Replace('/*__CIPHER_MODE__*/',    $modeMarker)
    $html = $html.Replace('/*__AES_KEY_B64__*/',    $aesKeyLit)
    $html = $html.Replace('/*__MAC_KEY_B64__*/',    $macKeyLit)
    $html = $html.Replace('/*__PAYLOAD_JSON__*/',   $blobJson)

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
        Html       = $html
        CipherMode = $CipherMode
        AesKeyB64  = [Convert]::ToBase64String($aesKey)
        MacKeyB64  = if ($null -ne $macKey) { [Convert]::ToBase64String($macKey) } else { $null }
        Expected   = @($expected)
    }
}

Export-ModuleMember -Function `
    Test-AesGcmAvailable, `
    Invoke-AesCbcEncrypt, `
    Invoke-AesCbcDecrypt, `
    Invoke-HmacSha256, `
    Test-HmacConstantTime, `
    Invoke-AesCbcHmacEncrypt, `
    Invoke-AesCbcHmacDecrypt, `
    Invoke-AesGcmEncrypt, `
    Invoke-AesGcmDecrypt, `
    Get-DefaultPayloadManifest, `
    New-SmugglingHtmlBundle
