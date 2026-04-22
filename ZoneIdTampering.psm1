Set-StrictMode -Version Latest

<#
Generates malformed Zone.Identifier streams to probe:
  * Our own MotwFinder parser's tolerance/rejection.
  * Windows/SmartScreen behaviour on pathological streams (e.g. the
    CVE-2022-44698 Magniber padding shape, ZoneId downgrades, BOMs).

Byte-level emitters are cross-platform.  Writing the streams to real
NTFS ADS requires Windows; on non-Windows we fall back to literal
"<file>:Zone.Identifier" sidecar files which the detector's sidecar
reader can consume.
#>

$script:Variants = @(
    @{
        Name        = 'Empty'
        Description = 'Stream exists but contains zero bytes.'
        Builder     = { ,[byte[]]::new(0) }
        ParseExpectation = 'throw'
    },
    @{
        Name        = 'WhitespaceOnly'
        Description = 'Stream contains only whitespace.'
        Builder     = { ,[System.Text.Encoding]::ASCII.GetBytes("   `r`n`t  ") }
        ParseExpectation = 'throw'
    },
    @{
        Name        = 'MissingZoneId'
        Description = '[ZoneTransfer] header but no ZoneId key.'
        Builder     = { ,[System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nHostUrl=https://example.com/`r`n") }
        ParseExpectation = 'throw'
    },
    @{
        Name        = 'MissingHeader'
        Description = 'ZoneId=3 with no [ZoneTransfer] section header.'
        Builder     = { ,[System.Text.Encoding]::ASCII.GetBytes("ZoneId=3`r`nHostUrl=https://example.com/`r`n") }
        ParseExpectation = 'parse'   # our current parser accepts this
    },
    @{
        Name        = 'ZoneIdZero'
        Description = 'ZoneId=0 (Local) on a file that was obviously downloaded -- "downgrade".'
        Builder     = { ,[System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=0`r`nHostUrl=https://cdn.discordapp.com/x`r`n") }
        ParseExpectation = 'parse'
    },
    @{
        Name        = 'NonIntegerZoneId'
        Description = 'ZoneId=abc -- malformed integer value (CVE-2022-44698 family).'
        Builder     = { ,[System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=abc`r`n") }
        ParseExpectation = 'throw'
    },
    @{
        Name        = 'NegativeZoneId'
        Description = 'ZoneId=-1 -- negative; undefined behaviour per spec.'
        Builder     = { ,[System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=-1`r`n") }
        ParseExpectation = 'parse'
    },
    @{
        Name        = 'PaddedCve202244698'
        Description = 'Zone.Identifier padded with nulls after a valid ZoneTransfer -- shape used by Magniber (CVE-2022-44698) to confuse SmartScreen.'
        Builder     = {
            $head = [System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example/`r`n")
            $pad  = [byte[]]::new(1024)
            $out  = [byte[]]::new($head.Length + $pad.Length)
            [Buffer]::BlockCopy($head, 0, $out, 0, $head.Length)
            [Buffer]::BlockCopy($pad,  0, $out, $head.Length, $pad.Length)
            ,$out
        }
        ParseExpectation = 'parse'
    },
    @{
        Name        = 'ExtraKeys'
        Description = 'Extra keys beyond ZoneId/HostUrl/ReferrerUrl (should be ignored).'
        Builder     = {
            ,[System.Text.Encoding]::ASCII.GetBytes(@"
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.com/
HostUrl=https://cdn.example.com/file.zip
LastWriterPackageFamilyName=Microsoft.Edge_8wekyb3d8bbwe
AppZoneId=3
"@)
        }
        ParseExpectation = 'parse'
    },
    @{
        Name        = 'Utf16LeBom'
        Description = 'UTF-16LE encoded stream with BOM (Windows notepad default).'
        Builder     = {
            $bom  = [byte[]](0xFF, 0xFE)
            $body = [System.Text.Encoding]::Unicode.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example/`r`n")
            $out  = [byte[]]::new($bom.Length + $body.Length)
            [Buffer]::BlockCopy($bom,  0, $out, 0, $bom.Length)
            [Buffer]::BlockCopy($body, 0, $out, $bom.Length, $body.Length)
            ,$out
        }
        ParseExpectation = 'throw'   # our parser reads bytes as ASCII; fails
    },
    @{
        Name        = 'Utf8Bom'
        Description = 'UTF-8 BOM prefix ahead of the ZoneTransfer section.'
        Builder     = {
            $bom  = [byte[]](0xEF, 0xBB, 0xBF)
            $body = [System.Text.Encoding]::UTF8.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`n")
            $out  = [byte[]]::new($bom.Length + $body.Length)
            [Buffer]::BlockCopy($bom,  0, $out, 0, $bom.Length)
            [Buffer]::BlockCopy($body, 0, $out, $bom.Length, $body.Length)
            ,$out
        }
        ParseExpectation = 'parse'   # BOM lives in the leading '[' line -- our parser tolerates via Trim
    },
    @{
        Name        = 'HugeHostUrl'
        Description = 'HostUrl of 8KB -- exercises any size-based heuristics.'
        Builder     = {
            $url  = 'https://' + ('a' * 8000) + '.example/'
            ,[System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=$url`r`n")
        }
        ParseExpectation = 'parse'
    },
    @{
        Name        = 'TrailingGarbage'
        Description = 'Valid section followed by garbage non-KV lines.'
        Builder     = {
            ,[System.Text.Encoding]::ASCII.GetBytes("[ZoneTransfer]`r`nZoneId=3`r`nthis is not a key value line`r`nnor is this`r`n")
        }
        ParseExpectation = 'parse'
    }
)

function Get-ZoneIdTamperingVariants {
    [CmdletBinding()] param()
    foreach ($v in $script:Variants) {
        [pscustomobject]@{
            Name             = $v.Name
            Description      = $v.Description
            ParseExpectation = $v.ParseExpectation
        }
    }
}

function New-TamperedZoneIdentifierBytes {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Variant)
    $spec = $script:Variants | Where-Object Name -eq $Variant | Select-Object -First 1
    if (-not $spec) {
        throw "Unknown tampering variant: $Variant. Known: $((Get-ZoneIdTamperingVariants).Name -join ', ')"
    }
    & $spec.Builder
}

function New-TamperedFixtureFile {
    <#
    .SYNOPSIS
        Create a marker file and attach the chosen tampered Zone.Identifier.
        Uses real NTFS ADS on Windows; falls back to a colon-in-filename
        sidecar on other OSes (so fixtures can be authored cross-platform
        and shipped to Windows for real testing).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Variant
    )
    $markerBytes = [System.Text.Encoding]::UTF8.GetBytes("MOTW-TEST marker for $Variant")
    [System.IO.File]::WriteAllBytes($Path, $markerBytes)

    $adsBytes = New-TamperedZoneIdentifierBytes -Variant $Variant

    $isWindows = $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows
    if ($isWindows) {
        $adsPath = "$Path`:Zone.Identifier"
        [System.IO.File]::WriteAllBytes($adsPath, $adsBytes)
    } else {
        $sidecar = "${Path}:Zone.Identifier"  # literal filename on Linux/macOS
        [System.IO.File]::WriteAllBytes($sidecar, $adsBytes)
    }
    [pscustomobject]@{
        Path    = $Path
        Variant = $Variant
    }
}

Export-ModuleMember -Function `
    Get-ZoneIdTamperingVariants, `
    New-TamperedZoneIdentifierBytes, `
    New-TamperedFixtureFile
