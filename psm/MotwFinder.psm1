Set-StrictMode -Version Latest

$script:RiskyExtensions = @(
    '.lnk', '.hta', '.wsf', '.chm', '.js', '.jse', '.vbs', '.vbe',
    '.ps1', '.psm1', '.msc', '.cpl', '.scr', '.jar', '.bat', '.cmd',
    '.pif', '.url', '.settingcontent-ms'
)

$script:UrlShorteners = @(
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io',
    'tiny.cc', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy', 'rebrand.ly'
)

function Get-ZoneName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ZoneId)
    switch ($ZoneId) {
        0       { 'Local' }
        1       { 'Intranet' }
        2       { 'Trusted' }
        3       { 'Internet' }
        4       { 'Untrusted' }
        default { "Unknown($ZoneId)" }
    }
}

function ConvertFrom-ZoneIdentifier {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Text)
    process {
        if ([string]::IsNullOrWhiteSpace($Text)) {
            throw 'Zone.Identifier content is empty.'
        }

        $zoneId      = $null
        $referrerUrl = $null
        $hostUrl     = $null

        foreach ($line in ($Text -split "`r?`n")) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith('[') -or $trimmed.StartsWith(';')) { continue }
            $eq = $trimmed.IndexOf('=')
            if ($eq -lt 1) { continue }
            $key = $trimmed.Substring(0, $eq).Trim()
            $val = $trimmed.Substring($eq + 1).Trim()
            switch ($key) {
                'ZoneId' {
                    $parsed = 0
                    if (-not [int]::TryParse($val, [ref]$parsed)) {
                        throw "Invalid ZoneId value: '$val'."
                    }
                    $zoneId = $parsed
                }
                'ReferrerUrl' { $referrerUrl = $val }
                'HostUrl'     { $hostUrl     = $val }
            }
        }

        if ($null -eq $zoneId) {
            throw 'Zone.Identifier is missing ZoneId.'
        }

        [pscustomobject]@{
            ZoneId      = $zoneId
            ZoneName    = Get-ZoneName -ZoneId $zoneId
            ReferrerUrl = $referrerUrl
            HostUrl     = $hostUrl
        }
    }
}

function Read-MotwStream {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    # Resolve to a filesystem-absolute path first. Relative paths can mis-
    # resolve when Get-Content runs inside a module session state, which
    # silently returns null and masquerades as "no MOTW".
    try {
        $full = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    } catch {
        Write-Verbose "Read-MotwStream: cannot resolve path '$Path': $_"
        return $null
    }
    try {
        Get-Content -LiteralPath $full -Stream 'Zone.Identifier' -Raw -ErrorAction Stop
    } catch {
        Write-Verbose "Read-MotwStream: no Zone.Identifier on '$full' ($($_.Exception.GetType().Name): $($_.Exception.Message))"
        return $null
    }
}

function Get-FileMotw {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $raw = Read-MotwStream -Path $Path
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try {
        ConvertFrom-ZoneIdentifier -Text $raw
    } catch {
        Write-Verbose "Unparseable Zone.Identifier on '$Path': $_"
        return $null
    }
}

function Find-Motw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [datetime]$Since
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path not found: $Path"
    }

    Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ($PSBoundParameters.ContainsKey('Since') -and $_.LastWriteTime -lt $Since) {
                return
            }
            $info = Get-FileMotw -Path $_.FullName
            if ($null -ne $info) {
                [pscustomobject]@{
                    Path          = $_.FullName
                    ZoneId        = $info.ZoneId
                    ZoneName      = $info.ZoneName
                    HostUrl       = $info.HostUrl
                    ReferrerUrl   = $info.ReferrerUrl
                    LastWriteTime = $_.LastWriteTime
                }
            }
        }
}

function Test-SuspiciousMotwUrl {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)][AllowNull()][AllowEmptyString()][string]$Url)
    process {
        if ([string]::IsNullOrWhiteSpace($Url)) { return $null }

        if ($Url.StartsWith('\\')) {
            return 'UNC / file path referrer'
        }

        $lower = $Url.ToLowerInvariant()
        if ($lower.StartsWith('file:')) {
            return 'file:// URL (often WebDAV or SMB share)'
        }

        $hostName = $null
        $uri = $null
        if ([System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri)) {
            $hostName = $uri.Host
        }
        if (-not $hostName) { return $null }
        $hostName = $hostName.ToLowerInvariant()

        if ($hostName -match '^\d{1,3}(\.\d{1,3}){3}$') {
            return "Bare IP address host ($hostName)"
        }
        if ($uri.HostNameType -eq [System.UriHostNameType]::IPv6) {
            return "Bare IPv6 host ($hostName)"
        }

        if ($hostName -eq 'cdn.discordapp.com' -or $hostName -eq 'media.discordapp.net') {
            return "Discord CDN ($hostName) -- commonly abused for malware delivery"
        }
        if ($hostName -eq 'raw.githubusercontent.com' -or $hostName -eq 'gist.githubusercontent.com') {
            return "Raw GitHub content ($hostName)"
        }
        if ($hostName -like '*.mediafire.com' -or $hostName -like '*.mega.nz' -or $hostName -eq 'dl.dropboxusercontent.com') {
            return "File-share direct-download host ($hostName)"
        }
        if ($script:UrlShorteners -contains $hostName) {
            return "URL shortener ($hostName) -- obfuscated origin"
        }

        return $null
    }
}

function Get-MotwFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Raw,
        [AllowNull()][pscustomobject]$Parsed
    )

    if ($null -eq $Parsed) {
        $snippet = if ($Raw.Length -gt 160) { $Raw.Substring(0, 160) + '...' } else { $Raw }
        [pscustomobject]@{
            Path        = $Path
            Rule        = 'UnparseableZoneIdentifier'
            Severity    = 'Medium'
            Reason      = 'Zone.Identifier stream exists but failed to parse (possible tampering, CVE-2022-44698-style)'
            ZoneId      = $null
            ZoneName    = $null
            HostUrl     = $null
            ReferrerUrl = $null
            Evidence    = $snippet
        }
        return
    }

    $ext = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($Parsed.ZoneId -eq 3 -and $script:RiskyExtensions -contains $ext) {
        [pscustomobject]@{
            Path        = $Path
            Rule        = 'DangerousExtensionFromInternet'
            Severity    = 'High'
            Reason      = "Internet-zone file with high-risk extension '$ext'"
            ZoneId      = $Parsed.ZoneId
            ZoneName    = $Parsed.ZoneName
            HostUrl     = $Parsed.HostUrl
            ReferrerUrl = $Parsed.ReferrerUrl
            Evidence    = $null
        }
    }

    $hostReason     = Test-SuspiciousMotwUrl -Url $Parsed.HostUrl
    $referrerReason = Test-SuspiciousMotwUrl -Url $Parsed.ReferrerUrl
    $originReason   = $hostReason, $referrerReason | Where-Object { $_ } | Select-Object -First 1
    if ($originReason) {
        [pscustomobject]@{
            Path        = $Path
            Rule        = 'SuspiciousOrigin'
            Severity    = 'Medium'
            Reason      = $originReason
            ZoneId      = $Parsed.ZoneId
            ZoneName    = $Parsed.ZoneName
            HostUrl     = $Parsed.HostUrl
            ReferrerUrl = $Parsed.ReferrerUrl
            Evidence    = $null
        }
    }

    if ($Parsed.ZoneId -eq 3 -and
        [string]::IsNullOrWhiteSpace($Parsed.HostUrl) -and
        [string]::IsNullOrWhiteSpace($Parsed.ReferrerUrl)) {
        [pscustomobject]@{
            Path        = $Path
            Rule        = 'MissingProvenance'
            Severity    = 'Info'
            Reason      = 'Internet-zone MOTW present but HostUrl and ReferrerUrl are both empty (WebDAV copy, manual unblock, or stripped)'
            ZoneId      = $Parsed.ZoneId
            ZoneName    = $Parsed.ZoneName
            HostUrl     = $null
            ReferrerUrl = $null
            Evidence    = $null
        }
    }
}

function Find-SuspiciousMotw {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Path,
        [datetime]$Since
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path not found: $Path"
    }

    Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            if ($PSBoundParameters.ContainsKey('Since') -and $_.LastWriteTime -lt $Since) { return }

            $raw = Read-MotwStream -Path $_.FullName
            if ([string]::IsNullOrWhiteSpace($raw)) { return }

            $parsed = $null
            try { $parsed = ConvertFrom-ZoneIdentifier -Text $raw } catch { }

            foreach ($finding in (Get-MotwFindings -Path $_.FullName -Raw $raw -Parsed $parsed)) {
                $finding | Add-Member -NotePropertyName LastWriteTime -NotePropertyValue $_.LastWriteTime -Force -PassThru
            }
        }
}

Export-ModuleMember -Function `
    ConvertFrom-ZoneIdentifier, `
    Get-ZoneName, `
    Read-MotwStream, `
    Get-FileMotw, `
    Find-Motw, `
    Test-SuspiciousMotwUrl, `
    Get-MotwFindings, `
    Find-SuspiciousMotw
