Set-StrictMode -Version Latest

<#
Propagation scanner.  Takes a drop directory (typically ~/Downloads) and
an expected.json manifest produced by New-SmugglingPayload.ps1, then:

  * Reads MOTW on each outer drop.
  * For each container whose expected manifest declares InnerFiles,
    extracts/mounts with every extractor available on the host and reads
    MOTW on the inner files.

Reports one row per (file, section, extractor) with PASS / FAIL / MISSING.
#>

Import-Module (Join-Path $PSScriptRoot 'MotwFinder.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'PayloadBuilders.psm1') -Force

function Test-OuterMotwPropagation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DropDir,
        [Parameter(Mandatory)][object[]]$Expected
    )
    foreach ($exp in $Expected) {
        $path = Join-Path $DropDir $exp.FileName
        $row  = [ordered]@{
            FileName    = $exp.FileName
            Section     = 'outer'
            Extractor   = $null
            ExpectMotw  = [bool]$exp.ExpectMotw
            ActualMotw  = $null
            ZoneName    = $null
            HostUrl     = $null
            ReferrerUrl = $null
            Status      = $null
            Reason      = $null
        }
        if (-not (Test-Path -LiteralPath $path)) {
            $row.Status = 'MISSING'
            $row.Reason = 'File not present in drop directory'
        } else {
            $motw = Get-FileMotw -Path $path
            $row.ActualMotw  = [bool]$motw
            $row.ZoneName    = if ($motw) { $motw.ZoneName }    else { $null }
            $row.HostUrl     = if ($motw) { $motw.HostUrl }     else { $null }
            $row.ReferrerUrl = if ($motw) { $motw.ReferrerUrl } else { $null }
            $row.Status      = if ($row.ActualMotw -eq $row.ExpectMotw) { 'PASS' } else { 'FAIL' }
        }
        [pscustomobject]$row
    }
}

function Get-AvailableExtractors {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ContainerPath)
    $ext = [System.IO.Path]::GetExtension($ContainerPath).ToLowerInvariant()
    $list = [System.Collections.Generic.List[string]]::new()

    if ($ext -eq '.zip') {
        $list.Add('Expand-Archive')      # never propagates -- useful baseline
        if (Test-ExternalTool @('7z','7z.exe','7zz')) { $list.Add('7z') }
    }
    if ($ext -in @('.iso', '.img')) {
        if (Get-Command Mount-DiskImage -ErrorAction SilentlyContinue) { $list.Add('Mount-DiskImage') }
        if (Test-ExternalTool @('7z','7z.exe','7zz')) { $list.Add('7z') }
    }
    if ($ext -eq '.7z') {
        if (Test-ExternalTool @('7z','7z.exe','7zz')) { $list.Add('7z') }
    }
    return $list.ToArray()
}

function Expand-ContainerToTemp {
    <#
    .SYNOPSIS
        Open a container with the given extractor and return a handle with
        the path the caller should read.  For Mount-DiskImage the path is
        the mount volume (not a copy) so the Zone.Identifier stream is
        observed in-situ.  Caller must pass the handle back to
        Dismount-ContainerHandle for cleanup.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ContainerPath,
        [Parameter(Mandatory)][ValidateSet('Expand-Archive','7z','Mount-DiskImage')][string]$Method
    )

    $dest = Join-Path ([System.IO.Path]::GetTempPath()) ("motwprop_" + [guid]::NewGuid().ToString('N'))

    switch ($Method) {
        'Expand-Archive' {
            New-Item -Path $dest -ItemType Directory | Out-Null
            Expand-Archive -LiteralPath $ContainerPath -DestinationPath $dest -Force
            return @{ Path = $dest; IsMount = $false; ImagePath = $null }
        }
        '7z' {
            New-Item -Path $dest -ItemType Directory | Out-Null
            $tool = Test-ExternalTool @('7z','7z.exe','7zz')
            if (-not $tool) { throw '7z not available.' }
            & $tool x "-o$dest" '-y' $ContainerPath | Out-Null
            return @{ Path = $dest; IsMount = $false; ImagePath = $null }
        }
        'Mount-DiskImage' {
            $img = Mount-DiskImage -ImagePath $ContainerPath -PassThru
            Start-Sleep -Milliseconds 500
            $vol = $img | Get-Volume
            $drive = if ($vol.DriveLetter) { "$($vol.DriveLetter):\" } else { $null }
            if (-not $drive) {
                Dismount-DiskImage -ImagePath $ContainerPath | Out-Null
                throw "Mounted $ContainerPath but got no drive letter."
            }
            return @{ Path = $drive; IsMount = $true; ImagePath = $ContainerPath }
        }
    }
}

function Dismount-ContainerHandle {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Handle)
    if ($Handle.IsMount) {
        Dismount-DiskImage -ImagePath $Handle.ImagePath -ErrorAction SilentlyContinue | Out-Null
    } elseif ($Handle.Path -and (Test-Path -LiteralPath $Handle.Path)) {
        Remove-Item -LiteralPath $Handle.Path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-InnerMotwPropagation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ContainerPath,
        [Parameter(Mandatory)][object[]]$InnerSpec,
        [Parameter(Mandatory)][string[]]$Extractors
    )
    $containerName = Split-Path $ContainerPath -Leaf
    foreach ($method in $Extractors) {
        $handle = $null
        try {
            $handle = Expand-ContainerToTemp -ContainerPath $ContainerPath -Method $method
        } catch {
            foreach ($inner in $InnerSpec) {
                [pscustomobject][ordered]@{
                    FileName    = "$containerName\$($inner.Path)"
                    Section     = 'inner'
                    Extractor   = $method
                    ExpectMotw  = [bool]$inner.ExpectMotw
                    ActualMotw  = $null
                    ZoneName    = $null
                    HostUrl     = $null
                    ReferrerUrl = $null
                    Status      = 'ERROR'
                    Reason      = "Extractor failed: $_"
                }
            }
            continue
        }

        try {
            foreach ($inner in $InnerSpec) {
                $innerPath = Join-Path $handle.Path $inner.Path
                $row = [ordered]@{
                    FileName    = "$containerName\$($inner.Path)"
                    Section     = 'inner'
                    Extractor   = $method
                    ExpectMotw  = [bool]$inner.ExpectMotw
                    ActualMotw  = $null
                    ZoneName    = $null
                    HostUrl     = $null
                    ReferrerUrl = $null
                    Status      = $null
                    Reason      = $inner.Reason
                }
                if (-not (Test-Path -LiteralPath $innerPath)) {
                    $row.Status = 'MISSING'
                    if (-not $row.Reason) { $row.Reason = 'Inner file not found after extraction' }
                } else {
                    $motw = Get-FileMotw -Path $innerPath
                    $row.ActualMotw  = [bool]$motw
                    $row.ZoneName    = if ($motw) { $motw.ZoneName }    else { $null }
                    $row.HostUrl     = if ($motw) { $motw.HostUrl }     else { $null }
                    $row.ReferrerUrl = if ($motw) { $motw.ReferrerUrl } else { $null }
                    $row.Status      = if ($row.ActualMotw -eq $row.ExpectMotw) { 'PASS' } else { 'FAIL' }
                }
                [pscustomobject]$row
            }
        } finally {
            Dismount-ContainerHandle -Handle $handle
        }
    }
}

function Invoke-MotwPropagationScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DropDir,
        [Parameter(Mandatory)][string]$ExpectedManifest,
        [string[]]$Extractors
    )
    if (-not (Test-Path -LiteralPath $ExpectedManifest)) {
        throw "Expected manifest not found: $ExpectedManifest"
    }
    if (-not (Test-Path -LiteralPath $DropDir)) {
        throw "Drop directory not found: $DropDir"
    }

    $expected = Get-Content -LiteralPath $ExpectedManifest -Raw | ConvertFrom-Json
    if ($expected -isnot [array]) { $expected = @($expected) }

    $results = @()
    $results += Test-OuterMotwPropagation -DropDir $DropDir -Expected $expected

    foreach ($exp in $expected) {
        $hasInner = $false
        try { $hasInner = [bool]$exp.Expected.InnerFiles } catch { $hasInner = $false }
        if (-not $hasInner) { continue }

        $path = Join-Path $DropDir $exp.FileName
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $use = @(if ($Extractors -and @($Extractors).Count -gt 0) { $Extractors } else { Get-AvailableExtractors $path })
        if ($use.Count -eq 0) {
            [pscustomobject][ordered]@{
                FileName    = $exp.FileName
                Section     = 'inner'
                Extractor   = $null
                ExpectMotw  = $null
                ActualMotw  = $null
                ZoneName    = $null
                HostUrl     = $null
                ReferrerUrl = $null
                Status      = 'SKIP'
                Reason      = 'No extractor available on this host for this container type'
            }
            continue
        }
        $results += Test-InnerMotwPropagation -ContainerPath $path -InnerSpec @($exp.Expected.InnerFiles) -Extractors $use
    }

    $results
}

Export-ModuleMember -Function `
    Test-OuterMotwPropagation, `
    Test-InnerMotwPropagation, `
    Get-AvailableExtractors, `
    Expand-ContainerToTemp, `
    Dismount-ContainerHandle, `
    Invoke-MotwPropagationScan
