Set-StrictMode -Version Latest

<#
Compares MOTW propagation across two delivery paths for identical bytes:
  * `git clone` -- never applies MOTW (files arrive via the git object
    protocol, never through the browser's download pipeline).  This is
    the evergreen bypass; every file in the working tree reads as
    "local origin" to SmartScreen / Office Protected View.
  * Browser "Download ZIP" (e.g. GitHub archive) -- does get MOTW on
    the outer archive.  Inner propagation depends on the extractor,
    same matrix as the smuggling harness.

Includes a fixture builder (`New-GitMotwFixtureRepo`) that creates a
local bare repo populated with benign marker files so the whole harness
can run offline.
#>

Import-Module (Join-Path $PSScriptRoot 'MotwFinder.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'PayloadBuilders.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'PropagationScanner.psm1') -Force

function Invoke-Git {
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments, Mandatory)][string[]]$GitArgs)
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { throw 'git not found on PATH.' }
    & $git.Source @GitArgs
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function New-GitMotwFixtureRepo {
    <#
    .SYNOPSIS
        Build a local bare repo populated with Tier-1-shaped marker files.
        Returns the bare repo path; use it as the -Source for a clone test.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
    New-Item -Path $Path -ItemType Directory | Out-Null

    $bare = Join-Path $Path 'fixture.git'
    $work = Join-Path $Path 'work'
    New-Item -Path $bare -ItemType Directory | Out-Null
    New-Item -Path $work -ItemType Directory | Out-Null

    Invoke-Git -- init --bare --quiet $bare | Out-Null

    $prev = Get-Location
    try {
        Set-Location -LiteralPath $work
        Invoke-Git -- init --quiet | Out-Null
        Invoke-Git -- config user.email 'motw-test@local' | Out-Null
        Invoke-Git -- config user.name  'motw-test'       | Out-Null
        Invoke-Git -- config commit.gpgsign false         | Out-Null

        $exts = '.txt','.lnk','.hta','.js','.vbs','.ps1','.bat','.wsf','.cmd','.scr'
        foreach ($ext in $exts) {
            $p    = New-MarkerFileBytes -Extension $ext -Comment 'git-fixture'
            $name = "fixture$ext"
            [System.IO.File]::WriteAllBytes((Join-Path $work $name), $p.Bytes)
        }

        Invoke-Git -- add . | Out-Null
        Invoke-Git -- commit --quiet -m 'seed benign marker fixtures' | Out-Null
        Invoke-Git -- remote add origin $bare | Out-Null
        Invoke-Git -- push --quiet -u origin HEAD:refs/heads/main | Out-Null
    } finally {
        Set-Location $prev
    }

    $bare
}

function Get-MotwPathsInTree {
    <#
    .SYNOPSIS
        Walk a directory skipping .git internals, return one row per file
        with MOTW observed / not observed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$DeliveryLabel
    )
    $rootFull = (Resolve-Path -LiteralPath $Root).ProviderPath
    Get-ChildItem -LiteralPath $rootFull -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' -and $_.Name -ne '.gitattributes' } |
        ForEach-Object {
            $motw = Get-FileMotw -Path $_.FullName
            $rel = $_.FullName.Substring($rootFull.Length).TrimStart('\','/')
            [pscustomobject]@{
                Delivery = $DeliveryLabel
                Path     = $rel
                HasMotw  = [bool]$motw
                HostUrl  = if ($motw) { $motw.HostUrl } else { $null }
                ZoneName = if ($motw) { $motw.ZoneName } else { $null }
            }
        }
}

function Invoke-GitCloneAndScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$CloneDir
    )
    if (Test-Path -LiteralPath $CloneDir) { Remove-Item -LiteralPath $CloneDir -Recurse -Force }
    Invoke-Git -- clone --quiet $Source $CloneDir | Out-Null
    Get-MotwPathsInTree -Root $CloneDir -DeliveryLabel 'git-clone'
}

function Test-GitMotwPropagation {
    <#
    .SYNOPSIS
        Clone a repo and scan for MOTW.  Optionally also scan a
        browser-downloaded ZIP archive of the same repo for comparison.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$WorkDir,
        [string]$DownloadedArchive,
        [string[]]$Extractors
    )

    if (-not (Test-Path -LiteralPath $WorkDir)) {
        New-Item -Path $WorkDir -ItemType Directory | Out-Null
    }

    $results = [System.Collections.Generic.List[object]]::new()

    $cloneDir = Join-Path $WorkDir 'clone'
    $cloneRows = Invoke-GitCloneAndScan -Source $Source -CloneDir $cloneDir
    foreach ($r in $cloneRows) { $results.Add($r) }

    if ($DownloadedArchive) {
        if (-not (Test-Path -LiteralPath $DownloadedArchive)) {
            throw "Downloaded archive not found: $DownloadedArchive"
        }

        $motw = Get-FileMotw -Path $DownloadedArchive
        $results.Add([pscustomobject]@{
            Delivery = 'download-archive:outer'
            Path     = Split-Path $DownloadedArchive -Leaf
            HasMotw  = [bool]$motw
            HostUrl  = if ($motw) { $motw.HostUrl } else { $null }
            ZoneName = if ($motw) { $motw.ZoneName } else { $null }
        })

        $ext = if ($Extractors -and $Extractors.Count -gt 0) { $Extractors } else { Get-AvailableExtractors $DownloadedArchive }
        foreach ($method in $ext) {
            $handle = $null
            try {
                $handle = Expand-ContainerToTemp -ContainerPath $DownloadedArchive -Method $method
                $innerRows = Get-MotwPathsInTree -Root $handle.Path -DeliveryLabel "download-archive:$method"
                foreach ($r in $innerRows) { $results.Add($r) }
            } finally {
                if ($handle) { Dismount-ContainerHandle -Handle $handle }
            }
        }
    }

    $results.ToArray()
}

Export-ModuleMember -Function `
    Invoke-Git, `
    New-GitMotwFixtureRepo, `
    Get-MotwPathsInTree, `
    Invoke-GitCloneAndScan, `
    Test-GitMotwPropagation
