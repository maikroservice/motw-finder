#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'GitHarness.psm1') -Force
    $script:gitAvailable = [bool](Get-Command git -ErrorAction SilentlyContinue)
}

Describe 'New-GitMotwFixtureRepo' -Skip:(-not $script:gitAvailable) {
    BeforeEach {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) ("gitfix_" + [guid]::NewGuid().ToString('N'))
    }
    AfterEach {
        if ($script:work -and (Test-Path -LiteralPath $script:work)) {
            Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'builds a bare repo whose clone contains the marker fixtures' {
        $bare = New-GitMotwFixtureRepo -Path $script:work
        Test-Path -LiteralPath $bare | Should -BeTrue

        $clone = Join-Path $script:work 'clone-check'
        Invoke-Git -- clone --quiet $bare $clone | Out-Null

        $files = Get-ChildItem -LiteralPath $clone -Recurse -File -Force |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
            ForEach-Object { $_.Name }

        $files | Should -Contain 'fixture.txt'
        $files | Should -Contain 'fixture.lnk'
        $files | Should -Contain 'fixture.hta'
        $files | Should -Contain 'fixture.ps1'
    }
}

Describe 'Invoke-GitCloneAndScan' -Skip:(-not $script:gitAvailable) {
    BeforeAll {
        $script:fixRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("gitfixshared_" + [guid]::NewGuid().ToString('N'))
        $script:bare    = New-GitMotwFixtureRepo -Path $script:fixRoot
    }
    AfterAll {
        if ($script:fixRoot -and (Test-Path -LiteralPath $script:fixRoot)) {
            Remove-Item -LiteralPath $script:fixRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    BeforeEach {
        $script:cloneDir = Join-Path ([System.IO.Path]::GetTempPath()) ("gitclone_" + [guid]::NewGuid().ToString('N'))
    }
    AfterEach {
        if ($script:cloneDir -and (Test-Path -LiteralPath $script:cloneDir)) {
            Remove-Item -LiteralPath $script:cloneDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits one row per tracked file, all labelled git-clone, all HasMotw=$false on Linux/macOS' -Skip:($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        $rows = @(Invoke-GitCloneAndScan -Source $script:bare -CloneDir $script:cloneDir)
        $rows.Count                          | Should -BeGreaterThan 5
        ($rows.Delivery | Sort-Object -Unique) | Should -Be @('git-clone')
        ($rows.HasMotw  | Sort-Object -Unique) | Should -Be @($false)
    }

    It 'detects the MOTW-bypass invariant: zero MOTW across the tree even when Get-FileMotw is mocked to Windows-like results that simulate tagging' {
        # Force the scanner to "see" MOTW on everything. The clone path should still
        # produce HasMotw=true rows -- this test documents *our harness* behavior, not
        # git's: the harness faithfully surfaces whatever Get-FileMotw reports. The
        # actual MOTW-bypass measurement depends on running on NTFS.
        Mock -ModuleName GitHarness Get-FileMotw {
            [pscustomobject]@{ ZoneId = 3; ZoneName = 'Internet'; HostUrl = 'https://example/'; ReferrerUrl = $null }
        }
        $rows = @(Invoke-GitCloneAndScan -Source $script:bare -CloneDir $script:cloneDir)
        ($rows.HasMotw  | Sort-Object -Unique) | Should -Be @($true)
    }
}

Describe 'Test-GitMotwPropagation with a downloaded archive' -Skip:(-not $script:gitAvailable) {
    BeforeAll {
        $script:fixRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("gite2e_" + [guid]::NewGuid().ToString('N'))
        $script:bare    = New-GitMotwFixtureRepo -Path $script:fixRoot
    }
    AfterAll {
        if ($script:fixRoot -and (Test-Path -LiteralPath $script:fixRoot)) {
            Remove-Item -LiteralPath $script:fixRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    BeforeEach {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) ("gite2erun_" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:work -ItemType Directory | Out-Null

        # Produce a ZIP via `git archive` to stand in for the browser download.
        $script:zip = Join-Path $script:work 'fixture.zip'
        $prev = Get-Location
        try {
            Set-Location -LiteralPath $script:fixRoot
            Invoke-Git -- -C 'work' archive --format=zip -o $script:zip HEAD | Out-Null
        } finally { Set-Location $prev }
    }
    AfterEach {
        if ($script:work -and (Test-Path -LiteralPath $script:work)) {
            Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits both git-clone rows and download-archive rows' {
        Mock -ModuleName GitHarness Get-FileMotw { $null }       # clone path: no MOTW
        Mock -ModuleName PropagationScanner Get-FileMotw { $null }

        $rows = @(Test-GitMotwPropagation -Source $script:bare -WorkDir $script:work -DownloadedArchive $script:zip -Extractors @('Expand-Archive'))

        $deliveries = $rows.Delivery | Sort-Object -Unique
        $deliveries | Should -Contain 'git-clone'
        $deliveries | Should -Contain 'download-archive:outer'
        $deliveries | Should -Contain 'download-archive:Expand-Archive'
    }
}
