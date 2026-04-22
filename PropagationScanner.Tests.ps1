#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'PropagationScanner.psm1') -Force
}

Describe 'Test-OuterMotwPropagation' {
    BeforeEach {
        $script:drop = Join-Path ([System.IO.Path]::GetTempPath()) ("drop_" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:drop -ItemType Directory | Out-Null
    }
    AfterEach {
        if ($script:drop -and (Test-Path -LiteralPath $script:drop)) {
            Remove-Item -LiteralPath $script:drop -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports PASS when expected MOTW matches observed' {
        $fn = 'marker.txt'
        Set-Content -LiteralPath (Join-Path $script:drop $fn) -Value 'x'
        Mock -ModuleName PropagationScanner Get-FileMotw {
            [pscustomobject]@{ ZoneId = 3; ZoneName = 'Internet'; HostUrl = 'https://example/'; ReferrerUrl = $null }
        }
        $expected = @([pscustomobject]@{ FileName = $fn; ExpectMotw = $true })
        $rows = @(Test-OuterMotwPropagation -DropDir $script:drop -Expected $expected)
        $rows.Count        | Should -Be 1
        $rows[0].Status    | Should -Be 'PASS'
        $rows[0].ActualMotw | Should -BeTrue
        $rows[0].HostUrl   | Should -Be 'https://example/'
    }

    It 'reports FAIL when expected MOTW is missing' {
        $fn = 'marker.lnk'
        Set-Content -LiteralPath (Join-Path $script:drop $fn) -Value 'x'
        Mock -ModuleName PropagationScanner Get-FileMotw { $null }
        $expected = @([pscustomobject]@{ FileName = $fn; ExpectMotw = $true })
        $rows = @(Test-OuterMotwPropagation -DropDir $script:drop -Expected $expected)
        $rows[0].Status | Should -Be 'FAIL'
    }

    It 'reports MISSING when the file was never dropped' {
        Mock -ModuleName PropagationScanner Get-FileMotw { $null }
        $expected = @([pscustomobject]@{ FileName = 'ghost.txt'; ExpectMotw = $true })
        $rows = @(Test-OuterMotwPropagation -DropDir $script:drop -Expected $expected)
        $rows[0].Status | Should -Be 'MISSING'
    }
}

Describe 'Test-InnerMotwPropagation' {
    BeforeEach {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) ("innerwork_" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:work -ItemType Directory | Out-Null

        # Build a fake extracted directory we can hand to the mocked extractor
        $script:extract = Join-Path $script:work 'extract'
        New-Item -Path $script:extract -ItemType Directory | Out-Null
        Set-Content -LiteralPath (Join-Path $script:extract 'inner.lnk') -Value 'x'

        $script:container = Join-Path $script:work 'container.zip'
        Set-Content -LiteralPath $script:container -Value 'zipbytes'

        Mock -ModuleName PropagationScanner Expand-ContainerToTemp {
            @{ Path = $script:extract; IsMount = $false; ImagePath = $null }
        }
        Mock -ModuleName PropagationScanner Dismount-ContainerHandle { }
    }
    AfterEach {
        if ($script:work -and (Test-Path -LiteralPath $script:work)) {
            Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'PASSes when MOTW propagates and was expected' {
        Mock -ModuleName PropagationScanner Get-FileMotw {
            [pscustomobject]@{ ZoneId = 3; ZoneName = 'Internet'; HostUrl = $null; ReferrerUrl = $null }
        }
        $inner = @(@{ Path = 'inner.lnk'; ExpectMotw = $true; Reason = 'should propagate' })
        $rows  = @(Test-InnerMotwPropagation -ContainerPath $script:container -InnerSpec $inner -Extractors @('Expand-Archive'))
        $rows.Count       | Should -Be 1
        $rows[0].Status   | Should -Be 'PASS'
        $rows[0].Extractor | Should -Be 'Expand-Archive'
    }

    It 'FAILs when MOTW was expected but propagation did not occur' {
        Mock -ModuleName PropagationScanner Get-FileMotw { $null }
        $inner = @(@{ Path = 'inner.lnk'; ExpectMotw = $true; Reason = 'should propagate' })
        $rows  = @(Test-InnerMotwPropagation -ContainerPath $script:container -InnerSpec $inner -Extractors @('Expand-Archive'))
        $rows[0].Status | Should -Be 'FAIL'
    }

    It 'PASSes when non-propagation is the expected bypass shape' {
        Mock -ModuleName PropagationScanner Get-FileMotw { $null }
        $inner = @(@{ Path = 'inner.lnk'; ExpectMotw = $false; Reason = 'Expand-Archive never propagates' })
        $rows  = @(Test-InnerMotwPropagation -ContainerPath $script:container -InnerSpec $inner -Extractors @('Expand-Archive'))
        $rows[0].Status | Should -Be 'PASS'
    }

    It 'runs once per extractor and attributes results' {
        Mock -ModuleName PropagationScanner Get-FileMotw { $null }
        $inner = @(@{ Path = 'inner.lnk'; ExpectMotw = $false })
        $rows  = @(Test-InnerMotwPropagation -ContainerPath $script:container -InnerSpec $inner -Extractors @('Expand-Archive','7z'))
        $rows.Count | Should -Be 2
        ($rows.Extractor | Sort-Object) | Should -Be @('7z','Expand-Archive')
    }
}

Describe 'Invoke-MotwPropagationScan end-to-end' {
    BeforeEach {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) ("e2e_" + [guid]::NewGuid().ToString('N'))
        $script:drop = Join-Path $script:work 'drop'
        $script:ex   = Join-Path $script:work 'extract'
        New-Item -Path $script:drop -ItemType Directory -Force | Out-Null
        New-Item -Path $script:ex   -ItemType Directory -Force | Out-Null

        Set-Content -LiteralPath (Join-Path $script:drop 'marker.txt') -Value 'x'
        Set-Content -LiteralPath (Join-Path $script:drop 'container.zip') -Value 'z'
        Set-Content -LiteralPath (Join-Path $script:ex   'inner.lnk')  -Value 'x'

        $expected = @(
            @{ FileName = 'marker.txt';    ExpectMotw = $true;  Expected = @{} }
            @{ FileName = 'container.zip'; ExpectMotw = $true;  Expected = @{ InnerFiles = @(@{ Path = 'inner.lnk'; ExpectMotw = $false; Reason = 'bypass' }) } }
        )
        $script:mf = Join-Path $script:work 'expected.json'
        $expected | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:mf

        Mock -ModuleName PropagationScanner Expand-ContainerToTemp {
            @{ Path = $script:ex; IsMount = $false; ImagePath = $null }
        }
        Mock -ModuleName PropagationScanner Dismount-ContainerHandle { }
        Mock -ModuleName PropagationScanner Get-AvailableExtractors { @('Expand-Archive') }
    }
    AfterEach {
        if ($script:work -and (Test-Path -LiteralPath $script:work)) {
            Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'produces one outer row per item plus one inner row per (container, extractor, inner)' {
        Mock -ModuleName PropagationScanner Get-FileMotw {
            param($Path)
            if ((Split-Path $Path -Leaf) -eq 'inner.lnk') { return $null }  # bypass
            [pscustomobject]@{ ZoneId = 3; ZoneName = 'Internet'; HostUrl = $null; ReferrerUrl = $null }
        }
        $rows = @(Invoke-MotwPropagationScan -DropDir $script:drop -ExpectedManifest $script:mf -Extractors @('Expand-Archive'))
        $outer = @($rows | Where-Object Section -eq 'outer')
        $inner = @($rows | Where-Object Section -eq 'inner')
        $outer.Count | Should -Be 2
        $inner.Count | Should -Be 1
        ($outer | Where-Object Status -ne 'PASS') | Should -BeNullOrEmpty
        $inner[0].Status | Should -Be 'PASS'   # bypass is the expected shape here
    }
}
