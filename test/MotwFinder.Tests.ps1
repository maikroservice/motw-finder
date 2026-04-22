#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '../psm/MotwFinder.psm1'
    Import-Module $modulePath -Force
}

Describe 'ConvertFrom-ZoneIdentifier' {
    It 'parses a full zone identifier' {
        $raw = "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://example.com/`r`nHostUrl=https://cdn.example.com/file.zip`r`n"
        $info = ConvertFrom-ZoneIdentifier -Text $raw
        $info.ZoneId      | Should -Be 3
        $info.ZoneName    | Should -Be 'Internet'
        $info.ReferrerUrl | Should -Be 'https://example.com/'
        $info.HostUrl     | Should -Be 'https://cdn.example.com/file.zip'
    }

    It 'parses a minimal zone identifier' {
        $info = ConvertFrom-ZoneIdentifier -Text "[ZoneTransfer]`nZoneId=2`n"
        $info.ZoneId      | Should -Be 2
        $info.ZoneName    | Should -Be 'Trusted'
        $info.ReferrerUrl | Should -BeNullOrEmpty
        $info.HostUrl     | Should -BeNullOrEmpty
    }

    It 'ignores unknown keys and tolerates whitespace around = ' {
        $info = ConvertFrom-ZoneIdentifier -Text "[ZoneTransfer]`n  ZoneId = 1 `nLastWriterPackageFamilyName=foo`n"
        $info.ZoneId | Should -Be 1
    }

    It 'throws on empty input' {
        { ConvertFrom-ZoneIdentifier -Text '' } | Should -Throw
    }

    It 'throws when ZoneId is missing' {
        { ConvertFrom-ZoneIdentifier -Text "[ZoneTransfer]`nHostUrl=https://x/`n" } | Should -Throw
    }

    It 'throws when ZoneId is not an integer' {
        { ConvertFrom-ZoneIdentifier -Text "[ZoneTransfer]`nZoneId=abc`n" } | Should -Throw
    }
}

Describe 'Get-ZoneName' {
    It 'maps <Zid> to <Name>' -TestCases @(
        @{ Zid = 0; Name = 'Local' }
        @{ Zid = 1; Name = 'Intranet' }
        @{ Zid = 2; Name = 'Trusted' }
        @{ Zid = 3; Name = 'Internet' }
        @{ Zid = 4; Name = 'Untrusted' }
    ) {
        Get-ZoneName -ZoneId $Zid | Should -Be $Name
    }

    It 'labels unknown zones' {
        Get-ZoneName -ZoneId 99 | Should -Be 'Unknown(99)'
    }
}

Describe 'Find-Motw (integration)' {
    BeforeEach {
        $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("motw_" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:tmp -ItemType Directory | Out-Null
    }
    AfterEach {
        if ($script:tmp -and (Test-Path -LiteralPath $script:tmp)) {
            Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns only files that have a parseable Zone.Identifier' {
        $script:a = Join-Path $script:tmp 'a.exe'
        $script:b = Join-Path $script:tmp 'b.txt'
        $sub = Join-Path $script:tmp 'sub'
        New-Item -Path $sub -ItemType Directory | Out-Null
        $script:c = Join-Path $sub 'c.docx'
        Set-Content -LiteralPath $script:a -Value 'x'
        Set-Content -LiteralPath $script:b -Value 'x'
        Set-Content -LiteralPath $script:c -Value 'x'

        Mock -ModuleName MotwFinder Get-FileMotw { $null }
        Mock -ModuleName MotwFinder Get-FileMotw -ParameterFilter { $Path -eq $script:a } -MockWith {
            [pscustomobject]@{ ZoneId = 3; ZoneName = 'Internet'; HostUrl = 'https://dl/file'; ReferrerUrl = $null }
        }
        Mock -ModuleName MotwFinder Get-FileMotw -ParameterFilter { $Path -eq $script:c } -MockWith {
            [pscustomobject]@{ ZoneId = 4; ZoneName = 'Untrusted'; HostUrl = $null; ReferrerUrl = $null }
        }

        $results = Find-Motw -Path $script:tmp | Sort-Object Path
        $results.Count          | Should -Be 2
        $results[0].Path        | Should -Be $script:a
        $results[0].ZoneId      | Should -Be 3
        $results[0].HostUrl     | Should -Be 'https://dl/file'
        $results[1].Path        | Should -Be $script:c
        $results[1].ZoneId      | Should -Be 4
    }

    It 'filters by -Since using LastWriteTime' {
        $script:old = Join-Path $script:tmp 'old.exe'
        $script:new = Join-Path $script:tmp 'new.exe'
        Set-Content -LiteralPath $script:old -Value 'x'
        Set-Content -LiteralPath $script:new -Value 'x'
        (Get-Item -LiteralPath $script:old).LastWriteTime = (Get-Date).AddDays(-7)

        Mock -ModuleName MotwFinder Get-FileMotw {
            [pscustomobject]@{ ZoneId = 3; ZoneName = 'Internet'; HostUrl = $null; ReferrerUrl = $null }
        }

        $since = (Get-Date).AddDays(-1)
        $results = @(Find-Motw -Path $script:tmp -Since $since)
        $results.Count   | Should -Be 1
        $results[0].Path | Should -Be $script:new
    }

    It 'returns nothing when no files are marked' {
        Set-Content -LiteralPath (Join-Path $script:tmp 'clean.txt') -Value 'x'
        Mock -ModuleName MotwFinder Get-FileMotw { $null }

        $results = @(Find-Motw -Path $script:tmp)
        $results.Count | Should -Be 0
    }
}
