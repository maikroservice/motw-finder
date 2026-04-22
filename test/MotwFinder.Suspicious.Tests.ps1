#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot 'MotwFinder.psm1'
    Import-Module $modulePath -Force
}

Describe 'Test-SuspiciousMotwUrl' {
    It 'returns $null for an empty or null URL' {
        Test-SuspiciousMotwUrl -Url ''    | Should -BeNullOrEmpty
        Test-SuspiciousMotwUrl -Url $null | Should -BeNullOrEmpty
    }

    It 'returns $null for an ordinary HTTPS URL' {
        Test-SuspiciousMotwUrl -Url 'https://www.microsoft.com/en-us/download/foo.msi' | Should -BeNullOrEmpty
    }

    It 'flags Discord CDN' {
        Test-SuspiciousMotwUrl -Url 'https://cdn.discordapp.com/attachments/123/456/payload.iso' | Should -Match 'Discord'
    }

    It 'flags raw GitHub content' {
        Test-SuspiciousMotwUrl -Url 'https://raw.githubusercontent.com/x/y/main/loader.js' | Should -Match 'GitHub'
    }

    It 'flags URL shorteners' {
        Test-SuspiciousMotwUrl -Url 'https://bit.ly/abc'      | Should -Match 'shortener'
        Test-SuspiciousMotwUrl -Url 'https://tinyurl.com/abc' | Should -Match 'shortener'
    }

    It 'flags bare IPv4 hosts' {
        Test-SuspiciousMotwUrl -Url 'http://185.220.100.1/payload.exe' | Should -Match 'IP'
    }

    It 'flags file:// URLs' {
        Test-SuspiciousMotwUrl -Url 'file://server/share/x.lnk' | Should -Match 'file'
    }

    It 'flags UNC paths' {
        Test-SuspiciousMotwUrl -Url '\\attacker\share\x.lnk' | Should -Match -RegularExpression '(?i)UNC|file'
    }
}

Describe 'Get-MotwFindings rule engine' {
    BeforeAll {
        function New-ParsedInfo {
            param([int]$ZoneId = 3, [string]$HostUrl, [string]$ReferrerUrl)
            [pscustomobject]@{
                ZoneId      = $ZoneId
                ZoneName    = Get-ZoneName -ZoneId $ZoneId
                HostUrl     = $HostUrl
                ReferrerUrl = $ReferrerUrl
            }
        }
    }

    Context 'DangerousExtensionFromInternet' {
        It 'flags .<ext> at ZoneId=3 as High' -TestCases @(
            @{ ext = 'lnk' }
            @{ ext = 'hta' }
            @{ ext = 'wsf' }
            @{ ext = 'chm' }
            @{ ext = 'js'  }
            @{ ext = 'vbs' }
            @{ ext = 'ps1' }
            @{ ext = 'scr' }
        ) {
            $parsed = New-ParsedInfo -ZoneId 3 -HostUrl 'https://example.com/'
            $findings = Get-MotwFindings -Path "C:\x\payload.$ext" -Raw 'x' -Parsed $parsed
            $hit = $findings | Where-Object Rule -eq 'DangerousExtensionFromInternet'
            $hit                 | Should -Not -BeNullOrEmpty
            $hit.Severity        | Should -Be 'High'
        }

        It 'does not flag a .pdf from the Internet zone' {
            $parsed = New-ParsedInfo -ZoneId 3 -HostUrl 'https://example.com/'
            $findings = Get-MotwFindings -Path 'C:\x\report.pdf' -Raw 'x' -Parsed $parsed
            ($findings | Where-Object Rule -eq 'DangerousExtensionFromInternet') | Should -BeNullOrEmpty
        }

        It 'does not flag a .lnk that is not Internet-zone' {
            $parsed = New-ParsedInfo -ZoneId 1 -HostUrl 'https://intranet/'
            $findings = Get-MotwFindings -Path 'C:\x\payload.lnk' -Raw 'x' -Parsed $parsed
            ($findings | Where-Object Rule -eq 'DangerousExtensionFromInternet') | Should -BeNullOrEmpty
        }
    }

    Context 'SuspiciousOrigin' {
        It 'flags a Discord CDN HostUrl as Medium' {
            $parsed = New-ParsedInfo -ZoneId 3 -HostUrl 'https://cdn.discordapp.com/a/b/x.iso'
            $findings = Get-MotwFindings -Path 'C:\x\x.iso' -Raw 'x' -Parsed $parsed
            $hit = $findings | Where-Object Rule -eq 'SuspiciousOrigin'
            $hit.Severity | Should -Be 'Medium'
            $hit.Reason   | Should -Match 'Discord'
        }

        It 'flags a suspicious ReferrerUrl even when HostUrl is benign' {
            $parsed = New-ParsedInfo -ZoneId 3 -HostUrl 'https://example.com/' -ReferrerUrl 'https://bit.ly/abc'
            $findings = Get-MotwFindings -Path 'C:\x\x.zip' -Raw 'x' -Parsed $parsed
            ($findings | Where-Object Rule -eq 'SuspiciousOrigin') | Should -Not -BeNullOrEmpty
        }
    }

    Context 'UnparseableZoneIdentifier' {
        It 'flags a non-null Raw + null Parsed as Medium' {
            $findings = Get-MotwFindings -Path 'C:\x\weird.bin' -Raw 'garbage bytes' -Parsed $null
            $hit = $findings | Where-Object Rule -eq 'UnparseableZoneIdentifier'
            $hit.Severity | Should -Be 'Medium'
        }
    }

    Context 'MissingProvenance' {
        It 'flags ZoneId=3 with no HostUrl and no ReferrerUrl as Info' {
            $parsed = New-ParsedInfo -ZoneId 3
            $findings = Get-MotwFindings -Path 'C:\x\x.zip' -Raw 'x' -Parsed $parsed
            $hit = $findings | Where-Object Rule -eq 'MissingProvenance'
            $hit.Severity | Should -Be 'Info'
        }

        It 'does not flag MissingProvenance when HostUrl is present' {
            $parsed = New-ParsedInfo -ZoneId 3 -HostUrl 'https://example.com/'
            $findings = Get-MotwFindings -Path 'C:\x\x.zip' -Raw 'x' -Parsed $parsed
            ($findings | Where-Object Rule -eq 'MissingProvenance') | Should -BeNullOrEmpty
        }
    }

    It 'can emit multiple findings for one file' {
        $parsed = New-ParsedInfo -ZoneId 3 -HostUrl 'https://cdn.discordapp.com/a/b/x.lnk'
        $findings = @(Get-MotwFindings -Path 'C:\x\payload.lnk' -Raw 'x' -Parsed $parsed)
        $rules = $findings.Rule | Sort-Object -Unique
        $rules | Should -Contain 'DangerousExtensionFromInternet'
        $rules | Should -Contain 'SuspiciousOrigin'
    }

    It 'emits nothing for a clean Intranet-zone Office doc' {
        $parsed = New-ParsedInfo -ZoneId 1 -HostUrl 'https://intranet.corp/doc.docx'
        $findings = @(Get-MotwFindings -Path 'C:\x\doc.docx' -Raw 'x' -Parsed $parsed)
        $findings.Count | Should -Be 0
    }
}

Describe 'Find-SuspiciousMotw (integration)' {
    BeforeEach {
        $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("motw_sus_" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:tmp -ItemType Directory | Out-Null
    }
    AfterEach {
        if ($script:tmp -and (Test-Path -LiteralPath $script:tmp)) {
            Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'surfaces a high-severity finding for a .lnk smuggled via Discord' {
        $script:bad = Join-Path $script:tmp 'invoice.lnk'
        $script:clean = Join-Path $script:tmp 'readme.txt'
        Set-Content -LiteralPath $script:bad -Value 'x'
        Set-Content -LiteralPath $script:clean -Value 'x'

        Mock -ModuleName MotwFinder Read-MotwStream { $null }
        Mock -ModuleName MotwFinder Read-MotwStream -ParameterFilter { $Path -eq $script:bad } -MockWith {
            "[ZoneTransfer]`nZoneId=3`nHostUrl=https://cdn.discordapp.com/a/b/invoice.iso`n"
        }
        Mock -ModuleName MotwFinder Read-MotwStream -ParameterFilter { $Path -eq $script:clean } -MockWith {
            "[ZoneTransfer]`nZoneId=1`nHostUrl=https://intranet/`n"
        }

        $findings = @(Find-SuspiciousMotw -Path $script:tmp)
        $byRule = $findings | Group-Object Rule -AsHashTable -AsString
        $byRule['DangerousExtensionFromInternet'] | Should -Not -BeNullOrEmpty
        $byRule['SuspiciousOrigin']               | Should -Not -BeNullOrEmpty
        $findings.Path | Should -Not -Contain $script:clean
    }

    It 'surfaces Unparseable when stream bytes exist but fail to parse' {
        $script:weird = Join-Path $script:tmp 'weird.bin'
        Set-Content -LiteralPath $script:weird -Value 'x'

        Mock -ModuleName MotwFinder Read-MotwStream { $null }
        Mock -ModuleName MotwFinder Read-MotwStream -ParameterFilter { $Path -eq $script:weird } -MockWith {
            'not a valid zone identifier'
        }

        $findings = @(Find-SuspiciousMotw -Path $script:tmp)
        $findings.Count        | Should -Be 1
        $findings[0].Rule      | Should -Be 'UnparseableZoneIdentifier'
        $findings[0].Severity  | Should -Be 'Medium'
    }

    It 'returns nothing when no files carry Zone.Identifier' {
        Set-Content -LiteralPath (Join-Path $script:tmp 'plain.txt') -Value 'x'
        Mock -ModuleName MotwFinder Read-MotwStream { $null }
        @(Find-SuspiciousMotw -Path $script:tmp).Count | Should -Be 0
    }
}
