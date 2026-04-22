#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../psm/MotwFinder.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../psm/ZoneIdTampering.psm1') -Force
}

Describe 'Get-ZoneIdTamperingVariants' {
    It 'returns at least the known-dangerous variants' {
        $names = (Get-ZoneIdTamperingVariants).Name
        $names | Should -Contain 'Empty'
        $names | Should -Contain 'MissingZoneId'
        $names | Should -Contain 'ZoneIdZero'
        $names | Should -Contain 'NonIntegerZoneId'
        $names | Should -Contain 'PaddedCve202244698'
        $names | Should -Contain 'Utf16LeBom'
    }
}

Describe 'New-TamperedZoneIdentifierBytes' {
    It 'produces bytes for every known variant' {
        foreach ($v in (Get-ZoneIdTamperingVariants)) {
            $bytes = New-TamperedZoneIdentifierBytes -Variant $v.Name
            $bytes | Should -BeOfType byte
        }
    }

    It 'throws for an unknown variant' {
        { New-TamperedZoneIdentifierBytes -Variant 'NoSuchThing' } | Should -Throw
    }

    It 'Empty variant returns zero bytes' {
        (New-TamperedZoneIdentifierBytes -Variant 'Empty').Length | Should -Be 0
    }

    It 'Utf16LeBom starts with FF FE' {
        $b = New-TamperedZoneIdentifierBytes -Variant 'Utf16LeBom'
        $b[0] | Should -Be 0xFF
        $b[1] | Should -Be 0xFE
    }

    It 'PaddedCve202244698 is materially larger than a normal stream' {
        (New-TamperedZoneIdentifierBytes -Variant 'PaddedCve202244698').Length | Should -BeGreaterThan 1000
    }
}

Describe 'Parser response matrix (variant x ConvertFrom-ZoneIdentifier)' {
    $cases = @(
        @{ Variant = 'Empty';              Expect = 'throw' }
        @{ Variant = 'WhitespaceOnly';     Expect = 'throw' }
        @{ Variant = 'MissingZoneId';      Expect = 'throw' }
        @{ Variant = 'MissingHeader';      Expect = 'parse' }
        @{ Variant = 'ZoneIdZero';         Expect = 'parse' }
        @{ Variant = 'NonIntegerZoneId';   Expect = 'throw' }
        @{ Variant = 'NegativeZoneId';     Expect = 'parse' }
        @{ Variant = 'PaddedCve202244698'; Expect = 'parse' }
        @{ Variant = 'ExtraKeys';          Expect = 'parse' }
        @{ Variant = 'Utf16LeBom';         Expect = 'throw' }
        @{ Variant = 'Utf8Bom';            Expect = 'parse' }
        @{ Variant = 'HugeHostUrl';        Expect = 'parse' }
        @{ Variant = 'TrailingGarbage';    Expect = 'parse' }
    )
    It 'matches the declared ParseExpectation for <Variant>' -TestCases $cases {
        $bytes = New-TamperedZoneIdentifierBytes -Variant $Variant
        $text  = [System.Text.Encoding]::UTF8.GetString($bytes)
        if ($Expect -eq 'throw') {
            { ConvertFrom-ZoneIdentifier -Text $text } | Should -Throw
        } else {
            $result = ConvertFrom-ZoneIdentifier -Text $text
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'New-TamperedFixtureFile on non-Windows (sidecar fallback)' {
    BeforeEach {
        $script:work = Join-Path ([System.IO.Path]::GetTempPath()) ("tamper_" + [guid]::NewGuid().ToString('N'))
        New-Item -Path $script:work -ItemType Directory | Out-Null
    }
    AfterEach {
        if ($script:work -and (Test-Path -LiteralPath $script:work)) {
            Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'creates the marker file and the sidecar Zone.Identifier' -Skip:($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        $target = Join-Path $script:work 'marker-empty.txt'
        New-TamperedFixtureFile -Path $target -Variant 'Empty' | Out-Null

        Test-Path -LiteralPath $target                              | Should -BeTrue
        Test-Path -LiteralPath "${target}:Zone.Identifier"          | Should -BeTrue
        (Get-Item -LiteralPath "${target}:Zone.Identifier").Length  | Should -Be 0
    }

    It 'writes the expected padded shape for CVE-2022-44698 variant' -Skip:($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        $target = Join-Path $script:work 'marker-padded.txt'
        New-TamperedFixtureFile -Path $target -Variant 'PaddedCve202244698' | Out-Null
        (Get-Item -LiteralPath "${target}:Zone.Identifier").Length  | Should -BeGreaterThan 1000
    }
}
