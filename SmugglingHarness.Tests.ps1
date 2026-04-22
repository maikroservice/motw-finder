#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'SmugglingHarness.psm1') -Force
}

Describe 'AES-GCM round-trip' -Skip:(-not (Test-AesGcmAvailable)) {
    It 'encrypts and decrypts back to the same plaintext' {
        $key   = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
        $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $plain = [System.Text.Encoding]::UTF8.GetBytes('MOTW-TEST-PAYLOAD-7b3d hello world')

        $ct = Invoke-AesGcmEncrypt -Key $key -Nonce $nonce -Plaintext $plain
        $ct.Length | Should -Be ($plain.Length + 16)

        $out = Invoke-AesGcmDecrypt -Key $key -Nonce $nonce -CiphertextWithTag $ct
        [System.Text.Encoding]::UTF8.GetString($out) | Should -Be ([System.Text.Encoding]::UTF8.GetString($plain))
    }

    It 'detects tampering via the GCM tag' {
        $key   = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
        $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
        $plain = [System.Text.Encoding]::UTF8.GetBytes('hello')

        $ct = Invoke-AesGcmEncrypt -Key $key -Nonce $nonce -Plaintext $plain
        $ct[0] = [byte](($ct[0] -bxor 0xFF))  # flip a byte
        { Invoke-AesGcmDecrypt -Key $key -Nonce $nonce -CiphertextWithTag $ct } | Should -Throw
    }
}

Describe 'New-SmugglingHtmlBundle' -Skip:(-not (Test-AesGcmAvailable)) {
    BeforeAll {
        $script:items = @(
            [pscustomobject]@{
                FileName   = 'a.txt'
                Bytes      = [System.Text.Encoding]::UTF8.GetBytes('alpha')
                Mime       = 'text/plain'
                ExpectMotw = $true
                Expected   = @{}
            },
            [pscustomobject]@{
                FileName   = 'b.bin'
                Bytes      = [byte[]](1..64)
                Mime       = 'application/octet-stream'
                ExpectMotw = $true
                Expected   = @{}
            }
        )
    }

    It 'produces HTML with the template placeholders filled in' {
        $bundle = New-SmugglingHtmlBundle -Items $script:items
        $bundle.Html | Should -Not -Match '\{\{COUNT\}\}'
        $bundle.Html | Should -Not -Match '/\*__PAYLOAD_JSON__\*/'
        $bundle.Html | Should -Not -Match '/\*__KEY_B64__\*/'
        $bundle.Html | Should -Match '>Drop 2 test payloads<'
    }

    It 'emits an Expected manifest with one entry per item' {
        $bundle = New-SmugglingHtmlBundle -Items $script:items
        $bundle.Expected.Count | Should -Be 2
        $bundle.Expected[0].FileName | Should -Be 'a.txt'
        $bundle.Expected[1].SizeBytes | Should -Be 64
    }

    It 'embeds payloads that round-trip via AES-GCM back to the original bytes' {
        $bundle = New-SmugglingHtmlBundle -Items $script:items
        $keyBytes = [Convert]::FromBase64String($bundle.KeyB64)

        # Extract the JSON array fed to the browser.
        $m = [regex]::Match($bundle.Html, 'const BLOBS = (\[.*?\]);', 'Singleline')
        $m.Success | Should -BeTrue
        $blobs = $m.Groups[1].Value | ConvertFrom-Json

        for ($i = 0; $i -lt $script:items.Count; $i++) {
            $iv = [Convert]::FromBase64String($blobs[$i].iv)
            $ct = [Convert]::FromBase64String($blobs[$i].c)
            $plain = Invoke-AesGcmDecrypt -Key $keyBytes -Nonce $iv -CiphertextWithTag $ct
            $plain.Length       | Should -Be $script:items[$i].Bytes.Length
            (,$plain -join ',') | Should -Be ((,$script:items[$i].Bytes) -join ',')
        }
    }

    It 'uses a fresh key and fresh nonces on each invocation' {
        $b1 = New-SmugglingHtmlBundle -Items $script:items
        $b2 = New-SmugglingHtmlBundle -Items $script:items
        $b1.KeyB64 | Should -Not -Be $b2.KeyB64
    }
}

Describe 'Get-DefaultPayloadManifest' {
    It 'returns at least the Tier 1 core set with expected-MOTW flags' {
        $manifest = Get-DefaultPayloadManifest
        $manifest.Count | Should -BeGreaterThan 5
        ($manifest | Where-Object FileName -eq 'marker.txt')    | Should -Not -BeNullOrEmpty
        ($manifest | Where-Object FileName -eq 'marker.hta')    | Should -Not -BeNullOrEmpty
        ($manifest | Where-Object FileName -eq 'marker.docx')   | Should -Not -BeNullOrEmpty
        ($manifest | Where-Object FileName -eq 'marker.docm')   | Should -Not -BeNullOrEmpty
        ($manifest | Where-Object FileName -eq 'container.zip') | Should -Not -BeNullOrEmpty
    }

    It 'marks every item with ExpectMotw = true (browser should tag the outer drop)' {
        $manifest = Get-DefaultPayloadManifest
        $manifest | ForEach-Object { $_.ExpectMotw | Should -BeTrue }
    }
}
