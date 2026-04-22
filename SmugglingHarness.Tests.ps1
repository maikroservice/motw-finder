#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'SmugglingHarness.psm1') -Force
}

Describe 'AES-CBC primitive round-trip' {
    It 'encrypts and decrypts back to the same plaintext' {
        $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $key   = [byte[]]::new(32); $rng.GetBytes($key)
        $iv    = [byte[]]::new(16); $rng.GetBytes($iv)
        $rng.Dispose()
        $plain = [System.Text.Encoding]::UTF8.GetBytes('MOTW-TEST-PAYLOAD-7b3d hello world')

        $ct  = Invoke-AesCbcEncrypt -Key $key -InitVector $iv -Plaintext $plain
        $out = Invoke-AesCbcDecrypt -Key $key -InitVector $iv -Ciphertext $ct

        [System.Text.Encoding]::UTF8.GetString($out) | Should -Be ([System.Text.Encoding]::UTF8.GetString($plain))
    }
}

Describe 'Invoke-AesCbcHmacEncrypt / Decrypt (Encrypt-then-MAC)' {
    BeforeAll {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $script:aesKey = [byte[]]::new(32); $rng.GetBytes($script:aesKey)
        $script:macKey = [byte[]]::new(32); $rng.GetBytes($script:macKey)
        $script:iv     = [byte[]]::new(16); $rng.GetBytes($script:iv)
        $rng.Dispose()
        $script:plain  = [System.Text.Encoding]::UTF8.GetBytes('some secret payload')
    }

    It 'round-trips a plaintext via encrypt/decrypt' {
        $r   = Invoke-AesCbcHmacEncrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $script:iv -Plaintext $script:plain
        $out = Invoke-AesCbcHmacDecrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $script:iv -Ciphertext $r.Ciphertext -Tag $r.Tag
        [System.Text.Encoding]::UTF8.GetString($out) | Should -Be ([System.Text.Encoding]::UTF8.GetString($script:plain))
    }

    It 'rejects a tampered ciphertext' {
        $r = Invoke-AesCbcHmacEncrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $script:iv -Plaintext $script:plain
        $bad = [byte[]]::new($r.Ciphertext.Length)
        [Buffer]::BlockCopy($r.Ciphertext, 0, $bad, 0, $r.Ciphertext.Length)
        $bad[0] = [byte](($bad[0] -bxor 0xFF))
        { Invoke-AesCbcHmacDecrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $script:iv -Ciphertext $bad -Tag $r.Tag } |
            Should -Throw
    }

    It 'rejects a tampered IV' {
        $r = Invoke-AesCbcHmacEncrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $script:iv -Plaintext $script:plain
        $badIv = [byte[]]::new($script:iv.Length)
        [Buffer]::BlockCopy($script:iv, 0, $badIv, 0, $script:iv.Length)
        $badIv[0] = [byte](($badIv[0] -bxor 0xFF))
        { Invoke-AesCbcHmacDecrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $badIv -Ciphertext $r.Ciphertext -Tag $r.Tag } |
            Should -Throw
    }

    It 'rejects a wrong MAC key' {
        $r = Invoke-AesCbcHmacEncrypt -AesKey $script:aesKey -MacKey $script:macKey -InitVector $script:iv -Plaintext $script:plain
        $otherMac = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($otherMac)
        { Invoke-AesCbcHmacDecrypt -AesKey $script:aesKey -MacKey $otherMac -InitVector $script:iv -Ciphertext $r.Ciphertext -Tag $r.Tag } |
            Should -Throw
    }
}

Describe 'Test-HmacConstantTime' {
    It 'returns true for equal byte arrays' {
        $a = [byte[]](1,2,3,4)
        $b = [byte[]](1,2,3,4)
        Test-HmacConstantTime -A $a -B $b | Should -BeTrue
    }
    It 'returns false for different byte arrays' {
        Test-HmacConstantTime -A ([byte[]](1,2,3,4)) -B ([byte[]](1,2,3,5)) | Should -BeFalse
    }
    It 'returns false for different lengths without reading past the shorter' {
        Test-HmacConstantTime -A ([byte[]](1,2,3,4)) -B ([byte[]](1,2,3)) | Should -BeFalse
    }
}

Describe 'AES-GCM round-trip (PS7+ only)' -Skip:(-not (Test-AesGcmAvailable)) {
    It 'encrypts and decrypts back to the same plaintext' {
        $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $key   = [byte[]]::new(32); $rng.GetBytes($key)
        $nonce = [byte[]]::new(12); $rng.GetBytes($nonce)
        $rng.Dispose()
        $plain = [System.Text.Encoding]::UTF8.GetBytes('MOTW-TEST-PAYLOAD-7b3d hello world')

        $ct = Invoke-AesGcmEncrypt -Key $key -Nonce $nonce -Plaintext $plain
        $ct.Length | Should -Be ($plain.Length + 16)

        $out = Invoke-AesGcmDecrypt -Key $key -Nonce $nonce -CiphertextWithTag $ct
        [System.Text.Encoding]::UTF8.GetString($out) | Should -Be ([System.Text.Encoding]::UTF8.GetString($plain))
    }
}

Describe 'New-SmugglingHtmlBundle (default CbcHmac)' {
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

    It 'fills every template placeholder' {
        $bundle = New-SmugglingHtmlBundle -Items $script:items
        $bundle.Html | Should -Not -Match '\{\{COUNT\}\}'
        $bundle.Html | Should -Not -Match '/\*__PAYLOAD_JSON__\*/'
        $bundle.Html | Should -Not -Match '/\*__AES_KEY_B64__\*/'
        $bundle.Html | Should -Not -Match '/\*__MAC_KEY_B64__\*/'
        $bundle.Html | Should -Not -Match '/\*__CIPHER_MODE__\*/'
        $bundle.Html | Should -Match '>Drop 2 test payloads<'
        $bundle.Html | Should -Match "MODE\s*=\s*'cbc-hmac'"
    }

    It 'emits Expected, CipherMode, and both key fields' {
        $bundle = New-SmugglingHtmlBundle -Items $script:items
        $bundle.Expected.Count | Should -Be 2
        $bundle.CipherMode      | Should -Be 'CbcHmac'
        $bundle.AesKeyB64       | Should -Not -BeNullOrEmpty
        $bundle.MacKeyB64       | Should -Not -BeNullOrEmpty
    }

    It 'embedded payloads round-trip back to the original bytes' {
        $bundle = New-SmugglingHtmlBundle -Items $script:items
        $aesKey = [Convert]::FromBase64String($bundle.AesKeyB64)
        $macKey = [Convert]::FromBase64String($bundle.MacKeyB64)

        $m = [regex]::Match($bundle.Html, 'const BLOBS\s*=\s*(\[.*?\]);', 'Singleline')
        $m.Success | Should -BeTrue
        $blobs = $m.Groups[1].Value | ConvertFrom-Json

        for ($i = 0; $i -lt $script:items.Count; $i++) {
            $iv  = [Convert]::FromBase64String($blobs[$i].iv)
            $ct  = [Convert]::FromBase64String($blobs[$i].c)
            $tag = [Convert]::FromBase64String($blobs[$i].t)
            $plain = Invoke-AesCbcHmacDecrypt -AesKey $aesKey -MacKey $macKey -InitVector $iv -Ciphertext $ct -Tag $tag
            $plain.Length        | Should -Be $script:items[$i].Bytes.Length
            (,$plain -join ',')  | Should -Be ((,$script:items[$i].Bytes) -join ',')
        }
    }

    It 'uses a fresh key pair on each invocation' {
        $b1 = New-SmugglingHtmlBundle -Items $script:items
        $b2 = New-SmugglingHtmlBundle -Items $script:items
        $b1.AesKeyB64 | Should -Not -Be $b2.AesKeyB64
        $b1.MacKeyB64 | Should -Not -Be $b2.MacKeyB64
    }
}

Describe 'New-SmugglingHtmlBundle -CipherMode Gcm (PS7+ only)' -Skip:(-not (Test-AesGcmAvailable)) {
    It 'produces a GCM-flavoured bundle with no MAC key' {
        $items = @([pscustomobject]@{ FileName='a.txt'; Bytes=[System.Text.Encoding]::UTF8.GetBytes('a'); Mime='text/plain'; ExpectMotw=$true; Expected=@{} })
        $bundle = New-SmugglingHtmlBundle -Items $items -CipherMode Gcm
        $bundle.CipherMode | Should -Be 'Gcm'
        $bundle.MacKeyB64  | Should -BeNullOrEmpty
        $bundle.Html       | Should -Match "MODE\s*=\s*'gcm'"
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
