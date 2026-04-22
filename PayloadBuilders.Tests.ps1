#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'PayloadBuilders.psm1') -Force
}

Describe 'Marker builders' {
    It 'emits a marker.txt containing the shared marker string' {
        $p = New-MarkerFileBytes -Extension '.txt'
        $p.FileName | Should -Be 'marker.txt'
        [System.Text.Encoding]::UTF8.GetString($p.Bytes) | Should -Match (Get-MotwTestMarker)
    }

    It 'normalises extensions missing a leading dot' {
        (New-MarkerFileBytes -Extension 'lnk').FileName | Should -Be 'marker.lnk'
    }

    It 'emits a minimal .hta whose title is the marker' {
        $p = New-MarkerHtaBytes
        $p.FileName | Should -Be 'marker.hta'
        [System.Text.Encoding]::UTF8.GetString($p.Bytes) | Should -Match (Get-MotwTestMarker)
    }
}

Describe 'New-ZipContainerBytes' {
    It 'produces a readable ZIP with the expected entries' {
        $items = @(
            @{ Name = 'a.txt'; Bytes = [System.Text.Encoding]::UTF8.GetBytes('alpha') },
            @{ Name = 'sub/b.txt'; Bytes = [System.Text.Encoding]::UTF8.GetBytes('beta') }
        )
        $p = New-ZipContainerBytes -Items $items -ArchiveName 'test.zip'
        $p.FileName | Should -Be 'test.zip'

        Add-Type -AssemblyName System.IO.Compression            -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $ms = [System.IO.MemoryStream]::new($p.Bytes)
        $zip = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            $names = $zip.Entries | ForEach-Object { $_.FullName }
            $names | Should -Contain 'a.txt'
            $names | Should -Contain 'sub/b.txt'
        } finally { $zip.Dispose(); $ms.Dispose() }
    }
}

Describe 'New-OoxmlContainerBytes' {
    It 'produces a docx whose document.xml contains the marker' {
        $p = New-OoxmlContainerBytes -Kind docx
        $p.FileName | Should -Be 'marker.docx'

        Add-Type -AssemblyName System.IO.Compression            -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $ms = [System.IO.MemoryStream]::new($p.Bytes)
        $zip = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            $entry = $zip.Entries | Where-Object FullName -eq 'word/document.xml'
            $entry | Should -Not -BeNullOrEmpty
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $reader.ReadToEnd() | Should -Match (Get-MotwTestMarker) }
            finally { $reader.Dispose() }
        } finally { $zip.Dispose(); $ms.Dispose() }
    }

    It 'produces an xlsm archive with workbook + sheet parts' {
        $p = New-OoxmlContainerBytes -Kind xlsm
        $p.FileName | Should -Be 'marker.xlsm'

        Add-Type -AssemblyName System.IO.Compression            -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $ms = [System.IO.MemoryStream]::new($p.Bytes)
        $zip = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
        try {
            $names = $zip.Entries | ForEach-Object { $_.FullName }
            $names | Should -Contain 'xl/workbook.xml'
            $names | Should -Contain 'xl/worksheets/sheet1.xml'
        } finally { $zip.Dispose(); $ms.Dispose() }
    }
}

Describe 'External-tool-backed builders (skipped if tool missing)' {
    It 'builds a password-protected zip via 7z when present' -Skip:($null -eq (Test-ExternalTool @('7z','7z.exe','7zz'))) {
        $items = @(@{ Name = 'inside.txt'; Bytes = [System.Text.Encoding]::UTF8.GetBytes('secret') })
        $p = New-PasswordZipContainerBytes -Items $items -Password 'motwtest'
        $p.Bytes.Length | Should -BeGreaterThan 100
        # ZIP local file header signature 'PK\x03\x04'
        ($p.Bytes[0..3] -join ',') | Should -Be '80,75,3,4'
    }

    It 'builds an ISO via mkisofs/genisoimage/xorriso when present' -Skip:($null -eq (Test-ExternalTool @('genisoimage','mkisofs','xorriso','oscdimg.exe','oscdimg'))) {
        $items = @(@{ Name = 'readme.txt'; Bytes = [System.Text.Encoding]::UTF8.GetBytes('hi') })
        $p = New-IsoContainerBytes -Items $items
        $p.Bytes.Length | Should -BeGreaterThan 32768
        # ISO9660 Primary Volume Descriptor at sector 16 starts with 0x01 'CD001'
        $sig = [System.Text.Encoding]::ASCII.GetString($p.Bytes, 32769, 5)
        $sig | Should -Be 'CD001'
    }
}
