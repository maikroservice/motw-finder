Set-StrictMode -Version Latest

<#
Benign payload byte-builders used by the smuggling harness and the git harness.
Every builder returns a byte[] plus the recommended filename; nothing is
executable. Content is a known marker string so test harnesses can identify
drops regardless of extension.
#>

$script:MotwTestMarker = 'MOTW-TEST-PAYLOAD-7b3d'

function Get-MotwTestMarker {
    [CmdletBinding()] param()
    $script:MotwTestMarker
}

function New-MarkerFileBytes {
    <#
    .SYNOPSIS
        Emit a plain marker file with the given extension. Not a real
        executable/script -- just a text marker the runner can recognise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Extension,
        [string]$Comment
    )
    $ext = if ($Extension.StartsWith('.')) { $Extension } else { ".$Extension" }
    $body = "$script:MotwTestMarker ext=$ext"
    if ($Comment) { $body += " comment=$Comment" }
    [pscustomobject]@{
        FileName = "marker$ext"
        Bytes    = [System.Text.Encoding]::UTF8.GetBytes($body)
    }
}

function New-MarkerHtaBytes {
    <#
    .SYNOPSIS
        Minimal .hta that, if mshta opens it, just sets window.title.
        Still benign -- no shell execution, no ActiveX.
    #>
    [CmdletBinding()] param()
    $html = @"
<!doctype html>
<html><head><title>$script:MotwTestMarker</title>
<hta:application id='hta' border='thin' />
<script>document.title='$script:MotwTestMarker';</script>
</head><body>MOTW test HTA.</body></html>
"@
    [pscustomobject]@{
        FileName = 'marker.hta'
        Bytes    = [System.Text.Encoding]::UTF8.GetBytes($html)
    }
}

function New-ZipContainerBytes {
    <#
    .SYNOPSIS
        Build a ZIP archive in memory containing the given items.
    .PARAMETER Items
        Array of hashtables @{ Name = 'x.txt'; Bytes = [byte[]]@(...) }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable[]]$Items,
        [string]$ArchiveName = 'container.zip'
    )
    Add-Type -AssemblyName System.IO.Compression            -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $ms = [System.IO.MemoryStream]::new()
    try {
        $zip = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            foreach ($item in $Items) {
                $entry = $zip.CreateEntry($item.Name, [System.IO.Compression.CompressionLevel]::Optimal)
                $stream = $entry.Open()
                try { $stream.Write($item.Bytes, 0, $item.Bytes.Length) }
                finally { $stream.Dispose() }
            }
        } finally { $zip.Dispose() }
        [pscustomobject]@{ FileName = $ArchiveName; Bytes = $ms.ToArray() }
    } finally { $ms.Dispose() }
}

function New-OoxmlContainerBytes {
    <#
    .SYNOPSIS
        Build a minimal valid OOXML document (docx/docm/xlsx/xlsm).
        Produces a file Word/Excel will actually open so the MOTW->
        Protected-View gate is observable.  Does NOT include a real
        vbaProject.bin; .docm/.xlsm here behave like their macro-free
        siblings but keep the extension for MOTW tests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('docx','docm','xlsx','xlsm')][string]$Kind
    )

    $marker = $script:MotwTestMarker

    $contentTypes = switch -Regex ($Kind) {
        '^doc' {
            @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"@
        }
        '^xls' {
            @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>
"@
        }
    }

    $topRels = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="$(if ($Kind -like 'doc*') { 'word/document.xml' } else { 'xl/workbook.xml' })"/>
</Relationships>
"@

    $items = New-Object System.Collections.Generic.List[hashtable]
    $items.Add(@{ Name = '[Content_Types].xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($contentTypes) })
    $items.Add(@{ Name = '_rels/.rels';         Bytes = [System.Text.Encoding]::UTF8.GetBytes($topRels) })

    if ($Kind -like 'doc*') {
        $docXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>$marker</w:t></w:r></w:p></w:body>
</w:document>
"@
        $items.Add(@{ Name = 'word/document.xml'; Bytes = [System.Text.Encoding]::UTF8.GetBytes($docXml) })
    } else {
        $wbXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>
"@
        $wbRels = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>
"@
        $sheetXml = @"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>$marker</t></is></c></row></sheetData>
</worksheet>
"@
        $items.Add(@{ Name = 'xl/workbook.xml';             Bytes = [System.Text.Encoding]::UTF8.GetBytes($wbXml) })
        $items.Add(@{ Name = 'xl/_rels/workbook.xml.rels';  Bytes = [System.Text.Encoding]::UTF8.GetBytes($wbRels) })
        $items.Add(@{ Name = 'xl/worksheets/sheet1.xml';    Bytes = [System.Text.Encoding]::UTF8.GetBytes($sheetXml) })
    }

    $result = New-ZipContainerBytes -Items $items.ToArray() -ArchiveName "marker.$Kind"
    $result
}

function Test-ExternalTool {
    param([Parameter(Mandatory)][string[]]$Candidates)
    foreach ($c in $Candidates) {
        $found = Get-Command $c -ErrorAction SilentlyContinue
        if ($found) { return $found.Source }
    }
    return $null
}

function New-PasswordZipContainerBytes {
    <#
    .SYNOPSIS
        Build a password-protected ZIP via the 7z CLI.  Errors clearly if
        7z is not on PATH.  Password-encryption with native .NET would
        require a third-party library; shelling out is the pragmatic call.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable[]]$Items,
        [Parameter(Mandatory)][string]$Password,
        [string]$ArchiveName = 'container-pw.zip'
    )
    $sevenZip = Test-ExternalTool -Candidates @('7z','7z.exe','7zz')
    if (-not $sevenZip) {
        throw '7z CLI not found on PATH -- install 7-Zip to build password-protected archives.'
    }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("pwzip_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path $work -ItemType Directory | Out-Null
    try {
        foreach ($item in $Items) {
            $dest = Join-Path $work $item.Name
            $parent = Split-Path $dest -Parent
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory | Out-Null }
            [System.IO.File]::WriteAllBytes($dest, $item.Bytes)
        }
        $archive = Join-Path $work $ArchiveName
        $names = $Items | ForEach-Object { $_.Name }
        $prevPwd = Get-Location
        Set-Location -LiteralPath $work
        try {
            & $sevenZip a -tzip "-p$Password" -mem=AES256 $archive $names | Out-Null
            if (-not (Test-Path -LiteralPath $archive)) { throw '7z failed to create archive.' }
            [pscustomobject]@{ FileName = $ArchiveName; Bytes = [System.IO.File]::ReadAllBytes($archive) }
        } finally { Set-Location $prevPwd }
    } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

function New-IsoContainerBytes {
    <#
    .SYNOPSIS
        Build an ISO9660 image containing the given items.  Requires an
        external mastering tool (oscdimg from Windows ADK, or mkisofs /
        genisoimage / xorriso on Linux).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable[]]$Items,
        [string]$ArchiveName = 'container.iso',
        [string]$VolumeLabel = 'MOTWTEST'
    )
    $tool = Test-ExternalTool -Candidates @('genisoimage','mkisofs','xorriso','oscdimg.exe','oscdimg')
    if (-not $tool) {
        throw 'No ISO mastering tool found -- install genisoimage/mkisofs/xorriso (Linux) or the Windows ADK (oscdimg.exe).'
    }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("iso_" + [guid]::NewGuid().ToString('N'))
    $src  = Join-Path $work 'src'
    New-Item -Path $src -ItemType Directory -Force | Out-Null
    try {
        foreach ($item in $Items) {
            $dest = Join-Path $src $item.Name
            $parent = Split-Path $dest -Parent
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -Path $parent -ItemType Directory | Out-Null }
            [System.IO.File]::WriteAllBytes($dest, $item.Bytes)
        }
        $iso = Join-Path $work $ArchiveName
        $exe = Split-Path $tool -Leaf
        switch -Regex ($exe) {
            '^(genisoimage|mkisofs)' {
                & $tool -quiet -o $iso -V $VolumeLabel -J -r $src | Out-Null
            }
            '^xorriso' {
                & $tool -as mkisofs -quiet -o $iso -V $VolumeLabel -J -r $src | Out-Null
            }
            '^oscdimg' {
                & $tool "-n" "-l$VolumeLabel" $src $iso | Out-Null
            }
        }
        if (-not (Test-Path -LiteralPath $iso)) { throw "ISO tool ($tool) failed." }
        [pscustomobject]@{ FileName = $ArchiveName; Bytes = [System.IO.File]::ReadAllBytes($iso) }
    } finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Export-ModuleMember -Function `
    Get-MotwTestMarker, `
    New-MarkerFileBytes, `
    New-MarkerHtaBytes, `
    New-ZipContainerBytes, `
    New-OoxmlContainerBytes, `
    New-PasswordZipContainerBytes, `
    New-IsoContainerBytes, `
    Test-ExternalTool
