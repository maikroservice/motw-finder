#Requires -Version 5.1
<#
.SYNOPSIS
    Serve a directory (the smuggling HTML + its expected.json) over
    http://localhost so browsers treat downloads as Internet zone
    (ZoneId=3) instead of Untrusted (ZoneId=4, the "file:///" origin
    you get when opening the HTML via a file:// URL).

.DESCRIPTION
    Minimal in-process HTTP server using System.Net.HttpListener.
    Stops on Ctrl+C.

.EXAMPLE
    .\Start-SmugglingServer.ps1 -Root C:\motw-test
    # Then in your browser, open:  http://localhost:8080/smuggle.html
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)][string]$Root,
    [int]$Port = 8080
)

$Root = (Resolve-Path -LiteralPath $Root).ProviderPath

$mime = @{
    '.html' = 'text/html; charset=utf-8'
    '.htm'  = 'text/html; charset=utf-8'
    '.js'   = 'application/javascript'
    '.json' = 'application/json'
    '.css'  = 'text/css'
    '.txt'  = 'text/plain'
}

$listener = [System.Net.HttpListener]::new()
$prefix = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)
try { $listener.Start() } catch {
    throw "Failed to bind $prefix. Run as Admin once with ``netsh http add urlacl url=$prefix user=$env:USERNAME``, or pick another -Port."
}

Write-Host ("Serving {0} on {1}" -f $Root, $prefix) -ForegroundColor Green
Write-Host "Press Ctrl+C to stop."

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response
        try {
            $rel = [uri]::UnescapeDataString($req.Url.AbsolutePath.TrimStart('/'))
            if (-not $rel) { $rel = 'smuggle.html' }
            $full = Join-Path $Root $rel

            # No path traversal outside Root
            $fullResolved = $null
            try { $fullResolved = (Resolve-Path -LiteralPath $full -ErrorAction Stop).ProviderPath } catch {}
            if (-not $fullResolved -or -not $fullResolved.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $fullResolved -PathType Leaf)) {
                $res.StatusCode = 404
                $body = [System.Text.Encoding]::UTF8.GetBytes('404')
                $res.OutputStream.Write($body, 0, $body.Length)
                Write-Host ("404  {0}" -f $rel)
                continue
            }

            $ext = [System.IO.Path]::GetExtension($fullResolved).ToLowerInvariant()
            $res.ContentType = $mime[$ext]
            if (-not $res.ContentType) { $res.ContentType = 'application/octet-stream' }
            $bytes = [System.IO.File]::ReadAllBytes($fullResolved)
            $res.ContentLength64 = $bytes.Length
            $res.OutputStream.Write($bytes, 0, $bytes.Length)
            Write-Host ("200  {0}  ({1} bytes)" -f $rel, $bytes.Length)
        } catch {
            Write-Host ("ERR  {0}: {1}" -f $rel, $_.Exception.Message) -ForegroundColor Red
        } finally {
            $res.OutputStream.Close()
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
    Write-Host "`nListener stopped." -ForegroundColor Yellow
}
