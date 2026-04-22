# motw-finder

PowerShell tooling for hunting Mark-of-the-Web (NTFS `Zone.Identifier` ADS) on
Windows, plus a research harness for measuring where MOTW propagation breaks
(HTML smuggling, container extraction, `git clone`, `Zone.Identifier` tampering).

Built for defenders: detection engineering, IR triage, and verifying that
MOTW/SmartScreen gates on your fleet still catch what they're supposed to.
Every harness payload is a benign marker string with no executable behaviour.

## Requirements

- **All tools (detector, scanner, tampering generator, git harness,
  smuggling harness):** Windows PowerShell 5.1 or PowerShell 7+.
  The smuggling harness defaults to AES-256-CBC + HMAC-SHA256
  (Encrypt-then-MAC), which works on both editions.  Passing
  `-CipherMode Gcm` switches to AES-GCM, which requires PowerShell 7+
  (.NET 5+).
- **Pester 5** for the test suites.
- **Optional external tools, detected at runtime:**
  - `7z` / `7z.exe` / `7zz` — password-protected ZIP and 7z containers, 7z-based extraction
  - `genisoimage` / `mkisofs` / `xorriso` (Linux) or `oscdimg.exe` (Windows ADK) — ISO/IMG generation
  - `git` — git-clone comparison harness

## Repository layout

```
motw-finder/
|-- *.ps1                 # runnable scripts (Find-Motw, New-SmugglingPayload, ...)
|-- psm/                  # module files (*.psm1) + smuggling-template.html asset
|-- test/                 # Pester test suites (*.Tests.ps1)
`-- README.md, .gitignore
```

## Module map

**Runnable scripts (repo root)**

| Script | Role |
|---|---|
| `Find-Motw.ps1` | List every marked file under a path. |
| `Find-SuspiciousMotw.ps1` | Rule-based hunt: dangerous-extension-from-Internet, suspicious host, unparseable stream, missing provenance. |
| `New-SmugglingPayload.ps1` | CLI: emits `smuggle.html` + `expected.json` for later scanning. |
| `Start-SmugglingServer.ps1` | Minimal local HTTP server (`System.Net.HttpListener`) for serving the smuggling page so browsers treat drops as Internet zone instead of Untrusted. |
| `Test-MotwPropagation.ps1` | Walk a directory and print `HasMotw = True/False` per file. Includes a banner explaining how detection works. |
| `Debug-MotwScan.ps1` | Per-file diagnostic: prints the raw `Zone.Identifier` bytes, parser output, and candidate renames. Use when the scanner result looks wrong. |
| `New-TamperedFixtures.ps1` | CLI: produces a directory of files each carrying a different tampered stream. |
| `Test-GitMotwPropagation.ps1` | CLI, supports `-BuildFixtureRepo` for offline use. |

**Modules (`psm/`)**

| File | Role |
|---|---|
| `psm/MotwFinder.psm1` | Core detector: read `Zone.Identifier`, parse it, classify suspicious patterns. |
| `psm/PayloadBuilders.psm1` | Benign byte-builders for marker files, ZIP, OOXML, password ZIP, ISO. |
| `psm/SmugglingHarness.psm1` | AES-CBC+HMAC (default, PS 5.1-compatible) or AES-GCM (PS 7+) encryption; Tier-1 manifest builder; produces the smuggling HTML. |
| `psm/smuggling-template.html` | Browser-side WebCrypto decrypt + `<a download>` drop loop. Dual-mode: switches between CBC+HMAC and GCM at runtime based on the embedded mode marker. |
| `psm/PropagationScanner.psm1` | Library-only utilities used by `psm/GitHarness.psm1`: `Get-AvailableExtractors`, `Expand-ContainerToTemp`, `Dismount-ContainerHandle`. Not called by the CLI any more. |
| `psm/ZoneIdTampering.psm1` | 13 malformed-stream variants (CVE-2022-44698 padding, ZoneId downgrade, BOMs, missing header, etc.). |
| `psm/GitHarness.psm1` | Fixture-repo builder + clone-vs-download-archive MOTW comparison. |

Every `.psm1` in `psm/` has a sibling `<Name>.Tests.ps1` in `test/`.

## Quick start — detection

```powershell
# List every marked file under a path
.\Find-Motw.ps1 -Path "$env:USERPROFILE\Downloads"

# Hunt: only files whose MOTW smells suspicious
.\Find-SuspiciousMotw.ps1 -Path "$env:USERPROFILE\Downloads"

# Same, since a date (e.g. since the last Windows update)
.\Find-SuspiciousMotw.ps1 -Path "$env:USERPROFILE\Downloads" -Since (Get-Date).AddDays(-7)
```

## Quick start — HTML-smuggling harness

```powershell
# 1. Generate the smuggling page + expected-MOTW manifest.
#    Default cipher is AES-CBC + HMAC-SHA256. Add -CipherMode Gcm on PS 7+
#    to emit AES-GCM instead (more realistic for modern samples).
.\New-SmugglingPayload.ps1 -OutputDir C:\motw-test

# 2. Serve the page over http://localhost so drops land as Internet zone
#    (ZoneId=3). Opening smuggle.html via file:// works too, but drops
#    then land as Untrusted zone (ZoneId=4) with HostUrl=file:///, which
#    is not what real phishing delivery looks like.
.\Start-SmugglingServer.ps1 -Root C:\motw-test        # defaults to port 8080
# keep this window open; Ctrl+C to stop

# 3. In a browser, open http://localhost:8080/smuggle.html and click the
#    "Drop" button next to each payload. Every payload has its own button
#    so every click is a user gesture -- that avoids Chrome/Edge/Firefox
#    throttling automatic multi-downloads. For risky extensions
#    (.lnk, .ps1, .bat, .vbs, .hta, .js, ...) the browser still prompts
#    "Keep / Discard" in its downloads panel; click "Keep" on each.
#    Every payload carries the marker string "MOTW-TEST-PAYLOAD-7b3d".

# 4. Walk the drop folder and print HasMotw per file.
.\Test-MotwPropagation.ps1 -Path "$env:USERPROFILE\Downloads"
```

The output is a plain table, one row per file:

```
FileName       HasMotw ZoneName  HostUrl
--------       ------- --------  -------
container.zip  True    Internet  http://localhost:8080/
marker.docm    True    Internet  http://localhost:8080/
marker.txt     True    Internet  http://localhost:8080/
marker.pdf     True    Internet  http://localhost:8080/
marker.lnk     False
...

7 file(s) total: 5 with MOTW, 2 without.
```

How detection works (also printed as a banner on every run unless
`-HideMethodBanner` is passed):

> MOTW lives in an NTFS Alternate Data Stream named `Zone.Identifier` on
> the file itself (e.g. `C:\path\foo.exe:Zone.Identifier`). The script
> reads that stream with
> `Get-Content -LiteralPath <file> -Stream 'Zone.Identifier' -Raw`. If
> the read succeeds and the content parses as `[ZoneTransfer]` with an
> integer `ZoneId`, `HasMotw = True` and the zone name + HostUrl +
> ReferrerUrl are surfaced. If the stream is absent (the stream read
> raises `ItemNotFoundException`) or the content is malformed,
> `HasMotw = False`.

### Why the local HTTP server matters

Browsers compute the outer `HostUrl` field of the `Zone.Identifier` from
the page's origin:

| How you opened `smuggle.html`   | `HostUrl` baked into MOTW      | Zone        |
|---------------------------------|---------------------------------|-------------|
| `file:///C:/motw-test/...`      | `file:///`                      | Untrusted (4) |
| `http://localhost:8080/...`     | `http://localhost:8080/`        | Internet (3)  |
| Real public URL                 | That URL                        | Internet (3)  |

For measuring actual bypass shapes against SmartScreen / Office Protected
View, you want Internet zone. The `Untrusted` zone can trigger additional
gates that wouldn't fire on a real phish and will confuse your results.
`Start-SmugglingServer.ps1` is a ~70-line `HttpListener` so you don't
need IIS, Python, or Node just for this.

### Browser bypass tips

- **Risky extensions blocked.** Chrome, Edge, and Firefox refuse to
  auto-download `.lnk`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsf`,
  `.hta`, `.chm`, `.scr`, etc. The file is staged in the downloads panel
  with a **Keep / Discard** choice — click Keep on each to land it on
  disk. If you don't, those rows show MISSING in the scanner output.
- **Container delivery instead.** The realistic attacker shape is to
  deliver a `.zip` or `.iso` containing the risky inner file; browsers
  don't block containers, and propagation through the extractor is
  exactly what the scanner's inner-container matrix measures.
- **Diagnostic.** If the scanner result looks wrong, run
  `Debug-MotwScan.ps1 -DropDir ... -ExpectedManifest ...` — it prints
  the raw `Zone.Identifier` bytes per file, and lists any
  collision-renamed candidates in the drop dir.

## Quick start — Zone.Identifier tampering

```powershell
# Produce a tree of files each with a different malformed Zone.Identifier.
# Run on Windows for real NTFS ADS; on Linux/macOS it falls back to
# literal "<file>:Zone.Identifier" sidecar files.
.\New-TamperedFixtures.ps1 -OutputDir C:\motw-tamper

# See how the detector classifies each
.\Find-SuspiciousMotw.ps1 -Path C:\motw-tamper
```

## Quick start — git-clone vs download comparison

```powershell
# Offline: build a local fixture repo and scan its clone.
# Clone path should produce zero Zone.Identifier streams — that's the bypass.
.\Test-GitMotwPropagation.ps1 -BuildFixtureRepo -WorkDir C:\git-test

# Live: clone a real URL and compare against a browser-downloaded ZIP.
.\Test-GitMotwPropagation.ps1 `
    -Source https://github.com/owner/repo.git `
    -DownloadedArchive "$env:USERPROFILE\Downloads\repo-main.zip" `
    -WorkDir C:\git-test
```

## Running the tests

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser   # once
Invoke-Pester .\test
```

Tests are designed to run on Linux/macOS too — any Describe that needs
real NTFS ADS or an external tool is guarded with `-Skip`.

## What each harness actually measures

### HTML-smuggling harness
The browser writes every payload from a `Blob`. Modern Chrome/Edge/Firefox
tag these with `Zone.Identifier` (so they appear with `HasMotw = True`
in the scanner output). Interesting observations:

- **Outer drops served via `http://localhost`** should report
  `ZoneName = Internet` and the server URL as `HostUrl`. If you serve
  via `file://` they show `ZoneName = Untrusted` and `HostUrl = file:///`
  instead — realistic phish testing wants Internet zone, which is why
  `Start-SmugglingServer.ps1` exists.
- **Containers (`.zip`, `.iso`, `.img`)** get MOTW on the container
  itself. Whether the *inner* file keeps MOTW after extraction depends
  on the extractor: Explorer's Shell32 COM and Mount-DiskImage propagate
  (post-CVE-2022-41091 patch for ISO/IMG); 7-Zip 22.00+ propagates for
  ZIP; older 7-Zip, WinRAR ≤ 6.22, and all `Expand-Archive` /
  `System.IO.Compression.ZipFile` paths drop the mark. Test by
  extracting into a subfolder and re-running the scanner against that
  subfolder.
- **Password-protected ZIP** — historically strips MOTW from inner files
  across every extractor. Expect `HasMotw = False` on the contents.

### Zone.Identifier tampering
Each variant probes either the parser or SmartScreen itself. Variants
the detector currently `throw`s on (Empty / MissingZoneId /
NonIntegerZoneId / Utf16LeBom) become `UnparseableZoneIdentifier` findings
in `Find-SuspiciousMotw`. Variants it parses (`ZoneIdZero`,
`PaddedCve202244698`) are good test data for whether your *rule set*
notices a downgrade or a Magniber-shaped padding attack.

### Git harness
`git clone` never goes through the browser download pipeline, so no
file in the working tree gets `Zone.Identifier`. The harness asserts
this directly: every file under the clone directory should read
`HasMotw = $false`. If any are marked, something unusual is going on
(corporate MDM post-processing, `safe.directory` hook, etc.) and is
worth investigating.

## Known limitations

- **Tier 3 extractor coverage.** The scanner uses `Expand-Archive`,
  `7z`, and `Mount-DiskImage`. Shell32 COM extraction (which
  *does* propagate MOTW) isn't wired up; neither are WinRAR/PeaZip.
  Adding them is straightforward — extend
  `PropagationScanner.Get-AvailableExtractors` and
  `Expand-ContainerToTemp`.
- **OneNote (`.one`) payloads.** The format isn't implemented in
  `PayloadBuilders`; OneNote-based smuggling isn't exercised.
- **WebDAV / Outlook / Teams paths.** Not covered — these aren't HTML-
  smuggling delivery vectors. They need a separate harness (WebDAV
  server or Outlook automation).
- **Non-NTFS hosts.** The git harness and tampering generator run on
  Linux/macOS but assertions about MOTW presence are vacuous there —
  MOTW is an NTFS ADS feature.
- **No signed payloads.** Testing Authenticode-signed binaries or LNKs
  requires a code-signing cert; out of scope here.

## Safety

Every payload the harness can generate is a benign marker: plain text,
minimal HTA with a `document.title` set, or an OOXML document whose
body contains `MOTW-TEST-PAYLOAD-7b3d`. No payload calls into the shell,
drops follow-on files, or persists. The AES-CBC+HMAC (or AES-GCM)
encryption in the HTML template reproduces the *shape* of real HTML
smuggling for detection work; it isn't obfuscating malicious content.
The local HTTP server only binds `http://localhost:<port>` and never
makes outbound connections. Use this tooling on systems you own or are
authorised to test.
