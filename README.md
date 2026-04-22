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

## Module map

| File | Role |
|---|---|
| `MotwFinder.psm1` | Core detector: read `Zone.Identifier`, parse it, classify suspicious patterns. |
| `Find-Motw.ps1` | List every marked file under a path. |
| `Find-SuspiciousMotw.ps1` | Rule-based hunt: dangerous-extension-from-Internet, suspicious host, unparseable stream, missing provenance. |
| `PayloadBuilders.psm1` | Benign byte-builders for marker files, ZIP, OOXML, password ZIP, ISO. |
| `SmugglingHarness.psm1` | AES-CBC+HMAC (default, PS 5.1-compatible) or AES-GCM (PS 7+) encryption; Tier-1 manifest builder; produces the smuggling HTML. |
| `smuggling-template.html` | Browser-side WebCrypto decrypt + `<a download>` drop loop. Dual-mode: switches between CBC+HMAC and GCM at runtime based on the embedded mode marker. |
| `New-SmugglingPayload.ps1` | CLI: emits `smuggle.html` + `expected.json` for later scanning. |
| `PropagationScanner.psm1` | Compares observed MOTW to expected manifest; recurses into containers via each available extractor. |
| `Test-MotwPropagation.ps1` | CLI over the scanner. Exits non-zero if any FAIL. |
| `ZoneIdTampering.psm1` | 13 malformed-stream variants (CVE-2022-44698 padding, ZoneId downgrade, BOMs, missing header, etc.). |
| `New-TamperedFixtures.ps1` | CLI: produces a directory of files each carrying a different tampered stream. |
| `GitHarness.psm1` | Fixture-repo builder + clone-vs-download-archive MOTW comparison. |
| `Test-GitMotwPropagation.ps1` | CLI, supports `-BuildFixtureRepo` for offline use. |

Every `.psm1` has a sibling `.Tests.ps1`.

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
# 1. Generate the smuggling page + expected-MOTW manifest
#    (default cipher is AES-CBC + HMAC-SHA256; add -CipherMode Gcm on PS 7+
#     for AES-GCM realism)
.\New-SmugglingPayload.ps1 -OutputDir C:\motw-test

# 2. Open C:\motw-test\smuggle.html in each browser you want to exercise
#    (Chrome, Edge, Firefox, etc.) and click "Drop N payloads".
#    Every payload carries the marker string "MOTW-TEST-PAYLOAD-7b3d".

# 3. Scan the drop folder against the expected manifest
.\Test-MotwPropagation.ps1 `
    -DropDir "$env:USERPROFILE\Downloads" `
    -ExpectedManifest C:\motw-test\expected.json
```

Output is a PASS/FAIL table per (file, section, extractor). The scanner
recurses into every container that has `Expected.InnerFiles` in the
manifest, using whichever extractors are on PATH — `Expand-Archive`,
`7z`, and `Mount-DiskImage` for ISO/IMG.

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
Invoke-Pester .
```

Tests are designed to run on Linux/macOS too — any Describe that needs
real NTFS ADS or an external tool is guarded with `-Skip`.

## What each harness actually measures

### HTML-smuggling harness
The browser writes every payload from a `Blob`. Modern Chrome/Edge/Firefox
tag these with `Zone.Identifier`, so **outer** MOTW should land on every
drop. The interesting results are:

- **ISO / IMG with inner `.lnk`** — on a fully-patched Windows post-
  CVE-2022-41091, mounting should propagate MOTW. If the scanner reports
  FAIL on the inner `.lnk` with `Mount-DiskImage`, your machine is behind
  on the Nov 2022 patch.
- **ZIP via `Expand-Archive`** — never propagates. This is the baseline
  "bypass shape".
- **ZIP via 7z** — propagation depends on version. 7-Zip 22.00+ (June
  2022) propagates; older versions don't.
- **Password-protected ZIP** — historically strips MOTW across most
  extractors regardless of version.

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
drops follow-on files, or persists. The AES-GCM encryption in the HTML
template reproduces the *shape* of real HTML smuggling for detection
work; it isn't obfuscating malicious content. Use this tooling on
systems you own or are authorised to test.
