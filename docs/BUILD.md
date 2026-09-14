# Build, Run, Test, and Release — Residential Connect

## Prerequisites

- **Windows 10/11 x64** for actually *running* the app (WPF UI + Windows
  DPAPI are Windows-only).
- **.NET 10 SDK** — <https://dotnet.microsoft.com/download/dotnet/10.0>
- Google Chrome or Microsoft Edge installed (used by OPEN BROWSER in V0.1 —
  see README "Known limitations").
- Visual Studio 2022 (17.8+) with the ".NET desktop development" workload,
  *or* just the .NET SDK + your editor of choice for CLI-only workflows.

The solution also **restores and compiles on Linux/macOS** for the four
non-UI class libraries and the test project, and even cross-compiles the
WPF client itself (see "Cross-platform notes" below) — this is how this
repository's own CI/dev-sandbox checks were run without a Windows machine.
Actually *running* the app and its Windows-specific behavior (DPAPI,
launching Chrome, real proxy auth) requires Windows.

## 1. Clone and restore

```bash
git clone https://github.com/chomane/residential-connect.git
cd residential-connect
dotnet restore ResidentialConnect.sln
```

## 2. Build the full solution

```bash
dotnet build ResidentialConnect.sln -c Debug
# or
dotnet build ResidentialConnect.sln -c Release
```

Expected output: `Build succeeded. 0 Warning(s) 0 Error(s)` across all 6
projects (`Core`, `Security`, `Proxy`, `Browser`, `Client`, `Tests`).

## 3. Run the automated tests

```bash
dotnet test tests/ResidentialConnect.Tests/ResidentialConnect.Tests.csproj
```

Expected output (as last verified in this repository):

```
Passed!  - Failed: 0, Passed: 20, Skipped: 0, Total: 20
```

Covers: proxy configuration validation, CSV import/parsing (including
per-row failure isolation), credential encryption/decryption round-trips
and negative cases, connectivity test result handling, and secret-scrubbing
of log messages. See `docs/ARCHITECTURE.md` → "Testing strategy" for the
full mapping of tests to requirements.

## 4. Run the app (Windows, Visual Studio)

1. Open `ResidentialConnect.sln` in Visual Studio.
2. Set `ResidentialConnect.Client` as the startup project (it already is,
   as the only executable project).
3. Press F5 (Debug) or Ctrl+F5 (Run without debugging).
4. The main window opens: **Settings / Manage Proxies → Add Proxy** to add
   your first Webshare Dedicated Static Residential proxy, then select it
   and click **CONNECT** on the main screen.

## 5. Run the app (Windows, CLI)

```powershell
dotnet run --project src\ResidentialConnect.Client\ResidentialConnect.Client.csproj
```

## 6. Produce the Windows x64 Release build

Framework-dependent (smaller output, requires the .NET 10 Desktop Runtime
on the target machine — install via
<https://dotnet.microsoft.com/download/dotnet/10.0>, "Desktop Runtime"):

```powershell
dotnet publish src\ResidentialConnect.Client\ResidentialConnect.Client.csproj `
    -c Release -r win-x64 --self-contained false `
    -o publish\win-x64
```

Self-contained (larger output, no runtime install needed on the target
machine — bundles the .NET runtime):

```powershell
dotnet publish src\ResidentialConnect.Client\ResidentialConnect.Client.csproj `
    -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true `
    -o publish\win-x64-standalone
```

Either command produces `ResidentialConnect.exe` plus its dependent DLLs
under the chosen output folder. **This publish step itself was verified in
this repository's Linux build sandbox** (framework-dependent, producing a
valid `PE32+ executable for MS Windows ... x86-64` binary) — but the
resulting `.exe` has only been *compiled*, not *executed*, outside Windows.
Running it, exercising DPAPI-backed credential storage, launching a real
browser, and confirming the observed IP is the Webshare exit IP all require
a real Windows 10/11 x64 machine — see the acceptance checklist below.

## 7. Optional: installer/package

For V0.1, the simplest "installer" is distributing the self-contained
publish folder (step 6) as a zip, or wrapping it with a lightweight tool
such as:

- **MSIX packaging** (via Visual Studio's "Windows Application Packaging
  Project", or `dotnet publish` with `-p:WindowsPackageType=MSIX` once a
  package manifest is added), or
- A simple installer generator such as
  [Inno Setup](https://jrsoftware.org/isinfo.php) pointed at the
  `publish\win-x64` folder.

Neither is included in this V0.1 delivery (per scope — "if practical"); the
zipped publish folder is sufficient to satisfy the "release build for
Windows x64" requirement and the acceptance test below.

## Cross-platform notes (how this was verified without Windows)

The `.csproj` files target `net10.0` (libraries) and `net10.0-windows`
(the WPF client). By default, the .NET SDK refuses to even *restore* a
`-windows` TFM project on a non-Windows OS (`NETSDK1100`). This repository
sets `<EnableWindowsTargeting>true</EnableWindowsTargeting>` in
`Directory.Build.props` — a documented, standard MSBuild property that
lifts that restriction so `net10.0-windows` projects can be **compiled**
(not run) on Linux/macOS. This has **zero effect when building on real
Windows** and does not change any runtime behavior; it only unlocks
compilation elsewhere, which is what allowed:

- `dotnet build ResidentialConnect.sln` (all 6 projects, including the WPF
  client) to succeed in this sandbox.
- `dotnet publish ... -r win-x64` to produce a real Windows PE executable
  from this sandbox.
- `dotnet test` to run the full xUnit suite using fakes for
  Windows-only primitives (`IDataProtector` → `FakeReversibleProtector`
  instead of the real `DpapiDataProtector`).

## Windows-only acceptance checklist (cannot be verified in this sandbox)

The following must be exercised on a real Windows 10/11 x64 machine before
calling V0.1 fully verified — see also README → "Known limitations":

1. `DpapiDataProtector.Protect`/`Unprotect` round-trips using real
   `CryptProtectData`/`CryptUnprotectData` (the sandbox only exercises the
   `FileCredentialStore` logic around it, via a fake protector).
2. Adding a **real** Webshare Dedicated Static Residential proxy (host,
   port, username, password, protocol) and clicking **Test** / **CONNECT**
   — confirms DNS/TCP reachability, HTTP CONNECT or SOCKS5 authentication,
   and that the reported public IP/latency are correct.
3. Clicking **OPEN BROWSER** — confirms `InstalledBrowserProvider` finds a
   real Chrome/Edge install, `LocalForwardingProxy` correctly relays and
   authenticates browser traffic with no credential prompt, and the
   isolated `--user-data-dir` does not touch the user's normal browser
   profile.
4. Visiting an IP-checking site (e.g. `https://api.ipify.org`) inside that
   browser window and confirming it reports the **Webshare residential
   IP**, not the machine's normal Internet IP — the explicit V0.1
   acceptance test from the product brief.
5. Confirming `%LOCALAPPDATA%\ResidentialConnect\Logs\*.log` never contains
   the plaintext password, even after a failed authentication attempt.
