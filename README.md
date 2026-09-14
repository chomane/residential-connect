# Residential Connect (V0.1)

A Windows desktop application that lets a non-technical user select a
country, click **CONNECT**, and browse through a dedicated **Webshare
Static Residential proxy** — without ever seeing the words "proxy",
"SOCKS", "port", or "authentication".

This is **V0.1**: a focused proof of local browser connectivity through a
single, manually-configured Webshare Dedicated Static Residential proxy. It
is **not** an anti-detect browser, a scraping tool, a multi-account manager,
or a VPN.

---

## What V0.1 does

- Manage a local list of proxy profiles (add / edit / delete / select / test
  / CSV import), backed by Webshare Dedicated Static Residential proxy
  credentials.
- **CONNECT**: validates the selected proxy, authenticates, makes a real
  HTTPS request through it, reports the observed public IP and latency.
- **OPEN BROWSER**: launches an isolated, proxy-routed Chromium browser
  session (Chrome or Edge, whichever is installed) with **automatic**
  proxy authentication — no credential prompt, no touching the user's normal
  browser profile.
- Stores proxy passwords **encrypted at rest** via Windows DPAPI — never in
  plaintext, never in the proxies list file, never in logs.

## What V0.1 deliberately does NOT do

- No whole-computer routing / system proxy changes.
- No kill switch, automatic failover, or automatic IP provisioning.
- No fingerprint spoofing, anti-detect features, or automation/bots.
- No Cloud Browser, accounts, billing, or subscriptions.
- No remote backend of any kind — this is a fully local, single-user app.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the codebase is
structured so these features can be added later without reworking V0.1.

---

## Project layout

```
src/
  ResidentialConnect.Core      Models, interfaces (abstractions), no I/O
  ResidentialConnect.Security  Windows DPAPI-backed encrypted credential storage
  ResidentialConnect.Proxy     HTTP CONNECT + SOCKS5 client, connectivity
                                testing, CSV import, JSON proxy repository,
                                local unauthenticated loopback relay
  ResidentialConnect.Browser   Chromium browser discovery + launch through
                                the local relay, isolated profile directory
  ResidentialConnect.Client    WPF UI (composition root, MainWindow,
                                Manage Proxies, Add/Edit Proxy)
tests/
  ResidentialConnect.Tests     xUnit tests for validation, CSV import,
                                credential encryption, and result handling
docs/
  ARCHITECTURE.md              Design rationale + future-version hooks
  BUILD.md                     Build/run/publish instructions (Windows)
  samples/sample-proxies.csv   Placeholder-only CSV import example
```

## Platform & target framework

- **.NET 10** (`net10.0` for libraries, `net10.0-windows` for the WPF
  client). .NET 10 is used because it is the current LTS-track SDK
  available in this environment and supports everything V0.1 needs
  (`SocketsHttpHandler` SOCKS5 support since .NET 6, DPAPI via
  `System.Security.Cryptography.ProtectedData`). If your organization
  standardizes on .NET 8 LTS instead, retarget the `TargetFramework`
  properties — no API used here is .NET-10-specific.
- **WPF** for the UI — the most reliable, well-supported way to ship a
  native Windows desktop app with .NET today.
- Windows 10/11 x64.

## Quick start (Windows)

1. Install the [.NET 10 SDK](https://dotnet.microsoft.com/download) (or the
   matching Desktop Runtime, for a framework-dependent release build).
2. Have Google Chrome or Microsoft Edge installed (V0.1 uses whichever is
   present — see [Known limitations](#known-limitations-for-v01)).
3. Clone this repository and open `ResidentialConnect.sln` in Visual Studio
   2022+ (or build from the CLI — see [`docs/BUILD.md`](docs/BUILD.md)).
4. Run the `ResidentialConnect.Client` project (F5). The main window opens.
5. Click **Settings / Manage Proxies → Add Proxy** and enter a Webshare
   Dedicated Static Residential proxy's host, port, username, password,
   protocol (HTTP or SOCKS5), country code, and city. (Never commit real
   credentials — see [Security](#security).)
6. Back on the main window, select the proxy, click **CONNECT**. On success
   you'll see the public IP observed through the proxy and its latency.
7. Click **OPEN BROWSER**. A new, isolated browser window opens already
   routed through the proxy; visiting an IP-checking site should show the
   Webshare IP, not your real Internet IP.

Full build/publish/release instructions: [`docs/BUILD.md`](docs/BUILD.md).

## Security

- Proxy passwords are **never** written in plaintext to disk, to the proxy
  list file, or to log files.
- Passwords are encrypted with **Windows DPAPI**
  (`CryptProtectData`/`CryptUnprotectData` via
  `System.Security.Cryptography.ProtectedData`), scoped to the current
  Windows user account — encrypted files are unreadable by other Windows
  accounts on the same machine and cannot be decrypted at all on a
  different machine.
- The proxy list (`%LOCALAPPDATA%\ResidentialConnect\proxies.json`) stores
  only non-secret fields (host, port, username, country, city, a random
  credential *reference key*) — never the password itself.
- All diagnostic logging goes through a scrubbing helper
  (`SecretScrubber`) that redacts anything that looks like a
  password/token/API key/URI userinfo before it's written to the log file,
  as defense in depth on top of "never pass a secret into a log call".
- `.gitignore` excludes all build output, local app data, and anything
  that could carry secrets. **No real Webshare credentials are anywhere in
  this repository** — every example/sample uses obvious placeholders
  (`your_webshare_username`, RFC 5737 documentation IP ranges, etc.).

## Known limitations for V0.1

These are explicitly acceptable trade-offs for a V0.1 proof of
connectivity, called out here so they're not mistaken for oversights:

- **Browser dependency**: OPEN BROWSER requires an already-installed Chrome
  or Edge. `IBrowserProvider` is the seam for a future release to ship and
  manage its own bundled Chromium build instead — see
  `docs/ARCHITECTURE.md`.
- **No system-wide routing**: CONNECT proves connectivity via a direct
  HTTPS request; it does not change the Windows system proxy or route any
  other application's traffic. Only the app-launched browser is routed.
- **Windows-only runtime**: DPAPI and the WPF UI require Windows. The
  non-UI libraries (`Core`, `Security`, `Proxy`, `Browser`) also compile
  and unit-test on Linux/macOS (see `docs/BUILD.md`), which is how this
  project's automated checks run in a non-Windows CI/dev sandbox — but the
  full application must be run and acceptance-tested on real Windows 10/11
  x64.
- **Country/city metadata is provider-supplied**: V0.1 has no live
  geo-IP verification; it trusts the country/city you type in (or import
  from Webshare's CSV export) and only cross-checks the observed public IP
  against the configured host when that host is itself a bare IP literal.

## License / usage

Internal MVP for a commercial connectivity product. See your organization's
licensing terms.
