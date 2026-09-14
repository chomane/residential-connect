# Architecture — Residential Connect V0.1

## Goals driving the design

1. **Extreme simplicity for the end user** — the UI never mentions proxies,
   SOCKS, ports, or authentication. All of that complexity lives behind a
   handful of Core interfaces.
2. **Never leak a secret** — passwords are encrypted at rest (Windows
   DPAPI), never logged, never serialized into the plain proxy-list JSON,
   and never committed to source control.
3. **Modular for the road-map** — V0.1 only implements local browser
   connectivity, but the codebase already has named seams (interfaces) for
   whole-computer routing, kill switch, failover, provider API integration,
   accounts/billing, and a Cloud Browser — **without implementing any of
   them**, so V0.2+ can be additive rather than a rewrite.

## Project map and responsibilities

```
ResidentialConnect.Core       — Pure C#, no I/O, no third-party deps.
                                 Models (ProxyProfile, ProxyTestResult,
                                 ConnectionState), interfaces
                                 (IProxyRepository, ICredentialStore,
                                 IProxyConnectivityTester, IConnectionManager,
                                 IBrowserLauncher, ILocalForwardingProxy),
                                 validation (ProxyValidation), a tiny
                                 offline country/flag lookup
                                 (CountryCatalog), app data paths
                                 (AppPaths), and logging abstractions
                                 (IAppLogger, SecretScrubber).
                                 Also hosts Abstractions/Future/* — interfaces
                                 for V0.2+ features, intentionally
                                 unimplemented in V0.1.

ResidentialConnect.Security   — DPAPI-backed secret storage.
                                 IDataProtector abstracts the OS primitive
                                 (DpapiDataProtector on Windows) so
                                 FileCredentialStore can be unit-tested
                                 cross-platform with a fake protector.
                                 FileCredentialStore persists one encrypted
                                 file per secret under
                                 %LOCALAPPDATA%\ResidentialConnect\Credentials,
                                 named by an opaque GUID-based key
                                 (CredentialKeyFactory) that is the only
                                 thing ProxyProfile ever stores.

ResidentialConnect.Proxy      — Everything proxy-protocol related:
                                 - Http/ProxyWebProxyFactory: builds a
                                   System.Net.WebProxy for either an HTTP
                                   proxy or a socks5:// proxy (both
                                   supported natively by
                                   SocketsHttpHandler since .NET 6).
                                 - HttpProxyConnectivityTester: the single
                                   implementation of "validate + authenticate
                                   + HTTPS request + measure latency +
                                   compare IP" used by both the Test button
                                   and the CONNECT button.
                                 - IpEcho/IpifyEchoService: queries a short
                                   ordered list of public IP-echo endpoints.
                                 - Csv/*: Webshare-style CSV parsing
                                   (IP,Port,Username,Password,Country,City)
                                   and import (validates + stores credentials
                                   + persists profiles, per-row error
                                   reporting).
                                 - Repository/JsonProxyRepository: CRUD +
                                   selection persisted to proxies.json
                                   (non-secret fields only).
                                 - Forwarding/*: the local, unauthenticated
                                   loopback relay used by OPEN BROWSER (see
                                   "Automatic browser proxy auth" below).
                                 - DefaultConnectionManager: the
                                   IConnectionManager used by the main
                                   screen's CONNECT/DISCONNECT button.

ResidentialConnect.Browser     — IBrowserProvider (finds a Chromium
                                 executable) + IBrowserLauncher
                                 (ChromiumBrowserLauncher: starts the local
                                 relay, launches the browser with
                                 --proxy-server pointed at that relay and an
                                 isolated --user-data-dir, stops the relay
                                 when the browser process exits).

ResidentialConnect.Client      — WPF UI: App.xaml.cs is a small hand-rolled
                                 composition root (no DI container needed at
                                 this size) that wires concrete
                                 implementations to the Core interfaces.
                                 MainWindow, ManageProxiesWindow, and
                                 AddEditProxyWindow are thin — all real logic
                                 lives in Core/Security/Proxy/Browser so it
                                 is unit-testable without any UI framework.
```

## Why HTTP CONNECT *and* SOCKS5 in V0.1

Webshare's Dedicated Static Residential proxies are typically offered over
both an HTTP(S) endpoint (CONNECT-based tunneling) and a SOCKS5 endpoint.
.NET's `SocketsHttpHandler` (which backs `HttpClientHandler`/`HttpClient` on
every OS since .NET 6) natively understands both `http://` and `socks5://`
proxy URIs, including username/password authentication for SOCKS5 (RFC
1929). `ProxyProfile.Protocol` + `ProxyWebProxyFactory` is the single place
that decides which scheme to build, so `HttpProxyConnectivityTester` and
`DefaultConnectionManager` needed no protocol-specific branching — both
protocols share one, well-tested code path for validate/authenticate/test.

## Automatic browser proxy authentication (the tricky part)

Chromium's `--proxy-server` command-line flag has **no way to embed a
password**, and Manifest V3 removed the `webRequest` blocking APIs an
extension would need to answer a `407 Proxy Authentication Required`
challenge programmatically. Both of these are the reason many DIY
"launch Chrome with a proxy" scripts end up popping the native OS
credential dialog — which fails the "no credential prompts" requirement.

**Solution used here**: `ResidentialConnect.Proxy.Forwarding` implements a
tiny **unauthenticated HTTP proxy bound to `127.0.0.1`**
(`LocalForwardingProxy`). `ChromiumBrowserLauncher`:

1. Starts this relay on an ephemeral loopback port, configured with the
   *real* Webshare host/port/username/password (resolved once via
   `ICredentialStore`, kept only in memory for the browser session).
2. Launches Chrome/Edge with `--proxy-server=127.0.0.1:<port>` — the
   browser sees a proxy that requires **no authentication at all**, so it
   never prompts.
3. Every TCP connection the browser opens to that relay is transparently
   relayed to the real upstream proxy, with the relay performing the actual
   HTTP CONNECT (`Proxy-Authorization: Basic ...`) or SOCKS5
   (RFC 1929 username/password subnegotiation) handshake on the browser's
   behalf — see `HttpConnectUpstreamConnector` and `Socks5UpstreamConnector`.
4. When the browser process exits, the relay is stopped, closing the
   loopback listener.

This keeps credentials out of the browser process entirely, requires no
Chrome extension, works identically for both proxy protocols, and needs no
elevation or system-wide proxy changes.

## Logging & secret hygiene

- `IAppLogger` is a minimal structured logger; the WPF client's
  `SimpleFileLogger` appends timestamped lines to
  `%LOCALAPPDATA%\ResidentialConnect\Logs\app-YYYYMMDD.log`.
- **Primary control**: no code path ever passes a raw password into a log
  call — passwords are resolved from `ICredentialStore` only at the moment
  they're needed (building a `WebProxy`/upstream connector) and are not
  retained anywhere else.
- **Defense in depth**: `SecretScrubber.Scrub(...)` redacts
  `password=...`/`token=...`/`secret=...`/`Authorization: ...`-style
  substrings and `user:pass@host` URI userinfo before any message reaches
  the log sink, in case a future change accidentally interpolates one.
- `HttpProxyConnectivityTester` and `LocalForwardingProxy` always log
  through `SecretScrubber`.

## Data storage layout (Windows)

```
%LOCALAPPDATA%\ResidentialConnect\
  proxies.json          Non-secret proxy profile fields + selected proxy id
  Credentials\*.cred    One DPAPI-encrypted file per stored password
  Logs\app-*.log        Non-secret diagnostic logs (scrubbed)
  BrowserProfiles\<id>  Isolated Chromium --user-data-dir per proxy profile
```

None of this is checked into source control; `.gitignore` also excludes
build output (`bin/`, `obj/`) and the `publish/` folder used for release
builds.

## Extension points reserved for future versions (NOT implemented in V0.1)

All declared in `ResidentialConnect.Core.Abstractions.Future`, each with an
XML-doc banner explicitly stating "PLANNED FOR A FUTURE RELEASE - NOT
IMPLEMENTED IN V0.1":

| Interface                        | Future feature                                   |
|-----------------------------------|---------------------------------------------------|
| `ISystemRoutingProvider`          | Whole-computer traffic routing                     |
| `IPerApplicationRoutingProvider`  | Per-application routing                            |
| `IKillSwitch`                     | Kill switch on unexpected disconnect               |
| `IFailoverPolicy`                 | Automatic failover / proxy replacement             |
| `IProxyProvisioningService`       | Webshare API integration, automatic IP provisioning|
| `IAccountService`                 | User accounts                                      |
| `IRemoteConfigService`            | Remote configuration                               |
| `IUpdateService`                  | Automatic application updates                      |
| `ICloudBrowserService`            | Standalone Cloud Browser product                   |

`IBrowserProvider` (in `ResidentialConnect.Browser`, not `Future`) is the
seam for shipping/managing a bundled Chromium build instead of depending on
an installed Chrome/Edge — V0.1's `InstalledBrowserProvider` is explicitly
documented as a temporary implementation of that interface.

`ProxyProfile.Protocol` already models multiple transports
(`ProxyProtocol.Http` / `.Socks5`); adding a third transport later is an
enum + factory-branch change, not a redesign.

## Testing strategy

`tests/ResidentialConnect.Tests` (xUnit) covers exactly the areas called
out as required, using in-memory/fake test doubles
(`InMemoryProxyRepository`, `InMemoryCredentialStore`,
`FakeReversibleProtector`, `NullLogger`) so the suite runs on any OS with no
network access and no real Windows DPAPI:

- **Proxy configuration validation** (`ProxyValidationTests`) — valid
  profile, invalid port ranges, missing password, invalid host, missing
  country.
- **Proxy import/parsing** (`ProxyCsvParserTests`, `ProxyCsvImporterTests`)
  — well-formed CSV, header-row auto-detection, blank-line handling,
  per-row success/failure isolation (one bad row doesn't abort the batch),
  credentials stored separately from the profile record.
- **Credential encryption/decryption** (`CredentialEncryptionTests`) —
  round-trip save/retrieve, ciphertext file never contains the plaintext
  password, missing-key retrieval, deletion.
- **Health/connectivity test result handling** (`ProxyTestResultTests`) —
  `Successful`/`Failed` factory methods populate the expected fields.
- **Secret scrubbing** (`SecretScrubberTests`) — password key/value pairs
  and URI userinfo are redacted from log messages.

`HttpProxyConnectivityTester`, `LocalForwardingProxy`, and
`ChromiumBrowserLauncher` themselves are exercised end-to-end only on real
Windows against a real (placeholder-configured in dev) proxy and browser —
see the **Known limitations** section of the README for exactly what still
needs a Windows machine to verify.
