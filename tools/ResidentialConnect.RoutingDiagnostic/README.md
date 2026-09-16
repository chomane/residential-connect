# ResidentialConnect.RoutingDiagnostic

Headless, scriptable acceptance test for Whole Computer mode's WinDivert
reflection fix AND (2026-09-16 addition) its UDP/DNS leak-protection
handles. This is **not** part of the shipped desktop app — it is a
standalone console tool for a Windows tester (or a CI runner on a Windows
host with Administrator rights) to run the full acceptance test — the
original TCP acceptance test described in
`ResidentialConnect_GenSpark_Handoff_2026-09-15.md`, plus the newer UDP/DNS
checks — without any manual clicking, curling, or timing.

## What it does

1. Loads the already-configured proxy profile(s) from the same on-disk
   store the real app uses (`AppPaths.ProxiesFilePath` /
   `AppPaths.CredentialsDirectory`), so it exercises the exact same
   `ProxyProfile` + password the desktop app would use — no
   duplicated/faked credentials.
2. **Before** starting routing: makes a real TCP+TLS baseline request, and
   sends one raw, hand-built UDP/53 DNS query directly over a socket to a
   public resolver (default `1.1.1.1`) — both must succeed, proving normal
   networking (TCP *and* UDP) works before any interception exists.
3. Starts `WinDivertSystemTrafficRouter` (Whole Computer routing) for the
   selected profile, exactly like `DefaultConnectionManager` does.
4. **While Active:**
   - Makes a real TCP+TLS request to a known-good HTTPS endpoint (default:
     `https://1.1.1.1`) from a genuine, unmodified `HttpClient` in this
     process — traffic that has no idea it is being intercepted, exactly
     mirroring what `curl.exe` or any other ordinary Windows application
     would do.
   - Optionally checks the observed egress IP against `api.ipify.org` to
     confirm traffic is actually leaving via the proxy (not leaking direct).
   - Repeats the exact same raw UDP/53 DNS query from step 2 — this time a
     **PASS requires NO response** (a timeout), proving the DNS-block
     WinDivert Drop handle (`BypassFilterBuilder.BuildDnsFilter`) actually
     stops the query from leaving the machine.
   - Makes an HTTP/3-exact (`HttpVersionPolicy.RequestVersionExact`, QUIC
     over UDP/443) request to an HTTP/3-capable endpoint (default:
     `https://cloudflare-quic.com/`) — a **PASS requires the request to
     fail/time out**, proving the general UDP-block handle
     (`BypassFilterBuilder.BuildUdpBlockFilter`) also stops non-DNS UDP. If
     `System.Net.Quic.QuicConnection.IsSupported` is `false` on this
     machine (missing msquic/TLS 1.3/OS prerequisites), this check is
     reported **SKIP**, never silently as PASS or FAIL.
5. Stops routing (`StopAsync`) and:
   - Repeats the raw UDP/53 DNS query, this time expecting it to **succeed
     again**, confirming UDP networking (not just TCP) is fully restored.
   - Re-runs the TCP+TLS request, expecting it to still succeed via the
     normal (direct) path, confirming clean TCP disconnect too.
6. Prints a `[PASS]`/`[FAIL]`/`[SKIP]` line per step, a final **acceptance
   summary banner** with six independently-reported results, and sets the
   process exit code (`0` = full pass, non-zero = failure), so it can be
   wired into a script or CI step without a human reading prose output.

## Requirements

- Windows 10/11 x64.
- **Run as Administrator** (same requirement as
  `ISystemTrafficRouter.RequiresElevation`).
- At least one proxy profile already added and saved via the main app
  (Add Proxy -> Test -> Save) before running this tool, so a real,
  already-verified password is available through `ICredentialStore`.
- Outbound UDP/53 to the DNS probe server (default `1.1.1.1:53`) must be
  reachable from this machine/network *before* routing starts — otherwise
  the pre-routing UDP baseline (step 2) fails and the tool cannot
  distinguish "this app blocked it" from "something else already blocks
  it". Use `--dns-test-ip` to point at a different resolver if needed.
- HTTP/3 support is optional, not required — if this machine's .NET/OS
  cannot attempt QUIC at all, the corresponding check is reported `SKIP`
  and does not fail the overall run.

## Usage

From an elevated PowerShell/cmd, from the repo root:

```
cd tools/ResidentialConnect.RoutingDiagnostic
dotnet run -c Release
```

Or build/publish once and run the exe directly:

```
dotnet publish tools/ResidentialConnect.RoutingDiagnostic/ResidentialConnect.RoutingDiagnostic.csproj -c Release -r win-x64 -o publish/routing-diagnostic
cd publish/routing-diagnostic
ResidentialConnect.RoutingDiagnostic.exe
```

### Options

| Option | Meaning | Default |
|---|---|---|
| `--test-url <url>` | HTTPS URL to request through Whole Computer routing (TCP checks) | `https://1.1.1.1` |
| `--timeout-seconds <n>` | Per-request timeout in seconds for TCP/HTTP checks (also used for the HTTP/3 check) | `15` |
| `--udp-timeout-seconds <n>` | Per-probe timeout in seconds for the raw UDP/53 DNS checks | `5` |
| `--skip-ip-check` | Skip the `api.ipify.org` egress-IP-changed verification | off |
| `--profile-id <guid>` | Use a specific saved proxy profile id instead of the currently selected/first one | none (uses selected/first) |
| `--dns-test-ip <ip>` | Public DNS resolver IP for the raw UDP/53 probe | `1.1.1.1` |
| `--dns-test-host <name>` | Hostname to query in the raw UDP/53 probe | `example.com` |
| `--quic-test-url <url>` | HTTP/3-capable HTTPS URL for the UDP/443 QUIC block check | `https://cloudflare-quic.com/` |

## Reading the output

Each line is prefixed `[PASS]`, `[FAIL]`, or `[SKIP]` with a step name:

- `ELEVATION`, `PROFILE`, `ROUTER-SUPPORTED` — preconditions.
- `BASELINE-REQUEST` — TCP sanity check that the network works at all
  *before* routing starts. If this fails, fix your network first; it is
  unrelated to Whole Computer mode.
- `RAW-UDP-DNS-BASELINE` — the raw UDP/53 probe *before* routing starts.
  Must PASS (a real response received) for the later
  `UDP-DNS-BLOCKED-WHILE-ACTIVE` result to mean anything — see the
  Requirements section above.
- `ROUTING-START` — `StartAsync` reached `Active`.
- `ROUTED-REQUEST` — **the original TCP acceptance test.** If this fails
  with a timeout, that matches the original bug this fix targets
  (reflection not completing the SYN/SYN-ACK handshake). If it fails with a
  connection reset shortly after connecting, that matches the checkpoint's
  "ReflectProof" partial-progress symptom — capture a packet trace
  (Wireshark) during this exact run and compare against WinDivert's
  `streamdump.c` expected sequence.
- `EGRESS-IP-CHANGED` — confirms traffic actually left via the proxy, not
  just that *some* HTTPS request happened to succeed (e.g. via a leak).
- `UDP-DNS-BLOCKED-WHILE-ACTIVE` — **PASS means the raw UDP/53 probe got NO
  response** while Active. A FAIL here means plain DNS is leaking outside
  the proxy — inspect `BypassFilterBuilder.BuildDnsFilter` /
  `DnsLeakGuard`.
- `UDP-QUIC-BLOCKED-WHILE-ACTIVE` — **PASS means the HTTP/3 request could
  NOT complete** while Active. **SKIP means HTTP/3 is unavailable on this
  machine** (`QuicConnection.IsSupported == false`) — this is a genuine
  capability gap, not evidence either way, and does not fail the overall
  run. A FAIL here means non-DNS UDP (QUIC/HTTP-3) is leaking — inspect
  `BypassFilterBuilder.BuildUdpBlockFilter`.
- `ROUTING-STOP` — confirms clean teardown.
- `UDP-DNS-RESTORED-AFTER-DISCONNECT` — the raw UDP/53 probe again after
  `StopAsync`; must PASS (respond normally again).
- `POST-DISCONNECT-REQUEST` — confirms normal TCP networking is restored
  afterward.

After the step log, an **`=== ACCEPTANCE SUMMARY ===`** banner reports six
independent results explicitly, regardless of which step above produced
each one:

```
[PASS] TCP routed through proxy
[PASS] Proxy egress verified (IP changed)
[PASS] UDP/53 (DNS) blocked while Active
[PASS] General UDP/QUIC (HTTP/3) blocked while Active     <- or [SKIP] with a reason
[PASS] UDP restored after disconnect
[PASS] TCP restored after disconnect
```

The final line is one of:

```
=== OVERALL RESULT: PASS - Whole Computer mode routed real TCP traffic, blocked UDP leaks, and cleaned up correctly. ===
=== OVERALL RESULT: FAIL - see the failed step(s) and acceptance summary above. Do NOT consider Whole Computer mode / PR #3 verified. ===
```

A SKIPped HTTP/3 check (a genuine, detected capability limitation on that
specific machine) does **not** turn an otherwise-passing run into FAIL; an
actual FAIL on any required check does.

A PASS here is the evidence needed before PR #3 can be considered for
merge (per the handoff's explicit "do not merge until proven stable"
instruction) — but it should still be followed by a short real-world check
(e.g. opening Telegram Desktop or a normal browser while connected) before
fully trusting it, since this tool only proves specific test
destinations/protocols, not every protocol/traffic pattern a real desktop
generates.
