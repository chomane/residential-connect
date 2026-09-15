# ResidentialConnect.RoutingDiagnostic

Headless, scriptable acceptance test for Whole Computer mode's WinDivert
reflection fix. This is **not** part of the shipped desktop app — it is a
standalone console tool for a Windows tester (or a CI runner on a Windows
host with Administrator rights) to run the exact acceptance test described
in `ResidentialConnect_GenSpark_Handoff_2026-09-15.md` without any manual
clicking, curling, or timing.

## What it does

1. Loads the already-configured proxy profile(s) from the same on-disk
   store the real app uses (`AppPaths.ProxiesFilePath` /
   `AppPaths.CredentialsDirectory`), so it exercises the exact same
   `ProxyProfile` + password the desktop app would use — no
   duplicated/faked credentials.
2. Starts `WinDivertSystemTrafficRouter` (Whole Computer routing) for the
   selected profile, exactly like `DefaultConnectionManager` does.
3. Makes a real TCP+TLS request to a known-good HTTPS endpoint (default:
   `https://1.1.1.1`) from a genuine, unmodified `HttpClient` in this
   process — traffic that has no idea it is being intercepted, exactly
   mirroring what `curl.exe` or any other ordinary Windows application
   would do.
4. Optionally checks the observed egress IP against `api.ipify.org` to
   confirm traffic is actually leaving via the proxy (not leaking direct).
5. Stops routing and re-runs the same request, expecting it to still
   succeed via the normal (direct) path, confirming clean disconnect.
6. Prints a `[PASS]`/`[FAIL]` line per step and sets the process exit code
   (`0` = full pass, non-zero = failure), so it can be wired into a script
   or CI step without a human reading prose output.

## Requirements

- Windows 10/11 x64.
- **Run as Administrator** (same requirement as
  `ISystemTrafficRouter.RequiresElevation`).
- At least one proxy profile already added and saved via the main app
  (Add Proxy -> Test -> Save) before running this tool, so a real,
  already-verified password is available through `ICredentialStore`.

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
| `--test-url <url>` | HTTPS URL to request through Whole Computer routing | `https://1.1.1.1` |
| `--timeout-seconds <n>` | Per-request timeout in seconds | `15` |
| `--skip-ip-check` | Skip the `api.ipify.org` egress-IP-changed verification | off |
| `--profile-id <guid>` | Use a specific saved proxy profile id instead of the currently selected/first one | none (uses selected/first) |

## Reading the output

Each line is prefixed `[PASS]` or `[FAIL]` with a step name:

- `ELEVATION`, `PROFILE`, `ROUTER-SUPPORTED` — preconditions.
- `BASELINE-REQUEST` — sanity check that the network works at all *before*
  routing starts. If this fails, fix your network first; it is unrelated
  to Whole Computer mode.
- `ROUTING-START` — `StartAsync` reached `Active`.
- `ROUTED-REQUEST` — **the actual acceptance test.** If this fails with a
  timeout, that matches the original bug this fix targets (reflection not
  completing the SYN/SYN-ACK handshake). If it fails with a connection
  reset shortly after connecting, that matches the checkpoint's
  "ReflectProof" partial-progress symptom — capture a packet trace
  (Wireshark) during this exact run and compare against WinDivert's
  `streamdump.c` expected sequence.
- `EGRESS-IP-CHANGED` — confirms traffic actually left via the proxy, not
  just that *some* HTTPS request happened to succeed (e.g. via a leak).
- `ROUTING-STOP`, `POST-DISCONNECT-REQUEST` — confirms clean teardown and
  that normal networking is restored afterward.

The final line is one of:

```
=== OVERALL RESULT: PASS - Whole Computer mode routed real traffic and cleaned up correctly. ===
=== OVERALL RESULT: FAIL - see the failed step(s) above. Do NOT consider Whole Computer mode / PR #3 verified. ===
```

A `PASS` here is the evidence needed before PR #3 can be considered for
merge (per the handoff's explicit "do not merge until proven stable"
instruction) — but it should still be followed by a short real-world check
(e.g. opening Telegram Desktop or a normal browser while connected) before
fully trusting it, since this tool only proves one HTTPS destination over
plain TCP, not every protocol/traffic pattern a real desktop generates.
