# ResidentialConnect.StreamdumpParity

An **isolated, single-purpose diagnostic** created 2026-09-15 after the third
real-Windows run of `ResidentialConnect.RoutingDiagnostic` still failed even
after moving the production capture loops to dedicated threads and raising
WinDivert's queue headroom.

## Why this tool exists

The third instrumented run showed:

- The target flow's first **three** SYN packets were reflected and
  `WinDivertSend`-ed successfully (Win32 success, no error code), but **no**
  return-leg SYN-ACK was ever captured for any of them.
- Only the **fourth** SYN retransmit (at ~7 seconds) finally coincided with a
  captured/reflected SYN-ACK - and even then the connection was immediately
  reset (`SocketException: forcibly closed`) rather than completing a TLS
  handshake.
- The return capture thread clearly *can* process a SYN-ACK instantly once
  one exists (the 4th SYN and the SYN-ACK were captured essentially at the
  same millisecond) - ruling out simple thread starvation as the primary
  cause.

Per WinDivert's own documentation, a successful `WinDivertSend()` does **not**
guarantee the Windows TCP/IP stack actually accepted/processed the injected
packet - and inbound packet injection specifically depends on the
`WINDIVERT_DATA_NETWORK.IfIdx`/`SubIfIdx` values in the `WINDIVERT_ADDRESS`
being valid for the packet's claimed direction/interface. Our production
router currently reuses the captured packet's *own* `WINDIVERT_ADDRESS`
(including whatever `IfIdx`/`SubIfIdx` it already carried) for reinjection -
exactly what the official `streamdump.c` example does too - but production's
architecture differs from `streamdump.c` in several other ways (two separate
handles/filters instead of one, a flow table, an actual proxy relay with an
HTTP CONNECT hop) that could independently be responsible.

This tool isolates the **one** variable that matters first: does the basic,
single-handle, official-algorithm reflection technique reliably complete a
real TCP handshake on this specific Windows machine at all, with **zero**
involvement from anything else Residential Connect's production router does?

## What this tool does NOT do

- No flow table (`RedirectFlowTable`) - it hard-codes exactly one target
  flow plus one local listening port, resolved once at startup.
- No `TransparentForwardingProxy`, no `IUpstreamConnector`, no HTTP CONNECT,
  no proxy profile, no credentials of any kind.
- No DNS-leak-protection handle.
- No separate forward/return WinDivert handles - **one** `NETWORK`-layer
  handle, exactly like `streamdump.c`.
- Zero project references to `ResidentialConnect.Routing` / `.Proxy` /
  `.Core` - this tool's `WinDivertNative.cs` is an independent,
  from-scratch re-implementation of the P/Invoke layer, specifically so a
  PASS/FAIL here is not silently coupled to (or hiding a bug shared with)
  production's own ABI/struct code. It also serves as a second, independent
  re-verification of the `WINDIVERT_ADDRESS` bit layout against the real
  WinDivert 2.2.2 `windivert.h` header (re-fetched and quoted in that file's
  doc comments).

## What it does

1. Opens a local `TcpListener` on an ephemeral port (the "PROXY" role in
   `streamdump.c` terms).
2. Resolves the target host (default `1.1.1.1:443`).
3. Builds a WinDivert filter restricted to **only**: traffic to/from the
   target IP:port, and traffic to/from the local listener's port - nothing
   else on the machine is captured or logged.
4. Opens **one** `WINDIVERT_LAYER_NETWORK` handle with that filter (matching
   `streamdump.c`'s `WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0)`
   call exactly).
5. Starts a dedicated background thread running the capture loop (a lesson
   carried over from the production ThreadPool-starvation investigation,
   even though this test does not expect that variable to matter here).
6. Issues a real outbound `TcpClient.ConnectAsync` to the target - the same
   kind of real, unaware, un-proxied connection attempt
   `ResidentialConnect.RoutingDiagnostic`'s `HttpClient` makes against
   production.
7. For every captured packet, applies the **exact** `streamdump.c` reflection
   algorithm (PORT&rarr;PROXY / PROXY&rarr;PORT), reusing the packet's own
   captured `WINDIVERT_ADDRESS` and only modifying what the official example
   modifies (source/destination IP, the relevant TCP port, and the
   `Outbound` bit) - no additional field is touched.
8. Logs, for every single captured packet: timestamp (ms since process
   start), source/destination IP:port, SYN/ACK/RST/FIN flags, sequence and
   ACK numbers, `Outbound`/`Loopback`/`Impostor`/`IPChecksumValid`/
   `TCPChecksumValid`, `Network.IfIdx`/`SubIfIdx`, and the IP/TCP checksum
   fields both before and after `WinDivertHelperCalcChecksums`.
9. Logs the moment (if ever) the local listener's `AcceptTcpClientAsync`
   completes, and what apparent peer endpoint it reports.
10. Prints a final PASS/FAIL verdict plus an explicit interpretation of what
    that result means for where to look next.

## How to interpret the result

- **PASS** (the handshake completes quickly, no multi-second gap before a
  SYN-ACK is captured): basic WinDivert reflection works fine on this
  machine. The bug is very likely specific to production's own two-handle /
  flow-table / relay / CONNECT architecture - the next investigation should
  compare this tool's single-handle filter/algorithm against
  `WinDivertSystemTrafficRouter`'s two-handle design line by line.
- **FAIL** (this test *also* shows the first N SYNs seemingly ignored, or a
  multi-second delay before any SYN-ACK, or a handshake that completes but
  is then reset): the problem is almost certainly not in Residential
  Connect's proxy/relay code at all. Focus next on: `Network.IfIdx`/
  `SubIfIdx` handling (are these being left as whatever the ORIGINAL captured
  packet had, when a genuinely different interface index might be required
  for the reflected direction on this machine's NIC/driver stack?), the
  `IPChecksum`/`TCPChecksum` validity flags in `WINDIVERT_ADDRESS` (should
  `WinDivertHelperCalcChecksums`'s 4th `flags` argument be non-zero to force
  recalculation of specific fields rather than "all applicable"?), the
  P/Invoke ABI (re-verified independently by this tool's own
  `WinDivertNative.ValidateAbi`), or Windows Filtering
  Platform/anti-spoofing/NIC-offload behavior specific to this machine.

## Usage

```powershell
cd tools\ResidentialConnect.StreamdumpParity
dotnet run -c Release
```

Optional arguments: `--target-host HOST` (default `1.1.1.1`), `--target-port
PORT` (default `443`), `--timeout-seconds N` (default `15`).

Must be run as Administrator (WinDivert requirement). No proxy profile,
credentials, or prior app configuration is needed - this tool is completely
self-contained.
