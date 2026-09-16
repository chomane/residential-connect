# Verified checkpoints

This file records specific commits that have been **confirmed working on
real Windows hardware** by an explicit acceptance run, together with the
exact evidence that confirmed it and the files that implement the verified
behavior. Its purpose is to give every subsequent change a clear, named
baseline to preserve: unless a NEW real-Windows diagnostic run produces
contradicting evidence, the files listed under a checkpoint must not be
modified as a side effect of unrelated work.

---

## TCP VERIFIED — commit `145c130119cd889cf8dc3ec45e761e43ee1c008d` (2026-09-16)

**Status: Whole Computer (V0.2) TCP traffic routing is VERIFIED end-to-end on
real Windows 10/11 x64 hardware.**

### Real-Windows acceptance evidence

A real-Windows run of `tools/ResidentialConnect.RoutingDiagnostic` at this
commit produced:

- A redirected HTTPS request (via an ordinary `HttpClient` with **no** proxy
  configured on it - exactly like curl.exe or any other unaware Windows
  application) succeeded with **HTTP 200**.
- `app->upstream` transferred real application payload (the client's TLS
  ClientHello and beyond) - not zero bytes.
- `upstream->app` transferred real application payload (the server's TLS
  response and beyond) - not zero bytes.
- The RETURN capture handle correctly captured and reflected
  **established-flow** packets carrying `Impostor=True` (the relay's own ACK
  for the client's post-handshake DATA, not just the initial `SYN,ACK`) -
  this was the specific, final blocker fixed by this commit.
- The egress IP, verified via `https://api.ipify.org`, changed from the
  machine's real Internet IP to the **residential proxy's** IP while routing
  was Active.
- `StopAsync()` cleanly restored **direct**, unrouted networking afterward
  (the post-disconnect request in the same diagnostic run succeeded exactly
  as the pre-routing baseline request did).
- The diagnostic tool's own final line read:
  `=== OVERALL RESULT: PASS - Whole Computer mode routed real traffic and cleaned up correctly. ===`

### What this checkpoint covers

The full TCP reflection/redirect pipeline for Whole Computer mode:

1. WinDivert-based interception of real, non-loopback outbound TCP traffic
   (forward leg) and the local relay's own reply traffic (return leg).
2. Full 4-tuple packet **reflection** (swap source/destination, flip
   direction from Outbound to Inbound, recalculate checksums, reinject) -
   including for established-flow DATA segments carrying `Impostor=True` on
   BOTH the forward and return legs, not just the SYN/SYN-ACK handshake.
3. `RedirectFlowTable`'s NAT-style flow tracking, keyed by client port, for
   the full lifetime of a redirected TCP connection.
4. `TransparentForwardingProxy` accepting the kernel-redirected connection,
   resolving the original destination, and opening an authenticated upstream
   tunnel (`HttpConnectUpstreamConnector` for HTTP CONNECT proxies).
5. `UpstreamRelayHelper`'s bidirectional byte-splicing relay (the
   `Task.WhenAny`-based pattern already used successfully by V0.1's
   `LocalForwardingProxy`).
6. Fail-closed behavior end-to-end, and a clean, complete restoration of
   direct networking on `StopAsync()`.

### Files that implement this VERIFIED behavior (do not modify without new real-Windows evidence)

- `src/ResidentialConnect.Routing/BypassFilterBuilder.cs` -
  `BuildForwardFilter` and `BuildReturnFilter` specifically (both
  deliberately do NOT exclude `impostor` packets - see that file's own
  extensive remarks for the two real-Windows fixes that established this).
  `BuildDnsFilter` is a separate, DNS-only concern - see the UDP/DNS
  checkpoint note below.
- `src/ResidentialConnect.Routing/PacketRedirectPlanner.cs` - the pure
  forward/return redirect decision logic (`PlanForward`, `PlanReturn`,
  `RedirectDecision`, `CapturedTcpPacket`).
- `src/ResidentialConnect.Routing/RedirectFlowTable.cs` - the flow-tracking
  NAT table.
- `src/ResidentialConnect.Routing/WinDivertSystemTrafficRouter.cs` - the TCP
  forward/return capture loops, dedicated-thread scheduling, queue
  headroom, reflection application, and checksum/send logic. (Its DNS/UDP
  handle wiring is additive and covered separately - see below.)
- `src/ResidentialConnect.Routing/WinDivertNative.cs` - the P/Invoke ABI
  layer (struct layouts, `MarkInbound`, `CalcChecksums`, etc.).
- `src/ResidentialConnect.Proxy/Forwarding/TransparentForwardingProxy.cs` -
  the accept loop, original-destination resolution, and relay wiring (its
  diagnostic-only logging additions are fine to extend; its actual
  connection-handling/relay-invocation logic is the verified part).
- `src/ResidentialConnect.Proxy/Forwarding/UpstreamRelayHelper.cs` - the
  shared bidirectional relay (`RelayBidirectionalAsync`/`CopyAsync`) used by
  both V0.1's `LocalForwardingProxy` and V0.2's `TransparentForwardingProxy`.
- `src/ResidentialConnect.Proxy/Forwarding/HttpConnectUpstreamConnector.cs` -
  the upstream HTTP CONNECT handshake.

**Any further work on Whole Computer mode (DNS leak protection, UDP
handling, etc.) must be strictly additive to this list** - new WinDivert
handles, new filter-builder methods, new diagnostic steps - never a
modification of the TCP reflection/redirect/relay logic above, unless a new
real-Windows diagnostic run produces contradicting evidence and this
checkpoint is explicitly revised (with the new evidence recorded here).
