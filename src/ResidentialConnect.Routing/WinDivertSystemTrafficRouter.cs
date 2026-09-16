using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Dns;

namespace ResidentialConnect.Routing;

/// <summary>
/// <see cref="ISystemTrafficRouter"/> implementation for V0.2, built on
/// <a href="https://reqrypt.org/windivert.html">WinDivert</a> - a mature,
/// widely-used, dual-licensed (LGPLv3/GPLv2) Windows kernel driver + user-mode
/// library for capturing, modifying, and re-injecting network packets. This
/// router calls the official native WinDivert 2.2.2 API directly (see
/// <see cref="WinDivertNative"/>) via the <c>Native.WinDivert</c> package
/// (which ships the official, unmodified <c>WinDivert.dll</c>/<c>WinDivert64.sys</c>
/// binaries) rather than through a third-party managed wrapper - see
/// <see cref="WinDivertNative"/>'s remarks for why. WinDivert was chosen, per
/// the product requirement, specifically to AVOID inventing a custom network
/// driver/protocol - it is the standard, proven component the Windows
/// community already uses for exactly this "system-wide transparent proxy
/// redirect" use case (the same fundamental technique used by numerous
/// public WinDivert-based proxy tools, and documented by WinDivert's own
/// <c>streamdump.c</c> example).
/// </summary>
/// <remarks>
/// <para><b>How interception/redirection actually works (the "reflection" pattern):</b></para>
/// <list type="number">
/// <item>Four WinDivert handles are opened at <see cref="WinDivertNative.Layer.Network"/>
/// (the only layer that can both capture AND re-inject modified packets):
///   <list type="bullet">
///   <item>A <b>DNS-block handle</b> (see <see cref="DnsLeakGuard"/>) opened
///   with <see cref="WinDivertNative.OpenFlags.Drop"/> - the driver itself
///   silently drops matching packets in-kernel; nothing is ever delivered to
///   user mode. This alone is V0.2's entire DNS leak protection.</item>
///   <item>A <b>UDP-block handle</b> (2026-09-16 addition; see
///   <see cref="BypassFilterBuilder.BuildUdpBlockFilter"/>), ALSO opened
///   with <see cref="WinDivertNative.OpenFlags.Drop"/> and ALSO entirely
///   in-kernel/fail-closed. Blocks every other real, non-loopback outbound
///   UDP packet (i.e. everything except UDP/53, which the DNS-block handle
///   above already owns) because the current Residential Connect upstream
///   implementation does not proxy UDP: HTTP CONNECT is TCP-only, and our
///   current SOCKS5 connector implements TCP CONNECT only (SOCKS5 UDP
///   ASSOCIATE is not implemented) - see that method's remarks for the full
///   rationale. This is purely additive: it does not touch the DNS-block
///   handle or either TCP handle below.</item>
///   <item>A <b>forward handle</b> capturing real, non-loopback outbound TCP
///   traffic (<see cref="BypassFilterBuilder.BuildForwardFilter"/>), excluding
///   traffic to the upstream proxy itself and the local relay's own reply
///   traffic (see that method's remarks for why the latter exclusion is
///   required). Deliberately does <b>NOT</b> exclude <c>impostor</c> packets
///   - see <see cref="BypassFilterBuilder"/> class remarks for the
///   2026-09-15 real-Windows evidence that doing so silently discarded the
///   client's own handshake-completing ACK.</item>
///   <item>A <b>return handle</b> capturing the local transparent relay's
///   own reply traffic back toward the redirected application
///   (<see cref="BypassFilterBuilder.BuildReturnFilter"/>). As of a
///   2026-09-16 fix, this ALSO deliberately does not exclude <c>impostor</c>
///   packets, for the same reason one hop later - see
///   <see cref="BypassFilterBuilder"/> class remarks.</item>
///   </list>
/// </item>
/// <item>
/// For each captured forward/return packet, <see cref="PacketRedirectPlanner"/>
/// decides whether/how to <b>reflect</b> it: swap source and destination
/// address/port (recovering the piece of information the forward leg
/// necessarily discards - the real destination port - from
/// <see cref="RedirectFlowTable"/>), then flip the packet's direction from
/// Outbound to Inbound (<see cref="WinDivertNative.MarkInbound"/>) before
/// recalculating checksums and re-injecting it with <c>WinDivertSend</c>.
/// See <see cref="RedirectDecision"/>'s remarks for the full worked example
/// of both legs and, importantly, WHY a naive "just rewrite the destination,
/// keep Outbound" approach (this router's own earlier, broken design) does
/// not actually work - it is not a WinDivert-supported way to deliver a
/// packet locally, and real Windows testing observed exactly the predicted
/// symptom (traffic timing out / getting reset) until reflection was
/// implemented.
/// </item>
/// </list>
/// <para><b>Loop prevention:</b> as of the 2026-09-15/16 fixes, NEITHER the
/// forward nor the return filter excludes <c>impostor</c> packets any more
/// (only the DNS-block filter still does) - see
/// <see cref="BypassFilterBuilder"/> class remarks for the real-Windows
/// evidence that WinDivert's Impostor flag is a flow-provenance marker, not
/// a "this exact packet was re-sent unchanged" marker, and that excluding it
/// on either leg silently discarded genuine established-flow packets
/// (the client's handshake-completing ACK on the forward leg; the relay's
/// own ACK for established-flow DATA on the return leg). Loop prevention
/// instead relies on three OTHER independent mechanisms: (a) every packet
/// this router itself reflects and re-sends is explicitly marked
/// <c>Inbound</c> before re-injection, so it can never again match either
/// filter's mandatory <c>outbound</c> clause, regardless of its impostor
/// flag; (b) the forward filter also excludes any packet addressed to the
/// upstream proxy's own host:port and any packet SOURCED from the local
/// relay's own listening port, and the return filter requires
/// <c>tcp.SrcPort == relayPort</c> (<see cref="BypassFilterBuilder"/>
/// remarks) - together satisfying "Residential Connect's own upstream proxy
/// connection must bypass its own interception path"; (c)
/// <see cref="PacketRedirectPlanner"/>'s own flow-table gate fail-closed
/// drops any packet that is not either a brand-new SYN or part of an
/// already-tracked flow.</para>
/// <para><b>Fail-closed:</b> <see cref="ITransparentForwardingProxy.Faulted"/>
/// drives an immediate transition to <see cref="SystemRoutingStatus.FailedClosed"/>;
/// while in that state (and at every other point where a captured packet does
/// not match a rule this class explicitly understands how to redirect), the
/// packet loops simply DROP the packet - it is never resent unmodified. The
/// unavoidable side effect (documented as a known limitation) is that any TCP
/// connection already open before Whole Computer mode was enabled, or in
/// flight at the moment of a fail-closed transition, stalls rather than
/// continuing over the real network.</para>
/// <para><b>Admin/elevation requirement:</b> <see cref="RequiresElevation"/>
/// is always true. Opening ANY WinDivert handle requires the calling process
/// to run as Administrator - <see cref="IsSupported"/> checks this up front
/// (see <see cref="IsCurrentProcessElevated"/>) purely via
/// <see cref="WindowsIdentity"/>/<see cref="WindowsPrincipal"/>, with NO driver
/// interaction at all, so checking it has no side effects. Actual driver
/// availability (the .sys/.dll files being present and loadable) is only
/// verified when <see cref="StartAsync"/> is actually called, since WinDivert
/// auto-installs/uninstalls its driver tied to the handle's own lifetime -
/// probing for it ahead of time would itself have side effects.</para>
/// <para><b>Safe shutdown:</b> <see cref="TearDownAsync"/> cancels the capture
/// loops' cancellation token, then calls <c>WinDivertShutdown(handle,
/// WINDIVERT_SHUTDOWN_RECV)</c> on every handle to unblock a thread currently
/// parked inside a blocking <c>WinDivertRecv</c> call, THEN awaits both loop
/// tasks to actually exit, and ONLY THEN closes the handles. Closing a handle
/// while a thread is still blocked inside <c>WinDivertRecv</c> for it is not
/// a safe stop sequence.</para>
/// <para><b>Capture-loop scheduling (2026-09-15 fix):</b> the forward and
/// return capture loops each run on their own dedicated, always-on
/// background <see cref="Thread"/> (<see cref="StartDedicatedThread"/>) -
/// NOT via <c>Task.Run</c>/the shared .NET ThreadPool. A first instrumented
/// Windows run (per-packet tuple/timestamp logging added for exactly this
/// purpose - see the <c>RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS</c> fields
/// below) showed the return leg's SYN-ACK for a brand-new flow arriving
/// several SECONDS after the corresponding forward SYN (during which the
/// forward loop kept servicing unrelated flows fine), with several queued
/// return captures then appearing together in a burst - the textbook
/// signature of one of the two loops not getting a ThreadPool worker
/// thread promptly under load, while WinDivert's own driver-side capture
/// queue (bounded by <c>WINDIVERT_PARAM_QUEUE_TIME</c>, 2000ms by default)
/// silently drops whatever it could not deliver to user mode in time. Each
/// loop is a tight, always-blocked-in-native-code <c>while</c> loop for the
/// life of the routing session - exactly the "long-running, always busy"
/// workload the ThreadPool is documented to be a poor fit for (new threads
/// are only added slowly, well after the pool's initial worker count is
/// exhausted). Dedicated threads guarantee both loops are serviced
/// immediately, independent of what else the process's ThreadPool is doing
/// (including the very HttpClient/SslStream work being routed).
/// <see cref="TrySetQueueHeadroom"/> additionally raises the driver-side
/// queue length/time above their defaults as a second, independent safety
/// margin against the same underlying failure mode.</para>
/// <para><b>TCP/UDP support status:</b> V0.2 is <b>TCP-only</b>. Only TCP
/// flows are redirected through the residential proxy. This matches the
/// current upstream connector implementations, not a protocol-level
/// impossibility: HTTP CONNECT is TCP-only by definition, and our current
/// SOCKS5 connector (<c>Socks5UpstreamConnector</c>) implements TCP CONNECT
/// only - SOCKS5 UDP ASSOCIATE is not implemented - so there is presently no
/// upstream path capable of carrying UDP through the residential proxy
/// (see <c>HttpConnectUpstreamConnector</c>/<c>Socks5UpstreamConnector</c>).
/// Plain UDP is therefore NOT redirected or proxied for arbitrary
/// applications; as of 2026-09-16 it is instead uniformly BLOCKED
/// (fail-closed) rather than left to leak direct - the DNS-block handle
/// above owns UDP/53 specifically, and the UDP-block handle above owns
/// every other UDP packet (see <see cref="BypassFilterBuilder.BuildUdpBlockFilter"/>).
/// This is a real, documented limitation, not a hidden gap - see
/// <c>docs/ARCHITECTURE.md</c> "Known limitations" and the acceptance-test
/// notes.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class WinDivertSystemTrafficRouter : ISystemTrafficRouter
{
    private const short ForwardPriority = 0;
    private const short ReturnPriority = 0;
    private const short DnsPriority = 0;
    private const short DnsV6Priority = 0;
    private const short UdpBlockPriority = 0;
    private const short IPv6BlockPriority = 0;
    private const short OtherProtocolBlockPriority = 0;

    private readonly IAppLogger _logger;
    private readonly RedirectFlowTable _flowTable;
    private readonly Func<ITransparentForwardingProxy> _relayFactory;
    private readonly Func<IDohResolver> _dohResolverFactory;
    private readonly RoutingStateMarker _stateMarker;
    private readonly object _lock = new();

    private SystemRoutingStatus _status = SystemRoutingStatus.Disabled;
    private volatile bool _failClosed;

    private ITransparentForwardingProxy? _relay;
    private IDohResolver? _dohResolver;
    private IntPtr _forwardHandle = WinDivertNative.InvalidHandle;
    private IntPtr _returnHandle = WinDivertNative.InvalidHandle;
    private IntPtr _dnsHandle = WinDivertNative.InvalidHandle;
    private IntPtr _dnsV6Handle = WinDivertNative.InvalidHandle;
    private IntPtr _udpBlockHandle = WinDivertNative.InvalidHandle;
    private IntPtr _ipv6BlockHandle = WinDivertNative.InvalidHandle;
    private IntPtr _otherProtocolBlockHandle = WinDivertNative.InvalidHandle;
    private CancellationTokenSource? _cts;
    private Task? _forwardLoopTask;
    private Task? _returnLoopTask;
    private Task? _dnsLoopTask;
    private Task? _dnsV6LoopTask;
    private long _dnsQueryCount;
    private long _dnsQuerySuccessCount;
    private long _dnsQueryFailureCount;

    // --- Temporary diagnostic instrumentation (2026-09-15) ---------------
    // Added to pin down exactly where the reflected TCP flow breaks down
    // after the reflection fix turned a hard timeout into a TLS handshake
    // failure ("The SSL connection could not be established"). Verbose
    // per-packet logging is OFF by default (so the shipped desktop app is
    // never noisy) and only turns on when the
    // RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS environment variable is "1" -
    // tools/ResidentialConnect.RoutingDiagnostic sets this for its own
    // process automatically. The four counters below are always maintained
    // (cheap Interlocked increments) and always summarized once, at Info
    // level, when routing stops, regardless of the verbose flag.
    private readonly bool _diagnosticsEnabled;
    private long _forwardCaptureCount;
    private long _returnCaptureCount;
    private long _successfulReinjectionCount;
    private long _sendFailureCount;
    // -----------------------------------------------------------------------

    public WinDivertSystemTrafficRouter(
        IAppLogger logger,
        Func<ITransparentForwardingProxy> relayFactory,
        RoutingStateMarker stateMarker,
        Func<IDohResolver> dohResolverFactory)
        : this(logger, relayFactory, stateMarker, dohResolverFactory, new RedirectFlowTable())
    {
    }

    /// <summary>Test-only seam allowing a caller to supply/inspect the flow table directly.</summary>
    internal WinDivertSystemTrafficRouter(
        IAppLogger logger,
        Func<ITransparentForwardingProxy> relayFactory,
        RoutingStateMarker stateMarker,
        Func<IDohResolver> dohResolverFactory,
        RedirectFlowTable flowTable)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _relayFactory = relayFactory ?? throw new ArgumentNullException(nameof(relayFactory));
        _stateMarker = stateMarker ?? throw new ArgumentNullException(nameof(stateMarker));
        _dohResolverFactory = dohResolverFactory ?? throw new ArgumentNullException(nameof(dohResolverFactory));
        _flowTable = flowTable ?? throw new ArgumentNullException(nameof(flowTable));
        _diagnosticsEnabled = Environment.GetEnvironmentVariable("RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS") == "1";
    }

    public bool IsSupported => OperatingSystem.IsWindows() && IsCurrentProcessElevated();

    public bool RequiresElevation => true;

    public SystemRoutingStatus Status
    {
        get { lock (_lock) { return _status; } }
    }

    public event EventHandler<SystemRoutingStatus>? StatusChanged;

    public async Task<SystemRoutingStatus> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrEmpty(password);

        lock (_lock)
        {
            if (_status == SystemRoutingStatus.Active)
            {
                return _status;
            }
        }

        if (!IsSupported)
        {
            _logger.Warning("WinDivertSystemTrafficRouter", "StartAsync called but Whole Computer mode is not supported here (not Windows, or the process is not running elevated).");
            SetStatus(SystemRoutingStatus.Unavailable);
            return SystemRoutingStatus.Unavailable;
        }

        SetStatus(SystemRoutingStatus.Starting);
        _failClosed = false;
        Interlocked.Exchange(ref _forwardCaptureCount, 0);
        Interlocked.Exchange(ref _returnCaptureCount, 0);
        Interlocked.Exchange(ref _successfulReinjectionCount, 0);
        Interlocked.Exchange(ref _sendFailureCount, 0);
        Interlocked.Exchange(ref _dnsQueryCount, 0);
        Interlocked.Exchange(ref _dnsQuerySuccessCount, 0);
        Interlocked.Exchange(ref _dnsQueryFailureCount, 0);

        try
        {
            // Validate our native struct layout assumptions BEFORE opening
            // any WinDivert handle - see WinDivertNative remarks for why
            // this matters (a mismatched ABI here previously caused
            // coreclr.dll access-violation crashes via a third-party
            // managed wrapper).
            WinDivertNative.ValidateAbi();

            // Pinned proxy IPv4 (2026-09-16 addition): resolve profile.Host
            // to an IPv4 address exactly ONCE, here, before opening any
            // WinDivert handle - then thread that SAME, single resolved
            // literal into BOTH the forward filter's own self-exclusion
            // clause below AND the relay's upstream connector (see
            // ITransparentForwardingProxy.StartAsync's pinnedProxyAddress
            // remarks). This closes a bootstrap-DNS-circularity/self-
            // interception gap: if the relay instead re-resolved
            // profile.Host itself when dialing the proxy, a second,
            // independent DNS answer could return a DIFFERENT IP than the
            // one this filter excludes, causing the relay's own upstream
            // tunnel to be captured and reflected by its own interception
            // rules.
            var addresses = await Dns.GetHostAddressesAsync(profile.Host, cancellationToken).ConfigureAwait(false);
            var ipv4Addresses = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
            if (ipv4Addresses.Count == 0)
            {
                throw new InvalidOperationException($"Could not resolve an IPv4 address for proxy host '{profile.Host}' - refusing to start Whole Computer mode (fail-closed).");
            }

            var pinnedProxyAddress = ipv4Addresses[0];

            _relay = _relayFactory();
            _relay.Faulted += OnRelayFaulted;
            var relayPort = await _relay.StartAsync(profile, password, IPAddress.Any, _flowTable, pinnedProxyAddress, cancellationToken).ConfigureAwait(false);

            // Session-scoped proxied DoH resolver (2026-09-16 addition):
            // configured with the SAME pinned proxy address as every other
            // upstream tunnel this session opens - see IDohResolver/
            // ProxiedDohResolver remarks. Configure() itself does no I/O
            // (only builds the HttpClient/connector), so it is safe to call
            // unconditionally before any DNS packet is ever captured.
            _dohResolver = _dohResolverFactory();
            _dohResolver.Configure(profile, password, pinnedProxyAddress);

            // Invariant (2026-09-16 correction): the exact IP physically
            // dialed by the upstream connector (pinnedProxyAddress, passed
            // to _relay.StartAsync above) MUST be the exact, and ONLY, IP
            // excluded from interception here. Building this self-exclusion
            // from the full ipv4Addresses list (every IPv4 address the
            // proxy hostname happened to resolve to) would create bypass
            // entries for addresses the relay never actually dials -
            // needless attack surface, and a mismatch against the "exact
            // dialed IP == exact excluded IP" invariant this clause exists
            // to guarantee. Always exactly one element.
            var forwardFilter = BypassFilterBuilder.BuildForwardFilter([pinnedProxyAddress], profile.Port, relayPort);
            var returnFilter = BypassFilterBuilder.BuildReturnFilter(relayPort);
            var dnsFilter = BypassFilterBuilder.BuildDnsFilter();
            var dnsV6Filter = BypassFilterBuilder.BuildDnsFilterV6();
            var udpBlockFilter = BypassFilterBuilder.BuildUdpBlockFilter();
            var ipv6BlockFilter = BypassFilterBuilder.BuildIPv6BlockFilter();
            var otherProtocolBlockFilter = BypassFilterBuilder.BuildOtherProtocolBlockFilter();

            // DNS handles are opened WITHOUT OpenFlags.Drop (2026-09-16
            // correction): plain UDP/53 is no longer simply blocked - it is
            // CAPTURED, answered via proxied DoH (see DnsLoop/DnsV6Loop
            // below), and a synthesized reply is sent back. The three
            // fail-closed block handles (general UDP, IPv6, other-protocol)
            // remain Drop-only/in-kernel, exactly as before - only DNS
            // changed from "block" to "capture and answer".
            _dnsHandle = OpenHandleOrThrow(dnsFilter, WinDivertNative.Layer.Network, DnsPriority, WinDivertNative.OpenFlags.None, "DNS (IPv4) capture");
            _dnsV6Handle = OpenHandleOrThrow(dnsV6Filter, WinDivertNative.Layer.Network, DnsV6Priority, WinDivertNative.OpenFlags.None, "DNS (IPv6) capture");
            // Additive, 2026-09-16: general UDP-block leak-protection handle
            // - see BypassFilterBuilder.BuildUdpBlockFilter remarks for why
            // this is a separate Drop handle rather than a change to the
            // DNS handle above, and why blocking (not proxying) is correct
            // given the current TCP-only upstream connectors. Like the DNS
            // handle, this is Drop-only: the driver discards matching
            // packets in-kernel, so there is no capture loop/thread for it
            // and it cannot itself affect the verified TCP forward/return
            // pipeline.
            _udpBlockHandle = OpenHandleOrThrow(udpBlockFilter, WinDivertNative.Layer.Network, UdpBlockPriority, WinDivertNative.OpenFlags.Drop, "UDP-block leak-protection");
            // Additive, 2026-09-16: public-IPv6 fail-closed block handle -
            // see BypassFilterBuilder.BuildIPv6BlockFilter remarks. Drop-only,
            // in-kernel, and (per that method's own filter string) never
            // overlaps the IPv6 DNS capture handle above.
            _ipv6BlockHandle = OpenHandleOrThrow(ipv6BlockFilter, WinDivertNative.Layer.Network, IPv6BlockPriority, WinDivertNative.OpenFlags.Drop, "IPv6 fail-closed block");
            // Additive, 2026-09-16: unsupported-public-IPv4-protocol
            // fail-closed block handle (e.g. ICMP) - see
            // BypassFilterBuilder.BuildOtherProtocolBlockFilter remarks.
            // Drop-only, in-kernel.
            _otherProtocolBlockHandle = OpenHandleOrThrow(otherProtocolBlockFilter, WinDivertNative.Layer.Network, OtherProtocolBlockPriority, WinDivertNative.OpenFlags.Drop, "unsupported-protocol fail-closed block");
            _forwardHandle = OpenHandleOrThrow(forwardFilter, WinDivertNative.Layer.Network, ForwardPriority, WinDivertNative.OpenFlags.None, "forward");
            _returnHandle = OpenHandleOrThrow(returnFilter, WinDivertNative.Layer.Network, ReturnPriority, WinDivertNative.OpenFlags.None, "return");

            // Give the driver-side per-handle capture queue extra headroom
            // as a second, independent safety margin on top of the dedicated
            // capture threads started below (see remarks on why both matter
            // - "2026-09-15 return-leg starvation" root cause). Defaults are
            // QUEUE_LENGTH=4096 packets / QUEUE_TIME=2000ms; a 3x bump costs
            // only a little extra kernel-pool memory and directly targets
            // the observed "reflected SYN-ACKs arrive several seconds late,
            // in a burst" symptom. Best-effort: if an older WinDivert build
            // rejects one of these params, capture still works with the
            // built-in defaults, just with less headroom - never fail the
            // whole start over this.
            TrySetQueueHeadroom(_forwardHandle, "forward");
            TrySetQueueHeadroom(_returnHandle, "return");
            TrySetQueueHeadroom(_dnsHandle, "DNS (IPv4)");
            TrySetQueueHeadroom(_dnsV6Handle, "DNS (IPv6)");

            _cts = new CancellationTokenSource();

            // --- Dedicated OS threads, NOT Task.Run/ThreadPool -----------
            // Root cause of the 2026-09-15 "SYN-ACK arrives ~7s late, right
            // before the HttpClient gives up" symptom: both capture loops
            // are tight `while` loops blocked almost the entire time inside
            // a native WinDivertRecv() call - i.e. long-running, blocking
            // work, which is exactly what the shared .NET ThreadPool is
            // documented to handle badly (it grows slowly, ~1 thread/sec
            // under sustained starvation, and only after the global
            // starvation detector kicks in). Scheduling both loops via
            // Task.Run meant they competed for ThreadPool worker threads
            // with everything else (including this very process's own
            // HttpClient/SslStream continuations) - if the return loop's
            // Task didn't get a thread promptly, WinDivert kept queuing
            // (and eventually dropping, per QUEUE_TIME) SYN-ACKs behind the
            // scenes while nothing serviced WinDivertRecv on the return
            // handle, exactly matching the observed diagnostic log (a long
            // silent gap on the return leg, then a burst of several
            // RETURN captures appearing together once a thread finally
            // became free). WinDivert's own documentation is explicit that
            // a handle must be serviced "as soon as possible" or captured
            // packets are dropped. Dedicated, always-on background threads
            // guarantee both loops always have a thread immediately
            // available, independent of ThreadPool/application load.
            _forwardLoopTask = StartDedicatedThread(() => ForwardLoop(_forwardHandle, relayPort, _cts.Token), "RC-WinDivert-Forward");
            _returnLoopTask = StartDedicatedThread(() => ReturnLoop(_returnHandle, _cts.Token), "RC-WinDivert-Return");
            // DNS capture loops (2026-09-16 addition): unlike the block
            // handles above (Drop-only, in-kernel, no user-mode
            // involvement), these two DO need a dedicated capture loop -
            // each captured query is handed to _dohResolver and answered
            // with a synthesized reply (see DnsLoop remarks). Same
            // dedicated-OS-thread rationale as the forward/return loops
            // applies equally here: a captured-but-not-serviced-in-time DNS
            // query is simply dropped by WinDivert's own queue, so this
            // loop must never be starved for a ThreadPool worker either.
            _dnsLoopTask = StartDedicatedThread(() => DnsLoop(_dnsHandle, AddressFamily.InterNetwork, _cts.Token), "RC-WinDivert-DNS-v4");
            _dnsV6LoopTask = StartDedicatedThread(() => DnsLoop(_dnsV6Handle, AddressFamily.InterNetworkV6, _cts.Token), "RC-WinDivert-DNS-v6");

            _stateMarker.MarkActive();
            _logger.Info("WinDivertSystemTrafficRouter", $"Whole Computer routing active. Forward filter: \"{forwardFilter}\". Relay listening on 0.0.0.0:{relayPort}.");
            SetStatus(SystemRoutingStatus.Active);
            return SystemRoutingStatus.Active;
        }
        catch (Exception ex)
        {
            _logger.Error("WinDivertSystemTrafficRouter", "Failed to start Whole Computer routing - tearing down any partially-created state (fail-closed: normal networking is left untouched).", ex);
            await TearDownAsync().ConfigureAwait(false);
            SetStatus(SystemRoutingStatus.Unavailable);
            return SystemRoutingStatus.Unavailable;
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (_status is SystemRoutingStatus.Disabled)
            {
                return;
            }
        }

        SetStatus(SystemRoutingStatus.Stopping);
        await TearDownAsync().ConfigureAwait(false);
        _stateMarker.ClearClean();
        SetStatus(SystemRoutingStatus.Disabled);
    }

    private async Task TearDownAsync()
    {
        _cts?.Cancel();

        // Safe shutdown sequence: WINDIVERT_SHUTDOWN_RECV unblocks a thread
        // currently parked inside a blocking WinDivertRecv() call for that
        // handle WITHOUT invalidating the handle itself. Only after both
        // capture loop tasks have actually observed this and returned do we
        // close the handles - closing a handle while a thread is still
        // blocked inside WinDivertRecv for it is not a safe stop sequence.
        ShutdownReceive(_forwardHandle);
        ShutdownReceive(_returnHandle);
        ShutdownReceive(_dnsHandle);
        ShutdownReceive(_dnsV6Handle);
        ShutdownReceive(_udpBlockHandle);
        ShutdownReceive(_ipv6BlockHandle);
        ShutdownReceive(_otherProtocolBlockHandle);

        if (_forwardLoopTask is not null)
        {
            try { await _forwardLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        if (_returnLoopTask is not null)
        {
            try { await _returnLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        if (_dnsLoopTask is not null)
        {
            try { await _dnsLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        if (_dnsV6LoopTask is not null)
        {
            try { await _dnsV6LoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        CloseHandle(ref _forwardHandle);
        CloseHandle(ref _returnHandle);
        CloseHandle(ref _dnsHandle);
        CloseHandle(ref _dnsV6Handle);
        CloseHandle(ref _udpBlockHandle);
        CloseHandle(ref _ipv6BlockHandle);
        CloseHandle(ref _otherProtocolBlockHandle);

        if (_relay is not null)
        {
            _relay.Faulted -= OnRelayFaulted;
            try { await _relay.StopAsync().ConfigureAwait(false); } catch { /* best-effort on teardown */ }
            _relay.Dispose();
            _relay = null;
        }

        if (_dohResolver is not null)
        {
            _dohResolver.Dispose();
            _dohResolver = null;
        }

        _logger.Info("WinDivertSystemTrafficRouter", $"Routing diagnostics summary: forwardCaptures={Interlocked.Read(ref _forwardCaptureCount)}, returnCaptures={Interlocked.Read(ref _returnCaptureCount)}, successfulReinjections={Interlocked.Read(ref _successfulReinjectionCount)}, sendFailures={Interlocked.Read(ref _sendFailureCount)}, dnsQueries={Interlocked.Read(ref _dnsQueryCount)}, dnsSuccesses={Interlocked.Read(ref _dnsQuerySuccessCount)}, dnsFailures={Interlocked.Read(ref _dnsQueryFailureCount)}.");

        _flowTable.Clear();
        _cts?.Dispose();
        _cts = null;
        _forwardLoopTask = null;
        _returnLoopTask = null;
        _dnsLoopTask = null;
        _dnsV6LoopTask = null;
        _failClosed = false;
    }

    private void OnRelayFaulted(object? sender, Exception ex)
    {
        _failClosed = true;
        _logger.Error("WinDivertSystemTrafficRouter", "Transparent relay faulted while Whole Computer mode was active - failing closed: intercepted traffic will now be DROPPED (never sent direct) until DISCONNECT.", ex);
        SetStatus(SystemRoutingStatus.FailedClosed);
    }

    private static IntPtr OpenHandleOrThrow(string filter, WinDivertNative.Layer layer, short priority, WinDivertNative.OpenFlags flags, string handleDescription)
    {
        var handle = WinDivertNative.Open(filter, layer, priority, (ulong)flags);
        if (handle == WinDivertNative.InvalidHandle || handle == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Failed to open the {handleDescription} WinDivert handle (Win32 error {error}). This usually means the process is not elevated, the WinDivert driver could not be loaded, another instance already holds a conflicting handle, or the filter string failed to compile.");
        }

        return handle;
    }

    /// <summary>
    /// Starts <paramref name="loopBody"/> on a dedicated, non-ThreadPool
    /// background <see cref="Thread"/> and returns a <see cref="Task"/> that
    /// completes when the thread exits - so existing await/teardown call
    /// sites (<see cref="TearDownAsync"/>) need no changes. See the long
    /// comment at the <c>Task.Run</c> call sites this replaces (in
    /// <see cref="StartAsync"/>) for the full root-cause rationale.
    /// </summary>
    private static Task StartDedicatedThread(Action loopBody, string threadName)
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                loopBody();
                tcs.TrySetResult();
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        })
        {
            IsBackground = true,
            Name = threadName,
            Priority = ThreadPriority.AboveNormal
        };
        thread.Start();
        return tcs.Task;
    }

    /// <summary>
    /// Best-effort: raises this handle's driver-side capture queue length
    /// and queue time above WinDivert's defaults (4096 packets / 2000ms) as
    /// a second, independent safety margin against the same
    /// captured-but-not-serviced-in-time packet loss the dedicated capture
    /// threads (see <see cref="StartDedicatedThread"/>) primarily address.
    /// Never throws and never fails the overall start - an older WinDivert
    /// build rejecting one of these params just means less headroom, not a
    /// reason to refuse to route at all.
    /// </summary>
    private void TrySetQueueHeadroom(IntPtr handle, string handleDescription)
    {
        const ulong queueLength = 8192; // default 4096
        const ulong queueTimeMs = 4096; // default 2000ms (min 128, max 16000)

        if (!WinDivertNative.SetParam(handle, WinDivertNative.Param.QueueLength, queueLength))
        {
            _logger.Debug("RoutingDiagnostics", $"Could not raise QueueLength on the {handleDescription} handle (Win32 error {Marshal.GetLastWin32Error()}); continuing with the driver default.");
        }

        if (!WinDivertNative.SetParam(handle, WinDivertNative.Param.QueueTime, queueTimeMs))
        {
            _logger.Debug("RoutingDiagnostics", $"Could not raise QueueTime on the {handleDescription} handle (Win32 error {Marshal.GetLastWin32Error()}); continuing with the driver default.");
        }
    }

    private static void ShutdownReceive(IntPtr handle)
    {
        if (handle == WinDivertNative.InvalidHandle || handle == IntPtr.Zero)
        {
            return;
        }

        // Best effort - if the handle is already gone this simply fails,
        // which is fine during teardown.
        WinDivertNative.ShutdownHandle(handle, WinDivertNative.Shutdown.Recv);
    }

    private static void CloseHandle(ref IntPtr handle)
    {
        if (handle != WinDivertNative.InvalidHandle && handle != IntPtr.Zero)
        {
            WinDivertNative.Close(handle);
        }

        handle = WinDivertNative.InvalidHandle;
    }

    private unsafe void ForwardLoop(IntPtr handle, int relayPort, CancellationToken cancellationToken)
    {
        var buffer = GC.AllocateUninitializedArray<byte>((int)WinDivertNative.MaxPacketSize, pinned: true);
        var processed = 0;

        try
        {
            fixed (byte* packetBuffer = buffer)
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    WinDivertNative.Address address = default;

                    if (!WinDivertNative.Recv(handle, packetBuffer, WinDivertNative.MaxPacketSize, out var recvLen, &address))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        var recvError = Marshal.GetLastWin32Error();
                        _logger.Warning("RoutingDiagnostics", $"WinDivertRecv failed on the forward handle (Win32 error {recvError}).");
                        continue;
                    }

                    if (recvLen == 0 || recvLen > WinDivertNative.MaxPacketSize)
                    {
                        continue;
                    }

                    ProcessForwardPacket(handle, packetBuffer, recvLen, &address, relayPort);

                    if (++processed % 512 == 0)
                    {
                        _flowTable.EvictIdle();
                    }
                }
            }
        }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                _logger.Error("WinDivertSystemTrafficRouter", "Forward capture loop terminated unexpectedly - failing closed.", ex);
                _failClosed = true;
                SetStatus(SystemRoutingStatus.FailedClosed);
            }
        }
    }

    private unsafe void ReturnLoop(IntPtr handle, CancellationToken cancellationToken)
    {
        var buffer = GC.AllocateUninitializedArray<byte>((int)WinDivertNative.MaxPacketSize, pinned: true);

        try
        {
            fixed (byte* packetBuffer = buffer)
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    WinDivertNative.Address address = default;

                    if (!WinDivertNative.Recv(handle, packetBuffer, WinDivertNative.MaxPacketSize, out var recvLen, &address))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        var recvError = Marshal.GetLastWin32Error();
                        _logger.Warning("RoutingDiagnostics", $"WinDivertRecv failed on the return handle (Win32 error {recvError}).");
                        continue;
                    }

                    if (recvLen == 0 || recvLen > WinDivertNative.MaxPacketSize)
                    {
                        continue;
                    }

                    ProcessReturnPacket(handle, packetBuffer, recvLen, &address);
                }
            }
        }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                _logger.Error("WinDivertSystemTrafficRouter", "Return capture loop terminated unexpectedly - failing closed.", ex);
                _failClosed = true;
                SetStatus(SystemRoutingStatus.FailedClosed);
            }
        }
    }

    /// <summary>
    /// Capture loop for one DNS handle (either the IPv4 or the IPv6 one -
    /// <paramref name="expectedFamily"/> is diagnostic-only, for log
    /// messages; parsing itself dispatches on which of
    /// <see cref="WinDivertNative.ParseUdpPacket"/>'s IPv4/IPv6 header
    /// out-pointers came back non-null, matching whichever handle actually
    /// captured the packet). 2026-09-16 addition, replacing the previous
    /// "DNS is simply Drop-blocked" design - see class remarks and
    /// <see cref="BypassFilterBuilder.BuildDnsFilter"/>/<see cref="BypassFilterBuilder.BuildDnsFilterV6"/>.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="ForwardLoop"/>/<see cref="ReturnLoop"/> (which
    /// synchronously reflect and resend within the same iteration),
    /// answering a DNS query requires a real, asynchronous HTTPS round-trip
    /// through the proxy (<see cref="IDohResolver.ResolveAsync"/>) - so each
    /// captured query's processing is dispatched onto its own fire-and-forget
    /// <see cref="Task"/> (<see cref="ProcessDnsQueryAsync"/>) rather than
    /// awaited inline, so this tight capture loop can immediately go back to
    /// <c>WinDivertRecv</c> for the NEXT query instead of blocking on one
    /// query's round-trip - exactly the same "always be ready to service the
    /// next captured packet promptly" principle documented on the dedicated
    /// capture threads (see class remarks "Capture-loop scheduling").
    /// </remarks>
    private unsafe void DnsLoop(IntPtr handle, AddressFamily expectedFamily, CancellationToken cancellationToken)
    {
        var buffer = GC.AllocateUninitializedArray<byte>((int)WinDivertNative.MaxPacketSize, pinned: true);

        try
        {
            fixed (byte* packetBuffer = buffer)
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    WinDivertNative.Address address = default;

                    if (!WinDivertNative.Recv(handle, packetBuffer, WinDivertNative.MaxPacketSize, out var recvLen, &address))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        var recvError = Marshal.GetLastWin32Error();
                        _logger.Warning("RoutingDiagnostics", $"WinDivertRecv failed on the DNS ({expectedFamily}) handle (Win32 error {recvError}).");
                        continue;
                    }

                    if (recvLen == 0 || recvLen > WinDivertNative.MaxPacketSize)
                    {
                        continue;
                    }

                    if (!TryParseUdpPacket(packetBuffer, recvLen, out var captured))
                    {
                        // Fail closed: an unparseable captured "DNS" packet
                        // is simply dropped - never resent unmodified.
                        continue;
                    }

                    var queryNumber = Interlocked.Increment(ref _dnsQueryCount);

                    // Fire-and-forget: resolving via DoH is a real,
                    // asynchronous HTTPS round-trip and must not block this
                    // tight capture loop from immediately servicing the
                    // NEXT query (see method remarks). The original captured
                    // query packet is NEVER resent/forwarded unmodified
                    // (fail-closed) - either a synthesized reply is sent
                    // back once the DoH round-trip completes, or nothing is
                    // sent at all and the application's own DNS client
                    // simply times out and retries; a direct, unproxied leak
                    // of the query is not possible either way.
                    _ = ProcessDnsQueryAsync(handle, captured, address, queryNumber, cancellationToken);
                }
            }
        }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                _logger.Error("WinDivertSystemTrafficRouter", $"DNS ({expectedFamily}) capture loop terminated unexpectedly - failing closed.", ex);
                _failClosed = true;
                SetStatus(SystemRoutingStatus.FailedClosed);
            }
        }
    }

    private async Task ProcessDnsQueryAsync(IntPtr handle, CapturedUdpPacket captured, WinDivertNative.Address address, long queryNumber, CancellationToken cancellationToken)
    {
        try
        {
            if (_dohResolver is null)
            {
                Interlocked.Increment(ref _dnsQueryFailureCount);
                return;
            }

            var dnsResponse = await _dohResolver.ResolveAsync(captured.Payload, cancellationToken).ConfigureAwait(false);
            var reply = DnsUdpReplyPacketBuilder.BuildReply(captured, dnsResponse);

            SendDnsReply(handle, reply, address, queryNumber);
            Interlocked.Increment(ref _dnsQuerySuccessCount);

            if (_diagnosticsEnabled)
            {
                _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [DNS #{queryNumber}] {captured.SrcAddr}:{captured.SrcPort} -> {captured.DstAddr}:{captured.DstPort} answered via proxied DoH ({dnsResponse.Length} byte response).");
            }
        }
        catch (OperationCanceledException)
        {
            // Routing is stopping - dropping silently is correct here.
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _dnsQueryFailureCount);
            _logger.Warning("RoutingDiagnostics", $"DNS query #{queryNumber} ({captured.SrcAddr}:{captured.SrcPort}) failed via proxied DoH ({ex.GetType().Name}); the application will see a timeout rather than a leaked direct query.");
        }
    }

    /// <summary>
    /// Sends a synthesized DNS reply (<see cref="DnsUdpReplyPacketBuilder.BuildReply"/>)
    /// back through the SAME DNS handle the original query was captured on -
    /// marked Inbound (<see cref="WinDivertNative.MarkInbound"/>), exactly
    /// like a real reflected TCP packet, so Windows' own TCP/IP stack
    /// delivers it to the querying application's UDP socket as a genuine
    /// incoming reply.
    /// </summary>
    private unsafe void SendDnsReply(IntPtr handle, byte[] reply, WinDivertNative.Address address, long queryNumber)
    {
        WinDivertNative.MarkInbound(&address);

        fixed (byte* replyBuffer = reply)
        {
            if (!WinDivertNative.CalcChecksums(replyBuffer, (uint)reply.Length, &address, 0))
            {
                var checksumError = Marshal.GetLastWin32Error();
                _logger.Warning("RoutingDiagnostics", $"WinDivertHelperCalcChecksums failed for DNS reply #{queryNumber} (Win32 error {checksumError}); dropping instead.");
                return;
            }

            if (!WinDivertNative.Send(handle, replyBuffer, (uint)reply.Length, out _, &address))
            {
                var sendError = Marshal.GetLastWin32Error();
                _logger.Warning("RoutingDiagnostics", $"WinDivertSend failed for DNS reply #{queryNumber} (Win32 error {sendError}); dropping instead.");
            }
        }
    }

    /// <summary>
    /// Parses a captured packet as a UDP datagram of either IP version, via
    /// <see cref="WinDivertNative.ParseUdpPacket"/> (the typed-IPv6/UDP
    /// sibling of <see cref="WinDivertNative.ParsePacket"/> used by the TCP
    /// path - see that method's remarks for why two managed declarations of
    /// the same native entry point exist). Copies the raw UDP payload bytes
    /// into a fresh managed array (<see cref="CapturedUdpPacket.Payload"/>)
    /// so the parsed result remains valid after this method returns, even
    /// though the native pointers themselves only remain valid while
    /// <paramref name="packetBuffer"/> is pinned by the caller's own
    /// <c>fixed</c> block.
    /// </summary>
    private static unsafe bool TryParseUdpPacket(byte* packetBuffer, uint packetLength, out CapturedUdpPacket captured)
    {
        captured = null!;

        var result = WinDivertNative.ParseUdpPacket(
            packetBuffer,
            packetLength,
            out var ipv4,
            out var ipv6,
            out var protocol,
            out _,
            out _,
            out _,
            out var udp,
            out var data,
            out var dataLen,
            out _,
            out _);

        if (!result || udp == null || protocol != 17)
        {
            return false;
        }

        IPAddress srcAddr;
        IPAddress dstAddr;
        AddressFamily family;

        if (ipv4 != null)
        {
            family = AddressFamily.InterNetwork;
            srcAddr = NativeIpv4ToIPAddress(ipv4->SrcAddr);
            dstAddr = NativeIpv4ToIPAddress(ipv4->DstAddr);
        }
        else if (ipv6 != null)
        {
            family = AddressFamily.InterNetworkV6;
            srcAddr = NativeIpv6ToIPAddress(ipv6->SrcAddr);
            dstAddr = NativeIpv6ToIPAddress(ipv6->DstAddr);
        }
        else
        {
            return false;
        }

        var payload = dataLen > 0 ? new byte[dataLen] : Array.Empty<byte>();
        if (dataLen > 0)
        {
            Marshal.Copy((IntPtr)data, payload, 0, (int)dataLen);
        }

        captured = new CapturedUdpPacket(
            family,
            srcAddr,
            NativePortToHost(udp->SrcPort),
            dstAddr,
            NativePortToHost(udp->DstPort),
            payload);

        return true;
    }

    private static unsafe IPAddress NativeIpv6ToIPAddress(byte* address)
    {
        var bytes = new byte[16];
        for (var i = 0; i < 16; i++)
        {
            bytes[i] = address[i];
        }

        return new IPAddress(bytes);
    }

    private unsafe void ProcessForwardPacket(IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address, int relayPort)
    {
        if (!TryParseTcpPacket(packetBuffer, recvLen, out var ip, out var tcp))
        {
            // Fail closed. Do not resend an unclassified packet.
            return;
        }

        var captured = CapturePacket(ip, tcp);
        var captureNumber = Interlocked.Increment(ref _forwardCaptureCount);

        if (_diagnosticsEnabled)
        {
            var directionBefore = address->Outbound ? "Outbound" : "Inbound";
            _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [FORWARD #{captureNumber}] {captured.SrcAddr}:{captured.SrcPort} -> {captured.DstAddr}:{captured.DstPort} flags=[{DescribeTcpFlags(captured)}] direction-before={directionBefore} Impostor={address->Impostor} {DescribeTcpDataFields(captured)}");
        }

        var decision = PacketRedirectPlanner.PlanForward(captured, _flowTable, relayPort, _failClosed);
        if (!decision.ShouldReflect)
        {
            // Fail closed: captured traffic is not resent directly. As of
            // the 2026-09-16 RejectStale addition, an untracked/stale
            // public forward-leg packet gets a locally-forged TCP RST sent
            // back to its own source (see PacketRedirectPlanner.PlanForward
            // remarks "Fail-closed by construction, with a bounded,
            // non-bypassing exception for stale public TCP") instead of
            // being silently dropped - the genuine fail-closed Drop case
            // (decision.Action == RedirectAction.Drop, i.e. either
            // _failClosed is true, or the packet is itself already
            // RST/FIN) is completely unchanged.
            if (decision.Action == RedirectAction.RejectStale)
            {
                SendForgedReset(handle, captured, address, captureNumber);
            }
            else if (_diagnosticsEnabled)
            {
                _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [FORWARD #{captureNumber}] DROPPED (no reflect decision; failClosed={_failClosed}).");
            }

            return;
        }

        ApplyReflection(ip, tcp, address, decision);

        if (_diagnosticsEnabled)
        {
            var directionAfter = address->Outbound ? "Outbound" : "Inbound";
            _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [FORWARD #{captureNumber}] reflected -> {decision.NewSrcAddr}:{decision.NewSrcPort} -> {decision.NewDstAddr}:{decision.NewDstPort} direction-after={directionAfter}");
        }

        RecalculateAndSend(handle, packetBuffer, recvLen, address, "forward", captured, captureNumber);
    }

    private unsafe void ProcessReturnPacket(IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address)
    {
        if (!TryParseTcpPacket(packetBuffer, recvLen, out var ip, out var tcp))
        {
            return;
        }

        var captured = CapturePacket(ip, tcp);
        var captureNumber = Interlocked.Increment(ref _returnCaptureCount);

        if (_diagnosticsEnabled)
        {
            var directionBefore = address->Outbound ? "Outbound" : "Inbound";
            _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [RETURN #{captureNumber}] relay reply captured {captured.SrcAddr}:{captured.SrcPort} -> {captured.DstAddr}:{captured.DstPort} flags=[{DescribeTcpFlags(captured)}] direction-before={directionBefore} Impostor={address->Impostor} {DescribeTcpDataFields(captured)}");
        }

        var decision = PacketRedirectPlanner.PlanReturn(captured, _flowTable, _failClosed);
        if (!decision.ShouldReflect)
        {
            if (_diagnosticsEnabled)
            {
                _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [RETURN #{captureNumber}] DROPPED (no reflect decision; failClosed={_failClosed}).");
            }

            return;
        }

        ApplyReflection(ip, tcp, address, decision);

        if (_diagnosticsEnabled)
        {
            var directionAfter = address->Outbound ? "Outbound" : "Inbound";
            _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [RETURN #{captureNumber}] reflected -> {decision.NewSrcAddr}:{decision.NewSrcPort} -> {decision.NewDstAddr}:{decision.NewDstPort} direction-after={directionAfter}");
        }

        RecalculateAndSend(handle, packetBuffer, recvLen, address, "return", captured, captureNumber);
    }

    /// <summary>Renders which of SYN/ACK/FIN/RST/PSH are set on a captured packet, for diagnostic logging only.</summary>
    private static string DescribeTcpFlags(CapturedTcpPacket packet)
    {
        var flags = new List<string>(5);
        if (packet.IsSyn) flags.Add("SYN");
        if (packet.IsAck) flags.Add("ACK");
        if (packet.IsFin) flags.Add("FIN");
        if (packet.IsRst) flags.Add("RST");
        if (packet.IsPsh) flags.Add("PSH");
        return flags.Count == 0 ? "-" : string.Join(",", flags);
    }

    /// <summary>
    /// Renders the extra diagnostic-only fields added 2026-09-16 (sequence
    /// number, ACK number, receive window, and TCP payload length) as a
    /// single string, for the "established-flow data transfer" investigation
    /// - see <see cref="CapturedTcpPacket"/>'s remarks. Deliberately never
    /// includes the payload BYTES themselves, only its length.
    /// </summary>
    private static string DescribeTcpDataFields(CapturedTcpPacket packet) =>
        $"seq={packet.SeqNum} ack={packet.AckNum} window={packet.Window} payloadLen={packet.PayloadLength}";

    private static unsafe CapturedTcpPacket CapturePacket(WinDivertNative.IPv4Header* ip, WinDivertNative.TcpHeader* tcp)
    {
        var tcpFlags = tcp->HeaderLengthAndFlags;

        // Data offset (TCP header length in 32-bit words) occupies the high
        // nibble of the LOW byte of this little-endian-read ushort - see the
        // long-form byte-order explanation on CapturedTcpPacket's remarks.
        var tcpHeaderLengthBytes = ((tcpFlags & 0x00F0) >> 4) * 4;
        var ipTotalLength = BinaryPrimitives.ReverseEndianness(ip->Length);
        var ipHeaderLengthBytes = ip->HeaderLength * 4;
        var payloadLength = Math.Max(0, ipTotalLength - ipHeaderLengthBytes - tcpHeaderLengthBytes);

        return new CapturedTcpPacket(
            IsSyn: (tcpFlags & 0x0200) != 0,
            IsAck: (tcpFlags & 0x1000) != 0,
            IsFin: (tcpFlags & 0x0100) != 0,
            IsRst: (tcpFlags & 0x0400) != 0,
            SrcAddr: NativeIpv4ToIPAddress(ip->SrcAddr),
            SrcPort: NativePortToHost(tcp->SrcPort),
            DstAddr: NativeIpv4ToIPAddress(ip->DstAddr),
            DstPort: NativePortToHost(tcp->DstPort),
            IsPsh: (tcpFlags & 0x0800) != 0,
            SeqNum: BinaryPrimitives.ReverseEndianness(tcp->SeqNum),
            AckNum: BinaryPrimitives.ReverseEndianness(tcp->AckNum),
            Window: BinaryPrimitives.ReverseEndianness(tcp->Window),
            PayloadLength: payloadLength);
    }

    /// <summary>
    /// Applies a <see cref="RedirectDecision"/> to the real packet headers:
    /// swap source/destination address and port, and flip the packet's
    /// direction from Outbound to Inbound (<see cref="WinDivertNative.MarkInbound"/>)
    /// - the "reflection" that makes Windows' own TCP/IP stack treat this as
    /// a packet that genuinely arrived from the network. See
    /// <see cref="RedirectDecision"/>'s remarks for the full rationale.
    /// </summary>
    private static unsafe void ApplyReflection(WinDivertNative.IPv4Header* ip, WinDivertNative.TcpHeader* tcp, WinDivertNative.Address* address, RedirectDecision decision)
    {
        ip->SrcAddr = IPAddressToNativeIpv4(decision.NewSrcAddr!);
        ip->DstAddr = IPAddressToNativeIpv4(decision.NewDstAddr!);
        tcp->SrcPort = HostPortToNative(decision.NewSrcPort!.Value);
        tcp->DstPort = HostPortToNative(decision.NewDstPort!.Value);

        WinDivertNative.MarkInbound(address);
    }

    /// <summary>
    /// Builds (<see cref="TcpResetPacketBuilder.BuildIPv4Reset"/>), checksums,
    /// and sends a forged TCP RST+ACK back to <paramref name="captured"/>'s
    /// own source - the <see cref="RedirectAction.RejectStale"/> path (see
    /// <see cref="PacketRedirectPlanner"/> remarks). Marked Inbound before
    /// sending, exactly like a real reflected packet, so Windows' own TCP/IP
    /// stack delivers it to the application's socket as a genuine incoming
    /// reset rather than treating it as an ordinary (and, for this
    /// source/destination pairing, likely-anti-spoofing-rejected) outbound
    /// send.
    /// </summary>
    private unsafe void SendForgedReset(IntPtr handle, CapturedTcpPacket captured, WinDivertNative.Address* address, long captureNumber)
    {
        byte[] reset;
        try
        {
            reset = TcpResetPacketBuilder.BuildIPv4Reset(captured);
        }
        catch (InvalidOperationException ex)
        {
            // Defensive only - PacketRedirectPlanner.PlanForward should
            // never choose RejectStale for an already-RST/FIN packet (see
            // that guard in its own remarks). If this is ever hit, fail
            // closed by simply dropping rather than propagating.
            _logger.Warning("RoutingDiagnostics", $"SendForgedReset called for a packet that should never have reached RejectStale: {ex.Message}");
            return;
        }

        var resetAddress = *address;
        WinDivertNative.MarkInbound(&resetAddress);

        fixed (byte* resetBuffer = reset)
        {
            if (!WinDivertNative.CalcChecksums(resetBuffer, (uint)reset.Length, &resetAddress, 0))
            {
                var checksumError = Marshal.GetLastWin32Error();
                _logger.Warning("RoutingDiagnostics", $"WinDivertHelperCalcChecksums failed while building a forged RST for #{captureNumber} (Win32 error {checksumError}); dropping instead.");
                return;
            }

            if (!WinDivertNative.Send(handle, resetBuffer, (uint)reset.Length, out _, &resetAddress))
            {
                var sendError = Marshal.GetLastWin32Error();
                _logger.Warning("RoutingDiagnostics", $"WinDivertSend failed while sending a forged RST for #{captureNumber} (Win32 error {sendError}); dropping instead.");
                return;
            }
        }

        if (_diagnosticsEnabled)
        {
            _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [FORWARD #{captureNumber}] untracked/stale public TCP - sent a forged RST to {captured.SrcAddr}:{captured.SrcPort} instead of dropping silently.");
        }
    }

    private unsafe void RecalculateAndSend(IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address, string legName, CapturedTcpPacket captured, long captureNumber)
    {
        // flags == 0 means recalculate all applicable checksums.
        if (!WinDivertNative.CalcChecksums(packetBuffer, recvLen, address, 0))
        {
            var checksumError = Marshal.GetLastWin32Error();
            Interlocked.Increment(ref _sendFailureCount);
            _failClosed = true;
            _logger.Error("RoutingDiagnostics", $"WinDivertHelperCalcChecksums failed on the {legName} leg (#{captureNumber}, {captured.SrcAddr}:{captured.SrcPort} -> {captured.DstAddr}:{captured.DstPort}); failing closed. Win32 error {checksumError}.", new InvalidOperationException($"Win32 error {checksumError}."));
            SetStatus(SystemRoutingStatus.FailedClosed);
            return;
        }

        if (!WinDivertNative.Send(handle, packetBuffer, recvLen, out _, address))
        {
            var sendError = Marshal.GetLastWin32Error();
            Interlocked.Increment(ref _sendFailureCount);
            _failClosed = true;
            _logger.Error("RoutingDiagnostics", $"WinDivertSend failed on the {legName} leg (#{captureNumber}, {captured.SrcAddr}:{captured.SrcPort} -> {captured.DstAddr}:{captured.DstPort}); failing closed. Win32 error {sendError}.", new InvalidOperationException($"Win32 error {sendError}."));
            SetStatus(SystemRoutingStatus.FailedClosed);
            return;
        }

        Interlocked.Increment(ref _successfulReinjectionCount);
        if (_diagnosticsEnabled)
        {
            _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] [{legName.ToUpperInvariant()} #{captureNumber}] reinjected successfully.");
        }
    }

    private static unsafe bool TryParseTcpPacket(byte* packetBuffer, uint packetLength, out WinDivertNative.IPv4Header* ipv4Header, out WinDivertNative.TcpHeader* tcpHeader)
    {
        ipv4Header = null;
        tcpHeader = null;

        var result = WinDivertNative.ParsePacket(
            packetBuffer,
            packetLength,
            out var ip,
            out _,
            out var protocol,
            out _,
            out _,
            out var tcp,
            out _,
            out _,
            out _,
            out _,
            out _);

        if (!result || ip == null || tcp == null)
        {
            return false;
        }

        // IPv4 TCP only - V0.2 is TCP-only and does not handle IPv6.
        if (ip->Version != 4 || protocol != 6)
        {
            return false;
        }

        ipv4Header = ip;
        tcpHeader = tcp;
        return true;
    }

    /// <summary>TCP ports in the packet are stored in network (big-endian) byte order.</summary>
    private static int NativePortToHost(ushort nativePort) => BinaryPrimitives.ReverseEndianness(nativePort);

    private static ushort HostPortToNative(int hostPort)
    {
        if (hostPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(hostPort), hostPort, "TCP port must be between 1 and 65535.");
        }

        return BinaryPrimitives.ReverseEndianness((ushort)hostPort);
    }

    private static IPAddress NativeIpv4ToIPAddress(uint nativeAddress)
    {
        // WINDIVERT_IPHDR addresses are the four IPv4 bytes as they appear
        // in the packet. Windows is little-endian, so BitConverter restores
        // those four bytes in network-address order for IPAddress.
        return new IPAddress(BitConverter.GetBytes(nativeAddress));
    }

    private static uint IPAddressToNativeIpv4(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4)
        {
            throw new ArgumentException("Whole Computer V0.2 currently supports IPv4 addresses only.", nameof(address));
        }

        return BitConverter.ToUInt32(bytes, 0);
    }

    private static bool IsCurrentProcessElevated()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            // Defensive: any failure resolving elevation is treated as "not
            // elevated" - fail closed on the side of NOT offering Whole
            // Computer mode rather than risking an incorrect "supported".
            return false;
        }
    }

    private void SetStatus(SystemRoutingStatus status)
    {
        lock (_lock)
        {
            _status = status;
        }

        StatusChanged?.Invoke(this, status);
    }
}
