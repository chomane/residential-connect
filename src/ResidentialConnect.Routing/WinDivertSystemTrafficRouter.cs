using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using WinDivertSharp;

namespace ResidentialConnect.Routing;

/// <summary>
/// <see cref="ISystemTrafficRouter"/> implementation for V0.2, built on
/// <a href="https://reqrypt.org/windivert.html">WinDivert</a> - a mature,
/// widely-used, dual-licensed (LGPLv3/GPLv2) Windows kernel driver + user-mode
/// library for capturing, modifying, and re-injecting network packets,
/// accessed here via the <c>Aigio.WinDivertSharp</c> managed P/Invoke wrapper
/// and the <c>Native.WinDivert</c> package (which ships the official,
/// unmodified <c>WinDivert.dll</c>/<c>WinDivert64.sys</c> binaries). WinDivert
/// was chosen, per the product requirement, specifically to AVOID inventing a
/// custom network driver/protocol - it is the standard, proven component the
/// Windows community already uses for exactly this "system-wide transparent
/// proxy redirect" use case (the same fundamental technique used by numerous
/// public WinDivert-based proxy tools).
/// </summary>
/// <remarks>
/// <para><b>How interception/redirection actually works</b> (the "NAT" pattern):</para>
/// <list type="number">
/// <item>Three WinDivert handles are opened at <see cref="WinDivertLayer.Network"/>
/// (the only layer that can both capture AND re-inject modified packets -
/// <see cref="WinDivertLayer.Forward"/> is for transit/routed traffic, not
/// traffic to/from the local machine itself, and is explicitly documented as
/// not mixing well with NAT-style rewriting):
///   <list type="bullet">
///   <item>A <b>DNS-block handle</b> (see <see cref="DnsLeakGuard"/>) opened
///   with <see cref="WinDivertOpenFlags.Drop"/> - the driver itself silently
///   drops matching packets in-kernel; nothing is ever delivered to user
///   mode. This alone is V0.2's entire DNS leak protection.</item>
///   <item>A <b>forward handle</b> capturing real, non-loopback outbound TCP
///   traffic (<see cref="BypassFilterBuilder.BuildForwardFilter"/>), excluding
///   our own re-injected packets (<c>!impostor</c>) and excluding traffic to
///   the upstream proxy itself (the loop-prevention/self-exclusion rule).</item>
///   <item>A <b>return handle</b> capturing the local transparent relay's
///   own reply traffic back toward the redirected application
///   (<see cref="BypassFilterBuilder.BuildReturnFilter"/>).</item>
///   </list>
/// </item>
/// <item>For each captured forward packet, <see cref="PacketRedirectPlanner.PlanForward"/>
/// decides whether to rewrite it. A brand-new SYN has its true destination
/// recorded in <see cref="RedirectFlowTable"/> (keyed by the flow's client
/// TCP port) and its packet header destination rewritten to
/// <c>127.0.0.1:&lt;TransparentForwardingProxy port&gt;</c>; every subsequent
/// packet of an already-tracked flow gets the identical rewrite re-applied
/// (this is essential - rewriting only the SYN would not change what
/// destination the application's own TCP stack keeps addressing every later
/// packet to). Checksums are recalculated
/// (<c>WinDivertHelperCalcChecksums</c>) and the packet is re-injected
/// (<c>WinDivertSend</c>) on the SAME (outbound) direction.</item>
/// <item>The rewritten packet's destination is now a local address, so
/// Windows delivers it to <c>TransparentForwardingProxy</c>'s listening
/// socket (bound to <see cref="IPAddress.Any"/>) exactly as if the
/// application had dialed it directly - the accepted connection's remote
/// endpoint (as the OS reports it to the relay) is still the untouched
/// original client IP:port, which is exactly the key
/// <see cref="RedirectFlowTable"/> (as <see cref="IOriginalDestinationResolver"/>)
/// uses to tell the relay the ORIGINAL destination to actually tunnel to.</item>
/// <item>For each captured return packet (the relay's own replies, now
/// classified <c>loopback</c> because both endpoints are local machine
/// addresses), <see cref="PacketRedirectPlanner.PlanReturn"/> rewrites the
/// packet's SOURCE address/port to impersonate the real original
/// destination the application believes it is talking to, recalculates
/// checksums, and re-injects it - without this step the application's own
/// TCP stack would reject the reply as not matching any connection it
/// expects.</item>
/// </list>
/// <para><b>Loop prevention:</b> two independent mechanisms combine to make
/// re-interception impossible: (a) every packet WinDivert itself re-injects
/// is automatically tagged <c>impostor</c>, and both the forward and DNS
/// filters explicitly exclude impostor packets; (b) the forward filter also
/// excludes any packet addressed to the upstream proxy's own host:port
/// (<see cref="BypassFilterBuilder"/> remarks) - this is what specifically
/// satisfies "Residential Connect's own upstream proxy connection must
/// bypass its own interception path", covering both the relay's per-flow
/// tunnels AND this app's own connectivity-test HTTPS call.</para>
/// <para><b>Fail-closed:</b> <see cref="TransparentForwardingProxy.Faulted"/>
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
/// <para><b>TCP/UDP support status:</b> V0.2 is <b>TCP-only</b>. Only TCP
/// flows are redirected through the residential proxy (matching the fact
/// that both HTTP CONNECT and SOCKS5 upstream tunnels are inherently
/// TCP-based - see <c>HttpConnectUpstreamConnector</c>/<c>Socks5UpstreamConnector</c>).
/// Plain UDP is NOT redirected or proxied for arbitrary applications; the
/// only UDP-specific handling at all is the DNS-leak block described above
/// (which blocks, rather than proxies, UDP/53). This is a real, documented
/// limitation, not a hidden gap - see <c>docs/ARCHITECTURE.md</c> "Known
/// limitations" and the acceptance-test notes.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("windows")]
public sealed class WinDivertSystemTrafficRouter : ISystemTrafficRouter
{
    private const short ForwardPriority = 0;
    private const short ReturnPriority = 0;
    private const short DnsPriority = 0;
    private static readonly IntPtr InvalidHandle = new(-1);

    private readonly IAppLogger _logger;
    private readonly RedirectFlowTable _flowTable;
    private readonly Func<ITransparentForwardingProxy> _relayFactory;
    private readonly RoutingStateMarker _stateMarker;
    private readonly object _lock = new();

    private SystemRoutingStatus _status = SystemRoutingStatus.Disabled;
    private volatile bool _failClosed;

    private ITransparentForwardingProxy? _relay;
    private IntPtr _forwardHandle = InvalidHandle;
    private IntPtr _returnHandle = InvalidHandle;
    private IntPtr _dnsHandle = InvalidHandle;
    private CancellationTokenSource? _cts;
    private Task? _forwardLoopTask;
    private Task? _returnLoopTask;

    public WinDivertSystemTrafficRouter(
        IAppLogger logger,
        Func<ITransparentForwardingProxy> relayFactory,
        RoutingStateMarker stateMarker)
        : this(logger, relayFactory, stateMarker, new RedirectFlowTable())
    {
    }

    /// <summary>Test-only seam allowing a caller to supply/inspect the flow table directly.</summary>
    internal WinDivertSystemTrafficRouter(
        IAppLogger logger,
        Func<ITransparentForwardingProxy> relayFactory,
        RoutingStateMarker stateMarker,
        RedirectFlowTable flowTable)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _relayFactory = relayFactory ?? throw new ArgumentNullException(nameof(relayFactory));
        _stateMarker = stateMarker ?? throw new ArgumentNullException(nameof(stateMarker));
        _flowTable = flowTable ?? throw new ArgumentNullException(nameof(flowTable));
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

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(profile.Host, cancellationToken).ConfigureAwait(false);
            var ipv4Addresses = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
            if (ipv4Addresses.Count == 0)
            {
                throw new InvalidOperationException($"Could not resolve an IPv4 address for proxy host '{profile.Host}' - refusing to start Whole Computer mode (fail-closed).");
            }

            _relay = _relayFactory();
            _relay.Faulted += OnRelayFaulted;
            var relayPort = await _relay.StartAsync(profile, password, IPAddress.Any, _flowTable, cancellationToken).ConfigureAwait(false);

            var forwardFilter = BypassFilterBuilder.BuildForwardFilter(ipv4Addresses, profile.Port);
            var returnFilter = BypassFilterBuilder.BuildReturnFilter(relayPort);
            var dnsFilter = BypassFilterBuilder.BuildDnsFilter();

            _dnsHandle = OpenHandleOrThrow(dnsFilter, WinDivertLayer.Network, DnsPriority, WinDivertOpenFlags.Drop, "DNS leak-protection");
            _forwardHandle = OpenHandleOrThrow(forwardFilter, WinDivertLayer.Network, ForwardPriority, WinDivertOpenFlags.None, "forward");
            _returnHandle = OpenHandleOrThrow(returnFilter, WinDivertLayer.Network, ReturnPriority, WinDivertOpenFlags.None, "return");

            _cts = new CancellationTokenSource();
            var relayAddress = IPAddress.Loopback;
            _forwardLoopTask = Task.Run(() => ForwardLoop(_forwardHandle, relayAddress, relayPort, _cts.Token), CancellationToken.None);
            _returnLoopTask = Task.Run(() => ReturnLoop(_returnHandle, _cts.Token), CancellationToken.None);

            _stateMarker.MarkActive();
            _logger.Info("WinDivertSystemTrafficRouter", $"Whole Computer routing active. Forward filter: \"{forwardFilter}\". Relay listening on 127.0.0.1:{relayPort}.");
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

        // WinDivertClose() on another thread reliably unblocks a thread
        // currently parked in WinDivertRecv() for that same handle - the
        // documented, standard way to stop a capture loop.
        CloseHandle(ref _forwardHandle);
        CloseHandle(ref _returnHandle);
        CloseHandle(ref _dnsHandle);

        if (_forwardLoopTask is not null)
        {
            try { await _forwardLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        if (_returnLoopTask is not null)
        {
            try { await _returnLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        if (_relay is not null)
        {
            _relay.Faulted -= OnRelayFaulted;
            try { await _relay.StopAsync().ConfigureAwait(false); } catch { /* best-effort on teardown */ }
            _relay.Dispose();
            _relay = null;
        }

        _flowTable.Clear();
        _cts?.Dispose();
        _cts = null;
        _forwardLoopTask = null;
        _returnLoopTask = null;
        _failClosed = false;
    }

    private void OnRelayFaulted(object? sender, Exception ex)
    {
        _failClosed = true;
        _logger.Error("WinDivertSystemTrafficRouter", "Transparent relay faulted while Whole Computer mode was active - failing closed: intercepted traffic will now be DROPPED (never sent direct) until DISCONNECT.", ex);
        SetStatus(SystemRoutingStatus.FailedClosed);
    }

    private IntPtr OpenHandleOrThrow(string filter, WinDivertLayer layer, short priority, WinDivertOpenFlags flags, string handleDescription)
    {
        var handle = WinDivert.WinDivertOpen(filter, layer, priority, flags);
        if (handle == InvalidHandle)
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Failed to open the {handleDescription} WinDivert handle (Win32 error {error}). This usually means the process is not elevated, the WinDivert driver could not be loaded, or another instance already holds a conflicting handle.");
        }

        return handle;
    }

    private static void CloseHandle(ref IntPtr handle)
    {
        if (handle != InvalidHandle && handle != IntPtr.Zero)
        {
            WinDivert.WinDivertClose(handle);
        }

        handle = InvalidHandle;
    }

    private void ForwardLoop(IntPtr handle, IPAddress relayAddress, int relayPort, CancellationToken cancellationToken)
    {
        var buffer = new WinDivertBuffer(ushort.MaxValue);
        var processed = 0;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var address = new WinDivertAddress();
                uint recvLen = 0;
                if (!WinDivert.WinDivertRecv(handle, buffer, ref address, ref recvLen))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    // Transient recv errors (e.g. a packet was too large for
                    // the buffer) are logged and skipped; a genuinely closed
                    // handle (our own StopAsync/TearDownAsync) is what the
                    // cancellation check above is for.
                    continue;
                }

                ProcessForwardPacket(handle, buffer, recvLen, ref address, relayAddress, relayPort);

                if (++processed % 512 == 0)
                {
                    _flowTable.EvictIdle();
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
        finally
        {
            buffer.Dispose();
        }
    }

    private void ReturnLoop(IntPtr handle, CancellationToken cancellationToken)
    {
        var buffer = new WinDivertBuffer(ushort.MaxValue);
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var address = new WinDivertAddress();
                uint recvLen = 0;
                if (!WinDivert.WinDivertRecv(handle, buffer, ref address, ref recvLen))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    continue;
                }

                ProcessReturnPacket(handle, buffer, recvLen, ref address);
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
        finally
        {
            buffer.Dispose();
        }
    }

    private unsafe void ProcessForwardPacket(IntPtr handle, WinDivertBuffer buffer, uint recvLen, ref WinDivertAddress address, IPAddress relayAddress, int relayPort)
    {
        var parsed = WinDivert.WinDivertHelperParsePacket(buffer, recvLen);
        if (parsed.IPv4Header == null || parsed.TcpHeader == null)
        {
            // Not an IPv4/TCP packet (should not happen given our filter -
            // defensive only). Fail closed: never resend something this
            // code did not explicitly classify.
            return;
        }

        var ip = parsed.IPv4Header;
        var tcp = parsed.TcpHeader;

        var captured = new CapturedTcpPacket(
            IsSyn: tcp->Syn != 0,
            IsAck: tcp->Ack != 0,
            IsFin: tcp->Fin != 0,
            IsRst: tcp->Rst != 0,
            SrcPort: tcp->SrcPort,
            DstPort: tcp->DstPort,
            DstAddr: ip->DstAddr);

        var decision = PacketRedirectPlanner.PlanForward(captured, _flowTable, relayAddress, relayPort, _failClosed);
        if (!decision.ShouldRewrite)
        {
            // Fail-closed: drop rather than resend unmodified.
            return;
        }

        ip->DstAddr = decision.NewAddress!;
        tcp->DstPort = (ushort)decision.NewPort!.Value;

        WinDivert.WinDivertHelperCalcChecksums(buffer, recvLen, ref address, WinDivertChecksumHelperParam.All);
        WinDivert.WinDivertSend(handle, buffer, recvLen, ref address);
    }

    private unsafe void ProcessReturnPacket(IntPtr handle, WinDivertBuffer buffer, uint recvLen, ref WinDivertAddress address)
    {
        var parsed = WinDivert.WinDivertHelperParsePacket(buffer, recvLen);
        if (parsed.IPv4Header == null || parsed.TcpHeader == null)
        {
            return;
        }

        var ip = parsed.IPv4Header;
        var tcp = parsed.TcpHeader;

        var captured = new CapturedTcpPacket(
            IsSyn: tcp->Syn != 0,
            IsAck: tcp->Ack != 0,
            IsFin: tcp->Fin != 0,
            IsRst: tcp->Rst != 0,
            SrcPort: tcp->SrcPort,
            DstPort: tcp->DstPort,
            DstAddr: ip->DstAddr);

        var decision = PacketRedirectPlanner.PlanReturn(captured, _flowTable, _failClosed);
        if (!decision.ShouldRewrite)
        {
            return;
        }

        ip->SrcAddr = decision.NewAddress!;
        tcp->SrcPort = (ushort)decision.NewPort!.Value;

        WinDivert.WinDivertHelperCalcChecksums(buffer, recvLen, ref address, WinDivertChecksumHelperParam.All);
        WinDivert.WinDivertSend(handle, buffer, recvLen, ref address);
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
