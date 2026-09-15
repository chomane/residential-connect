using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

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
/// <item>Three WinDivert handles are opened at <see cref="WinDivertNative.Layer.Network"/>
/// (the only layer that can both capture AND re-inject modified packets):
///   <list type="bullet">
///   <item>A <b>DNS-block handle</b> (see <see cref="DnsLeakGuard"/>) opened
///   with <see cref="WinDivertNative.OpenFlags.Drop"/> - the driver itself
///   silently drops matching packets in-kernel; nothing is ever delivered to
///   user mode. This alone is V0.2's entire DNS leak protection.</item>
///   <item>A <b>forward handle</b> capturing real, non-loopback outbound TCP
///   traffic (<see cref="BypassFilterBuilder.BuildForwardFilter"/>), excluding
///   our own re-injected packets (<c>!impostor</c>), traffic to the upstream
///   proxy itself, and the local relay's own reply traffic (see that method's
///   remarks for why the last exclusion is required).</item>
///   <item>A <b>return handle</b> capturing the local transparent relay's
///   own reply traffic back toward the redirected application
///   (<see cref="BypassFilterBuilder.BuildReturnFilter"/>).</item>
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
/// <para><b>Loop prevention:</b> three independent mechanisms combine to make
/// re-interception impossible: (a) every packet WinDivert itself re-injects
/// is automatically tagged <c>impostor</c>, and both the forward and DNS
/// filters explicitly exclude impostor packets; (b) reflected packets are
/// marked <c>Inbound</c>, so they no longer match either filter's
/// <c>outbound</c> clause even before the impostor tag is considered; (c) the
/// forward filter also excludes any packet addressed to the upstream proxy's
/// own host:port and any packet SOURCED from the local relay's own listening
/// port (<see cref="BypassFilterBuilder"/> remarks) - together satisfying
/// "Residential Connect's own upstream proxy connection must bypass its own
/// interception path".</para>
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
public sealed class WinDivertSystemTrafficRouter : ISystemTrafficRouter
{
    private const short ForwardPriority = 0;
    private const short ReturnPriority = 0;
    private const short DnsPriority = 0;

    private readonly IAppLogger _logger;
    private readonly RedirectFlowTable _flowTable;
    private readonly Func<ITransparentForwardingProxy> _relayFactory;
    private readonly RoutingStateMarker _stateMarker;
    private readonly object _lock = new();

    private SystemRoutingStatus _status = SystemRoutingStatus.Disabled;
    private volatile bool _failClosed;

    private ITransparentForwardingProxy? _relay;
    private IntPtr _forwardHandle = WinDivertNative.InvalidHandle;
    private IntPtr _returnHandle = WinDivertNative.InvalidHandle;
    private IntPtr _dnsHandle = WinDivertNative.InvalidHandle;
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
            // Validate our native struct layout assumptions BEFORE opening
            // any WinDivert handle - see WinDivertNative remarks for why
            // this matters (a mismatched ABI here previously caused
            // coreclr.dll access-violation crashes via a third-party
            // managed wrapper).
            WinDivertNative.ValidateAbi();

            var addresses = await Dns.GetHostAddressesAsync(profile.Host, cancellationToken).ConfigureAwait(false);
            var ipv4Addresses = addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToList();
            if (ipv4Addresses.Count == 0)
            {
                throw new InvalidOperationException($"Could not resolve an IPv4 address for proxy host '{profile.Host}' - refusing to start Whole Computer mode (fail-closed).");
            }

            _relay = _relayFactory();
            _relay.Faulted += OnRelayFaulted;
            var relayPort = await _relay.StartAsync(profile, password, IPAddress.Any, _flowTable, cancellationToken).ConfigureAwait(false);

            var forwardFilter = BypassFilterBuilder.BuildForwardFilter(ipv4Addresses, profile.Port, relayPort);
            var returnFilter = BypassFilterBuilder.BuildReturnFilter(relayPort);
            var dnsFilter = BypassFilterBuilder.BuildDnsFilter();

            _dnsHandle = OpenHandleOrThrow(dnsFilter, WinDivertNative.Layer.Network, DnsPriority, WinDivertNative.OpenFlags.Drop, "DNS leak-protection");
            _forwardHandle = OpenHandleOrThrow(forwardFilter, WinDivertNative.Layer.Network, ForwardPriority, WinDivertNative.OpenFlags.None, "forward");
            _returnHandle = OpenHandleOrThrow(returnFilter, WinDivertNative.Layer.Network, ReturnPriority, WinDivertNative.OpenFlags.None, "return");

            _cts = new CancellationTokenSource();
            _forwardLoopTask = Task.Run(() => ForwardLoop(_forwardHandle, relayPort, _cts.Token), CancellationToken.None);
            _returnLoopTask = Task.Run(() => ReturnLoop(_returnHandle, _cts.Token), CancellationToken.None);

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

        if (_forwardLoopTask is not null)
        {
            try { await _forwardLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        if (_returnLoopTask is not null)
        {
            try { await _returnLoopTask.ConfigureAwait(false); } catch { /* loop already logs its own faults */ }
        }

        CloseHandle(ref _forwardHandle);
        CloseHandle(ref _returnHandle);
        CloseHandle(ref _dnsHandle);

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

    private unsafe void ProcessForwardPacket(IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address, int relayPort)
    {
        if (!TryParseTcpPacket(packetBuffer, recvLen, out var ip, out var tcp))
        {
            // Fail closed. Do not resend an unclassified packet.
            return;
        }

        var captured = CapturePacket(ip, tcp);

        var decision = PacketRedirectPlanner.PlanForward(captured, _flowTable, relayPort, _failClosed);
        if (!decision.ShouldReflect)
        {
            // Fail closed: captured traffic is not resent directly.
            return;
        }

        ApplyReflection(ip, tcp, address, decision);
        RecalculateAndSend(handle, packetBuffer, recvLen, address, "forward");
    }

    private unsafe void ProcessReturnPacket(IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address)
    {
        if (!TryParseTcpPacket(packetBuffer, recvLen, out var ip, out var tcp))
        {
            return;
        }

        var captured = CapturePacket(ip, tcp);

        var decision = PacketRedirectPlanner.PlanReturn(captured, _flowTable, _failClosed);
        if (!decision.ShouldReflect)
        {
            return;
        }

        ApplyReflection(ip, tcp, address, decision);
        RecalculateAndSend(handle, packetBuffer, recvLen, address, "return");
    }

    private static unsafe CapturedTcpPacket CapturePacket(WinDivertNative.IPv4Header* ip, WinDivertNative.TcpHeader* tcp)
    {
        var tcpFlags = tcp->HeaderLengthAndFlags;
        return new CapturedTcpPacket(
            IsSyn: (tcpFlags & 0x0200) != 0,
            IsAck: (tcpFlags & 0x1000) != 0,
            IsFin: (tcpFlags & 0x0100) != 0,
            IsRst: (tcpFlags & 0x0400) != 0,
            SrcAddr: NativeIpv4ToIPAddress(ip->SrcAddr),
            SrcPort: NativePortToHost(tcp->SrcPort),
            DstAddr: NativeIpv4ToIPAddress(ip->DstAddr),
            DstPort: NativePortToHost(tcp->DstPort));
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

    private unsafe void RecalculateAndSend(IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address, string legName)
    {
        // flags == 0 means recalculate all applicable checksums.
        if (!WinDivertNative.CalcChecksums(packetBuffer, recvLen, address, 0))
        {
            _failClosed = true;
            _logger.Error("WinDivertSystemTrafficRouter", $"WinDivert checksum recalculation failed on the {legName} leg; failing closed.", new InvalidOperationException($"Win32 error {Marshal.GetLastWin32Error()}."));
            SetStatus(SystemRoutingStatus.FailedClosed);
            return;
        }

        if (!WinDivertNative.Send(handle, packetBuffer, recvLen, out _, address))
        {
            _failClosed = true;
            _logger.Error("WinDivertSystemTrafficRouter", $"WinDivert packet reinjection failed on the {legName} leg; failing closed.", new InvalidOperationException($"Win32 error {Marshal.GetLastWin32Error()}."));
            SetStatus(SystemRoutingStatus.FailedClosed);
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
