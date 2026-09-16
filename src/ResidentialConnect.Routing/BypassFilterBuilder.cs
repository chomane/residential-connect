using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ResidentialConnect.Routing;

/// <summary>
/// Pure, side-effect-free construction of the WinDivert filter-language
/// strings used by <see cref="WinDivertSystemTrafficRouter"/> and
/// <see cref="DnsLeakGuard"/>. Deliberately kept free of any WinDivert
/// P/Invoke call (or any other native/Windows-only dependency) so it can be
/// unit tested on any OS, in this sandbox, without a real WinDivert driver -
/// unlike the packet-capture loops themselves, which require a real Windows
/// kernel and can only be exercised on a real Windows machine.
/// </summary>
/// <remarks>
/// <para>
/// <b>Loop prevention / self-exclusion (see <see cref="ISystemTrafficRouter"/>
/// XML docs and the product requirement "Residential Connect's own upstream
/// proxy connection must bypass its own interception path"):</b> the forward
/// filter excludes every packet whose destination is the resolved upstream
/// proxy IP(s):port. This single rule is sufficient to exclude BOTH (a) this
/// application's own initial connectivity-test HTTPS call
/// (<c>HttpProxyConnectivityTester</c>, which talks to the proxy host:port
/// directly) and (b) every per-flow tunnel <c>TransparentForwardingProxy</c>
/// opens to that exact same host:port on behalf of a redirected application -
/// because both of those legitimately need to reach the proxy itself, and
/// nothing else on the machine has any reason to be dialing that specific
/// residential proxy endpoint while Whole Computer mode is active.
/// </para>
/// <para>
/// <b>Why the forward filter does NOT exclude impostor packets (2026-09-15
/// fix):</b> an earlier revision of this filter included <c>!impostor</c>,
/// on the (reasonable-sounding, but empirically wrong for this specific
/// reflection technique) assumption that excluding every impostor-flagged
/// packet was a safe, simple way to prevent re-interception loops of our
/// own injected traffic. A dedicated, isolated single-handle "streamdump
/// parity" diagnostic - completely independent of this
/// router/relay/flow-table code, see
/// <c>tools/ResidentialConnect.StreamdumpParity</c> - proved on real
/// Windows hardware that the client's own final ACK (the packet that
/// completes the reflected TCP 3-way handshake, and which
/// <c>TransparentForwardingProxy</c>'s <c>AcceptTcpClientAsync</c> cannot
/// return without) is itself captured with <c>Impostor</c> set, even though
/// it is a genuine, newly-generated packet from the client machine's own
/// TCP/IP stack, not a re-injected duplicate of anything WinDivert itself
/// sent. This matches WinDivert's documented Impostor semantics: once a
/// TCP flow's SYN was itself an injected/reflected packet, later genuine
/// packets belonging to that SAME flow keep being tagged Impostor for the
/// life of the connection - it is a flow-provenance marker, not a
/// "this exact byte sequence was re-sent unchanged" marker.
/// <c>!impostor</c> in the forward filter was therefore silently discarding
/// the one packet needed to ever complete a redirected handshake, exactly
/// explaining the previously-observed symptom: SYN reflected, relay
/// generates a SYN-ACK, SYN-ACK reflected to the client, but the client's
/// completing ACK never reached user mode at all, so
/// <c>TransparentForwardingProxy</c> never saw a completed connection to
/// accept.
/// </para>
/// <para>
/// <b>Why removing the impostor exclusion here does NOT reopen a
/// re-interception loop:</b> loop prevention for this router's own
/// injected traffic does not rely on the impostor flag at all - it relies
/// on the Outbound/Inbound direction flip that is the core of the
/// reflection technique itself (see <see cref="PacketRedirectPlanner"/>
/// remarks). Every packet THIS router reflects and re-sends (both the
/// forward leg's SYN and the return leg's SYN-ACK/data) is explicitly
/// marked Inbound before re-injection (see
/// <see cref="WinDivertNative.MarkInbound"/>). Both this forward filter
/// and <see cref="BuildReturnFilter"/> require <c>outbound</c> - an
/// already-Inbound packet can never match either filter's base condition
/// again, regardless of its impostor flag, so this router's own
/// reflected/re-injected packets are structurally impossible to
/// re-capture and re-process a second time. The packets this relaxation
/// newly allows through are exclusively genuine, new, real Outbound
/// packets generated fresh by the local machine's own TCP/IP stack (the
/// client's completing ACK, and any of its later data/FIN packets) - and
/// <see cref="PacketRedirectPlanner.PlanForward"/> still fail-closed drops
/// any such packet whose source port is not either a brand-new SYN or an
/// already-tracked flow in <see cref="RedirectFlowTable"/>, so this
/// relaxation cannot cause an untracked or unrelated impostor packet to be
/// reflected either. In short: direction (Outbound-only capture plus
/// mandatory Inbound re-injection) combined with the existing flow-table
/// gate in <see cref="PacketRedirectPlanner"/> - not a blanket impostor
/// exclusion clause - are what actually prevent loops here.
/// </para>
/// <para>
/// <b>Why the RETURN filter does NOT exclude impostor packets either
/// (2026-09-16 fix):</b> after the forward-filter fix above shipped and was
/// confirmed working on real Windows hardware (the 3-way handshake now
/// completes, <c>TransparentForwardingProxy</c> accepts the connection, and
/// the upstream HTTP CONNECT succeeds), a NEW real-Windows diagnostic run
/// isolated the next blocker: for the target flow, the client's TLS
/// ClientHello (a genuine, established-flow DATA segment - flags
/// <c>ACK,PSH</c>, 673-byte payload) was captured on the FORWARD leg with
/// <c>Impostor=True</c> and reflected into the relay successfully, but the
/// RETURN leg never captured the relay's own ACK for that data at all - only
/// the earlier <c>SYN,ACK</c> was ever seen on RETURN. The client then
/// retransmitted the identical ClientHello segment repeatedly (classic
/// "my data was never ACKed" TCP behavior), and the upstream tunnel was torn
/// down with an <c>IOException</c> ("An existing connection was forcibly
/// closed by the remote host") and zero bytes ever relayed in either
/// direction. This is the exact same root cause as the forward leg, one hop
/// later: the relay's own ACK for a flow whose SYN-ACK was itself reflected
/// is, per WinDivert's documented flow-provenance Impostor semantics (see
/// the forward-filter remarks above), ALSO tagged <c>Impostor=True</c> - and
/// <c>!impostor</c> on this RETURN filter was silently discarding it, so the
/// client never received an ACK for its ClientHello and the relay's TCP
/// stack itself eventually reset the connection when writes to a peer that
/// stopped acknowledging kept failing. An independent, isolated single-handle
/// "streamdump parity" test (see <c>tools/ResidentialConnect.StreamdumpParity</c>,
/// extended 2026-09-16 to verify bidirectional established-flow DATA, not
/// just the handshake) already proved WinDivert reflection itself correctly
/// carries data in BOTH directions - ruling out a fundamental
/// reflection/checksum/ABI problem and pointing squarely at this filter's own
/// <c>!impostor</c> clause as the cause.
/// </para>
/// <para>
/// <b>Why removing the impostor exclusion here ALSO does not reopen a loop:</b>
/// exactly the same three mechanisms already relied on for the forward leg
/// apply here, unchanged: (a) this filter still requires <c>outbound</c> -
/// every packet this router itself reflects and re-sends is explicitly
/// marked Inbound before re-injection (<see cref="WinDivertNative.MarkInbound"/>),
/// so this router's own reflected/re-injected packets can never match this
/// filter's <c>outbound</c> clause a second time, regardless of their
/// impostor flag; (b) this filter still requires
/// <c>tcp.SrcPort == relayPort</c> - only the local relay's own traffic can
/// ever match it at all; (c) <see cref="PacketRedirectPlanner.PlanReturn"/>'s
/// own flow-table gate still fail-closed drops any captured packet whose
/// destination port is not an already-tracked flow in
/// <see cref="RedirectFlowTable"/>. Removing <c>!impostor</c> here only
/// allows through genuine, new, real Outbound packets from the relay's own
/// TCP stack on its own listening port - exactly the packets this filter
/// exists to capture in the first place.
/// </para>
/// <para>
/// The forward filter ALSO excludes any packet whose SOURCE port is the
/// local relay's own listening port (<c>tcp.SrcPort != relayPort</c>). This
/// is required by the packet-reflection redirect technique (see
/// <see cref="PacketRedirectPlanner"/>/<see cref="RedirectDecision"/>
/// remarks): once the relay's own TCP stack starts replying to a reflected
/// connection, those reply packets are ordinary, genuinely-outbound,
/// non-loopback TCP packets (their destination looks like a real remote
/// peer) and would otherwise ALSO match the forward filter's base
/// conditions - which must be prevented, or the forward handle would race
/// the dedicated return handle to reinterpret the relay's own replies as a
/// brand-new application connection attempt.
/// </para>
/// <para>
/// The WinDivert filter language's <c>processId</c> field is deliberately
/// NOT used for self-exclusion: per WinDivert's own documentation it "is not
/// supported by the WINDIVERT_LAYER_NETWORK*" layers (the layer this router
/// uses, since it is the only layer that can both capture AND re-inject
/// modified packets) - so a destination/source-port-based exclusion is not
/// just simpler but the only option available at this layer.
/// </para>
/// <para>
/// <b>Filter-syntax note:</b> the upstream-proxy exclusion intentionally
/// uses De Morgan form - <c>(tcp.DstPort != PORT or ip.DstAddr != IP)</c> -
/// rather than the seemingly-equivalent grouped negation
/// <c>not (tcp.DstPort == PORT and ip.DstAddr == IP)</c>. The grouped form
/// was found to be rejected by the WinDivert filter parser (Win32 error 87,
/// <c>ERROR_INVALID_PARAMETER</c>) during live Windows testing; the De
/// Morgan form compiles and behaves identically.
/// </para>
/// </remarks>
public static class BypassFilterBuilder
{
    /// <summary>
    /// Builds the filter for the FORWARD capture handle: real, non-loopback
    /// outbound TCP traffic, excluding traffic to the upstream proxy itself
    /// and the local relay's own reply traffic (see class remarks for why
    /// the latter is required by the reflection technique). Deliberately
    /// does NOT exclude <c>impostor</c> packets - see class remarks
    /// "Why the forward filter does NOT exclude impostor packets" for the
    /// 2026-09-15 evidence (an isolated streamdump-parity diagnostic) that
    /// the client's own handshake-completing ACK for a reflected flow is
    /// itself flagged Impostor, and excluding it silently prevented every
    /// redirected TCP connection from ever completing its 3-way handshake.
    /// </summary>
    public static string BuildForwardFilter(IReadOnlyCollection<IPAddress> proxyIPv4Addresses, int proxyPort, int relayPort)
    {
        ArgumentNullException.ThrowIfNull(proxyIPv4Addresses);

        if (proxyPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(proxyPort), proxyPort, "Proxy port must be between 1 and 65535.");
        }

        if (relayPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(relayPort), relayPort, "Relay port must be between 1 and 65535.");
        }

        var ipv4 = proxyIPv4Addresses.Where(a => a is not null && a.AddressFamily == AddressFamily.InterNetwork).Distinct().ToList();
        if (ipv4.Count == 0)
        {
            // No IPv4 address could be pinned for the upstream proxy (e.g.
            // DNS resolution returned only IPv6, or failed). We cannot build
            // a safe self-exclusion rule in that case - the caller (the
            // router's StartAsync) treats this as a hard failure and refuses
            // to start Whole Computer mode at all (fail-closed: better to
            // not intercept anything than to intercept without a working
            // loop-prevention rule).
            throw new InvalidOperationException(
                "Cannot build the whole-computer traffic filter without at least one resolved IPv4 address for the upstream proxy host - refusing to start (fail-closed).");
        }

        var baseFilter = "outbound and !loopback and tcp";
        var relayExclusion = $"tcp.SrcPort != {relayPort.ToString(CultureInfo.InvariantCulture)}";
        var proxyExclusions = ipv4.Select(ip =>
            $"(tcp.DstPort != {proxyPort.ToString(CultureInfo.InvariantCulture)} or ip.DstAddr != {ip})");

        var clauses = new[] { baseFilter, relayExclusion }.Concat(proxyExclusions);
        return string.Join(" and ", clauses);
    }

    /// <summary>
    /// Builds the filter for the RETURN capture handle: the local relay's
    /// own reply traffic (source port = <paramref name="relayPort"/>) on its
    /// way back out to the redirected application. Deliberately does NOT
    /// exclude <c>impostor</c> packets - see class remarks "Why the RETURN
    /// filter does NOT exclude impostor packets either (2026-09-16 fix)" for
    /// the real-Windows evidence that the relay's own ACK for the client's
    /// established-flow DATA (e.g. its TLS ClientHello) is itself flagged
    /// Impostor, for exactly the same flow-provenance reason the forward
    /// leg's completing ACK was.
    /// </summary>
    /// <remarks>
    /// Unlike an earlier revision of this router, this filter deliberately
    /// does NOT require <c>loopback</c>. Under the packet-reflection
    /// technique (see <see cref="PacketRedirectPlanner"/> remarks) the relay
    /// listens on a real local machine address (<c>IPAddress.Any</c>, not
    /// <c>127.0.0.1</c>) and its TCP stack believes each redirected
    /// connection's remote peer is the real, non-local original destination
    /// address - so the relay's own reply packets are NOT classified
    /// <c>loopback</c> by WinDivert (both endpoints must be local-machine
    /// addresses for that classification, and here the apparent remote peer
    /// is not). Requiring <c>loopback</c> here (the previous, broken design)
    /// meant this filter could never actually match the relay's real reply
    /// traffic, silently breaking Whole Computer mode.
    /// </remarks>
    public static string BuildReturnFilter(int relayPort)
    {
        if (relayPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(relayPort), relayPort, "Relay port must be between 1 and 65535.");
        }

        return $"outbound and tcp and tcp.SrcPort == {relayPort.ToString(CultureInfo.InvariantCulture)}";
    }

    /// <summary>
    /// Builds the filter for the DNS leak-protection capture handle: plain
    /// UDP port-53 queries leaving the machine (never loopback - a locally
    /// running DNS-ish service on 127.0.0.1:53 is not something Whole
    /// Computer mode needs to intervene on, and would not represent a leak).
    /// See <see cref="DnsLeakGuard"/> for what happens to captured queries.
    /// Deliberately UNCHANGED by the 2026-09-16 UDP-block addition below -
    /// see <see cref="BuildUdpBlockFilter"/> remarks for why DNS/53 keeps its
    /// own separate handle rather than being folded into the general UDP
    /// block.
    /// </summary>
    public static string BuildDnsFilter()
    {
        return "outbound and !loopback and !impostor and udp and udp.DstPort == 53";
    }

    /// <summary>
    /// Builds the filter for the general UDP-block leak-protection capture
    /// handle (2026-09-16 addition): every other real, non-loopback outbound
    /// UDP packet leaving the machine while Whole Computer mode is Active -
    /// specifically excluding UDP/53 (already handled by its own,
    /// unchanged, separate <see cref="BuildDnsFilter"/> handle, so the two
    /// Drop handles never overlap the same packet).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why block ALL other UDP outright, additively, rather than proxy
    /// it:</b> the current Residential Connect upstream implementation does
    /// not proxy UDP. HTTP CONNECT is TCP-only, and our current SOCKS5
    /// connector implements TCP CONNECT only; SOCKS5 UDP ASSOCIATE is not
    /// implemented (see <see cref="ResidentialConnect.Proxy.Forwarding.Socks5UpstreamConnector"/>).
    /// There is therefore no upstream path that could carry a redirected UDP
    /// packet through the residential proxy at all - unlike TCP, where
    /// <see cref="WinDivertSystemTrafficRouter"/>'s reflection technique
    /// hands a redirected connection to <c>TransparentForwardingProxy</c>,
    /// which opens a real upstream TCP tunnel. Given that constraint, the
    /// only two options are: (a) let non-DNS UDP through unmodified, which
    /// would let protocols like QUIC/HTTP-3 (UDP/443), WebRTC/STUN, or any
    /// UDP-based application traffic reach the real network directly and
    /// completely bypass the residential proxy even while Whole Computer
    /// mode reports Active - a silent leak of exactly the kind the
    /// product's fail-closed requirement forbids - or (b) block it. Per that
    /// requirement ("never silently fall back to the user's real
    /// connection"), (b) is the only consistent choice: an application using
    /// QUIC (most modern browsers automatically retry over HTTP/2 or HTTP/1.1
    /// on TCP/443 when UDP/443 is unreachable - the "fallback to TCP"
    /// behavior this design deliberately relies on rather than reimplements)
    /// or any other UDP protocol will see that traffic fail/time out rather
    /// than silently egressing outside the proxy.
    /// </para>
    /// <para>
    /// <b>Why this is a SEPARATE handle from the DNS-block handle, not a
    /// single merged filter:</b> keeping <see cref="BuildDnsFilter"/>
    /// completely unchanged (per the standing instruction not to modify
    /// verified/working leak-protection behavior) was simpler and safer than
    /// rewriting one combined filter string - two independent
    /// <c>WinDivertNative.OpenFlags.Drop</c> handles with non-overlapping
    /// <c>udp.DstPort</c> conditions (this one explicitly excludes 53) behave
    /// identically to one combined filter would, without touching a single
    /// already-verified line.
    /// </para>
    /// <para>
    /// <b>Fail-closed, in-kernel, zero user-mode involvement:</b> exactly
    /// like the DNS-block handle, this filter is opened with
    /// <see cref="WinDivertNative.OpenFlags.Drop"/> - the WinDivert driver
    /// itself silently drops every matching packet before it ever reaches
    /// user mode. There is no capture loop, no thread, and no possibility of
    /// a captured-but-not-yet-processed packet slipping through this handle,
    /// unlike the forward/return TCP handles (which must actually inspect
    /// and reflect packets in user mode).
    /// </para>
    /// </remarks>
    public static string BuildUdpBlockFilter()
    {
        return "outbound and !loopback and udp and udp.DstPort != 53";
    }
}
