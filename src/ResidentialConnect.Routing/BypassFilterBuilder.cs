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
/// <b>Filter-syntax note (empirically required, real-Windows verified):</b>
/// every exclusion in this file is written in pure De Morgan form - a
/// negated SINGLE test (<c>!loopback</c>, <c>!impostor</c>, <c>ip.DstAddr !=
/// X</c>, <c>!udp</c>) or a parenthesized OR of negated comparisons (e.g.
/// <c>(tcp.DstPort != PORT or ip.DstAddr != IP)</c>) - and this file
/// deliberately NEVER writes <c>not (...)</c> around a compound
/// (multi-clause) expression. A 2026-09-16 real-Windows test confirmed that
/// WinDivert's filter parser REJECTS a grouped negation of a compound
/// expression with Win32 error 87 (<c>ERROR_INVALID_PARAMETER</c>), even
/// though the parenthesized-group grammar itself is otherwise valid; the
/// equivalent De Morgan expansion compiles and behaves identically. This
/// rule was re-confirmed and made explicit again in a 2026-09-16 correction
/// pass across every LAN/local-range exclusion added that day (IPv4 TCP,
/// IPv4 UDP, unsupported-IPv4-protocol, and IPv6 local-range exclusions all
/// previously used a single <c>not (A or B or C or ...)</c> group and were
/// rewritten to per-range De Morgan expansions - see
/// <see cref="Ipv4LanOrLocalExclusionClauses"/>/<see cref="Ipv6LocalExclusionClauses"/>).
/// </para>
/// <para>
/// <b>2026-09-16 correction: LAN/local bypass, IPv4 UDP parity, and IPv6
/// fail-closed policy (as further corrected the same day for filter
/// mutual-exclusivity and the De Morgan rule above).</b> A real-Windows test
/// revealed two additional defects beyond the unmatched-TCP-drop issue
/// documented on <see cref="PacketRedirectPlanner"/>: (1) plain UDP/53 was
/// being DROPPED (not proxied) - see <see cref="BuildDnsFilter"/>'s remarks
/// for the fix (now captured and answered via DNS-over-HTTPS through the
/// proxy, not blocked); (2) private/LAN destinations were being captured by
/// the same broad forward filter as public Internet traffic, subjecting
/// them to the same "no reflect decision" handling as public traffic even
/// though there is no proxy path (or need) for LAN devices. The filter
/// partition is now (each row captured by EXACTLY ONE handle - see
/// <see cref="BypassFilterBuilderTests"/> for tests asserting the DNS
/// handles are mutually exclusive and the IPv6 block never overlaps
/// IPv6 UDP/53):
/// <list type="bullet">
/// <item>IPv4 public TCP -&gt; the proven reflection/proxy engine (<see cref="BuildForwardFilter"/>/<see cref="BuildReturnFilter"/>).</item>
/// <item>IPv4 LAN TCP -&gt; excluded from <see cref="BuildForwardFilter"/> entirely (never captured; continues over the real NIC untouched).</item>
/// <item>UDP/53 (IPv4 OR IPv6) -&gt; captured and answered via proxied DoH (<see cref="BuildDnsFilter"/>/<see cref="BuildDnsFilterV6"/>), regardless of whether the configured DNS server is public or a LAN router - DNS must never bypass the proxy, even to a LAN resolver, because the QUERY CONTENT (hostnames visited) is exactly what must not leak. The IPv4 and IPv6 DNS filters are explicitly scoped (<c>ip</c> vs <c>ipv6</c>) so no packet can ever match both.</item>
/// <item>IPv4 public, non-DNS UDP -&gt; DROP (<see cref="BuildUdpBlockFilter"/>, now LAN-exempted, explicitly IPv4-scoped).</item>
/// <item>IPv4 LAN, non-DNS UDP -&gt; excluded from <see cref="BuildUdpBlockFilter"/>; continues over the real NIC untouched.</item>
/// <item>Public IPv6, ALL protocols EXCEPT UDP/53 -&gt; DROP (<see cref="BuildIPv6BlockFilter"/>) - V0.2 does not proxy IPv6 transport at all. UDP/53 is explicitly exempted from this block (see that method's remarks) so it is never double-matched/dropped by this handle instead of being captured by <see cref="BuildDnsFilterV6"/>.</item>
/// <item>Local IPv6 (loopback/link-local/ULA/multicast) -&gt; excluded from <see cref="BuildIPv6BlockFilter"/>; continues untouched.</item>
/// <item>Unsupported public IPv4 protocols (e.g. ICMP) -&gt; DROP (<see cref="BuildOtherProtocolBlockFilter"/>); LAN-exempted the same way.</item>
/// </list>
/// </para>
/// </remarks>
public static class BypassFilterBuilder
{
    /// <summary>
    /// Per-range De Morgan-negated IPv4 LAN/local clauses - i.e. "destination
    /// is NOT in this range", one clause per range, meant to be joined with
    /// <c>" and "</c> by callers (never wrapped in an outer <c>not (...)</c> -
    /// see class remarks "Filter-syntax note"). Each range's negation is
    /// either a single comparison (<c>ip.DstAddr != X</c> for the single-IP
    /// broadcast case) or a parenthesized OR of two comparisons
    /// (<c>(ip.DstAddr &lt; low or ip.DstAddr &gt; high)</c>) - the same
    /// parenthesized-OR shape already proven to compile on real Windows
    /// hardware by the existing upstream-proxy self-exclusion clause.
    /// </summary>
    /// <remarks>
    /// Ranges excluded, each an IANA-reserved special-use IPv4 block:
    /// <list type="bullet">
    /// <item>10.0.0.0/8 (RFC 1918 private)</item>
    /// <item>172.16.0.0/12 (RFC 1918 private)</item>
    /// <item>192.168.0.0/16 (RFC 1918 private)</item>
    /// <item>169.254.0.0/16 (link-local / APIPA)</item>
    /// <item>127.0.0.0/8 (loopback net - belt-and-suspenders alongside the separate <c>!loopback</c> clause, which classifies by BOTH endpoints being local-machine addresses, not by destination range alone)</item>
    /// <item>224.0.0.0/4 (multicast, e.g. mDNS/SSDP)</item>
    /// <item>255.255.255.255 (limited broadcast)</item>
    /// </list>
    /// </remarks>
    private static readonly string[] Ipv4LanOrLocalExclusionClauses =
    [
        "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)",
        "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)",
        "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255)",
        "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)",
        "(ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255)",
        "(ip.DstAddr < 224.0.0.0 or ip.DstAddr > 239.255.255.255)",
        "ip.DstAddr != 255.255.255.255",
    ];

    /// <summary>
    /// Per-range De Morgan-negated IPv6 local-range clauses - the IPv6
    /// counterpart of <see cref="Ipv4LanOrLocalExclusionClauses"/>, covering
    /// loopback (::1), link-local (fe80::/10), unique-local/LAN (fc00::/7),
    /// and multicast (ff00::/8). Used by <see cref="BuildIPv6BlockFilter"/>
    /// so public IPv6 is blocked while these local ranges remain fully
    /// usable (e.g. local device discovery, LAN-only IPv6 services).
    /// </summary>
    private static readonly string[] Ipv6LocalExclusionClauses =
    [
        "ipv6.DstAddr != ::1",
        "(ipv6.DstAddr < fe80:: or ipv6.DstAddr > febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff)",
        "(ipv6.DstAddr < fc00:: or ipv6.DstAddr > fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff)",
        "(ipv6.DstAddr < ff00:: or ipv6.DstAddr > ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff)",
    ];

    /// <summary>
    /// Builds the filter for the FORWARD capture handle: real, non-loopback
    /// outbound IPv4 TCP traffic, excluding traffic to the upstream proxy
    /// itself, the local relay's own reply traffic (see class remarks for
    /// why the latter is required by the reflection technique), AND
    /// (2026-09-16 correction) any IPv4 LAN/local destination - see
    /// <see cref="Ipv4LanOrLocalExclusionClauses"/>. LAN TCP traffic (e.g. a
    /// browser talking to a router's admin UI, a local file share, a printer)
    /// has no proxy path and no reason to be intercepted at all; excluding it
    /// here means it is never even offered to <see cref="PacketRedirectPlanner"/>
    /// and simply continues over the real NIC untouched, exactly like the
    /// "IPv4 LAN TCP -&gt; untouched/bypass" row of the filter-partition table.
    /// Explicitly scoped with <c>ip</c> (IPv4) so a TCP-over-IPv6 packet is
    /// never captured here at all - it is instead exclusively handled by
    /// <see cref="BuildIPv6BlockFilter"/>, matching the "public IPv6, ALL
    /// protocols -&gt; DROP" row. Deliberately does NOT exclude
    /// <c>impostor</c> packets - see class remarks "Why the forward filter
    /// does NOT exclude impostor packets" for the 2026-09-15 evidence (an
    /// isolated streamdump-parity diagnostic) that the client's own
    /// handshake-completing ACK for a reflected flow is itself flagged
    /// Impostor, and excluding it silently prevented every redirected TCP
    /// connection from ever completing its 3-way handshake.
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

        var baseFilter = "outbound and !loopback and ip and tcp";
        var relayExclusion = $"tcp.SrcPort != {relayPort.ToString(CultureInfo.InvariantCulture)}";
        var proxyExclusions = ipv4.Select(ip =>
            $"(tcp.DstPort != {proxyPort.ToString(CultureInfo.InvariantCulture)} or ip.DstAddr != {ip})");

        var clauses = new[] { baseFilter, relayExclusion }
            .Concat(proxyExclusions)
            .Concat(Ipv4LanOrLocalExclusionClauses);
        return string.Join(" and ", clauses);
    }

    /// <summary>
    /// Builds the filter for the RETURN capture handle: the local relay's
    /// own reply traffic (source port = <paramref name="relayPort"/>) on its
    /// way back out to the redirected application. Explicitly scoped with
    /// <c>ip</c> (IPv4), matching <see cref="BuildForwardFilter"/> - the
    /// relay's upstream tunnels are IPv4-only in V0.2 (see
    /// <see cref="BuildIPv6BlockFilter"/> remarks), so its own reply traffic
    /// is always IPv4 too. Deliberately does NOT exclude <c>impostor</c>
    /// packets - see class remarks "Why the RETURN filter does NOT exclude
    /// impostor packets either (2026-09-16 fix)" for the real-Windows
    /// evidence that the relay's own ACK for the client's established-flow
    /// DATA (e.g. its TLS ClientHello) is itself flagged Impostor, for
    /// exactly the same flow-provenance reason the forward leg's completing
    /// ACK was.
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

        return $"outbound and ip and tcp and tcp.SrcPort == {relayPort.ToString(CultureInfo.InvariantCulture)}";
    }

    /// <summary>
    /// Builds the filter for the IPv4 DNS capture handle: plain UDP port-53
    /// queries leaving the machine over IPv4 (never loopback - a locally
    /// running DNS-ish service on 127.0.0.1:53 is not something Whole
    /// Computer mode needs to intervene on, and would not represent a leak).
    /// Explicitly scoped with <c>ip</c> (2026-09-16 correction, for
    /// mutual-exclusivity with <see cref="BuildDnsFilterV6"/> - WinDivert's
    /// <c>ip</c>/<c>ipv6</c> fields are "Is IPv4?"/"Is IPv6?" and a single
    /// packet can never satisfy both, so no packet can ever match both DNS
    /// handles). This filter INTENTIONALLY does not exclude LAN/router
    /// destinations (unlike <see cref="BuildForwardFilter"/>/
    /// <see cref="BuildUdpBlockFilter"/>'s LAN bypass) - see class remarks
    /// row "UDP/53 (IPv4 OR IPv6) -&gt; captured and answered via proxied
    /// DoH ... regardless of whether the configured DNS server is public or
    /// a LAN router": a home router acting as the configured DNS resolver
    /// still sees the plaintext hostname of every query, so the query
    /// CONTENT must be captured and answered via DoH instead, exactly the
    /// same as for a public resolver. See <see cref="DnsLeakGuard"/> for
    /// what happens to captured queries. Deliberately UNCHANGED (other than
    /// the explicit <c>ip</c> scoping) by the 2026-09-16 UDP-block addition
    /// below - see <see cref="BuildUdpBlockFilter"/> remarks for why DNS/53
    /// keeps its own separate handle rather than being folded into the
    /// general UDP block.
    /// </summary>
    public static string BuildDnsFilter()
    {
        return "outbound and !loopback and !impostor and ip and udp and udp.DstPort == 53";
    }

    /// <summary>
    /// Builds the filter for the IPv6 DNS capture handle (2026-09-16
    /// addition): plain UDP port-53 queries leaving the machine over IPv6.
    /// A Windows-configured DNS server may itself be an IPv6 literal (e.g.
    /// an IPv6-only LAN router or an IPv6 public resolver), so IPv6 DNS
    /// query CONTENT must be captured and answered via proxied DoH exactly
    /// like its IPv4 counterpart (<see cref="BuildDnsFilter"/>) - the two
    /// are mutually exclusive by construction (<c>ip</c> vs <c>ipv6</c>, see
    /// that method's remarks). This is distinct from, and unaffected by,
    /// <see cref="BuildIPv6BlockFilter"/>, which blocks IPv6 TRANSPORT
    /// wholesale EXCEPT this exact UDP/53 traffic (that method's own filter
    /// string explicitly exempts <c>udp.DstPort == 53</c> so the two IPv6
    /// handles never both match the same packet): an AAAA (or any other)
    /// DNS query is carried as a UDP/53 PAYLOAD, not as IPv6 transport for
    /// the eventual answer's connection - V0.2 answers every DNS query (A or
    /// AAAA) over the existing IPv4 DoH tunnel to the proxy, and the
    /// resulting IP addresses are handed back to the OS resolver cache; if
    /// an application then tries to actually CONNECT to a returned AAAA
    /// (IPv6) address, that connection attempt is separately caught and
    /// dropped by <see cref="BuildIPv6BlockFilter"/> - the two filters
    /// address two different layers (DNS query content vs. IPv6 transport)
    /// and are both required together.
    /// </summary>
    public static string BuildDnsFilterV6()
    {
        return "outbound and !loopback and !impostor and ipv6 and udp and udp.DstPort == 53";
    }

    /// <summary>
    /// Builds the filter for the general UDP-block leak-protection capture
    /// handle (2026-09-16 addition): outbound, non-loopback, PUBLIC (i.e.
    /// non-LAN/local - see <see cref="Ipv4LanOrLocalExclusionClauses"/>)
    /// IPv4 UDP traffic leaving the machine while Whole Computer mode is
    /// Active - specifically excluding UDP/53 (already handled by its own,
    /// unchanged, separate <see cref="BuildDnsFilter"/> handle, so the two
    /// Drop handles never overlap the same packet). Explicitly scoped with
    /// <c>ip</c> so this handle never matches any IPv6 traffic (which is
    /// exclusively <see cref="BuildIPv6BlockFilter"/>'s responsibility).
    /// LAN/local non-DNS UDP (e.g. mDNS, SSDP/UPnP discovery, a LAN game
    /// server, local file sharing) is deliberately EXEMPTED from this block
    /// (2026-09-16 correction: "IPv4 LAN, non-DNS UDP -&gt; bypass") and
    /// continues over the real NIC untouched, matching the same LAN-bypass
    /// treatment TCP already gets from <see cref="BuildForwardFilter"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why block ALL other PUBLIC UDP outright, additively, rather than
    /// proxy it:</b> the current Residential Connect upstream implementation
    /// does not proxy UDP. HTTP CONNECT is TCP-only, and our current SOCKS5
    /// connector implements TCP CONNECT only; SOCKS5 UDP ASSOCIATE is not
    /// implemented (see <see cref="ResidentialConnect.Proxy.Forwarding.Socks5UpstreamConnector"/>).
    /// There is therefore no upstream path that could carry a redirected UDP
    /// packet through the residential proxy at all - unlike TCP, where
    /// <see cref="WinDivertSystemTrafficRouter"/>'s reflection technique
    /// hands a redirected connection to <c>TransparentForwardingProxy</c>,
    /// which opens a real upstream TCP tunnel. Given that constraint, the
    /// only two options for PUBLIC UDP are: (a) let non-DNS UDP through
    /// unmodified, which would let protocols like QUIC/HTTP-3 (UDP/443),
    /// WebRTC/STUN, or any UDP-based application traffic reach the real
    /// network directly and completely bypass the residential proxy even
    /// while Whole Computer mode reports Active - a silent leak of exactly
    /// the kind the product's fail-closed requirement forbids - or (b) block
    /// it. Per that requirement ("never silently fall back to the user's
    /// real connection"), (b) is the only consistent choice for PUBLIC
    /// destinations: an application using QUIC (most modern browsers
    /// automatically retry over HTTP/2 or HTTP/1.1 on TCP/443 when UDP/443
    /// is unreachable - the "fallback to TCP" behavior this design
    /// deliberately relies on rather than reimplements) or any other UDP
    /// protocol will see that traffic fail/time out rather than silently
    /// egressing outside the proxy. LAN/local destinations have no proxy
    /// path relevance at all (nothing routes to a LAN peer through a
    /// residential Internet proxy), so blocking them would only break local
    /// functionality for zero privacy benefit - hence the LAN exemption.
    /// </para>
    /// <para>
    /// <b>Why this is a SEPARATE handle from the DNS-block handle, not a
    /// single merged filter:</b> keeping <see cref="BuildDnsFilter"/>
    /// completely unchanged (other than the explicit <c>ip</c> scoping, per
    /// the standing instruction not to modify verified/working leak-protection
    /// behavior beyond what correctness strictly requires) was simpler and
    /// safer than rewriting one combined filter string - two independent
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
        var clauses = new[] { "outbound", "!loopback", "ip", "udp", "udp.DstPort != 53" }
            .Concat(Ipv4LanOrLocalExclusionClauses);
        return string.Join(" and ", clauses);
    }

    /// <summary>
    /// Builds the filter for the IPv6 fail-closed block handle (2026-09-16
    /// correction, REPLACING an earlier, narrower <c>(tcp or udp)</c>-scoped
    /// proposal, and further corrected the same day to explicitly exempt
    /// UDP/53): blocks outbound, non-loopback PUBLIC IPv6 traffic of ANY
    /// protocol EXCEPT UDP/53, while Whole Computer mode is Active - because
    /// V0.2 does not proxy IPv6 transport at all (no IPv6 upstream connector
    /// exists), but DOES capture and answer IPv6 DNS queries via
    /// <see cref="BuildDnsFilterV6"/>. Explicitly exempts the local IPv6
    /// ranges this design intentionally preserves - loopback, link-local,
    /// ULA/LAN, and multicast - via <see cref="Ipv6LocalExclusionClauses"/>,
    /// matching the filter-partition table rows "public IPv6, all protocols
    /// -&gt; DROP" and "local IPv6 -&gt; bypass".
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why NOT scope this to <c>(tcp or udp)</c> only:</b> an earlier
    /// architecture draft limited this rule to TCP/UDP, on the (incorrect)
    /// assumption that those are the only protocols an application could
    /// meaningfully use over IPv6. That would have left ICMPv6, or any other
    /// IPv6-carried protocol, free to leak the real public IPv6 address and
    /// connectivity in full - defeating the entire point of this fail-closed
    /// rule. Scoping by IP VERSION alone (not by upper-layer protocol) is the
    /// only way to guarantee no IPv6 packet of any kind reaches the real
    /// network while Whole Computer mode reports Active.
    /// </para>
    /// <para>
    /// <b>Why UDP/53 must be explicitly exempted here (2026-09-16
    /// correction):</b> without this exemption, a genuine IPv6 DNS query
    /// would match BOTH this block handle AND <see cref="BuildDnsFilterV6"/>
    /// (both are opened at the same NETWORK layer and each independently
    /// receives a copy of any packet matching its own filter) - the query
    /// would be silently dropped by THIS handle before (or regardless of
    /// whether) the DNS-capture handle got to answer it via proxied DoH,
    /// breaking IPv6 DNS resolution entirely rather than routing it safely.
    /// The exemption clause is written as <c>(!udp or udp.DstPort != 53)</c>
    /// - a parenthesized OR of two negated single-field tests, never a
    /// grouped negation of a compound expression (see class remarks
    /// "Filter-syntax note"). This is also NOT written as the seemingly
    /// simpler <c>udp.DstPort != 53</c> alone: per WinDivert's own filter
    /// semantics, a protocol-specific field test "fails" (evaluates false)
    /// for a packet that does not actually carry that protocol - so for a
    /// non-UDP IPv6 packet, <c>udp.DstPort != 53</c> would ALSO evaluate
    /// false (the field is not relevant), which would incorrectly exempt
    /// every non-UDP IPv6 packet from this block instead of only exempting
    /// UDP/53 specifically. The <c>(!udp or udp.DstPort != 53)</c> form
    /// correctly evaluates true for every packet EXCEPT an actual UDP
    /// packet whose destination port is exactly 53.
    /// </para>
    /// <para>
    /// <b>Fail-closed, in-kernel, zero user-mode involvement:</b> opened
    /// with <see cref="WinDivertNative.OpenFlags.Drop"/>, exactly like the
    /// DNS-block and general-UDP-block handles - the WinDivert driver itself
    /// silently drops every matching packet before it ever reaches user
    /// mode.
    /// </para>
    /// </remarks>
    public static string BuildIPv6BlockFilter()
    {
        var clauses = new[] { "outbound", "!loopback", "ipv6", "(!udp or udp.DstPort != 53)" }
            .Concat(Ipv6LocalExclusionClauses);
        return string.Join(" and ", clauses);
    }

    /// <summary>
    /// Builds the filter for the "unsupported public IPv4 protocol"
    /// fail-closed block handle (2026-09-16 addition, correction #5):
    /// blocks outbound, non-loopback, PUBLIC IPv4 traffic whose IP protocol
    /// number is neither TCP (6) nor UDP (17) - for example ICMP (1),
    /// IGMP (2), GRE, ESP/AH (IPsec), etc. LAN/local IPv4 traffic of any
    /// protocol remains exempted via <see cref="Ipv4LanOrLocalExclusionClauses"/>
    /// (e.g. a LAN ping to a local router must keep working), matching the
    /// filter-partition table row "unsupported public IPv4 protocols -&gt;
    /// DROP".
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this rule is needed at all:</b> <see cref="BuildForwardFilter"/>
    /// only ever captures <c>tcp</c>, and <see cref="BuildUdpBlockFilter"/>/
    /// <see cref="BuildDnsFilter"/> only ever capture <c>udp</c> - none of
    /// the existing handles say anything about any OTHER IPv4 protocol
    /// (e.g. a bare ICMP echo request/traceroute probe, or any raw-socket
    /// protocol an application might open directly). Without an additive
    /// rule here, such traffic would silently egress over the real NIC,
    /// exposing the real public IPv4 connection through a protocol Whole
    /// Computer mode does not proxy or otherwise account for - exactly the
    /// kind of silent leak the product's fail-closed requirement forbids.
    /// </para>
    /// <para>
    /// <b>Filter-language note:</b> WinDivert's network-layer filter
    /// language exposes the raw IP protocol number as <c>ip.Protocol</c>
    /// (confirmed against reqrypt.org/windivert-doc.html s7); this filter
    /// uses that field directly rather than the <c>tcp</c>/<c>udp</c>
    /// layer-specific macros, since it must match packets that are NEITHER.
    /// </para>
    /// <para>
    /// <b>Fail-closed, in-kernel, zero user-mode involvement:</b> opened
    /// with <see cref="WinDivertNative.OpenFlags.Drop"/>, exactly like the
    /// other block handles.
    /// </para>
    /// </remarks>
    public static string BuildOtherProtocolBlockFilter()
    {
        var clauses = new[] { "outbound", "!loopback", "ip", "ip.Protocol != 6", "ip.Protocol != 17" }
            .Concat(Ipv4LanOrLocalExclusionClauses);
        return string.Join(" and ", clauses);
    }
}
