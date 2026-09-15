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
    /// outbound TCP traffic, excluding our own re-injected packets
    /// (<c>impostor</c>), excluding traffic to the upstream proxy itself,
    /// and excluding the local relay's own reply traffic (see class
    /// remarks for why the latter is required by the reflection technique).
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

        var baseFilter = "outbound and !loopback and !impostor and tcp";
        var relayExclusion = $"tcp.SrcPort != {relayPort.ToString(CultureInfo.InvariantCulture)}";
        var proxyExclusions = ipv4.Select(ip =>
            $"(tcp.DstPort != {proxyPort.ToString(CultureInfo.InvariantCulture)} or ip.DstAddr != {ip})");

        var clauses = new[] { baseFilter, relayExclusion }.Concat(proxyExclusions);
        return string.Join(" and ", clauses);
    }

    /// <summary>
    /// Builds the filter for the RETURN capture handle: the local relay's
    /// own reply traffic (source port = <paramref name="relayPort"/>) on its
    /// way back out to the redirected application.
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

        return $"outbound and !impostor and tcp and tcp.SrcPort == {relayPort.ToString(CultureInfo.InvariantCulture)}";
    }

    /// <summary>
    /// Builds the filter for the DNS leak-protection capture handle: plain
    /// UDP port-53 queries leaving the machine (never loopback - a locally
    /// running DNS-ish service on 127.0.0.1:53 is not something Whole
    /// Computer mode needs to intervene on, and would not represent a leak).
    /// See <see cref="DnsLeakGuard"/> for what happens to captured queries.
    /// </summary>
    public static string BuildDnsFilter()
    {
        return "outbound and !loopback and !impostor and udp and udp.DstPort == 53";
    }
}
