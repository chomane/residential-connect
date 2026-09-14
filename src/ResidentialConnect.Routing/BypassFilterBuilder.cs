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
/// The WinDivert filter language's <c>processId</c> field is deliberately
/// NOT used for self-exclusion: per WinDivert's own documentation it "is not
/// supported by the WINDIVERT_LAYER_NETWORK* layers" (the layer this router
/// uses, since it is the only layer that can both capture AND re-inject
/// modified packets) - so a destination-based exclusion is not just simpler
/// but the only option available at this layer.
/// </para>
/// </remarks>
public static class BypassFilterBuilder
{
    /// <summary>
    /// Builds the filter for the FORWARD capture handle: real, non-loopback
    /// outbound TCP traffic, excluding our own re-injected packets
    /// (<c>impostor</c>) and excluding traffic to the upstream proxy itself
    /// (see class remarks).
    /// </summary>
    public static string BuildForwardFilter(IReadOnlyCollection<IPAddress> proxyIPv4Addresses, int proxyPort)
    {
        var baseFilter = "outbound and !loopback and !impostor and tcp and tcp.DstPort != 0";

        var ipv4 = proxyIPv4Addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Distinct().ToList();
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

        var addressClause = string.Join(" or ", ipv4.Select(ip => $"ip.DstAddr == {ip}"));
        var exclusion = $"not (tcp.DstPort == {proxyPort.ToString(CultureInfo.InvariantCulture)} and ({addressClause}))";

        return $"{baseFilter} and {exclusion}";
    }

    /// <summary>
    /// Builds the filter for the RETURN capture handle: our own local relay's
    /// reply traffic (source = 127.0.0.1:<paramref name="relayPort"/>) on its
    /// way back out to the redirected application. This traffic is
    /// necessarily classified "loopback" by WinDivert (both endpoints are
    /// addresses of the local machine), so - unlike the forward filter - this
    /// one explicitly INCLUDES <c>loopback</c> rather than excluding it.
    /// </summary>
    public static string BuildReturnFilter(int relayPort)
    {
        return $"outbound and loopback and tcp and tcp.SrcPort == {relayPort.ToString(CultureInfo.InvariantCulture)}";
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
