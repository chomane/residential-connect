namespace ResidentialConnect.Routing;

/// <summary>
/// DNS leak protection for Whole Computer mode.
/// </summary>
/// <remarks>
/// <para>
/// <b>Chosen mechanism (V0.2, TCP-only architecture): BLOCK plain UDP/53
/// outright</b> rather than attempt to redirect/proxy DNS queries. V0.2's
/// <see cref="WinDivertSystemTrafficRouter"/> only implements TCP
/// redirection (see the TCP/UDP limitations note on
/// <c>ISystemTrafficRouter</c> and in <c>docs/ARCHITECTURE.md</c>) - there is
/// no upstream UDP relay to actually forward a DNS query through the
/// residential proxy's network path. Given that constraint, the two
/// available options are: (a) let UDP/53 through unmodified, which would let
/// applications resolve hostnames via the user's REAL, non-proxied network
/// path - a direct DNS leak that reveals which sites are being visited to
/// the user's normal ISP/network even while Whole Computer mode believes it
/// is routing everything through the proxy - or (b) block it. Per the
/// product's explicit fail-closed requirement ("never silently fall back to
/// the user's real connection"), (b) is the only option consistent with the
/// rest of the design: an application that cannot resolve a hostname will
/// fail loudly (DNS timeout/error) rather than silently leaking which
/// hostnames it is resolving over the real network.
/// </para>
/// <para>
/// <b>What this does NOT protect against</b> (documented, not silently
/// hidden - see "Known limitations"): DNS-over-HTTPS/DNS-over-TLS queries
/// that travel over TCP port 443/853 are TCP connections like any other, so
/// they ARE captured and redirected through the proxy by the normal TCP
/// path - correct/leak-free, but as a side effect of being ordinary TCP, not
/// because of anything DNS-specific in this class. Applications hard-coded
/// to use a specific DNS-over-HTTPS resolver by IP address (bypassing the
/// system resolver entirely) are still redirected like any other outbound
/// TCP connection. Plain UDP/53 queries are simply blocked (see above) -
/// this is a availability/safety trade-off (name resolution fails loudly)
/// documented as intentional, not a gap.
/// </para>
/// </remarks>
public static class DnsLeakGuard
{
    /// <summary>
    /// The WinDivert filter used to capture plain UDP/53 DNS queries that
    /// must be blocked while Whole Computer mode is active. See
    /// <see cref="BypassFilterBuilder.BuildDnsFilter"/> - the actual filter
    /// string is built there so all filter-string construction lives in one
    /// place; this class documents the policy those bytes implement.
    /// </summary>
    public const string Rationale =
        "V0.2 is TCP-only; plain UDP/53 DNS queries cannot be proxied, so they are " +
        "blocked outright (fail-closed) rather than allowed to leak over the real " +
        "network. DNS-over-HTTPS/TLS (TCP 443/853) is unaffected and is redirected " +
        "through the proxy like any other TCP connection.";
}
