using System.Net;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Answers raw DNS wire-format queries (RFC 8484 DNS-over-HTTPS message
/// bytes - a captured UDP/53 payload, verbatim) via an HTTPS request tunneled
/// through the SAME residential proxy Whole Computer mode is already using
/// for ordinary TCP traffic - 2026-09-16 addition ("UDP/53 (IPv4 OR IPv6)
/// -&gt; intercepted and answered using proxied DoH", replacing the earlier
/// "just block UDP/53 outright" design documented on <see cref="DnsLeakGuard"/>
/// era code). <c>WinDivertSystemTrafficRouter</c>'s DNS capture loops call
/// this once per captured query and forge a synthesized UDP reply from the
/// raw response bytes it returns - see <c>DnsUdpReplyPacketBuilder</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why THIS must never do its own hostname resolution locally:</b> the
/// entire point of proxying DNS is that the query CONTENT (which hostnames
/// are being resolved) must never be visible to the user's real, local
/// network/ISP. A correct implementation (see
/// <c>ResidentialConnect.Proxy.Dns.ProxiedDohResolver</c>) must reach the
/// DoH provider's hostname (e.g. <c>cloudflare-dns.com</c>) by dialing the
/// residential proxy directly (an <c>IUpstreamConnector</c>, exactly like
/// <c>TransparentForwardingProxy</c>'s own upstream tunnels) and letting the
/// PROXY's own exit node resolve that hostname - never
/// <see cref="System.Net.Dns"/> or any other local resolver call, which
/// would recreate the exact leak this whole mechanism exists to close.
/// </para>
/// <para>
/// <b>Session-scoped, not per-query:</b> <see cref="Configure"/> is called
/// exactly once, when Whole Computer routing starts (after the proxy's
/// IPv4 address has already been pinned - see
/// <see cref="ISystemTrafficRouter"/>/<c>WinDivertSystemTrafficRouter.StartAsync</c>
/// remarks on "pinned proxy IPv4"), and the resulting configured instance
/// (in particular its single, long-lived <c>HttpClient</c>/connection pool)
/// is reused for every DNS query captured for the life of that Whole
/// Computer session - opening a brand-new TCP+TLS tunnel to the DoH
/// provider for every single query would be needlessly slow and wasteful.
/// </para>
/// </remarks>
public interface IDohResolver : IDisposable
{
    /// <summary>
    /// Configures this resolver to reach the DoH provider through
    /// <paramref name="pinnedProxyAddress"/> (the SAME already-resolved
    /// proxy IPv4 literal <c>WinDivertSystemTrafficRouter.StartAsync</c>
    /// pins for every other upstream tunnel it opens this session). Must be
    /// called exactly once, before the first <see cref="ResolveAsync"/> call.
    /// </summary>
    void Configure(ProxyProfile profile, string password, IPAddress pinnedProxyAddress);

    /// <summary>
    /// Answers one captured DNS query. <paramref name="dnsQueryPayload"/> is
    /// the raw DNS wire-format bytes exactly as captured from the UDP/53
    /// packet (untouched/unparsed); the returned bytes are the raw DNS
    /// wire-format RESPONSE, to be embedded verbatim into a synthesized UDP
    /// reply packet.
    /// </summary>
    Task<byte[]> ResolveAsync(byte[] dnsQueryPayload, CancellationToken cancellationToken = default);
}
