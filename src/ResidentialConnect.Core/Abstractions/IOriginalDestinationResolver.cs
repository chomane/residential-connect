using System.Net;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Given the local loopback endpoint a redirected connection was accepted
/// from (i.e. the original application's own IP:port, unchanged by the
/// destination-rewrite that redirected it), resolves the ORIGINAL
/// destination host:port the application actually intended to connect to,
/// before <see cref="ISystemTrafficRouter"/> rewrote the packet's
/// destination to point at the local transparent relay.
/// </summary>
/// <remarks>
/// This is the seam between whole-computer packet-level NAT (which knows
/// "who is really trying to reach where") and
/// <c>ResidentialConnect.Proxy.Forwarding.TransparentForwardingProxy</c>
/// (which accepts the redirected TCP connection and needs to know where to
/// actually open the authenticated upstream tunnel). Kept as a Core
/// interface - rather than a concrete dependency on the Routing project's
/// NAT table - so <c>ResidentialConnect.Proxy</c> never needs to reference
/// <c>ResidentialConnect.Routing</c> (dependency direction stays
/// Core &lt;- Proxy &lt;- Routing &lt;- Client).
/// </remarks>
public interface IOriginalDestinationResolver
{
    /// <summary>
    /// Attempts to resolve the original destination for a redirected
    /// connection that was accepted from <paramref name="clientEndpoint"/>.
    /// Returns false if no matching NAT entry is known (e.g. it already
    /// expired, or the connection did not actually go through the router).
    /// </summary>
    bool TryResolve(IPEndPoint clientEndpoint, out string host, out int port);
}
