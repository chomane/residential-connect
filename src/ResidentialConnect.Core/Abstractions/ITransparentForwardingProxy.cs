using System.Net;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;



/// <summary>
/// The Whole Computer (V0.2) counterpart of <see cref="ILocalForwardingProxy"/>.
/// Where <see cref="ILocalForwardingProxy"/> is a loopback-only HTTP CONNECT
/// relay that the isolated OPEN BROWSER Chromium instance explicitly points
/// at via <c>--proxy-server</c>, this relay instead accepts raw, already
/// kernel-redirected TCP connections from ordinary desktop applications that
/// have no idea a proxy exists at all - <see cref="ISystemTrafficRouter"/>
/// is what makes the OS deliver their traffic here in the first place. There
/// is no HTTP CONNECT handshake with the local client (the application):
/// this relay must instead ask <see cref="IOriginalDestinationResolver"/>
/// what the application's ORIGINAL, pre-redirect destination was, then open
/// exactly the same kind of authenticated upstream tunnel V0.1 already uses
/// (see <c>Forwarding.HttpConnectUpstreamConnector</c> /
/// <c>Forwarding.Socks5UpstreamConnector</c>) and splice bytes bidirectionally.
/// </summary>
/// <remarks>
/// <b>Fail-closed:</b> if the original destination cannot be resolved, or
/// the upstream proxy connection/authentication fails, the accepted local
/// connection MUST be closed immediately. It must never be allowed to
/// connect anywhere else (in particular, never directly to the resolved
/// original destination without going through the proxy) - that would
/// defeat the entire purpose of Whole Computer mode and leak the
/// application's real traffic/IP.
/// </remarks>
public interface ITransparentForwardingProxy : IDisposable
{
    bool IsRunning { get; }

    int? Port { get; }

    /// <summary>
    /// Raised when the relay encounters a failure serious enough that it can
    /// no longer be trusted to keep proxying safely (e.g. the accept loop
    /// itself crashed). <see cref="ISystemTrafficRouter"/> subscribes to
    /// this to drive its own fail-closed transition
    /// (<see cref="Models.SystemRoutingStatus.FailedClosed"/>).
    /// </summary>
    event EventHandler<Exception>? Faulted;

    /// <summary>
    /// Starts listening on <paramref name="bindAddress"/> (typically
    /// <see cref="IPAddress.Any"/>, so real, non-loopback redirected
    /// connections can reach it - unlike <see cref="ILocalForwardingProxy"/>,
    /// which is intentionally loopback-only) and returns the bound port.
    /// </summary>
    /// <param name="pinnedProxyAddress">
    /// The single, already-resolved IPv4 literal to dial for EVERY upstream
    /// tunnel this relay opens - 2026-09-16 addition ("pinned proxy IPv4").
    /// <see cref="Core.Abstractions.ISystemTrafficRouter"/>'s caller resolves
    /// <see cref="ProxyProfile.Host"/> to an IPv4 address exactly ONCE,
    /// before opening any WinDivert handle (see that method's remarks), and
    /// builds the forward filter's own proxy self-exclusion clause
    /// (<see cref="Routing"/>'s <c>BypassFilterBuilder.BuildForwardFilter</c>)
    /// from that SAME resolved address. If this relay instead re-resolved
    /// <paramref name="profile"/>'s <see cref="ProxyProfile.Host"/> itself
    /// (e.g. inside <see cref="HttpConnectUpstreamConnector"/>'s own
    /// <c>TcpClient.ConnectAsync(string, int, ...)</c> overload, which
    /// performs its own independent DNS lookup) a second, independent DNS
    /// answer could return a DIFFERENT IP than the one the filter's
    /// self-exclusion clause actually excludes - at which point this
    /// relay's own outbound tunnel to the proxy would itself be captured by
    /// the forward filter and fed back into the reflection pipeline,
    /// exactly the self-interception loop the self-exclusion clause exists
    /// to prevent. Passing the identical, already-resolved literal here
    /// closes that gap: this relay dials the literal IP directly (bypassing
    /// its own connector's hostname resolution entirely for the proxy hop),
    /// guaranteeing it can never resolve to anything other than what the
    /// filter excludes.
    /// </param>
    Task<int> StartAsync(
        ProxyProfile profile,
        string password,
        IPAddress bindAddress,
        IOriginalDestinationResolver destinationResolver,
        IPAddress pinnedProxyAddress,
        CancellationToken cancellationToken = default);

    Task StopAsync();
}
