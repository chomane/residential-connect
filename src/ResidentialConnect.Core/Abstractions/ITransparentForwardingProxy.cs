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
    Task<int> StartAsync(
        ProxyProfile profile,
        string password,
        IPAddress bindAddress,
        IOriginalDestinationResolver destinationResolver,
        CancellationToken cancellationToken = default);

    Task StopAsync();
}
