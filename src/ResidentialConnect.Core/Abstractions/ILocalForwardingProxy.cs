using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// A tiny, unauthenticated HTTP/HTTPS proxy server bound to
/// <c>127.0.0.1</c> that a local browser instance can point at without
/// needing to know any credentials. Internally, every connection accepted
/// from the browser is relayed upstream to the real (authenticated)
/// residential proxy - see <see cref="ProxyProfile"/> - with the
/// username/password handshake performed transparently in-process.
/// </summary>
/// <remarks>
/// This design is what makes "Proxy authentication should happen
/// automatically without requiring the user to repeatedly type credentials"
/// possible: Chromium's <c>--proxy-server</c> command-line flag has no way
/// to embed a password, and Manifest V3 extensions can no longer intercept
/// <c>407 Proxy Authentication Required</c> challenges. Routing the browser
/// through a local loopback-only relay sidesteps both limitations entirely
/// without modifying the browser or touching the Windows system proxy.
/// </remarks>
public interface ILocalForwardingProxy : IDisposable
{
    bool IsRunning { get; }

    int? Port { get; }

    /// <summary>
    /// Starts listening on an available loopback-only TCP port and returns
    /// that port. <paramref name="password"/> is the already-decrypted
    /// proxy password (resolved once via ICredentialStore by the caller) and
    /// is kept only in memory for the lifetime of this relay - never logged,
    /// never written to disk by this component.
    /// </summary>
    Task<int> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default);

    Task StopAsync();
}
