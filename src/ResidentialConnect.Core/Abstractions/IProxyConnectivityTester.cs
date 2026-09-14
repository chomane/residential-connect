using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Verifies that a proxy is reachable, authenticates successfully, and can
/// serve traffic - by issuing a real HTTPS request to an IP-echo endpoint
/// through the proxy. Used by both the "Test" button in proxy management and
/// the CONNECT flow on the main screen, so behavior is identical and only
/// tested once.
/// </summary>
public interface IProxyConnectivityTester
{
    /// <summary>
    /// Attempts to connect to <paramref name="profile"/>, authenticate, and
    /// fetch the caller's public IP as observed by an external service.
    /// Never throws for expected failure modes - all outcomes are represented
    /// in the returned <see cref="ProxyTestResult"/>.
    /// </summary>
    Task<ProxyTestResult> TestAsync(ProxyProfile profile, CancellationToken cancellationToken = default);
}
