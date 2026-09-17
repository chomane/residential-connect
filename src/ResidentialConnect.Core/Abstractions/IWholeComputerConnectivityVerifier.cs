namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Outcome of one <see cref="IWholeComputerConnectivityVerifier.VerifyAsync"/>
/// call - whether a real, hostname-addressed HTTPS request actually
/// succeeded THROUGH the now-Active Whole Computer routing pipeline (not
/// through any explicit proxy configuration on the request itself - see
/// <see cref="IWholeComputerConnectivityVerifier"/> remarks for why that
/// distinction is the entire point of this check).
/// </summary>
public readonly record struct WholeComputerVerificationResult(
    bool Success,
    string? ObservedPublicIp,
    string? FailureMessage)
{
    public static WholeComputerVerificationResult Successful(string? observedPublicIp) =>
        new(true, observedPublicIp, null);

    public static WholeComputerVerificationResult Failed(string failureMessage) =>
        new(false, null, failureMessage);
}

/// <summary>
/// Verifies that Whole Computer routing, once <see cref="ISystemTrafficRouter"/>
/// reports <see cref="Models.SystemRoutingStatus.Active"/>, actually carries
/// REAL, hostname-addressed traffic end-to-end - not just that the WinDivert
/// handles opened successfully. <see cref="ResidentialConnect.Proxy.DefaultConnectionManager"/>
/// calls this exactly once, immediately after <c>ISystemTrafficRouter.StartAsync</c>
/// returns <c>Active</c> and strictly BEFORE ever reporting
/// <see cref="Models.ConnectionStatus.Connected"/> to the UI - and rolls the
/// routing back (<c>ISystemTrafficRouter.StopAsync</c>) and reports
/// <see cref="Models.ConnectionStatus.Error"/> instead if this fails.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why "hostname-addressed", specifically, matters (standing product
/// mandate, reiterated across this whole implementation effort): "no more
/// IP-literal-only acceptance tests; no declaring Whole Computer verified
/// until real hostname browsing works in the actual desktop app."</b> A
/// check that only proved a bare TCP/TLS handshake to a hard-coded IP
/// literal succeeded would NOT prove the thing that actually matters to a
/// real user: that an ordinary desktop application's normal,
/// hostname-based outbound connection (DNS resolution via the OS resolver,
/// then a TCP/TLS connection to whatever address that resolves to) is
/// correctly captured and redirected by <see cref="ISystemTrafficRouter"/>'s
/// packet-reflection filters and successfully tunnels through the upstream
/// residential proxy. <see cref="ResidentialConnect.Proxy.HostnameConnectivityVerifier"/>
/// (the concrete implementation) deliberately issues a plain
/// <c>HttpClient</c> request to a real HTTPS hostname with NO explicit
/// proxy configured on the request itself - relying entirely on
/// system-level packet interception to route it, exactly mirroring what a
/// real browser/desktop application would experience.
/// </para>
/// <para>
/// <b>Why this lives in <c>Core.Abstractions</c> (not directly in
/// <c>ResidentialConnect.Proxy</c> alongside its implementation):</b>
/// keeping the interface here lets <see cref="ResidentialConnect.Proxy.DefaultConnectionManager"/>
/// depend on the ABSTRACTION only, and lets tests inject a fully scriptable
/// fake (no real network call, no dependency on Whole Computer routing
/// actually being active) - exactly the same pattern already used for
/// <see cref="ISystemTrafficRouter"/> and <see cref="IProxyConnectivityTester"/>.
/// </para>
/// </remarks>
public interface IWholeComputerConnectivityVerifier
{
    Task<WholeComputerVerificationResult> VerifyAsync(CancellationToken cancellationToken = default);
}
