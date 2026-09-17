using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;

namespace ResidentialConnect.Proxy;

/// <summary>
/// Default <see cref="IWholeComputerConnectivityVerifier"/>: issues a plain
/// <see cref="HttpClient"/> HTTPS GET to a real, hostname-addressed public
/// endpoint with NO explicit proxy configuration on the request at all -
/// relying entirely on <see cref="ISystemTrafficRouter"/>'s system-level
/// packet interception to actually carry it. See the interface's remarks for
/// why hostname addressing specifically (never a bare IP literal) is the
/// whole point of this check - "no more IP-literal-only acceptance tests; no
/// declaring Whole Computer verified until real hostname browsing works in
/// the actual desktop app" is a standing product mandate, not just an
/// implementation detail.
/// </summary>
public sealed class HostnameConnectivityVerifier : IWholeComputerConnectivityVerifier
{
    private const string VerificationUrl = "https://api.ipify.org";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    private readonly IAppLogger _logger;

    public HostnameConnectivityVerifier(IAppLogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<WholeComputerVerificationResult> VerifyAsync(CancellationToken cancellationToken = default)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);

        try
        {
            // Deliberately NO HttpClientHandler.Proxy configuration here -
            // this request must travel through the OS's own TCP/IP stack
            // exactly like a real, unmodified desktop application's request
            // would, so that ISystemTrafficRouter's WinDivert interception
            // is the ONLY thing that can possibly make it reach the real
            // destination through the residential proxy. If routing is not
            // actually working, this request fails/times out - it never
            // silently falls back to the user's own direct connection,
            // because no proxy/fallback logic exists on this request at all.
            using var httpClient = new HttpClient { Timeout = Timeout };
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ResidentialConnect/0.2-WholeComputerVerify");

            var publicIp = await httpClient.GetStringAsync(VerificationUrl, timeoutCts.Token).ConfigureAwait(false);
            var trimmedIp = publicIp.Trim();

            _logger.Info("WholeComputerVerification", $"Hostname-based post-routing verification succeeded (observed public IP: {trimmedIp}).");
            return WholeComputerVerificationResult.Successful(trimmedIp);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return WholeComputerVerificationResult.Failed("Verification was cancelled.");
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("WholeComputerVerification", $"Hostname-based post-routing verification timed out after {Timeout.TotalSeconds:0}s.");
            return WholeComputerVerificationResult.Failed("Whole Computer routing did not carry a real hostname-addressed HTTPS request within the timeout. Routing has been rolled back.");
        }
        catch (Exception ex)
        {
            _logger.Warning("WholeComputerVerification", $"Hostname-based post-routing verification failed: {ex.GetType().Name} - {SecretScrubber.Scrub(ex.Message)}");
            return WholeComputerVerificationResult.Failed("Whole Computer routing could not carry a real hostname-addressed HTTPS request. Routing has been rolled back.");
        }
    }
}
