using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Http;
using ResidentialConnect.Proxy.IpEcho;

namespace ResidentialConnect.Proxy;

/// <summary>
/// Default <see cref="IProxyConnectivityTester"/> implementation. Performs a
/// real HTTPS request through the configured proxy (HTTP CONNECT tunnel or
/// SOCKS5, per <see cref="ProxyProfile.Protocol"/>), which simultaneously
/// proves: DNS/TCP reachability of the proxy, credential correctness
/// (authentication), and end-to-end HTTPS connectivity through it - exactly
/// the guarantee the V0.1 CONNECT button needs to give the user.
/// </summary>
public sealed class HttpProxyConnectivityTester : IProxyConnectivityTester
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

    private readonly ICredentialStore _credentialStore;
    private readonly IIpEchoService _ipEchoService;
    private readonly IAppLogger _logger;

    public HttpProxyConnectivityTester(ICredentialStore credentialStore, IIpEchoService ipEchoService, IAppLogger logger)
    {
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _ipEchoService = ipEchoService ?? throw new ArgumentNullException(nameof(ipEchoService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<ProxyTestResult> TestAsync(ProxyProfile profile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var configValidation = ProxyValidation.Validate(profile, "placeholder-not-checked");
        // Password presence is checked separately below (via credential store),
        // so re-validate everything except the "password required" rule here.
        var configErrors = configValidation.Errors.Where(e => e != "Password is required.").ToList();
        if (configErrors.Count > 0)
        {
            _logger.Warning("ProxyTest", $"Configuration invalid for proxy '{profile.Name}': {string.Join("; ", configErrors)}");
            return ProxyTestResult.Failed(ProxyTestFailureReason.InvalidConfiguration, string.Join(" ", configErrors));
        }

        var password = _credentialStore.Retrieve(profile.CredentialRef);
        if (string.IsNullOrEmpty(password))
        {
            _logger.Warning("ProxyTest", $"No stored credential found for proxy '{profile.Name}'.");
            return ProxyTestResult.Failed(ProxyTestFailureReason.InvalidConfiguration, "No stored password found for this proxy. Please edit the proxy and re-enter the password.");
        }

        _logger.Info("ProxyTest", $"Starting connectivity test for '{profile.Name}' ({profile.Host}:{profile.Port}, {profile.Protocol}).");

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(DefaultTimeout);

        var stopwatch = Stopwatch.StartNew();
        try
        {
            var webProxy = ProxyWebProxyFactory.Create(profile, password);
            using var handler = new HttpClientHandler
            {
                Proxy = webProxy,
                UseProxy = true,
                PreAuthenticate = true
            };
            using var httpClient = new HttpClient(handler)
            {
                Timeout = DefaultTimeout
            };
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ResidentialConnect/0.1");

            var publicIp = await _ipEchoService.GetPublicIpAsync(httpClient, timeoutCts.Token).ConfigureAwait(false);
            stopwatch.Stop();

            bool? ipMatches = IPAddress.TryParse(profile.Host, out var configuredIp)
                ? string.Equals(configuredIp.ToString(), publicIp, StringComparison.Ordinal)
                : null;

            _logger.Info("ProxyTest", $"Success for '{profile.Name}': public IP resolved in {stopwatch.ElapsedMilliseconds}ms.");
            return ProxyTestResult.Successful(publicIp, stopwatch.Elapsed, ipMatches);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger.Info("ProxyTest", $"Test for '{profile.Name}' was cancelled by caller.");
            return ProxyTestResult.Failed(ProxyTestFailureReason.Cancelled, "Cancelled.");
        }
        catch (OperationCanceledException)
        {
            _logger.Warning("ProxyTest", $"Test for '{profile.Name}' timed out after {DefaultTimeout.TotalSeconds:0}s.");
            return ProxyTestResult.Failed(ProxyTestFailureReason.ConnectionTimeout, $"Timed out after {DefaultTimeout.TotalSeconds:0} seconds.");
        }
        catch (HttpRequestException ex)
        {
            var reason = ClassifyHttpRequestException(ex);
            _logger.Warning("ProxyTest", $"Test for '{profile.Name}' failed: {reason} - {SecretScrubber.Scrub(ex.Message)}");
            return ProxyTestResult.Failed(reason, FriendlyMessage(reason, ex));
        }
        catch (SocketException ex)
        {
            _logger.Warning("ProxyTest", $"Test for '{profile.Name}' socket error: {SecretScrubber.Scrub(ex.Message)}");
            return ProxyTestResult.Failed(ProxyTestFailureReason.ConnectionRefused, "Could not reach the proxy host/port. Check the address and port.");
        }
        catch (Exception ex)
        {
            _logger.Error("ProxyTest", $"Unexpected error testing '{profile.Name}': {SecretScrubber.Scrub(ex.Message)}", ex);
            return ProxyTestResult.Failed(ProxyTestFailureReason.Unknown, "Unexpected error. See diagnostics log for details.");
        }
    }

    private static ProxyTestFailureReason ClassifyHttpRequestException(HttpRequestException ex)
    {
        if (ex.StatusCode == HttpStatusCode.ProxyAuthenticationRequired)
        {
            return ProxyTestFailureReason.AuthenticationFailed;
        }

        var message = ex.Message.ToLowerInvariant();
        if (message.Contains("407"))
        {
            return ProxyTestFailureReason.AuthenticationFailed;
        }

        if (message.Contains("name or service not known") || message.Contains("no such host"))
        {
            return ProxyTestFailureReason.DnsResolutionFailed;
        }

        if (message.Contains("refused"))
        {
            return ProxyTestFailureReason.ConnectionRefused;
        }

        if (message.Contains("ssl") || message.Contains("tls") || message.Contains("certificate"))
        {
            return ProxyTestFailureReason.TlsError;
        }

        return ProxyTestFailureReason.UnexpectedResponse;
    }

    private static string FriendlyMessage(ProxyTestFailureReason reason, HttpRequestException ex) => reason switch
    {
        ProxyTestFailureReason.AuthenticationFailed => "Proxy rejected the username/password (407 Proxy Authentication Required).",
        ProxyTestFailureReason.DnsResolutionFailed => "Could not resolve the proxy hostname. Check the address.",
        ProxyTestFailureReason.ConnectionRefused => "Connection to the proxy was refused. Check the host and port.",
        ProxyTestFailureReason.TlsError => "A TLS/SSL error occurred while connecting through the proxy.",
        _ => "Could not complete the request through the proxy."
    };
}
