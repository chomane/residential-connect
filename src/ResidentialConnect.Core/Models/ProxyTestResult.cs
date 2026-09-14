namespace ResidentialConnect.Core.Models;

/// <summary>
/// Outcome of a health/connectivity test (or a live CONNECT attempt) run
/// against a <see cref="ProxyProfile"/>. Used both by the "Test" button in
/// proxy management and by the main CONNECT flow so the two code paths share
/// one well-tested model.
/// </summary>
public sealed class ProxyTestResult
{
    public bool Success { get; init; }

    /// <summary>Public IP address observed through the proxy, if the request succeeded.</summary>
    public string? ObservedPublicIp { get; init; }

    /// <summary>Round-trip latency of the verification request.</summary>
    public TimeSpan? Latency { get; init; }

    /// <summary>
    /// True when the observed public IP matches the proxy's configured host
    /// (only meaningful when the configured host is itself an IP literal;
    /// Webshare's residential gateway host is usually a DNS name that is
    /// unrelated to the exit IP, so this is best-effort information only).
    /// </summary>
    public bool? IpMatchesConfiguredEndpoint { get; init; }

    /// <summary>Non-sensitive, user-facing error/status message.</summary>
    public string? Message { get; init; }

    /// <summary>Classification used to pick an icon/color and to drive tests.</summary>
    public ProxyTestFailureReason FailureReason { get; init; } = ProxyTestFailureReason.None;

    public DateTimeOffset TestedAtUtc { get; init; } = DateTimeOffset.UtcNow;

    public static ProxyTestResult Successful(string publicIp, TimeSpan latency, bool? ipMatches = null) => new()
    {
        Success = true,
        ObservedPublicIp = publicIp,
        Latency = latency,
        IpMatchesConfiguredEndpoint = ipMatches,
        Message = "Connected",
        FailureReason = ProxyTestFailureReason.None
    };

    public static ProxyTestResult Failed(ProxyTestFailureReason reason, string message) => new()
    {
        Success = false,
        Message = message,
        FailureReason = reason
    };
}

/// <summary>Coarse-grained reason a proxy test/connect attempt failed, used for diagnostics and tests.</summary>
public enum ProxyTestFailureReason
{
    None = 0,
    InvalidConfiguration,
    DnsResolutionFailed,
    ConnectionRefused,
    ConnectionTimeout,
    AuthenticationFailed,
    TlsError,
    UnexpectedResponse,
    Cancelled,
    Unknown
}
