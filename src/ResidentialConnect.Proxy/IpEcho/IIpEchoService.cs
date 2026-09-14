namespace ResidentialConnect.Proxy.IpEcho;

/// <summary>Tiny wrapper around "what is my public IP" HTTP(S) endpoints.</summary>
public interface IIpEchoService
{
    /// <summary>
    /// Issues an HTTPS GET through <paramref name="httpClient"/> (which the
    /// caller has already configured with the proxy under test) and returns
    /// the plain-text public IP address reported by the remote service.
    /// </summary>
    Task<string> GetPublicIpAsync(HttpClient httpClient, CancellationToken cancellationToken);
}
