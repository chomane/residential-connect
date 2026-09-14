using System.Net;

namespace ResidentialConnect.Proxy.IpEcho;

/// <summary>
/// Queries public "what is my IP" HTTPS endpoints. Tries a short ordered
/// list of providers so a single provider outage/rate-limit does not make
/// every CONNECT attempt fail; the first provider that returns a
/// parseable IP address wins.
/// </summary>
public sealed class IpifyEchoService : IIpEchoService
{
    // Plain-text IP endpoints only (no JSON parsing dependency needed).
    private static readonly string[] Endpoints =
    {
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://checkip.amazonaws.com"
    };

    public async Task<string> GetPublicIpAsync(HttpClient httpClient, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);

        Exception? lastError = null;
        foreach (var endpoint in Endpoints)
        {
            try
            {
                var raw = await httpClient.GetStringAsync(endpoint, cancellationToken).ConfigureAwait(false);
                var candidate = raw.Trim();
                if (IPAddress.TryParse(candidate, out var ip))
                {
                    return ip.ToString();
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                lastError = ex;
            }
        }

        throw lastError ?? new InvalidOperationException("No IP-echo endpoint returned a parseable IP address.");
    }
}
