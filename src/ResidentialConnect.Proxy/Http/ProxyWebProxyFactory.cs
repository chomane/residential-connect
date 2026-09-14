using System.Net;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Proxy.Http;

/// <summary>
/// Builds a <see cref="WebProxy"/> (the <see cref="IWebProxy"/> implementation
/// .NET's <c>SocketsHttpHandler</c> understands) from a <see cref="ProxyProfile"/>
/// plus its decrypted password. Centralized here so both the connectivity
/// tester and (indirectly, via generated PAC/launch args) the browser
/// launcher agree on exactly how a profile maps to a proxy URI.
/// </summary>
/// <remarks>
/// .NET's <see cref="System.Net.Http.SocketsHttpHandler"/> has supported the
/// <c>socks5://</c> scheme (with <see cref="WebProxy.Credentials"/> for
/// username/password auth per RFC 1929) since .NET 6, alongside the
/// long-standing <c>http://</c> scheme used for HTTP proxies and HTTPS
/// tunneling via CONNECT. This lets a single <see cref="IWebProxy"/>
/// abstraction cover both protocols required for V0.1.
/// </remarks>
public static class ProxyWebProxyFactory
{
    public static WebProxy Create(ProxyProfile profile, string password)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var scheme = profile.Protocol switch
        {
            ProxyProtocol.Http => "http",
            ProxyProtocol.Socks5 => "socks5",
            _ => throw new NotSupportedException($"Proxy protocol '{profile.Protocol}' is not supported.")
        };

        var uri = new Uri($"{scheme}://{profile.Host}:{profile.Port}");

        return new WebProxy(uri)
        {
            Credentials = new NetworkCredential(profile.Username, password)
        };
    }
}
