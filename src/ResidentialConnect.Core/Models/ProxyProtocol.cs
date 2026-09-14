namespace ResidentialConnect.Core.Models;

/// <summary>
/// Wire protocol used to talk to the proxy endpoint.
/// V0.1 supports HTTP/HTTPS CONNECT tunneling and SOCKS5 with username/password
/// authentication, which covers Webshare's Dedicated Static Residential proxy
/// offering. The enum lives in Core so future transports (e.g. a local
/// system-wide routing driver) can be added without breaking existing data.
/// </summary>
public enum ProxyProtocol
{
    /// <summary>HTTP/HTTPS proxy using the CONNECT method for TLS tunneling.</summary>
    Http = 0,

    /// <summary>SOCKS5 proxy with username/password authentication (RFC 1929).</summary>
    Socks5 = 1
}
