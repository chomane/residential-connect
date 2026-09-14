using System.Net.Sockets;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>
/// Establishes an authenticated TCP connection to a target host:port through
/// the real upstream residential proxy, hiding the protocol-specific
/// handshake (HTTP CONNECT vs SOCKS5) from <see cref="LocalForwardingProxy"/>.
/// </summary>
public interface IUpstreamConnector
{
    Task<TcpClient> ConnectAsync(string targetHost, int targetPort, CancellationToken cancellationToken);
}
