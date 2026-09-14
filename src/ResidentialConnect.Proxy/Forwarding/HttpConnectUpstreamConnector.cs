using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>
/// Opens a TCP connection to an upstream HTTP(S) proxy and issues an
/// authenticated CONNECT request to reach <c>targetHost:targetPort</c>. On
/// success, the returned <see cref="TcpClient"/>'s stream is a raw tunnel
/// the caller can relay bytes through (e.g. TLS bytes for an HTTPS site).
/// </summary>
public sealed class HttpConnectUpstreamConnector : IUpstreamConnector
{
    private readonly string _proxyHost;
    private readonly int _proxyPort;
    private readonly string _username;
    private readonly string _password;

    public HttpConnectUpstreamConnector(string proxyHost, int proxyPort, string username, string password)
    {
        _proxyHost = proxyHost;
        _proxyPort = proxyPort;
        _username = username;
        _password = password;
    }

    public async Task<TcpClient> ConnectAsync(string targetHost, int targetPort, CancellationToken cancellationToken)
    {
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(_proxyHost, _proxyPort, cancellationToken).ConfigureAwait(false);

            var stream = client.GetStream();
            var authToken = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{_username}:{_password}"));
            var request =
                $"CONNECT {targetHost}:{targetPort} HTTP/1.1\r\n" +
                $"Host: {targetHost}:{targetPort}\r\n" +
                $"Proxy-Authorization: Basic {authToken}\r\n" +
                "Proxy-Connection: Keep-Alive\r\n" +
                "\r\n";

            var requestBytes = Encoding.ASCII.GetBytes(request);
            await stream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);

            var statusLine = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
            // Drain remaining response headers until blank line.
            string line;
            do
            {
                line = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
            } while (!string.IsNullOrEmpty(line));

            if (!statusLine.Contains(" 200"))
            {
                if (statusLine.Contains(" 407"))
                {
                    throw new ProxyAuthenticationException($"Upstream proxy rejected credentials (CONNECT -> {statusLine}).");
                }

                throw new IOException($"Upstream proxy CONNECT failed: {statusLine}");
            }

            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>();
        var single = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(single, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (single[0] == (byte)'\n')
            {
                break;
            }

            if (single[0] != (byte)'\r')
            {
                bytes.Add(single[0]);
            }
        }

        return Encoding.ASCII.GetString(bytes.ToArray());
    }
}

/// <summary>Thrown when the upstream proxy rejects the configured credentials.</summary>
public sealed class ProxyAuthenticationException : Exception
{
    public ProxyAuthenticationException(string message) : base(message) { }
}
