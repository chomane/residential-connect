using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>
/// Minimal SOCKS5 client (RFC 1928 handshake + RFC 1929 username/password
/// authentication) used to reach a target host:port through an upstream
/// SOCKS5 residential proxy. Only the CONNECT command and USERNAME/PASSWORD
/// auth method are implemented - the subset Webshare's SOCKS5 endpoints and
/// V0.1 require.
/// </summary>
public sealed class Socks5UpstreamConnector : IUpstreamConnector
{
    private readonly string _proxyHost;
    private readonly int _proxyPort;
    private readonly string _username;
    private readonly string _password;

    public Socks5UpstreamConnector(string proxyHost, int proxyPort, string username, string password)
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

            // Greeting: version 5, 1 method offered = username/password (0x02).
            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x02 }, cancellationToken).ConfigureAwait(false);
            var greetingReply = await ReadExactAsync(stream, 2, cancellationToken).ConfigureAwait(false);
            if (greetingReply[0] != 0x05 || greetingReply[1] != 0x02)
            {
                throw new ProxyAuthenticationException("SOCKS5 proxy does not support username/password authentication.");
            }

            // Username/password auth subnegotiation (RFC 1929).
            var userBytes = Encoding.UTF8.GetBytes(_username);
            var passBytes = Encoding.UTF8.GetBytes(_password);
            var authRequest = new byte[3 + userBytes.Length + passBytes.Length];
            authRequest[0] = 0x01;
            authRequest[1] = (byte)userBytes.Length;
            Array.Copy(userBytes, 0, authRequest, 2, userBytes.Length);
            authRequest[2 + userBytes.Length] = (byte)passBytes.Length;
            Array.Copy(passBytes, 0, authRequest, 3 + userBytes.Length, passBytes.Length);

            await stream.WriteAsync(authRequest, cancellationToken).ConfigureAwait(false);
            var authReply = await ReadExactAsync(stream, 2, cancellationToken).ConfigureAwait(false);
            if (authReply[1] != 0x00)
            {
                throw new ProxyAuthenticationException("SOCKS5 proxy rejected the username/password.");
            }

            // CONNECT request with a domain-name address type (0x03) so the
            // proxy itself resolves DNS for the target (keeps DNS resolution
            // on the residential exit node, matching real browser behavior).
            var hostBytes = Encoding.ASCII.GetBytes(targetHost);
            var connectRequest = new byte[4 + 1 + hostBytes.Length + 2];
            connectRequest[0] = 0x05;
            connectRequest[1] = 0x01; // CONNECT
            connectRequest[2] = 0x00; // reserved
            connectRequest[3] = 0x03; // ATYP domain name
            connectRequest[4] = (byte)hostBytes.Length;
            Array.Copy(hostBytes, 0, connectRequest, 5, hostBytes.Length);
            var portBytes = BitConverter.GetBytes((ushort)targetPort);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(portBytes);
            }

            Array.Copy(portBytes, 0, connectRequest, 5 + hostBytes.Length, 2);

            await stream.WriteAsync(connectRequest, cancellationToken).ConfigureAwait(false);

            var connectReplyHeader = await ReadExactAsync(stream, 4, cancellationToken).ConfigureAwait(false);
            if (connectReplyHeader[1] != 0x00)
            {
                throw new IOException($"SOCKS5 CONNECT failed with reply code {connectReplyHeader[1]}.");
            }

            // Consume the bound address/port that follows, per ATYP.
            var atyp = connectReplyHeader[3];
            var addressLength = atyp switch
            {
                0x01 => 4,  // IPv4
                0x04 => 16, // IPv6
                0x03 => await ReadDomainLengthAsync(stream, cancellationToken).ConfigureAwait(false),
                _ => throw new IOException($"Unsupported SOCKS5 address type {atyp} in reply.")
            };

            await ReadExactAsync(stream, addressLength + 2, cancellationToken).ConfigureAwait(false); // address + port

            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<int> ReadDomainLengthAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var lenByte = await ReadExactAsync(stream, 1, cancellationToken).ConfigureAwait(false);
        return lenByte[0];
    }

    private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        var offset = 0;
        while (offset < count)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("Upstream SOCKS5 proxy closed the connection unexpectedly.");
            }

            offset += read;
        }

        return buffer;
    }
}
