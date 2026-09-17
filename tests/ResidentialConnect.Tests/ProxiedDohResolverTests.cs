using System.Net;
using System.Net.Sockets;
using System.Text;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Dns;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="ProxiedDohResolver"/> - specifically that it reaches
/// its DoH endpoint entirely THROUGH the configured upstream proxy tunnel
/// (never a direct connection, never a local DNS lookup of the DoH
/// hostname), round-trips the exact raw request/response bytes, and can only
/// be used after <see cref="ProxiedDohResolver.Configure"/>. Uses a real,
/// loopback-only fake "tunneling" HTTP CONNECT proxy (see
/// <see cref="RelayingUpstreamHttpProxyServer"/>) that actually forwards the
/// CONNECT target to a real local HTTP server - proving the
/// <see cref="System.Net.Http.SocketsHttpHandler.ConnectCallback"/> wiring
/// end-to-end, not just that <see cref="ResidentialConnect.Proxy.Forwarding.IUpstreamConnector"/>
/// was constructed.
/// </summary>
public class ProxiedDohResolverTests
{
    [Fact]
    public async Task ResolveAsync_SendsTheRawQueryBytes_AndReturnsTheRawResponseBytes_ThroughTheProxyTunnel()
    {
        using var fakeDohServer = new FakeRawDohHttpServer();
        var expectedResponse = new byte[] { 0xAB, 0xCD, 0x00, 0x81, 0x00, 0x01 };
        fakeDohServer.NextResponseBody = expectedResponse;

        using var fakeProxy = new RelayingUpstreamHttpProxyServer(IPAddress.Loopback, fakeDohServer.Port);

        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = fakeProxy.Port,
            Username = "webshare-user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        using var resolver = new ProxiedDohResolver(new NullLogger(), $"http://cloudflare-dns.com:{fakeDohServer.Port}/dns-query");
        resolver.Configure(profile, "s3cr3t-pass", IPAddress.Loopback);

        var query = new byte[] { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01 };
        var response = await resolver.ResolveAsync(query, CancellationToken.None);

        Assert.Equal(expectedResponse, response);
        Assert.Equal(query, fakeDohServer.LastReceivedRequestBody);
        Assert.Equal("application/dns-message", fakeDohServer.LastReceivedContentType);
        // The CONNECT target the fake proxy captured must be the DoH
        // HOSTNAME - never a locally pre-resolved IP - proving this
        // resolver never performs its own DNS lookup of the DoH endpoint
        // (see ProxiedDohResolver class remarks "Never resolves
        // cloudflare-dns.com locally").
        Assert.StartsWith("cloudflare-dns.com:", fakeProxy.LastConnectTarget);
    }

    [Fact]
    public async Task ResolveAsync_BeforeConfigure_Throws()
    {
        using var resolver = new ProxiedDohResolver(new NullLogger());

        await Assert.ThrowsAsync<InvalidOperationException>(() => resolver.ResolveAsync(new byte[] { 1, 2, 3 }, CancellationToken.None));
    }

    [Fact]
    public void Configure_CalledTwice_Throws()
    {
        using var fakeDohServer = new FakeRawDohHttpServer();
        using var fakeProxy = new RelayingUpstreamHttpProxyServer(IPAddress.Loopback, fakeDohServer.Port);

        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = fakeProxy.Port,
            Username = "user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        using var resolver = new ProxiedDohResolver(new NullLogger(), $"http://cloudflare-dns.com:{fakeDohServer.Port}/dns-query");
        resolver.Configure(profile, "pass", IPAddress.Loopback);

        Assert.Throws<InvalidOperationException>(() => resolver.Configure(profile, "pass", IPAddress.Loopback));
    }
}

/// <summary>
/// Minimal loopback-only raw HTTP/1.1 server that accepts exactly one POST
/// request (a DoH query) at a time and returns a canned raw response body -
/// standing in for <c>cloudflare-dns.com</c> in <see cref="ProxiedDohResolverTests"/>.
/// Deliberately reads/writes with no HTTP library dependency (matching the
/// same low-level style already used by <c>FakeUpstreamHttpProxyServer</c>
/// in <c>ForwardingProxyTests.cs</c>) so it never touches the real network.
/// </summary>
public sealed class FakeRawDohHttpServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;

    public FakeRawDohHttpServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public byte[] NextResponseBody { get; set; } = Array.Empty<byte>();

    public byte[]? LastReceivedRequestBody { get; private set; }

    public string? LastReceivedContentType { get; private set; }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                await HandleOneRequestAsync(client).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task HandleOneRequestAsync(TcpClient client)
    {
        var stream = client.GetStream();
        var headerLines = new List<string>();
        string line;
        while (!string.IsNullOrEmpty(line = await ReadLineAsync(stream).ConfigureAwait(false)))
        {
            headerLines.Add(line);
        }

        var contentLength = 0;
        foreach (var header in headerLines)
        {
            if (header.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                contentLength = int.Parse(header.Split(':', 2)[1].Trim());
            }
            else if (header.StartsWith("Content-Type:", StringComparison.OrdinalIgnoreCase))
            {
                LastReceivedContentType = header.Split(':', 2)[1].Trim();
            }
        }

        var body = new byte[contentLength];
        var offset = 0;
        while (offset < contentLength)
        {
            var read = await stream.ReadAsync(body.AsMemory(offset, contentLength - offset)).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            offset += read;
        }

        LastReceivedRequestBody = body;

        var responseHeader =
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: application/dns-message\r\n" +
            $"Content-Length: {NextResponseBody.Length}\r\n" +
            "Connection: close\r\n" +
            "\r\n";
        var responseHeaderBytes = Encoding.ASCII.GetBytes(responseHeader);
        await stream.WriteAsync(responseHeaderBytes).ConfigureAwait(false);
        await stream.WriteAsync(NextResponseBody).ConfigureAwait(false);
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream)
    {
        var bytes = new List<byte>();
        var single = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(single).ConfigureAwait(false);
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

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try { _acceptLoop.Wait(TimeSpan.FromSeconds(2)); } catch { /* best-effort */ }
        _cts.Dispose();
    }
}

/// <summary>
/// Fake upstream HTTP CONNECT proxy that, unlike <c>FakeUpstreamHttpProxyServer</c>
/// (which only echoes bytes back to the caller), actually opens a REAL TCP
/// connection to a fixed local target and splices bytes bidirectionally -
/// exactly what a real HTTP CONNECT proxy does. This is required to exercise
/// <see cref="ProxiedDohResolver"/>'s <c>SocketsHttpHandler.ConnectCallback</c>
/// end-to-end against a real (fake) DoH HTTP server on the other side of the
/// tunnel.
/// </summary>
public sealed class RelayingUpstreamHttpProxyServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly IPAddress _relayTargetAddress;
    private readonly int _relayTargetPort;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _acceptLoop;

    public RelayingUpstreamHttpProxyServer(IPAddress relayTargetAddress, int relayTargetPort)
    {
        _relayTargetAddress = relayTargetAddress;
        _relayTargetPort = relayTargetPort;
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>The exact "host:port" text this proxy last saw in a CONNECT request line.</summary>
    public string? LastConnectTarget { get; private set; }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                var client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                _ = HandleClientAsync(client);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task HandleClientAsync(TcpClient client)
    {
        using var _ = client;
        try
        {
            var stream = client.GetStream();
            var requestLine = await ReadLineAsync(stream).ConfigureAwait(false);
            // Drain remaining request headers until blank line.
            string line;
            while (!string.IsNullOrEmpty(line = await ReadLineAsync(stream).ConfigureAwait(false)))
            {
            }

            // "CONNECT host:port HTTP/1.1"
            var parts = requestLine.Split(' ');
            LastConnectTarget = parts.Length > 1 ? parts[1] : null;

            var responseBytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await stream.WriteAsync(responseBytes).ConfigureAwait(false);

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(_relayTargetAddress, _relayTargetPort).ConfigureAwait(false);
            var upstreamStream = upstream.GetStream();

            var toUpstream = PumpAsync(stream, upstreamStream);
            var toClient = PumpAsync(upstreamStream, stream);
            await Task.WhenAny(toUpstream, toClient).ConfigureAwait(false);
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task PumpAsync(NetworkStream from, NetworkStream to)
    {
        var buffer = new byte[8192];
        try
        {
            while (true)
            {
                var read = await from.ReadAsync(buffer).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                await to.WriteAsync(buffer.AsMemory(0, read)).ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream)
    {
        var bytes = new List<byte>();
        var single = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(single).ConfigureAwait(false);
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

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try { _acceptLoop.Wait(TimeSpan.FromSeconds(2)); } catch { /* best-effort */ }
        _cts.Dispose();
    }
}
