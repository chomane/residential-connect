using System.Net;
using System.Net.Sockets;
using System.Text;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Forwarding;

namespace ResidentialConnect.Tests;

public sealed class BrowserRelayLifecycleTests
{
    [Fact]
    public async Task StopAsync_ClosesEstablishedTunnelAndIdleClient_BeforeReturning()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = timeout.Token;
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        var profile = new ProxyProfile
        {
            Host = "127.0.0.1",
            Port = ((IPEndPoint)upstreamListener.LocalEndpoint).Port,
            Protocol = ProxyProtocol.Http,
            Username = "test-only"
        };
        using var relay = new LocalForwardingProxy(new NullLogger());
        var port = await relay.StartAsync(profile, "test-only", token);
        using var idle = new TcpClient();
        await idle.ConnectAsync(IPAddress.Loopback, port, token);
        // A partial request ensures this client is blocked in the request reader.
        await idle.GetStream().WriteAsync("CON"u8.ToArray(), token);
        using var browser = new TcpClient();
        await browser.ConnectAsync(IPAddress.Loopback, port, token);
        await browser.GetStream().WriteAsync(
            Encoding.ASCII.GetBytes("CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n"), token);
        using var upstream = await upstreamListener.AcceptTcpClientAsync(token);
        await ReadHeaderAsync(upstream.GetStream(), token);
        await upstream.GetStream().WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), token);
        await ReadHeaderAsync(browser.GetStream(), token);
        await relay.StopAsync().WaitAsync(token);
        Assert.False(relay.IsRunning);
        Assert.Null(relay.Port);
        await AssertClosedAsync(browser, token);
        await AssertClosedAsync(upstream, token);
        await AssertClosedAsync(idle, token);
        await relay.StopAsync();
        relay.Dispose();
        relay.Dispose();
    }

    private static async Task ReadHeaderAsync(NetworkStream stream, CancellationToken token)
    {
        var text = new StringBuilder();
        var buffer = new byte[1];
        while (!text.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            Assert.Equal(1, await stream.ReadAsync(buffer, token));
            text.Append((char)buffer[0]);
        }
    }

    private static async Task AssertClosedAsync(TcpClient client, CancellationToken token)
    {
        try { Assert.Equal(0, await client.GetStream().ReadAsync(new byte[1], token)); }
        catch (IOException) { /* A TCP reset also proves the socket was closed. */ }
    }
}
