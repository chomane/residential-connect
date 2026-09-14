using System.Net;
using System.Net.Sockets;
using System.Text;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Forwarding;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="TransparentForwardingProxy"/> - the Whole Computer
/// counterpart of <see cref="LocalForwardingProxy"/> (see
/// <see cref="ForwardingProxyTests"/> for that V0.1 coverage). These reuse
/// the exact same fake upstream HTTP CONNECT proxy server, but drive
/// <see cref="TransparentForwardingProxy"/> the way
/// <c>WinDivertSystemTrafficRouter</c> actually would: by accepting a raw,
/// already-kernel-redirected connection with NO CONNECT handshake from the
/// "application" side at all, and resolving the original destination purely
/// via <see cref="IOriginalDestinationResolver"/> (here, a real
/// <see cref="RedirectFlowTable"/>, proving the two components integrate
/// correctly).
/// </summary>
public class TransparentForwardingProxyTests
{
    [Fact]
    public async Task StartAsync_RedirectedConnection_ResolvesOriginalDestination_AndTunnelsThroughUpstream()
    {
        using var fakeUpstream = new FakeUpstreamHttpProxyServer();
        fakeUpstream.NextResponseStatusLine = "HTTP/1.1 200 Connection Established";
        fakeUpstream.EchoAfterConnect = true;
        var upstreamAcceptTask = fakeUpstream.AcceptOnceAsync();

        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = fakeUpstream.Port,
            Username = "webshare-user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        var flowTable = new RedirectFlowTable();
        using var relay = new TransparentForwardingProxy(new NullLogger());
        var relayPort = await relay.StartAsync(profile, "s3cr3t-pass", IPAddress.Loopback, flowTable, CancellationToken.None);

        Assert.True(relay.IsRunning);

        // Simulate the application's redirected TCP connection. In real
        // whole-computer routing, WinDivertSystemTrafficRouter records the
        // flow-table entry at SYN-rewrite time, strictly BEFORE the OS ever
        // delivers the connection to this relay - so a client port must be
        // bound and recorded before connecting, to avoid a benign test-only
        // race against the already-running accept loop.
        using var appSideClient = new TcpClient();
        appSideClient.Client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var appClientPort = ((IPEndPoint)appSideClient.Client.LocalEndPoint!).Port;
        flowTable.Record(appClientPort, "example.com", 443);

        await appSideClient.ConnectAsync(IPAddress.Loopback, relayPort);

        var appStream = appSideClient.GetStream();
        var payload = Encoding.ASCII.GetBytes("PING-THROUGH-TRANSPARENT-TUNNEL");
        await appStream.WriteAsync(payload);

        var echoBuffer = new byte[payload.Length];
        var echoRead = await ReadAtLeastAsync(appStream, echoBuffer, payload.Length);
        Assert.Equal(payload, echoBuffer[..echoRead]);

        var upstreamReceived = await upstreamAcceptTask;
        Assert.StartsWith("CONNECT example.com:443 HTTP/1.1", upstreamReceived.RequestText);

        await relay.StopAsync();
    }

    [Fact]
    public async Task StartAsync_UnresolvableDestination_ClosesConnection_FailClosed()
    {
        // No flow-table entry at all for this client port - the relay must
        // close the connection rather than guess/fall back anywhere.
        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = 1, // never dialed - no fake upstream needed for this test
            Username = "user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        var flowTable = new RedirectFlowTable();
        using var relay = new TransparentForwardingProxy(new NullLogger());
        var relayPort = await relay.StartAsync(profile, "pass", IPAddress.Loopback, flowTable, CancellationToken.None);

        using var appSideClient = new TcpClient();
        await appSideClient.ConnectAsync(IPAddress.Loopback, relayPort);
        var stream = appSideClient.GetStream();

        // The relay should close the connection quickly since it cannot
        // resolve an original destination for this (untracked) client port.
        var buffer = new byte[16];
        int read;
        try
        {
            read = await stream.ReadAsync(buffer);
        }
        catch (IOException)
        {
            read = 0;
        }

        Assert.Equal(0, read);

        await relay.StopAsync();
    }

    [Fact]
    public async Task StartAsync_UpstreamAuthFailure_ClosesRedirectedConnection_NeverConnectsDirect()
    {
        using var fakeUpstream = new FakeUpstreamHttpProxyServer();
        fakeUpstream.NextResponseStatusLine = "HTTP/1.1 407 Proxy Authentication Required";
        _ = fakeUpstream.AcceptOnceAsync();

        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = fakeUpstream.Port,
            Username = "wrong-user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        var flowTable = new RedirectFlowTable();
        using var relay = new TransparentForwardingProxy(new NullLogger());
        var relayPort = await relay.StartAsync(profile, "wrong-pass", IPAddress.Loopback, flowTable, CancellationToken.None);

        using var appSideClient = new TcpClient();
        await appSideClient.ConnectAsync(IPAddress.Loopback, relayPort);
        var appClientPort = ((IPEndPoint)appSideClient.Client.LocalEndPoint!).Port;
        flowTable.Record(appClientPort, "example.com", 443);

        var stream = appSideClient.GetStream();
        var buffer = new byte[16];
        int read;
        try
        {
            read = await stream.ReadAsync(buffer);
        }
        catch (IOException)
        {
            read = 0;
        }

        Assert.Equal(0, read);

        await relay.StopAsync();
    }

    [Fact]
    public async Task StopAsync_ClosesListener_SoNoFurtherRedirectedConnectionsAreAccepted()
    {
        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = 1,
            Username = "user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        var flowTable = new RedirectFlowTable();
        using var relay = new TransparentForwardingProxy(new NullLogger());
        var relayPort = await relay.StartAsync(profile, "pass", IPAddress.Loopback, flowTable, CancellationToken.None);

        await relay.StopAsync();

        Assert.False(relay.IsRunning);
        Assert.Null(relay.Port);

        using var client = new TcpClient();
        await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(IPAddress.Loopback, relayPort));
    }

    [Fact]
    public async Task StartAsync_BindsToGivenAddress_NotLoopbackOnly()
    {
        // Unlike LocalForwardingProxy (always loopback-only), the transparent
        // relay must be able to bind to IPAddress.Any so real,
        // kernel-redirected non-loopback connections can reach it.
        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = 1,
            Username = "user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        var flowTable = new RedirectFlowTable();
        using var relay = new TransparentForwardingProxy(new NullLogger());
        var relayPort = await relay.StartAsync(profile, "pass", IPAddress.Any, flowTable, CancellationToken.None);

        Assert.True(relay.IsRunning);
        Assert.Equal(relayPort, relay.Port);

        await relay.StopAsync();
    }

    private static async Task<int> ReadAtLeastAsync(NetworkStream stream, byte[] buffer, int minBytes)
    {
        var total = 0;
        while (total < minBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total));
            if (read == 0)
            {
                break;
            }
            total += read;
        }

        return total;
    }
}
