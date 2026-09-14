using System.Net;
using System.Net.Sockets;
using System.Text;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Forwarding;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the local loopback forwarding relay and its upstream
/// connectors - the exact path the OPEN BROWSER bug report identified as
/// unverified ("do not just claim this is fixed because unit tests pass").
/// These tests stand up a real, fake TCP "upstream proxy" listener on
/// loopback (never a real network call, never a real Webshare credential)
/// and drive HttpConnectUpstreamConnector / LocalForwardingProxy against it,
/// asserting:
///  - the CONNECT request sent upstream carries a correctly-formed
///    Proxy-Authorization: Basic header built from the configured
///    username/password,
///  - a 200 response lets bytes flow through the tunnel end-to-end,
///  - a 407 response is surfaced as a ProxyAuthenticationException rather
///    than silently succeeding or silently falling back to a direct
///    connection,
///  - LocalForwardingProxy's own loopback listener, given a browser-style
///    CONNECT request, performs the upstream handshake and relays the
///    "200 Connection Established" response plus tunneled bytes back to the
///    browser side.
/// </summary>
public class HttpConnectUpstreamConnectorTests
{
    [Fact]
    public async Task ConnectAsync_SendsCorrectProxyAuthorizationHeader_AndReturnsTunnelOn200()
    {
        using var fakeProxy = new FakeUpstreamHttpProxyServer();
        fakeProxy.NextResponseStatusLine = "HTTP/1.1 200 Connection Established";
        var acceptTask = fakeProxy.AcceptOnceAsync();

        var connector = new HttpConnectUpstreamConnector(IPAddress.Loopback.ToString(), fakeProxy.Port, "webshare-user", "s3cr3t-pass");

        using var tunnel = await connector.ConnectAsync("example.com", 443, CancellationToken.None);
        var received = await acceptTask;

        Assert.True(tunnel.Connected);
        Assert.StartsWith("CONNECT example.com:443 HTTP/1.1", received.RequestText);

        var expectedAuth = Convert.ToBase64String(Encoding.ASCII.GetBytes("webshare-user:s3cr3t-pass"));
        Assert.Contains($"Proxy-Authorization: Basic {expectedAuth}", received.RequestText);
    }

    [Fact]
    public async Task ConnectAsync_UpstreamReturns407_ThrowsProxyAuthenticationException_DoesNotSilentlyFallback()
    {
        using var fakeProxy = new FakeUpstreamHttpProxyServer();
        fakeProxy.NextResponseStatusLine = "HTTP/1.1 407 Proxy Authentication Required";
        _ = fakeProxy.AcceptOnceAsync();

        var connector = new HttpConnectUpstreamConnector(IPAddress.Loopback.ToString(), fakeProxy.Port, "wrong-user", "wrong-pass");

        await Assert.ThrowsAsync<ProxyAuthenticationException>(
            () => connector.ConnectAsync("example.com", 443, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectAsync_UpstreamReturnsOtherNon200_ThrowsIOException()
    {
        using var fakeProxy = new FakeUpstreamHttpProxyServer();
        fakeProxy.NextResponseStatusLine = "HTTP/1.1 502 Bad Gateway";
        _ = fakeProxy.AcceptOnceAsync();

        var connector = new HttpConnectUpstreamConnector(IPAddress.Loopback.ToString(), fakeProxy.Port, "user", "pass");

        await Assert.ThrowsAsync<IOException>(
            () => connector.ConnectAsync("example.com", 443, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectAsync_NeverLeaksCredentialsInPlainRequestBeyondTheSingleAuthorizedHeader()
    {
        // Defense-in-depth style assertion: the password must appear
        // exactly once, inside the (necessary) Basic auth header, and
        // never elsewhere in the raw request bytes (e.g. accidentally
        // duplicated into a comment/log-style line).
        using var fakeProxy = new FakeUpstreamHttpProxyServer();
        fakeProxy.NextResponseStatusLine = "HTTP/1.1 200 Connection Established";
        var acceptTask = fakeProxy.AcceptOnceAsync();

        const string password = "s3cr3t-pass";
        var connector = new HttpConnectUpstreamConnector(IPAddress.Loopback.ToString(), fakeProxy.Port, "webshare-user", password);
        using var tunnel = await connector.ConnectAsync("example.com", 443, CancellationToken.None);
        var received = await acceptTask;

        var plainTextOccurrences = CountOccurrences(received.RequestText, password);
        Assert.Equal(0, plainTextOccurrences);
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }
}

public class LocalForwardingProxyTests
{
    [Fact]
    public async Task StartAsync_HttpConnectRequest_IsTunneledThroughToUpstreamProxy()
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

        using var relay = new LocalForwardingProxy(new NullLogger());
        var localPort = await relay.StartAsync(profile, "s3cr3t-pass", CancellationToken.None);

        Assert.True(relay.IsRunning);
        Assert.Equal(localPort, relay.Port);

        using var browserSideClient = new TcpClient();
        await browserSideClient.ConnectAsync(IPAddress.Loopback, localPort);
        var browserStream = browserSideClient.GetStream();

        var connectRequest = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        var requestBytes = Encoding.ASCII.GetBytes(connectRequest);
        await browserStream.WriteAsync(requestBytes);

        var responseBuffer = new byte[4096];
        var read = await ReadAtLeastAsync(browserStream, responseBuffer, "HTTP/1.1 200 Connection Established".Length);
        var responseText = Encoding.ASCII.GetString(responseBuffer, 0, read);
        Assert.Contains("200 Connection Established", responseText);

        var upstreamReceived = await upstreamAcceptTask;
        Assert.StartsWith("CONNECT example.com:443 HTTP/1.1", upstreamReceived.RequestText);

        // Prove the tunnel actually relays application bytes end-to-end in
        // both directions once established (browser -> relay -> upstream and
        // back), not just the CONNECT handshake itself.
        var payload = Encoding.ASCII.GetBytes("PING-THROUGH-TUNNEL");
        await browserStream.WriteAsync(payload);
        var echoBuffer = new byte[payload.Length];
        var echoRead = await ReadAtLeastAsync(browserStream, echoBuffer, payload.Length);
        Assert.Equal(payload, echoBuffer[..echoRead]);

        await relay.StopAsync();
    }

    [Fact]
    public async Task StartAsync_UpstreamAuthFailure_DoesNotSilentlyServeBrowserADirectConnection()
    {
        // If the upstream proxy rejects credentials, the relay must NOT
        // silently connect the browser directly to the target instead - it
        // must fail the CONNECT to the browser (connection closed / error),
        // never returning "200 Connection Established" for a connection that
        // is not actually tunneled through the authenticated upstream proxy.
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

        using var relay = new LocalForwardingProxy(new NullLogger());
        var localPort = await relay.StartAsync(profile, "wrong-pass", CancellationToken.None);

        using var browserSideClient = new TcpClient();
        await browserSideClient.ConnectAsync(IPAddress.Loopback, localPort);
        var browserStream = browserSideClient.GetStream();

        var connectRequest = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        await browserStream.WriteAsync(Encoding.ASCII.GetBytes(connectRequest));

        // The relay must close the connection (or send a non-200 response)
        // rather than ever sending "200 Connection Established" for a
        // failed/unauthenticated upstream session.
        var responseBuffer = new byte[4096];
        int totalRead;
        try
        {
            totalRead = await browserSideClient.GetStream().ReadAsync(responseBuffer);
        }
        catch (IOException)
        {
            totalRead = 0;
        }

        var responseText = totalRead > 0 ? Encoding.ASCII.GetString(responseBuffer, 0, totalRead) : string.Empty;
        Assert.DoesNotContain("200 Connection Established", responseText);

        await relay.StopAsync();
    }

    [Fact]
    public async Task StopAsync_ClosesListener_SoNoFurtherBrowserConnectionsAreAccepted()
    {
        using var fakeUpstream = new FakeUpstreamHttpProxyServer();
        fakeUpstream.NextResponseStatusLine = "HTTP/1.1 200 Connection Established";

        var profile = new ProxyProfile
        {
            Host = IPAddress.Loopback.ToString(),
            Port = fakeUpstream.Port,
            Username = "user",
            Protocol = ProxyProtocol.Http,
            CountryCode = "US"
        };

        using var relay = new LocalForwardingProxy(new NullLogger());
        var localPort = await relay.StartAsync(profile, "pass", CancellationToken.None);
        await relay.StopAsync();

        Assert.False(relay.IsRunning);
        Assert.Null(relay.Port);

        using var client = new TcpClient();
        await Assert.ThrowsAnyAsync<Exception>(() => client.ConnectAsync(IPAddress.Loopback, localPort));
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

/// <summary>
/// Minimal fake upstream HTTP CONNECT proxy server used only in tests, bound
/// to an ephemeral loopback port. Captures the raw request text it received
/// so tests can assert on the exact bytes sent by the connector under test
/// (in particular the Proxy-Authorization header), and replies with a
/// configurable status line. Never touches the real network and never
/// contains any real Webshare credentials.
/// </summary>
public sealed class FakeUpstreamHttpProxyServer : IDisposable
{
    private readonly TcpListener _listener;

    public FakeUpstreamHttpProxyServer()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public string NextResponseStatusLine { get; set; } = "HTTP/1.1 200 Connection Established";

    /// <summary>
    /// When true, after a successful CONNECT the fake server keeps the
    /// connection open and echoes back whatever bytes it subsequently
    /// receives, so a test can prove end-to-end tunnel relaying. This runs
    /// as a background continuation AFTER <see cref="AcceptOnceAsync"/>
    /// already returned the captured handshake request - it must never be
    /// awaited as part of accepting the connection, otherwise the accept
    /// task can only complete once the echo loop's caller closes the
    /// connection, which the caller can only do AFTER first awaiting the
    /// accept task: a self-deadlock.
    /// </summary>
    public bool EchoAfterConnect { get; set; }

    public async Task<FakeUpstreamReceivedRequest> AcceptOnceAsync()
    {
        var client = await _listener.AcceptTcpClientAsync();
        var stream = client.GetStream();

        var requestText = await ReadRequestHeadTextAsync(stream);

        var responseBytes = Encoding.ASCII.GetBytes(NextResponseStatusLine + "\r\n\r\n");
        await stream.WriteAsync(responseBytes);

        if (EchoAfterConnect && NextResponseStatusLine.Contains("200"))
        {
            // Fire-and-forget: run the echo loop in the background so this
            // method can return the captured request immediately. The test
            // is responsible for eventually closing the browser-side (and
            // therefore, once relayed, this) connection, which ends the loop.
            _ = Task.Run(async () =>
            {
                var buffer = new byte[4096];
                try
                {
                    while (true)
                    {
                        var read = await stream.ReadAsync(buffer);
                        if (read == 0)
                        {
                            break;
                        }

                        await stream.WriteAsync(buffer.AsMemory(0, read));
                    }
                }
                catch (IOException)
                {
                    // Client closed the connection - normal end of the test.
                }
                catch (ObjectDisposedException)
                {
                    // Client/listener disposed - normal end of the test.
                }
                finally
                {
                    client.Dispose();
                }
            });
        }
        else
        {
            client.Dispose();
        }

        return new FakeUpstreamReceivedRequest(requestText);
    }

    private static async Task<string> ReadRequestHeadTextAsync(NetworkStream stream)
    {
        var buffer = new List<byte>();
        var single = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(single);
            if (read == 0)
            {
                break;
            }

            buffer.Add(single[0]);
            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' && buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' && buffer[^1] == (byte)'\n')
            {
                break;
            }
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    public void Dispose() => _listener.Stop();
}

public sealed record FakeUpstreamReceivedRequest(string RequestText);
