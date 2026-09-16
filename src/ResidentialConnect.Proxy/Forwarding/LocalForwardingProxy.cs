using System.Net;
using System.Net.Sockets;
using System.Text;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>
/// Unauthenticated loopback (127.0.0.1) HTTP proxy that the local browser
/// instance is pointed at via <c>--proxy-server=127.0.0.1:PORT</c>. Every
/// accepted connection is relayed to the real upstream residential proxy
/// using <see cref="IUpstreamConnector"/>, which performs the
/// username/password handshake transparently - so the browser never sees,
/// and never has to prompt for, the proxy credentials.
/// </summary>
public sealed class LocalForwardingProxy : ILocalForwardingProxy
{
    private readonly IAppLogger _logger;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private IUpstreamConnector? _connector;
    // Only the accept loop writes this collection. Stop awaits that loop
    // before draining it, including connections still reading request headers.
    private readonly List<Task> _clients = new();
    private readonly SemaphoreSlim _stopLock = new(1, 1);

    public LocalForwardingProxy(IAppLogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public bool IsRunning { get; private set; }
    public int? Port { get; private set; }

    public Task<int> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrEmpty(password);

        _connector = profile.Protocol switch
        {
            ProxyProtocol.Http => new HttpConnectUpstreamConnector(profile.Host, profile.Port, profile.Username, password),
            ProxyProtocol.Socks5 => new Socks5UpstreamConnector(profile.Host, profile.Port, profile.Username, password),
            _ => throw new NotSupportedException($"Protocol {profile.Protocol} not supported by the local forwarding proxy.")
        };

        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _cts = new CancellationTokenSource();
        IsRunning = true;

        var token = _cts.Token;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(token));

        _logger.Info("LocalForwardingProxy", $"Local relay listening on 127.0.0.1:{Port} -> upstream {profile.Host}:{profile.Port} ({profile.Protocol}).");
        return Task.FromResult(Port.Value);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await _listener!.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                _clients.RemoveAll(task => task.IsCompleted);
                _clients.Add(HandleClientAsync(client, cancellationToken));
            }
        }
        catch (OperationCanceledException)
        {
            // Expected on stop.
        }
        catch (ObjectDisposedException)
        {
            // Expected on stop.
        }
        catch (Exception ex)
        {
            _logger.Error("LocalForwardingProxy", "Accept loop terminated unexpectedly.", ex);
        }
    }

    private async Task HandleClientAsync(TcpClient browserClient, CancellationToken cancellationToken)
    {
        using var _ = browserClient;
        try
        {
            browserClient.NoDelay = true;
            var browserStream = browserClient.GetStream();
            var request = await RawHttpRequestReader.ReadAsync(browserStream, cancellationToken).ConfigureAwait(false);
            if (request is null)
            {
                return;
            }

            if (string.Equals(request.Method, "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                await HandleConnectAsync(browserStream, request, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await HandlePlainHttpAsync(browserStream, request, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ProxyAuthenticationException)
        {
            _logger.Debug("LocalForwardingProxy", $"Client session ended: {ex.GetType().Name}.");
        }
        catch (Exception ex)
        {
            _logger.Warning("LocalForwardingProxy", $"Unexpected error handling browser connection: {ex.GetType().Name}.");
        }
    }

    private async Task HandleConnectAsync(NetworkStream browserStream, RawHttpRequest request, CancellationToken cancellationToken)
    {
        var hostPort = request.Target.Split(':', 2);
        var targetHost = hostPort[0];
        var targetPort = hostPort.Length > 1 && int.TryParse(hostPort[1], out var p) ? p : 443;

        using var upstream = await _connector!.ConnectAsync(targetHost, targetPort, cancellationToken).ConfigureAwait(false);

        var okResponse = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
        await browserStream.WriteAsync(okResponse, cancellationToken).ConfigureAwait(false);

        await UpstreamRelayHelper.RelayBidirectionalAsync(browserStream, upstream.GetStream(), cancellationToken).ConfigureAwait(false);
    }

    private async Task HandlePlainHttpAsync(NetworkStream browserStream, RawHttpRequest request, CancellationToken cancellationToken)
    {
        // Absolute-form target, e.g. "http://example.com/path".
        var uri = new Uri(request.Target);
        using var upstream = await _connector!.ConnectAsync(uri.Host, uri.Port, cancellationToken).ConfigureAwait(false);
        var upstreamStream = upstream.GetStream();

        await upstreamStream.WriteAsync(request.RawHeaderBytes, cancellationToken).ConfigureAwait(false);
        await UpstreamRelayHelper.RelayBidirectionalAsync(browserStream, upstreamStream, cancellationToken).ConfigureAwait(false);
    }

    public async Task StopAsync()
    {
        await _stopLock.WaitAsync().ConfigureAwait(false);
        try
        {
            IsRunning = false;
            _cts?.Cancel();
            _listener?.Stop();
            Port = null;
            if (_acceptLoop is not null)
                await _acceptLoop.ConfigureAwait(false);
            await Task.WhenAll(_clients).ConfigureAwait(false);
            _clients.Clear();
            _acceptLoop = null;
            _listener = null;
            _connector = null;
            _cts?.Dispose();
            _cts = null;
        }
        finally { _stopLock.Release(); }
    }

    public void Dispose() => StopAsync().GetAwaiter().GetResult();
}
