using System.Net;
using System.Net.Sockets;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>
/// V0.2 Whole Computer counterpart of <see cref="LocalForwardingProxy"/>.
/// Accepts raw TCP connections that the OS kernel has already redirected
/// here (see <c>ResidentialConnect.Routing.WinDivertSystemTrafficRouter</c>)
/// from ordinary desktop applications that sent no HTTP CONNECT request at
/// all - they simply tried to connect directly to their real destination,
/// unaware that anything intercepted them. For each accepted connection,
/// this relay:
/// <list type="number">
/// <item>Asks <see cref="IOriginalDestinationResolver"/> what the
/// application's ORIGINAL destination host:port was (before the kernel
/// rewrote it to point here);</item>
/// <item>Opens an authenticated upstream tunnel to that original
/// destination through the selected proxy, reusing the exact same
/// <see cref="IUpstreamConnector"/> implementations
/// (<see cref="HttpConnectUpstreamConnector"/> / <see cref="Socks5UpstreamConnector"/>)
/// V0.1's OPEN BROWSER path already uses and already has tests for;</item>
/// <item>Splices bytes bidirectionally between the application and the
/// upstream tunnel.</item>
/// </list>
/// Fail-closed: if step 1 or step 2 fails, the accepted connection is closed
/// immediately - it is never allowed to fall through to a direct connection
/// to the real destination.
/// </summary>
public sealed class TransparentForwardingProxy : ITransparentForwardingProxy
{
    private readonly IAppLogger _logger;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptLoop;
    private IUpstreamConnector? _connector;
    private IOriginalDestinationResolver? _destinationResolver;

    public TransparentForwardingProxy(IAppLogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public bool IsRunning { get; private set; }
    public int? Port { get; private set; }

    public event EventHandler<Exception>? Faulted;

    public Task<int> StartAsync(
        ProxyProfile profile,
        string password,
        IPAddress bindAddress,
        IOriginalDestinationResolver destinationResolver,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(bindAddress);
        ArgumentNullException.ThrowIfNull(destinationResolver);

        _connector = profile.Protocol switch
        {
            ProxyProtocol.Http => new HttpConnectUpstreamConnector(profile.Host, profile.Port, profile.Username, password),
            ProxyProtocol.Socks5 => new Socks5UpstreamConnector(profile.Host, profile.Port, profile.Username, password),
            _ => throw new NotSupportedException($"Protocol {profile.Protocol} not supported by the transparent forwarding proxy.")
        };
        _destinationResolver = destinationResolver;

        _listener = new TcpListener(bindAddress, 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _cts = new CancellationTokenSource();
        IsRunning = true;

        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));

        _logger.Info("TransparentForwardingProxy", $"Transparent relay listening on {bindAddress}:{Port} -> upstream {profile.Host}:{profile.Port} ({profile.Protocol}).");
        return Task.FromResult(Port.Value);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var client = await _listener!.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                _ = HandleClientAsync(client, cancellationToken);
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
            // The accept loop itself dying is exactly the situation the
            // fail-closed contract cares about: if this relay can no longer
            // accept connections, ISystemTrafficRouter must be told so it
            // can start DROPPING intercepted packets rather than leaving
            // them stuck (which the OS could otherwise eventually time out
            // and - depending on the redirect implementation - risk falling
            // back to a direct path). Never swallow this silently.
            IsRunning = false;
            _logger.Error("TransparentForwardingProxy", "Accept loop terminated unexpectedly - signalling fault for fail-closed handling.", ex);
            Faulted?.Invoke(this, ex);
        }
    }

    private async Task HandleClientAsync(TcpClient localClient, CancellationToken cancellationToken)
    {
        using var _ = localClient;
        try
        {
            localClient.NoDelay = true;
            var clientEndpoint = (IPEndPoint?)localClient.Client.RemoteEndPoint;
            if (clientEndpoint is null || !_destinationResolver!.TryResolve(clientEndpoint, out var targetHost, out var targetPort))
            {
                // Fail closed: no known original destination for this
                // connection - never guess, never pass it through anywhere.
                _logger.Warning("TransparentForwardingProxy", "Could not resolve original destination for a redirected connection; closing it (fail-closed).");
                return;
            }

            var localStream = localClient.GetStream();

            TcpClient upstream;
            try
            {
                upstream = await _connector!.ConnectAsync(targetHost, targetPort, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ProxyAuthenticationException)
            {
                // Fail closed: the upstream proxy tunnel could not be
                // established (auth failure, unreachable, etc.) - close the
                // application's connection rather than ever letting it reach
                // targetHost:targetPort directly.
                _logger.Warning("TransparentForwardingProxy", $"Upstream proxy tunnel failed ({ex.GetType().Name}); closing redirected connection (fail-closed).");
                return;
            }

            using (upstream)
            {
                await UpstreamRelayHelper.RelayBidirectionalAsync(localStream, upstream.GetStream(), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            _logger.Debug("TransparentForwardingProxy", $"Redirected connection ended: {ex.GetType().Name}.");
        }
        catch (Exception ex)
        {
            _logger.Warning("TransparentForwardingProxy", $"Unexpected error handling redirected connection: {ex.GetType().Name}.");
        }
    }

    public Task StopAsync()
    {
        IsRunning = false;
        _cts?.Cancel();
        _listener?.Stop();
        Port = null;
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _cts?.Dispose();
    }
}
