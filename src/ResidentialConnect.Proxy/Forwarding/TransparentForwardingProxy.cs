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
            ProxyProtocol.Http => new HttpConnectUpstreamConnector(profile.Host, profile.Port, profile.Username, password, _logger),
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

    private static readonly bool DiagnosticsEnabled = Environment.GetEnvironmentVariable("RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS") == "1";

    private async Task HandleClientAsync(TcpClient localClient, CancellationToken cancellationToken)
    {
        using var _ = localClient;
        try
        {
            localClient.NoDelay = true;
            var clientEndpoint = (IPEndPoint?)localClient.Client.RemoteEndPoint;

            if (DiagnosticsEnabled)
            {
                _logger.Debug("RoutingDiagnostics", $"TransparentForwardingProxy accepted a redirected TCP connection from apparent peer {clientEndpoint}.");
            }

            if (clientEndpoint is null || !_destinationResolver!.TryResolve(clientEndpoint, out var targetHost, out var targetPort))
            {
                // Fail closed: no known original destination for this
                // connection - never guess, never pass it through anywhere.
                _logger.Warning("TransparentForwardingProxy", "Could not resolve original destination for a redirected connection; closing it (fail-closed).");
                return;
            }

            if (DiagnosticsEnabled)
            {
                _logger.Debug("RoutingDiagnostics", $"Resolved original destination for {clientEndpoint} -> {targetHost}:{targetPort}. Opening upstream tunnel.");
            }

            var localStream = localClient.GetStream();

            TcpClient upstream;
            try
            {
                upstream = await _connector!.ConnectAsync(targetHost, targetPort, cancellationToken).ConfigureAwait(false);

                if (DiagnosticsEnabled)
                {
                    // The connector only returns successfully after the
                    // upstream CONNECT/SOCKS5 handshake already reported
                    // success (see HttpConnectUpstreamConnector /
                    // Socks5UpstreamConnector - a non-200/non-success reply
                    // throws before returning). No credentials are logged
                    // here - only host:port and the fact that it succeeded.
                    _logger.Debug("RoutingDiagnostics", $"Upstream tunnel to {targetHost}:{targetPort} established (CONNECT/handshake succeeded).");
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or ProxyAuthenticationException)
            {
                // Fail closed: the upstream proxy tunnel could not be
                // established (auth failure, unreachable, etc.) - close the
                // application's connection rather than ever letting it reach
                // targetHost:targetPort directly.
                _logger.Warning("TransparentForwardingProxy", $"Upstream proxy tunnel failed ({ex.GetType().Name}); closing redirected connection (fail-closed).");
                if (DiagnosticsEnabled)
                {
                    _logger.Debug("RoutingDiagnostics", $"CONNECT/handshake to {targetHost}:{targetPort} FAILED: {DescribeExceptionChain(ex)}");
                }

                return;
            }

            using (upstream)
            {
                if (DiagnosticsEnabled)
                {
                    var (bytesAppToUpstream, bytesUpstreamToApp) = await RelayBidirectionalWithByteCountsAsync(localStream, upstream.GetStream(), cancellationToken).ConfigureAwait(false);
                    _logger.Debug("RoutingDiagnostics", $"Redirected session to {targetHost}:{targetPort} ended. Bytes app->upstream={bytesAppToUpstream}, upstream->app={bytesUpstreamToApp}. (Payload contents and credentials are never logged.)");
                }
                else
                {
                    await UpstreamRelayHelper.RelayBidirectionalAsync(localStream, upstream.GetStream(), cancellationToken).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            _logger.Debug("TransparentForwardingProxy", $"Redirected connection ended: {ex.GetType().Name}.");
        }
        catch (Exception ex)
        {
            _logger.Warning("TransparentForwardingProxy", $"Unexpected error handling redirected connection: {ex.GetType().Name}.");
            if (DiagnosticsEnabled)
            {
                _logger.Debug("RoutingDiagnostics", $"Unexpected error detail: {DescribeExceptionChain(ex)}");
            }
        }
    }

    /// <summary>
    /// Diagnostic-only variant of <see cref="UpstreamRelayHelper.RelayBidirectionalAsync"/>
    /// that additionally counts bytes copied in each direction, WITHOUT ever
    /// logging or returning the actual payload bytes/content. Only used when
    /// <see cref="DiagnosticsEnabled"/> is true.
    /// </summary>
    private static async Task<(long BytesAToB, long BytesBToA)> RelayBidirectionalWithByteCountsAsync(NetworkStream a, NetworkStream b, CancellationToken cancellationToken)
    {
        long bytesAToB = 0;
        long bytesBToA = 0;

        async Task CopyCountingAsync(NetworkStream from, NetworkStream to, Action<long> addBytes)
        {
            var buffer = new byte[81920];
            try
            {
                while (true)
                {
                    var read = await from.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    addBytes(read);
                    await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }
            }
            catch
            {
                // Connection closed by either side - normal end-of-session.
            }
        }

        var t1 = CopyCountingAsync(a, b, n => Interlocked.Add(ref bytesAToB, n));
        var t2 = CopyCountingAsync(b, a, n => Interlocked.Add(ref bytesBToA, n));
        await Task.WhenAny(t1, t2).ConfigureAwait(false);

        return (Interlocked.Read(ref bytesAToB), Interlocked.Read(ref bytesBToA));
    }

    /// <summary>
    /// Renders the full .NET exception chain (this exception plus every
    /// <see cref="Exception.InnerException"/>) as a single diagnostic
    /// string, for the routed-request TLS/connect failure investigation.
    /// Messages are passed through <see cref="SecretScrubber.Scrub"/> (via
    /// the logger's own scrubbing on write) so no credential-shaped text
    /// survives even if a lower layer ever included one by mistake.
    /// </summary>
    internal static string DescribeExceptionChain(Exception ex)
    {
        var parts = new List<string>();
        var current = ex;
        var depth = 0;
        while (current is not null && depth < 10)
        {
            parts.Add($"[{depth}] {current.GetType().FullName}: {current.Message}");
            current = current.InnerException;
            depth++;
        }

        return string.Join(" <-- ", parts);
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
