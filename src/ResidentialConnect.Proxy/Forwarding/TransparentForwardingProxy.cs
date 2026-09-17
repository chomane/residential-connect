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
        IPAddress pinnedProxyAddress,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(bindAddress);
        ArgumentNullException.ThrowIfNull(destinationResolver);
        ArgumentNullException.ThrowIfNull(pinnedProxyAddress);

        // Dial the pinned IPv4 LITERAL, never profile.Host, for the proxy
        // hop itself - see ITransparentForwardingProxy.StartAsync's
        // pinnedProxyAddress remarks for why a second, independent DNS
        // resolution here could silently diverge from the address the
        // WinDivert forward filter's own self-exclusion clause excludes,
        // reopening the exact self-interception loop that clause exists to
        // prevent.
        var pinnedProxyHost = pinnedProxyAddress.ToString();
        _connector = profile.Protocol switch
        {
            ProxyProtocol.Http => new HttpConnectUpstreamConnector(pinnedProxyHost, profile.Port, profile.Username, password, _logger),
            ProxyProtocol.Socks5 => new Socks5UpstreamConnector(pinnedProxyHost, profile.Port, profile.Username, password),
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
                _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] TransparentForwardingProxy accepted a redirected TCP connection from apparent peer {clientEndpoint}.");
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
                _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] Resolved original destination for {clientEndpoint} -> {targetHost}:{targetPort}. Opening upstream tunnel.");
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
                    _logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] Upstream tunnel to {targetHost}:{targetPort} established (CONNECT/handshake succeeded).");
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
                    var sessionLabel = $"[SESSION {clientEndpoint} -> {targetHost}:{targetPort}]";
                    var outcome = await RelayBidirectionalWithDiagnosticsAsync(localStream, upstream.GetStream(), _logger, sessionLabel, cancellationToken).ConfigureAwait(false);
                    _logger.Debug(
                        "RoutingDiagnostics",
                        $"[t={DiagnosticClock.ElapsedMs}ms] Redirected session to {targetHost}:{targetPort} ended. " +
                        $"First-completed direction=\"{outcome.FirstCompletedDirection}\" ({outcome.FirstCompletedReason}). " +
                        $"Bytes app->upstream={outcome.BytesAppToUpstream}, upstream->app={outcome.BytesUpstreamToApp}. " +
                        "(Payload contents and credentials are never logged.)");
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
    /// Outcome of one diagnostic-instrumented bidirectional relay session -
    /// see <see cref="RelayBidirectionalWithDiagnosticsAsync"/>. Deliberately
    /// contains only byte COUNTS and completion metadata, never payload
    /// bytes or credentials.
    /// </summary>
    private readonly record struct RelayOutcome(
        long BytesAppToUpstream,
        long BytesUpstreamToApp,
        string FirstCompletedDirection,
        string FirstCompletedReason);

    /// <summary>
    /// Diagnostic-only variant of <see cref="UpstreamRelayHelper.RelayBidirectionalAsync"/>,
    /// added 2026-09-16 to investigate the "upstream CONNECT returned 200,
    /// but the redirected session immediately ended with zero bytes in both
    /// directions" symptom (see this class's own diagnostic log line right
    /// after this method's call site, and <c>UpstreamRelayHelper</c>'s
    /// remarks on the underlying <c>Task.WhenAny</c> pattern this method
    /// shares with production). Only used when <see cref="DiagnosticsEnabled"/>
    /// is true; the non-diagnostic path (<see cref="UpstreamRelayHelper.RelayBidirectionalAsync"/>)
    /// is completely unchanged and used as-is when diagnostics are off.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Logs, for EACH direction independently: the moment its pump starts,
    /// its first <c>ReadAsync</c> result (including explicitly flagging an
    /// immediate EOF - <c>ReadAsync</c> returning 0 on the very first call),
    /// every EOF observed, its first successful <c>WriteAsync</c> byte
    /// count, and the exact exception type/message (never the payload) if
    /// the pump ends via an exception rather than a clean EOF. It then logs
    /// which of the two directions' pumps completed FIRST and why (EOF /
    /// cancelled / exception) - this is the exact question needed to
    /// determine whether the client ever sent ANY post-handshake bytes at
    /// all (a WinDivert established-flow-reflection problem) versus the
    /// upstream tunnel closing first (an upstream/proxy-side problem).
    /// </para>
    /// <para>
    /// <b>Never logs payload contents or credentials</b> - only byte counts,
    /// direction labels, exception types/messages, and timestamps.
    /// </para>
    /// </remarks>
    private static async Task<RelayOutcome> RelayBidirectionalWithDiagnosticsAsync(
        NetworkStream appStream,
        NetworkStream upstreamStream,
        IAppLogger logger,
        string sessionLabel,
        CancellationToken cancellationToken)
    {
        long bytesAppToUpstream = 0;
        long bytesUpstreamToApp = 0;

        async Task<string> PumpAsync(string directionLabel, NetworkStream from, NetworkStream to, Action<long> addBytes)
        {
            logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} [{directionLabel}] pump starting.");

            var buffer = new byte[81920];
            var firstReadLogged = false;
            long cumulative = 0;

            try
            {
                while (true)
                {
                    var read = await from.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);

                    if (!firstReadLogged)
                    {
                        firstReadLogged = true;
                        logger.Debug(
                            "RoutingDiagnostics",
                            $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} [{directionLabel}] first ReadAsync returned {read} byte(s)" +
                            (read == 0 ? " - IMMEDIATE EOF (no data was ever read on this direction)." : "."));
                    }

                    if (read == 0)
                    {
                        logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} [{directionLabel}] EOF (ReadAsync returned 0). Cumulative bytes this direction={cumulative}.");
                        return $"EOF, cumulative={cumulative}";
                    }

                    addBytes(read);
                    var isFirstWrite = cumulative == 0;
                    cumulative += read;

                    await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);

                    if (isFirstWrite)
                    {
                        logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} [{directionLabel}] first WriteAsync wrote {read} byte(s) onward.");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} [{directionLabel}] CANCELLED. Cumulative bytes this direction={cumulative}.");
                return $"cancelled, cumulative={cumulative}";
            }
            catch (Exception ex)
            {
                logger.Debug("RoutingDiagnostics", $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} [{directionLabel}] ended via {ex.GetType().Name} (\"{ex.Message}\"). Cumulative bytes this direction={cumulative}.");
                return $"{ex.GetType().Name}, cumulative={cumulative}";
            }
        }

        // NOTE: this Task.WhenAny pattern is shared with production's
        // UpstreamRelayHelper.RelayBidirectionalAsync - see that class's
        // remarks for the full analysis of what it actually does (it
        // returns control to the caller - which then disposes BOTH streams
        // - the instant the FIRST of the two directions completes, whether
        // by clean EOF, cancellation, or exception; the other, still-running
        // direction's pump is not awaited or given any grace period here -
        // it gets torn down by the caller's stream disposal shortly after
        // this method returns).
        var appToUpstreamTask = PumpAsync("app->upstream", appStream, upstreamStream, n => Interlocked.Add(ref bytesAppToUpstream, n));
        var upstreamToAppTask = PumpAsync("upstream->app", upstreamStream, appStream, n => Interlocked.Add(ref bytesUpstreamToApp, n));

        var firstCompletedTask = await Task.WhenAny(appToUpstreamTask, upstreamToAppTask).ConfigureAwait(false);
        var firstCompletedReason = await firstCompletedTask.ConfigureAwait(false);
        var firstCompletedDirection = firstCompletedTask == appToUpstreamTask ? "app->upstream" : "upstream->app";

        logger.Debug(
            "RoutingDiagnostics",
            $"[t={DiagnosticClock.ElapsedMs}ms] {sessionLabel} direction \"{firstCompletedDirection}\" completed FIRST ({firstCompletedReason}). " +
            "Per the Task.WhenAny relay pattern (see UpstreamRelayHelper remarks), the redirected session is now torn down " +
            "by the caller even if the OTHER direction's pump was still running.");

        return new RelayOutcome(
            Interlocked.Read(ref bytesAppToUpstream),
            Interlocked.Read(ref bytesUpstreamToApp),
            firstCompletedDirection,
            firstCompletedReason);
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
