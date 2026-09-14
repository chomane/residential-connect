using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Proxy;

/// <summary>
/// Default <see cref="IConnectionManager"/>. "Connecting" always means: run a
/// full <see cref="IProxyConnectivityTester"/> pass against the selected
/// profile first (exactly V0.1's behavior, unconditionally - so Whole
/// Computer mode gets exactly the same credential/reachability proof Browser
/// Only mode already relies on) and, only if that succeeds, additionally
/// start <see cref="ISystemTrafficRouter"/> when <see cref="ConnectionMode.WholeComputer"/>
/// was requested. <see cref="ConnectionMode.BrowserOnly"/> (the default)
/// never touches <see cref="ISystemTrafficRouter"/> at all - it is
/// byte-for-byte the same code path V0.1 shipped with.
/// </summary>
public sealed class DefaultConnectionManager : IConnectionManager
{
    private readonly IProxyConnectivityTester _tester;
    private readonly ICredentialStore _credentialStore;
    private readonly ISystemTrafficRouter? _trafficRouter;
    private readonly IAppLogger _logger;
    private readonly object _lock = new();

    private ConnectionState _currentState = ConnectionState.Idle;

    /// <summary>
    /// <paramref name="trafficRouter"/> is optional specifically so
    /// Browser-Only-only deployments/tests never need to construct a real
    /// (Windows-only, elevation-requiring) router at all - passing null means
    /// Whole Computer mode simply reports <see cref="SystemRoutingStatus.Unavailable"/>
    /// if ever requested. <paramref name="credentialStore"/> is needed only
    /// for the Whole Computer path, to resolve the plaintext password
    /// <see cref="ISystemTrafficRouter.StartAsync"/> needs to build the
    /// upstream HTTP CONNECT/SOCKS5 tunnel - exactly the same store and the
    /// same <see cref="ProxyProfile.CredentialRef"/> lookup
    /// <see cref="HttpProxyConnectivityTester"/> already uses for the
    /// connectivity test above, kept only in memory for the duration of this
    /// call, never logged.
    /// </summary>
    public DefaultConnectionManager(
        IProxyConnectivityTester tester,
        ICredentialStore credentialStore,
        IAppLogger logger,
        ISystemTrafficRouter? trafficRouter = null)
    {
        _tester = tester ?? throw new ArgumentNullException(nameof(tester));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _trafficRouter = trafficRouter;
    }

    public event EventHandler<ConnectionState>? StateChanged;

    public ConnectionState CurrentState
    {
        get { lock (_lock) { return _currentState; } }
    }

    public async Task<ConnectionState> ConnectAsync(ProxyProfile profile, ConnectionMode mode = ConnectionMode.BrowserOnly, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        SetState(new ConnectionState
        {
            Status = ConnectionStatus.Connecting,
            ActiveProxy = profile,
            Mode = mode,
            StatusMessage = mode == ConnectionMode.WholeComputer ? "Connecting (Whole Computer)..." : "Connecting..."
        });

        _logger.Info("ConnectionManager", $"CONNECT requested for '{profile.Name}' (mode={mode}).");

        var result = await _tester.TestAsync(profile, cancellationToken).ConfigureAwait(false);

        if (!result.Success)
        {
            var failedState = new ConnectionState
            {
                Status = ConnectionStatus.Error,
                ActiveProxy = profile,
                Mode = mode,
                StatusMessage = result.Message ?? "Connection failed."
            };
            _logger.Warning("ConnectionManager", $"Connect failed for '{profile.Name}': {result.FailureReason} - {result.Message}");
            SetState(failedState);
            return failedState;
        }

        _logger.Info("ConnectionManager", $"Proxy connectivity verified for '{profile.Name}'. Latency={result.Latency?.TotalMilliseconds:0}ms.");

        if (mode != ConnectionMode.WholeComputer)
        {
            var connectedState = new ConnectionState
            {
                Status = ConnectionStatus.Connected,
                ActiveProxy = profile,
                Mode = ConnectionMode.BrowserOnly,
                RoutingStatus = SystemRoutingStatus.Disabled,
                PublicIp = result.ObservedPublicIp,
                Latency = result.Latency,
                StatusMessage = "Connected"
            };
            SetState(connectedState);
            return connectedState;
        }

        // Whole Computer requested: connectivity is proven, now arm
        // whole-computer routing. If this fails for any reason, the CONNECT
        // attempt as a whole is reported as failed - Whole Computer mode
        // never "partially" succeeds by silently falling back to Browser
        // Only (that would defeat the fail-closed contract at the UX level).
        if (_trafficRouter is null)
        {
            var noRouterState = new ConnectionState
            {
                Status = ConnectionStatus.Error,
                ActiveProxy = profile,
                Mode = ConnectionMode.WholeComputer,
                RoutingStatus = SystemRoutingStatus.Unavailable,
                StatusMessage = "Whole Computer mode is not available on this build/platform."
            };
            _logger.Warning("ConnectionManager", "Whole Computer requested but no ISystemTrafficRouter was configured.");
            SetState(noRouterState);
            return noRouterState;
        }

        if (!_trafficRouter.IsSupported)
        {
            var unsupportedState = new ConnectionState
            {
                Status = ConnectionStatus.Error,
                ActiveProxy = profile,
                Mode = ConnectionMode.WholeComputer,
                RoutingStatus = SystemRoutingStatus.Unavailable,
                StatusMessage = "Whole Computer mode requires running Residential Connect as Administrator on Windows."
            };
            _logger.Warning("ConnectionManager", "Whole Computer requested but ISystemTrafficRouter.IsSupported is false (not elevated / not Windows).");
            SetState(unsupportedState);
            return unsupportedState;
        }

        var password = _credentialStore.Retrieve(profile.CredentialRef);
        if (string.IsNullOrEmpty(password))
        {
            // Should not happen - the connectivity test above already
            // required a stored password to succeed - but fail closed
            // explicitly rather than ever calling StartAsync with an empty
            // credential.
            var noPasswordState = new ConnectionState
            {
                Status = ConnectionStatus.Error,
                ActiveProxy = profile,
                Mode = ConnectionMode.WholeComputer,
                RoutingStatus = SystemRoutingStatus.Unavailable,
                StatusMessage = "No stored password found for this proxy."
            };
            _logger.Warning("ConnectionManager", $"Whole Computer requested for '{profile.Name}' but no stored credential was found.");
            SetState(noPasswordState);
            return noPasswordState;
        }

        // Subscribe once per CONNECT so a later, asynchronous fail-closed
        // transition (the upstream tunnel/relay faulting while already
        // Active) is reflected into ConnectionState/StateChanged for the UI,
        // without the UI needing to know ISystemTrafficRouter exists at all.
        _trafficRouter.StatusChanged += OnRoutingStatusChanged;

        SystemRoutingStatus routingStatus;
        try
        {
            routingStatus = await _trafficRouter.StartAsync(profile, password, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error("ConnectionManager", "ISystemTrafficRouter.StartAsync threw unexpectedly - treating as Unavailable (fail-closed).", ex);
            routingStatus = SystemRoutingStatus.Unavailable;
        }

        if (routingStatus != SystemRoutingStatus.Active)
        {
            _trafficRouter.StatusChanged -= OnRoutingStatusChanged;
            var failedRoutingState = new ConnectionState
            {
                Status = ConnectionStatus.Error,
                ActiveProxy = profile,
                Mode = ConnectionMode.WholeComputer,
                RoutingStatus = routingStatus,
                StatusMessage = "Could not start Whole Computer routing. Normal Windows networking was left untouched."
            };
            _logger.Warning("ConnectionManager", $"Whole Computer routing failed to start (status={routingStatus}) for '{profile.Name}'.");
            SetState(failedRoutingState);
            return failedRoutingState;
        }

        var activeState = new ConnectionState
        {
            Status = ConnectionStatus.Connected,
            ActiveProxy = profile,
            Mode = ConnectionMode.WholeComputer,
            RoutingStatus = SystemRoutingStatus.Active,
            PublicIp = result.ObservedPublicIp,
            Latency = result.Latency,
            StatusMessage = "Connected (Whole Computer)"
        };
        _logger.Info("ConnectionManager", $"Whole Computer routing active for '{profile.Name}'.");
        SetState(activeState);
        return activeState;
    }

    public async Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        _logger.Info("ConnectionManager", "DISCONNECT requested.");

        var wasWholeComputer = CurrentState.Mode == ConnectionMode.WholeComputer;

        if (_trafficRouter is not null && wasWholeComputer)
        {
            _trafficRouter.StatusChanged -= OnRoutingStatusChanged;
            try
            {
                await _trafficRouter.StopAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.Error("ConnectionManager", "Error stopping whole-computer routing during DISCONNECT.", ex);
            }
        }

        SetState(ConnectionState.Idle);
    }

    private void OnRoutingStatusChanged(object? sender, SystemRoutingStatus status)
    {
        // Reflects an asynchronous routing-status transition (in particular
        // FailedClosed, if the relay/upstream tunnel dies while Whole
        // Computer mode is already Active) into the UI-facing ConnectionState
        // without changing Status away from Connected - the fail-closed
        // packet drop is already happening at the routing layer; this just
        // makes it visible.
        lock (_lock)
        {
            if (_currentState.Mode != ConnectionMode.WholeComputer)
            {
                return;
            }

            var updated = new ConnectionState
            {
                Status = status == SystemRoutingStatus.FailedClosed ? ConnectionStatus.Error : _currentState.Status,
                ActiveProxy = _currentState.ActiveProxy,
                Mode = _currentState.Mode,
                RoutingStatus = status,
                PublicIp = _currentState.PublicIp,
                Latency = _currentState.Latency,
                StatusMessage = status == SystemRoutingStatus.FailedClosed
                    ? "Whole Computer routing failed - traffic is being blocked (fail-closed), not sent unprotected. Disconnect and retry."
                    : _currentState.StatusMessage
            };
            _currentState = updated;
            StateChanged?.Invoke(this, updated);
        }
    }

    private void SetState(ConnectionState state)
    {
        lock (_lock)
        {
            _currentState = state;
        }

        StateChanged?.Invoke(this, state);
    }
}
