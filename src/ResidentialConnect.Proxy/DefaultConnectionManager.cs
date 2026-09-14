using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Proxy;

/// <summary>
/// Default <see cref="IConnectionManager"/> for V0.1. "Connecting" means:
/// run a full <see cref="IProxyConnectivityTester"/> pass against the
/// selected profile and, if it succeeds, remember it as the active
/// connection for the UI/OPEN BROWSER flow to reference. This implementation
/// deliberately does NOT touch the Windows system proxy or route
/// whole-machine traffic - see
/// <see cref="Core.Abstractions.Future.ISystemRoutingProvider"/> for where
/// that would plug in for a future release.
/// </summary>
public sealed class DefaultConnectionManager : IConnectionManager
{
    private readonly IProxyConnectivityTester _tester;
    private readonly IAppLogger _logger;
    private readonly object _lock = new();

    private ConnectionState _currentState = ConnectionState.Idle;

    public DefaultConnectionManager(IProxyConnectivityTester tester, IAppLogger logger)
    {
        _tester = tester ?? throw new ArgumentNullException(nameof(tester));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public event EventHandler<ConnectionState>? StateChanged;

    public ConnectionState CurrentState
    {
        get { lock (_lock) { return _currentState; } }
    }

    public async Task<ConnectionState> ConnectAsync(ProxyProfile profile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        SetState(new ConnectionState
        {
            Status = ConnectionStatus.Connecting,
            ActiveProxy = profile,
            StatusMessage = "Connecting..."
        });

        _logger.Info("ConnectionManager", $"CONNECT requested for '{profile.Name}'.");

        var result = await _tester.TestAsync(profile, cancellationToken).ConfigureAwait(false);

        ConnectionState newState;
        if (result.Success)
        {
            newState = new ConnectionState
            {
                Status = ConnectionStatus.Connected,
                ActiveProxy = profile,
                PublicIp = result.ObservedPublicIp,
                Latency = result.Latency,
                StatusMessage = "Connected"
            };
            _logger.Info("ConnectionManager", $"Connected via '{profile.Name}'. Latency={result.Latency?.TotalMilliseconds:0}ms.");
        }
        else
        {
            newState = new ConnectionState
            {
                Status = ConnectionStatus.Error,
                ActiveProxy = profile,
                StatusMessage = result.Message ?? "Connection failed."
            };
            _logger.Warning("ConnectionManager", $"Connect failed for '{profile.Name}': {result.FailureReason} - {result.Message}");
        }

        SetState(newState);
        return newState;
    }

    public Task DisconnectAsync(CancellationToken cancellationToken = default)
    {
        _logger.Info("ConnectionManager", "DISCONNECT requested.");
        SetState(ConnectionState.Idle);
        return Task.CompletedTask;
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
