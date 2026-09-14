using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Orchestrates the "CONNECT" / "DISCONNECT" lifecycle shown on the main
/// screen. In V0.1 "connect" means: validate the proxy, authenticate, and
/// prove connectivity via a real HTTPS request - it does NOT touch the
/// Windows system proxy or route whole-machine traffic. Later versions can
/// extend this interface (or add sibling interfaces, see
/// <see cref="ISystemRoutingProvider"/> and <see cref="IKillSwitch"/>) without
/// breaking V0.1 behavior.
/// </summary>
public interface IConnectionManager
{
    /// <summary>Raised whenever <see cref="CurrentState"/> changes, for UI data-binding.</summary>
    event EventHandler<ConnectionState>? StateChanged;

    ConnectionState CurrentState { get; }

    Task<ConnectionState> ConnectAsync(ProxyProfile profile, CancellationToken cancellationToken = default);

    Task DisconnectAsync(CancellationToken cancellationToken = default);
}
