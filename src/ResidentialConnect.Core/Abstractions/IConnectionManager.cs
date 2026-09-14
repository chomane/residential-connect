using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Orchestrates the "CONNECT" / "DISCONNECT" lifecycle shown on the main
/// screen. In V0.1 "connect" means: validate the proxy, authenticate, and
/// prove connectivity via a real HTTPS request - it does NOT touch the
/// Windows system proxy or route whole-machine traffic.
/// </summary>
/// <remarks>
/// V0.2 adds <see cref="ConnectionMode"/> as an ADDITIVE parameter with a
/// default of <see cref="ConnectionMode.BrowserOnly"/> - existing callers
/// that only ever called the old two-argument overload continue to get
/// EXACTLY V0.1 behavior (proxy connectivity test only, no system routing
/// touched at all). Passing <see cref="ConnectionMode.WholeComputer"/>
/// additionally starts <see cref="ISystemTrafficRouter"/> - see
/// <see cref="Proxy.DefaultConnectionManager"/> for the orchestration and
/// its fail-closed handling of routing failures after CONNECT succeeded.
/// </remarks>
public interface IConnectionManager
{
    /// <summary>Raised whenever <see cref="CurrentState"/> changes, for UI data-binding.</summary>
    event EventHandler<ConnectionState>? StateChanged;

    ConnectionState CurrentState { get; }

    /// <summary>
    /// Connects using <paramref name="mode"/> (defaults to
    /// <see cref="ConnectionMode.BrowserOnly"/> - V0.1 behavior, unchanged).
    /// When <paramref name="mode"/> is <see cref="ConnectionMode.WholeComputer"/>,
    /// the connectivity test is run first (exactly as in Browser Only mode)
    /// and, only if it succeeds, whole-computer routing is additionally
    /// started - if routing itself cannot be started, the returned/broadcast
    /// state reflects <see cref="ConnectionStatus.Error"/> with
    /// <see cref="ConnectionState.RoutingStatus"/> set to
    /// <see cref="SystemRoutingStatus.Unavailable"/>, and normal (proxied
    /// browser-only) connectivity is torn back down too - Whole Computer mode
    /// never "partially" succeeds.
    /// </summary>
    Task<ConnectionState> ConnectAsync(ProxyProfile profile, ConnectionMode mode = ConnectionMode.BrowserOnly, CancellationToken cancellationToken = default);

    Task DisconnectAsync(CancellationToken cancellationToken = default);
}
