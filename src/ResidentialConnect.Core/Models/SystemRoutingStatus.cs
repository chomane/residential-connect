namespace ResidentialConnect.Core.Models;

/// <summary>
/// Lifecycle state of the whole-computer traffic router
/// (<see cref="Abstractions.ISystemTrafficRouter"/>). Mirrors, but is
/// intentionally distinct from, <see cref="ConnectionStatus"/> - the two are
/// combined by <see cref="ConnectionState"/> only when
/// <see cref="ConnectionState.Mode"/> is <see cref="ConnectionMode.WholeComputer"/>.
/// </summary>
public enum SystemRoutingStatus
{
    /// <summary>No interception is active; the machine's normal networking is untouched.</summary>
    Disabled = 0,

    /// <summary>Interception is being set up (filter installed, relay starting, bypass rules pinned).</summary>
    Starting = 1,

    /// <summary>Interception is active: matching TCP traffic is being redirected through the proxy.</summary>
    Active = 2,

    /// <summary>Interception is being torn down and normal networking is being restored.</summary>
    Stopping = 3,

    /// <summary>
    /// Interception was active but the upstream proxy/relay path failed.
    /// Per the fail-closed requirement, packets that would have been
    /// redirected are DROPPED (never silently allowed to go direct) while in
    /// this state, until the user disconnects or the path recovers.
    /// </summary>
    FailedClosed = 4,

    /// <summary>
    /// The router could not be started at all (missing elevation, driver
    /// unavailable, unsupported OS, etc.) - Whole Computer mode was never
    /// armed, so nothing was intercepted and the machine's normal networking
    /// was never touched.
    /// </summary>
    Unavailable = 5
}
