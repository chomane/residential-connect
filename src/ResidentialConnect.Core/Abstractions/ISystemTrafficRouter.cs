using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// V0.2: Whole-computer TCP traffic routing. When started, ordinary Windows
/// desktop applications' outbound TCP connections (e.g. Telegram Desktop, a
/// normal browser) are transparently redirected through the selected proxy,
/// in addition to (not instead of) the V0.1 <see cref="IBrowserLauncher"/>
/// isolated-browser path.
/// </summary>
/// <remarks>
/// <para>
/// This is functionally what <c>Abstractions.Future.ISystemRoutingProvider</c>
/// was a placeholder for. It is declared as its own, non-Future interface
/// (rather than "graduating" that stub in place) so V0.1's documented
/// "zero Future interfaces implemented" story stays accurate for the V0.1
/// tag/release, while V0.2 adds this new, real contract additively.
/// </para>
/// <para>
/// <b>Requires Administrator elevation on Windows</b> - the underlying
/// packet-interception driver (see the concrete implementation's remarks)
/// can only be opened by a process running elevated. <see cref="IsSupported"/>
/// reflects both "running on Windows" and "running elevated"; the UI must
/// check it before offering Whole Computer mode and explain the requirement
/// if it is not met, rather than silently failing.
/// </para>
/// <para>
/// <b>Fail-closed contract:</b> once <see cref="StartAsync"/> has
/// successfully reached <see cref="SystemRoutingStatus.Active"/>, this
/// component MUST NOT allow any packet matching its interception rules to
/// reach the real network unredirected - not even if the upstream proxy
/// connection fails. On upstream failure, implementations transition to
/// <see cref="SystemRoutingStatus.FailedClosed"/> and continue dropping
/// matching packets until <see cref="StopAsync"/> is called. "Stopping
/// interception" (which would let traffic flow directly/unproxied again) is
/// only ever a result of an explicit, user-initiated DISCONNECT.
/// </para>
/// </remarks>
public interface ISystemTrafficRouter
{
    /// <summary>
    /// True only when running on Windows AND the current process is
    /// elevated (Administrator) AND the underlying driver component is
    /// available on this machine. The UI uses this to enable/disable the
    /// Whole Computer option and to explain why it is unavailable.
    /// </summary>
    bool IsSupported { get; }

    /// <summary>Always true for this implementation - documented up front so the UI can explain the requirement rather than the user discovering a mysterious failure.</summary>
    bool RequiresElevation { get; }

    SystemRoutingStatus Status { get; }

    event EventHandler<SystemRoutingStatus>? StatusChanged;

    /// <summary>
    /// Starts intercepting and redirecting matching outbound TCP traffic
    /// through <paramref name="profile"/>. Returns the reached status -
    /// <see cref="SystemRoutingStatus.Active"/> on success, or
    /// <see cref="SystemRoutingStatus.Unavailable"/> if the router could not
    /// be started at all (in which case nothing was intercepted and normal
    /// networking was never touched).
    /// </summary>
    Task<SystemRoutingStatus> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops interception and restores normal Windows networking. This is
    /// the ONLY path by which traffic is ever allowed to flow direct/unproxied
    /// again after <see cref="StartAsync"/> has succeeded - see the
    /// fail-closed contract above.
    /// </summary>
    Task StopAsync(CancellationToken cancellationToken = default);
}
