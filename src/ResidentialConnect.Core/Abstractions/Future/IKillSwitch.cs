namespace ResidentialConnect.Core.Abstractions.Future;

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// When armed, blocks direct (non-proxied) traffic if the active proxy
/// connection drops unexpectedly, preventing IP leaks. Requires whole-computer
/// or per-application routing (see <see cref="ISystemRoutingProvider"/> /
/// <see cref="IPerApplicationRoutingProvider"/>) to be meaningful, so it is
/// modeled as its own interface rather than a flag on <c>IConnectionManager</c>.
/// </summary>
public interface IKillSwitch
{
    bool IsArmed { get; }

    void Arm();

    void Disarm();

    event EventHandler? TrafficBlocked;
}
