using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions.Future;

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// Represents whole-computer traffic routing through the active proxy
/// (e.g. by installing a WinDivert/TUN-based driver or configuring the
/// Windows system proxy + a local SOCKS-to-TUN bridge). Declaring the
/// interface now lets <c>IConnectionManager</c> and the UI reference a
/// stable contract later without a breaking change, while V0.1 ships zero
/// implementations of it.
/// </summary>
public interface ISystemRoutingProvider
{
    bool IsSupported { get; }

    Task EnableAsync(ProxyProfile profile, CancellationToken cancellationToken = default);

    Task DisableAsync(CancellationToken cancellationToken = default);
}
