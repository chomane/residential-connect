using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions.Future;

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// Routes only specific applications (by executable path) through a proxy,
/// as opposed to whole-computer routing (<see cref="ISystemRoutingProvider"/>)
/// or the single dedicated browser instance handled by
/// <see cref="IBrowserLauncher"/>.
/// </summary>
public interface IPerApplicationRoutingProvider
{
    Task AddApplicationAsync(string executablePath, ProxyProfile profile, CancellationToken cancellationToken = default);

    Task RemoveApplicationAsync(string executablePath, CancellationToken cancellationToken = default);

    IReadOnlyList<string> GetRoutedApplications();
}
