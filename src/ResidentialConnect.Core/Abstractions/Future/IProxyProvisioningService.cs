using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions.Future;

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// Integrates with the Webshare (or another provider's) management API to
/// list, purchase, and automatically replace/rotate proxies, removing the
/// need for the user to manually add/import proxy CSVs. V0.1 only supports
/// manual entry and CSV import via <c>IProxyRepository</c> /
/// <c>ProxyCsvImporter</c>.
/// </summary>
public interface IProxyProvisioningService
{
    Task<IReadOnlyList<ProxyProfile>> ListAvailableAsync(CancellationToken cancellationToken = default);

    Task<ProxyProfile> ProvisionAsync(string countryCode, CancellationToken cancellationToken = default);

    Task ReplaceAsync(Guid existingProfileId, CancellationToken cancellationToken = default);
}
