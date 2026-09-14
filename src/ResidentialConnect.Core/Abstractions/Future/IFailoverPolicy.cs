using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions.Future;

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// Decides whether/when to automatically switch to a replacement proxy after
/// the active one fails a health check, and (later) to request a brand-new
/// IP from the provider via <see cref="IProxyProvisioningService"/>.
/// </summary>
public interface IFailoverPolicy
{
    /// <summary>Given the current profile and its last failed test, choose a replacement, if any.</summary>
    ProxyProfile? SelectReplacement(ProxyProfile failedProfile, IReadOnlyList<ProxyProfile> candidates, ProxyTestResult lastFailure);
}
