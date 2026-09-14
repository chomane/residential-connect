namespace ResidentialConnect.Core.Abstractions.Future;

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// Placeholder for future user accounts and subscription billing
/// integration. V0.1 is a fully local, single-user application with no
/// backend, no accounts, and no billing.
/// </summary>
public interface IAccountService
{
    Task<bool> IsAuthenticatedAsync(CancellationToken cancellationToken = default);

    Task<bool> HasActiveSubscriptionAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
///
/// Placeholder for a remote configuration / feature-flag service and
/// automatic application updates.
/// </summary>
public interface IRemoteConfigService
{
    Task<string?> GetValueAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
/// Placeholder for automatic application update checks/installation.
/// </summary>
public interface IUpdateService
{
    Task<bool> IsUpdateAvailableAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// PLANNED FOR A FUTURE RELEASE - NOT IMPLEMENTED IN V0.1.
/// Placeholder for a standalone, server-hosted "Cloud Browser" product
/// (distinct from the local OPEN BROWSER feature in V0.1).
/// </summary>
public interface ICloudBrowserService
{
    Task<Uri> StartSessionAsync(CancellationToken cancellationToken = default);
}
