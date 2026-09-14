namespace ResidentialConnect.Browser;

/// <summary>
/// Abstraction over "which Chromium executable do we launch". V0.1 ships
/// <see cref="InstalledBrowserProvider"/>, which locates an already-installed
/// Chrome or Edge on the machine - a deliberate, documented shortcut for
/// V0.1 only. A future release can add a provider that manages/ships its own
/// bundled Chromium build and register it here with zero changes required in
/// <see cref="ChromiumBrowserLauncher"/> or the UI layer.
/// </summary>
public interface IBrowserProvider
{
    /// <summary>Returns the full path to a usable Chromium-based browser executable, or null if none was found.</summary>
    string? FindExecutable();

    string ProviderName { get; }
}
