using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Launches a browser instance whose traffic is routed through a given
/// proxy, using an isolated, application-controlled profile directory so the
/// user's normal Chrome/Edge profile is never touched.
/// </summary>
/// <remarks>
/// V0.1 implements this against whatever Chromium-based browser is already
/// installed on the machine (Chrome or Edge) - see
/// <c>ResidentialConnect.Browser.InstalledChromiumBrowserLauncher</c>. The
/// interface is deliberately provider-agnostic so a future release can ship
/// and manage its own bundled Chromium build (see
/// <c>ResidentialConnect.Browser.IBrowserProvider</c>) as a drop-in
/// replacement, with zero changes required in Core or the UI.
/// </remarks>
public interface IBrowserLauncher
{
    /// <summary>True if a supported browser was found and this launcher can be used.</summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Terminates managed browser trees and stops their relays. Cancellation
    /// only applies before cleanup starts; owned sessions are always cleaned up.
    /// </summary>
    Task DisconnectAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Launches the browser configured to use <paramref name="profile"/> for
    /// all traffic, with proxy authentication handled automatically (no
    /// credential prompt), and optionally navigates to <paramref name="startUrl"/>.
    /// </summary>
    Task<BrowserLaunchResult> LaunchAsync(
        ProxyProfile profile,
        string? startUrl = null,
        CancellationToken cancellationToken = default);
}

/// <summary>Outcome of a browser launch attempt.</summary>
public sealed class BrowserLaunchResult
{
    public bool Success { get; init; }
    public int? ProcessId { get; init; }
    public string? Message { get; init; }

    public static BrowserLaunchResult Successful(int processId) => new() { Success = true, ProcessId = processId };
    public static BrowserLaunchResult Failed(string message) => new() { Success = false, Message = message };
}
