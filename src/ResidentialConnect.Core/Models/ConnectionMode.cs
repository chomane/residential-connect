namespace ResidentialConnect.Core.Models;

/// <summary>
/// User-selectable scope of what gets routed through the selected proxy.
/// </summary>
public enum ConnectionMode
{
    /// <summary>
    /// V0.1 behavior, unchanged: only the isolated browser instance launched
    /// via OPEN BROWSER (<see cref="Abstractions.IBrowserLauncher"/>) is
    /// routed through the proxy. Nothing else on the machine is affected.
    /// Requires no elevation/administrator rights.
    /// </summary>
    BrowserOnly = 0,

    /// <summary>
    /// V0.2: routes ordinary Windows desktop applications' TCP traffic
    /// (e.g. Telegram Desktop, the user's normal browser) through the
    /// selected proxy as well, via <see cref="Abstractions.ISystemTrafficRouter"/>.
    /// Requires the app to run elevated (Administrator) - see
    /// <see cref="Abstractions.ISystemTrafficRouter.RequiresElevation"/>.
    /// </summary>
    WholeComputer = 1
}
