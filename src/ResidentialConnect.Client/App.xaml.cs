using System.IO;
using System.Windows;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Browser;
using ResidentialConnect.Proxy;
using ResidentialConnect.Proxy.Dns;
using ResidentialConnect.Proxy.Forwarding;
using ResidentialConnect.Proxy.IpEcho;
using ResidentialConnect.Proxy.Repository;
using ResidentialConnect.Routing;
using ResidentialConnect.Security.DataProtection;
using ResidentialConnect.Security.Storage;
using ResidentialConnect.Client.Services;

namespace ResidentialConnect.Client;

/// <summary>
/// Composition root: wires up all Core/Security/Proxy/Browser/Routing
/// implementations by hand (no DI container needed for an app this size)
/// and exposes them via the static <see cref="Services"/> holder so windows
/// created outside the constructor chain (dialogs) can resolve them too.
/// </summary>
public partial class App : Application
{
    public static AppServices Services { get; private set; } = null!;

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            // All cleanup awaits are context-free, so normal WPF shutdown can
            // wait for owned browsers and relays before terminating the app.
            Services?.BrowserLauncher.DisconnectAllAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            Services?.Logger.Error("BrowserLauncher", "Best-effort browser cleanup on exit failed.", ex);
        }
        finally
        {
            base.OnExit(e);
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AppPaths.EnsureDirectoriesExist();

        var logger = new SimpleFileLogger(Path.Combine(AppPaths.LogsDirectory, $"app-{DateTime.Now:yyyyMMdd}.log"));
        var protector = new DpapiDataProtector();
        var credentialStore = new FileCredentialStore(AppPaths.CredentialsDirectory, protector);
        var repository = new JsonProxyRepository(AppPaths.ProxiesFilePath, credentialStore, logger);
        var ipEcho = new IpifyEchoService();
        var tester = new HttpProxyConnectivityTester(credentialStore, ipEcho, logger);

        // V0.2: crash/force-close recovery check, run once at startup before
        // anything else touches routing state - see RoutingStateMarker
        // remarks for exactly what this does (and does not) need to repair.
        var routingStateMarker = new RoutingStateMarker(
            Path.Combine(AppPaths.RootDirectory, "whole-computer-routing.marker"),
            logger);
        routingStateMarker.RecoverFromPreviousSession();

        // ISystemTrafficRouter is only ever actually usable on Windows (it
        // requires the WinDivert native driver and Administrator elevation -
        // see WinDivertSystemTrafficRouter remarks). Constructing it here has
        // no side effects (no driver/handle is touched until StartAsync is
        // called), so it is safe to always construct on Windows and simply
        // never call it from DefaultConnectionManager when BrowserOnly is
        // selected.
        ISystemTrafficRouter? trafficRouter = OperatingSystem.IsWindows()
            ? new WinDivertSystemTrafficRouter(
                logger,
                () => new TransparentForwardingProxy(logger),
                routingStateMarker,
                () => new ProxiedDohResolver(logger))
            : null;

        var connectionManager = new DefaultConnectionManager(tester, credentialStore, logger, trafficRouter);
        var browserProvider = new InstalledBrowserProvider();
        var browserLauncher = new ChromiumBrowserLauncher(browserProvider, credentialStore, () => new LocalForwardingProxy(logger), logger);

        Services = new AppServices(logger, credentialStore, repository, tester, connectionManager, browserLauncher, trafficRouter);

        var mainWindow = new MainWindow(repository, connectionManager, browserLauncher, trafficRouter);
        mainWindow.Show();
    }
}

/// <summary>Bag of singleton services resolved from the composition root in <see cref="App"/>.</summary>
public sealed class AppServices
{
    public IAppLogger Logger { get; }
    public ICredentialStore CredentialStore { get; }
    public IProxyRepository Repository { get; }
    public IProxyConnectivityTester ConnectivityTester { get; }
    public IConnectionManager ConnectionManager { get; }
    public IBrowserLauncher BrowserLauncher { get; }

    /// <summary>Null on non-Windows builds; see <see cref="ISystemTrafficRouter.IsSupported"/> for the elevation/Windows check the UI must use before offering Whole Computer mode.</summary>
    public ISystemTrafficRouter? TrafficRouter { get; }

    public AppServices(
        IAppLogger logger,
        ICredentialStore credentialStore,
        IProxyRepository repository,
        IProxyConnectivityTester connectivityTester,
        IConnectionManager connectionManager,
        IBrowserLauncher browserLauncher,
        ISystemTrafficRouter? trafficRouter)
    {
        Logger = logger;
        CredentialStore = credentialStore;
        Repository = repository;
        ConnectivityTester = connectivityTester;
        ConnectionManager = connectionManager;
        BrowserLauncher = browserLauncher;
        TrafficRouter = trafficRouter;
    }
}
