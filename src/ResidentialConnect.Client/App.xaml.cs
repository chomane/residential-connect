using System.IO;
using System.Windows;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Browser;
using ResidentialConnect.Proxy;
using ResidentialConnect.Proxy.Forwarding;
using ResidentialConnect.Proxy.IpEcho;
using ResidentialConnect.Proxy.Repository;
using ResidentialConnect.Security.DataProtection;
using ResidentialConnect.Security.Storage;
using ResidentialConnect.Client.Services;

namespace ResidentialConnect.Client;

/// <summary>
/// Composition root: wires up all Core/Security/Proxy/Browser
/// implementations by hand (no DI container needed for an app this size)
/// and exposes them via the static <see cref="Services"/> holder so windows
/// created outside the constructor chain (dialogs) can resolve them too.
/// </summary>
public partial class App : Application
{
    public static AppServices Services { get; private set; } = null!;

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
        var connectionManager = new DefaultConnectionManager(tester, logger);
        var browserProvider = new InstalledBrowserProvider();
        var browserLauncher = new ChromiumBrowserLauncher(browserProvider, credentialStore, () => new LocalForwardingProxy(logger), logger);

        Services = new AppServices(logger, credentialStore, repository, tester, connectionManager, browserLauncher);

        var mainWindow = new MainWindow(repository, connectionManager, browserLauncher);
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

    public AppServices(
        IAppLogger logger,
        ICredentialStore credentialStore,
        IProxyRepository repository,
        IProxyConnectivityTester connectivityTester,
        IConnectionManager connectionManager,
        IBrowserLauncher browserLauncher)
    {
        Logger = logger;
        CredentialStore = credentialStore;
        Repository = repository;
        ConnectivityTester = connectivityTester;
        ConnectionManager = connectionManager;
        BrowserLauncher = browserLauncher;
    }
}
