using System.Diagnostics;
using System.Runtime.Versioning;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Browser;

/// <summary>
/// <see cref="IBrowserLauncher"/> implementation for V0.1: starts the local
/// unauthenticated loopback relay (<see cref="ILocalForwardingProxy"/>) for
/// the selected proxy, then launches a Chromium-based browser
/// (<see cref="IBrowserProvider"/>) pointed at that relay via
/// <c>--proxy-server=127.0.0.1:PORT</c>, using an isolated
/// <c>--user-data-dir</c> under the app's local data folder so the user's
/// normal browser profile is never touched. Because the browser only ever
/// talks to the loopback relay (which itself performs the real proxy's
/// username/password handshake), no proxy credential prompt is ever shown.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ChromiumBrowserLauncher : IBrowserLauncher
{
    private readonly IBrowserProvider _browserProvider;
    private readonly ICredentialStore _credentialStore;
    private readonly Func<ILocalForwardingProxy> _forwardingProxyFactory;
    private readonly IAppLogger _logger;

    public ChromiumBrowserLauncher(
        IBrowserProvider browserProvider,
        ICredentialStore credentialStore,
        Func<ILocalForwardingProxy> forwardingProxyFactory,
        IAppLogger logger)
    {
        _browserProvider = browserProvider ?? throw new ArgumentNullException(nameof(browserProvider));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _forwardingProxyFactory = forwardingProxyFactory ?? throw new ArgumentNullException(nameof(forwardingProxyFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public bool IsAvailable => _browserProvider.FindExecutable() is not null;

    public async Task<BrowserLaunchResult> LaunchAsync(ProxyProfile profile, string? startUrl = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var executable = _browserProvider.FindExecutable();
        if (executable is null)
        {
            _logger.Warning("BrowserLauncher", "No supported Chromium-based browser (Chrome/Edge) was found on this machine.");
            return BrowserLaunchResult.Failed("No supported browser (Chrome or Edge) was found. Please install one and try again.");
        }

        var password = _credentialStore.Retrieve(profile.CredentialRef);
        if (string.IsNullOrEmpty(password))
        {
            return BrowserLaunchResult.Failed("No stored password found for this proxy. Please edit the proxy and re-enter the password.");
        }

        try
        {
            var relay = _forwardingProxyFactory();
            var localPort = await relay.StartAsync(profile, password, cancellationToken).ConfigureAwait(false);

            var profileDir = Path.Combine(AppPaths.BrowserProfilesDirectory, profile.Id.ToString("N"));
            Directory.CreateDirectory(profileDir);

            var arguments = new List<string>
            {
                $"--proxy-server=127.0.0.1:{localPort}",
                $"--user-data-dir=\"{profileDir}\"",
                "--no-first-run",
                "--no-default-browser-check",
                "--new-window"
            };

            if (!string.IsNullOrWhiteSpace(startUrl))
            {
                arguments.Add(startUrl);
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false
            };
            foreach (var arg in arguments)
            {
                startInfo.ArgumentList.Add(arg);
            }

            var process = Process.Start(startInfo);
            if (process is null)
            {
                await relay.StopAsync().ConfigureAwait(false);
                return BrowserLaunchResult.Failed("Failed to start the browser process.");
            }

            _logger.Info("BrowserLauncher", $"Launched browser (pid={process.Id}) via local relay on port {localPort} for proxy '{profile.Name}'.");

            // Stop the relay once the browser process exits, to avoid leaking
            // a listening loopback port after the user closes the window.
            _ = process.WaitForExitAsync(CancellationToken.None).ContinueWith(async _ =>
            {
                await relay.StopAsync().ConfigureAwait(false);
                relay.Dispose();
            }, TaskScheduler.Default);

            return BrowserLaunchResult.Successful(process.Id);
        }
        catch (Exception ex)
        {
            _logger.Error("BrowserLauncher", "Failed to launch browser through proxy.", ex);
            return BrowserLaunchResult.Failed("Failed to launch the browser. See diagnostics log for details.");
        }
    }
}
