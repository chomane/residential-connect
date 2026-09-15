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
/// <remarks>
/// <b>Relay lifetime bugfix (V0.1, found during Whole Computer mode
/// hardening on 2026-09-15):</b> the original implementation stopped and
/// disposed the relay via
/// <c>process.WaitForExitAsync().ContinueWith(...)</c> on the
/// <see cref="Process"/> object returned by <see cref="Process.Start"/>.
/// That is unsafe with Chromium-based browsers: when an already-running
/// browser instance exists, or when the launched executable is itself a
/// short-lived stub/launcher, Chromium can hand off the actual browser
/// window to a *different*, longer-lived OS process while the
/// <see cref="Process"/> handle captured here exits almost immediately.
/// The previous code would then stop and dispose the loopback relay while
/// the real browser window was still open and actively using it, which
/// surfaces to the user as the browser suddenly failing every request with
/// <c>ERR_PROXY_CONNECTION_FAILED</c> shortly after launch.
/// <para>
/// The fix is to stop tying relay lifetime to that specific
/// <see cref="Process"/> object at all. Instead, every relay that is
/// successfully started and confirmed running is kept alive (strongly
/// referenced in <see cref="_activeRelays"/>) for the remaining lifetime of
/// the Residential Connect application process itself. The operating
/// system releases the underlying loopback TCP listener automatically when
/// this application process exits, so there is no listener/port leak across
/// application restarts - only within a single run, where the relay
/// deliberately outlives the short-lived launcher <see cref="Process"/>
/// object. This trades a theoretical "one relay per browser launch forever
/// running" cost (acceptable for a desktop utility with a small number of
/// launches per session) for correctness: the browser is never left pointed
/// at a relay that Residential Connect has already torn down.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class ChromiumBrowserLauncher : IBrowserLauncher
{
    private readonly IBrowserProvider _browserProvider;
    private readonly ICredentialStore _credentialStore;
    private readonly Func<ILocalForwardingProxy> _forwardingProxyFactory;
    private readonly IAppLogger _logger;

    // Keep relays alive for the lifetime of the Residential Connect process
    // rather than tying them to the (possibly short-lived) launcher
    // Process object - see the class-level <remarks> above for the full
    // root-cause analysis of why this is required.
    private readonly List<ILocalForwardingProxy> _activeRelays = new();
    private readonly object _relayLock = new();

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

        ILocalForwardingProxy? relay = null;

        try
        {
            relay = _forwardingProxyFactory();
            var localPort = await relay.StartAsync(profile, password, cancellationToken).ConfigureAwait(false);

            // Defense in depth: if the relay reports it is not actually up
            // right after StartAsync returned a port (e.g. the accept loop
            // crashed immediately - see LocalForwardingProxy.AcceptLoopAsync),
            // never launch the browser at all. Launching anyway with a dead
            // relay port is exactly the "silent direct-network bypass" risk
            // this fix must prevent - Chromium would either fail every
            // request outright (safe) or, in the worst case, some traffic
            // could be routed around a half-started relay. Failing loudly
            // here is the safer, explicit behavior.
            if (!relay.IsRunning || relay.Port != localPort)
            {
                await relay.StopAsync().ConfigureAwait(false);
                relay.Dispose();
                relay = null;
                _logger.Error("BrowserLauncher", "Local relay failed to start correctly; refusing to launch the browser to avoid an unproxied session.");
                return BrowserLaunchResult.Failed("Failed to start the local proxy relay. The browser was not launched, to avoid it using your normal internet connection unproxied.");
            }

            // Dedicated, per-proxy-profile isolated user-data-dir. Using a
            // GUID-based folder under the app's own local data root - never
            // the user's real Chrome/Edge profile directory - guarantees this
            // launch cannot collide with, or hand off to, the user's normal
            // browser session.
            var profileDir = Path.Combine(AppPaths.BrowserProfilesDirectory, profile.Id.ToString("N"));
            Directory.CreateDirectory(profileDir);

            // IMPORTANT: ChromiumArgumentsBuilder.Build() returns RAW argument
            // values. Do NOT wrap any of them in manual quote characters here
            // - ProcessStartInfo.ArgumentList applies correct Win32 quoting
            // automatically. Manually embedding quotes (a previous bug) is
            // what caused Chrome to receive a corrupted --user-data-dir value,
            // silently fall back to the user's real default profile, hand off
            // to an already-running Chrome instance, and ignore --proxy-server
            // entirely. See ChromiumArgumentsBuilder's class remarks for the
            // full root-cause analysis.
            var arguments = ChromiumArgumentsBuilder.Build(localPort, profileDir, startUrl);

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
                relay.Dispose();
                relay = null;
                return BrowserLaunchResult.Failed("Failed to start the browser process.");
            }

            // The browser has successfully started. Keep its relay strongly
            // referenced for the remaining lifetime of this Residential
            // Connect process instead of stopping it when this particular
            // Process object exits.
            //
            // We intentionally do NOT use
            // process.WaitForExitAsync().ContinueWith(...) to stop the relay
            // here. Chromium can start (or hand off to) a different,
            // longer-lived OS process while this launcher's Process object
            // exits almost immediately - stopping the relay on that exit
            // would kill the browser's proxy connection out from under a
            // still-open browser window (ERR_PROXY_CONNECTION_FAILED). The
            // OS reclaims the loopback listener when Residential Connect
            // itself exits, so no port is leaked across app restarts.
            lock (_relayLock)
            {
                _activeRelays.Add(relay);
            }

            _logger.Info("BrowserLauncher", $"Launched browser (pid={process.Id}) via persistent local relay on port {localPort} for proxy '{profile.Name}'.");

            return BrowserLaunchResult.Successful(process.Id);
        }
        catch (Exception ex)
        {
            if (relay is not null)
            {
                try
                {
                    await relay.StopAsync().ConfigureAwait(false);
                }
                catch
                {
                    // Preserve the original launch exception as the reported
                    // failure; a failure while tearing down an already-failed
                    // relay is not the interesting error here.
                }

                relay.Dispose();
            }

            _logger.Error("BrowserLauncher", "Failed to launch browser through proxy.", ex);
            return BrowserLaunchResult.Failed("Failed to launch the browser. See diagnostics log for details.");
        }
    }
}
