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
/// Keep each browser and relay until explicit disconnect, even if Chromium's
/// launcher exits early or hands off to another managed instance. Never stop
/// a relay merely because its original process exited.
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class ChromiumBrowserLauncher : IBrowserLauncher
{
    private readonly IBrowserProvider _browserProvider;
    private readonly ICredentialStore _credentialStore;
    private readonly Func<ILocalForwardingProxy> _forwardingProxyFactory;
    private readonly IAppLogger _logger;

    private sealed record Session(Process? Browser, ILocalForwardingProxy Relay, string? ProfilePath = null);
    private readonly List<Session> _sessions = new();
    private readonly HashSet<string> _pendingProfiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly Func<ProcessStartInfo, Process?> _startProcess;
    private readonly string _profilesDirectory;
    private readonly IBrowserProcessCatalog _processCatalog;

    public ChromiumBrowserLauncher(
        IBrowserProvider browserProvider,
        ICredentialStore credentialStore,
        Func<ILocalForwardingProxy> forwardingProxyFactory,
        IAppLogger logger)
        : this(browserProvider, credentialStore, forwardingProxyFactory, logger, Process.Start)
    {
    }

    internal ChromiumBrowserLauncher(
        IBrowserProvider browserProvider,
        ICredentialStore credentialStore,
        Func<ILocalForwardingProxy> forwardingProxyFactory,
        IAppLogger logger,
        Func<ProcessStartInfo, Process?> startProcess,
        string? profilesDirectory = null, IBrowserProcessCatalog? processCatalog = null)
    {
        _browserProvider = browserProvider ?? throw new ArgumentNullException(nameof(browserProvider));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _forwardingProxyFactory = forwardingProxyFactory ?? throw new ArgumentNullException(nameof(forwardingProxyFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _startProcess = startProcess ?? throw new ArgumentNullException(nameof(startProcess));
        _profilesDirectory = profilesDirectory ?? AppPaths.BrowserProfilesDirectory;
        _processCatalog = processCatalog ?? new WindowsBrowserProcessCatalog();
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

        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        ILocalForwardingProxy? relay = null;
        Process? process = null;
        string? profileDir = null;

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
                await CleanupAsync(new Session(null, relay)).ConfigureAwait(false);
                relay = null;
                _logger.Error("BrowserLauncher", "Local relay failed to start correctly; refusing to launch the browser to avoid an unproxied session.");
                return BrowserLaunchResult.Failed("Failed to start the local proxy relay. The browser was not launched, to avoid it using your normal internet connection unproxied.");
            }

            // Dedicated, per-proxy-profile isolated user-data-dir. Using a
            // GUID-based folder under the app's own local data root - never
            // the user's real Chrome/Edge profile directory - guarantees this
            // launch cannot collide with, or hand off to, the user's normal
            // browser session.
            profileDir = Path.GetFullPath(Path.Combine(_profilesDirectory, profile.Id.ToString("N")));
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

            cancellationToken.ThrowIfCancellationRequested();
            process = _startProcess(startInfo);
            if (process is null)
            {
                await CleanupAsync(new Session(null, relay)).ConfigureAwait(false);
                relay = null;
                return BrowserLaunchResult.Failed("Failed to start the browser process.");
            }

            _logger.Info("BrowserLauncher", $"Launched browser (pid={process.Id}) via persistent local relay on port {localPort} for proxy '{profile.Name}'.");

            var result = BrowserLaunchResult.Successful(process.Id);
            _sessions.Add(new Session(process, relay, profileDir));
            return result;
        }
        catch (Exception ex)
        {
            if (relay is not null)
            {
                try { await CleanupAsync(new Session(process, relay, profileDir)).ConfigureAwait(false); }
                catch (Exception cleanupError)
                {
                    _logger.Error("BrowserLauncher", "Failed to clean up an unsuccessful browser launch.", cleanupError);
                }
            }

            _logger.Error("BrowserLauncher", "Failed to launch browser through proxy.", ex);
            return BrowserLaunchResult.Failed("Failed to launch the browser. See diagnostics log for details.");
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task DisconnectAllAsync(CancellationToken cancellationToken = default)
    {
        // Cancellation may abort waiting for ownership, but must never abandon
        // the snapshot after it has been removed from the managed collection.
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var sessions = _sessions.ToArray();
            _sessions.Clear();
            List<Exception> errors = new();
            // Retain profile identities when a previous ownership query failed,
            // so a retry (including app exit) cannot silently return Ready.
            foreach (var profilePath in _pendingProfiles.ToArray())
            {
                try { await CleanupProfileAsync(profilePath).ConfigureAwait(false); }
                catch (Exception ex) { errors.Add(ex); }
            }
            foreach (var session in sessions)
            {
                try { await CleanupAsync(session).ConfigureAwait(false); }
                catch (Exception ex)
                {
                    errors.Add(ex);
                    _logger.Error("BrowserLauncher", "Failed to clean up a managed browser session.", ex);
                }
            }
            if (errors.Count > 0)
                throw new AggregateException("Managed browser cleanup failed.", errors);
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    private async Task CleanupAsync(Session session)
    {
        try
        {
            try
            {
                if (session.Browser is { } process)
                {
                    try { await TerminateAsync(process).ConfigureAwait(false); }
                    finally { process.Dispose(); }
                }
            }
            finally
            {
                // A dead launcher is not evidence that its browser window exited.
                if (session.ProfilePath is not null)
                    await CleanupProfileAsync(session.ProfilePath).ConfigureAwait(false);
            }
        }
        finally
        {
            try { await session.Relay.StopAsync().ConfigureAwait(false); }
            finally { session.Relay.Dispose(); }
        }
    }
    private async Task CleanupProfileAsync(string profilePath)
    {
        _pendingProfiles.Add(profilePath);
        var deadline = Stopwatch.StartNew();
        while (true)
        {
            var candidates = await Task.Run(_processCatalog.GetProcesses).ConfigureAwait(false);
            var found = false;
            var errors = new List<Exception>();
            try
            {
                foreach (var candidate in candidates)
                {
                    if (!ChromiumProfileOwnership.Matches(candidate.Name, candidate.CommandLine, profilePath))
                        continue;
                    found = true;
                    try { await TerminateAsync(candidate.Process).ConfigureAwait(false); }
                    catch (Exception ex) { errors.Add(ex); }
                }
            }
            finally
            {
                foreach (var candidate in candidates) candidate.Process.Dispose();
            }
            if (errors.Count > 0)
                throw new AggregateException("Managed Chromium termination failed.", errors);
            if (!found)
            {
                _pendingProfiles.Remove(profilePath);
                return;
            }
            if (deadline.Elapsed > TimeSpan.FromSeconds(10))
                throw new TimeoutException("Managed Chromium processes did not exit.");
            // Re-enumerate to include handoffs that occurred during termination.
            await Task.Delay(50).ConfigureAwait(false);
        }
    }

    private static async Task TerminateAsync(Process process)
    {
        if (!process.HasExited)
        {
            try { process.Kill(entireProcessTree: true); }
            catch (Exception ex) when ((ex is InvalidOperationException or System.ComponentModel.Win32Exception) && process.HasExited) { }
        }
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
    }
}
