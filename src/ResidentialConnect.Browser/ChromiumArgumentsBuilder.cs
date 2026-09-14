namespace ResidentialConnect.Browser;

/// <summary>
/// Pure, platform-independent construction of the Chromium command-line
/// arguments used by <see cref="ChromiumBrowserLauncher"/>. Extracted into
/// its own class (no OS/process dependency) specifically so the exact
/// argument VALUES can be unit-tested without launching a real browser -
/// this is the regression-test surface for the V0.1 OPEN BROWSER bug where
/// the <c>--user-data-dir</c> value was corrupted by manually embedding
/// literal quote characters into the argument string.
/// </summary>
/// <remarks>
/// <para>
/// ROOT CAUSE OF THE BUG THIS CLASS FIXES: every value added to
/// <see cref="System.Diagnostics.ProcessStartInfo.ArgumentList"/> is later
/// escaped/quoted automatically by .NET when it builds the actual Win32
/// process command line. The previous code built the user-data-dir argument
/// as <c>$"--user-data-dir=\"{profileDir}\""</c> - i.e. it embedded its own
/// literal <c>"</c> characters into the string. .NET's escaper then treated
/// those embedded quotes as characters that themselves needed escaping,
/// producing a command-line token whose value - once Chrome's own argv
/// parser (CommandLineToArgvW) unescaped the ONE outer quote pair .NET
/// added - still literally started and ended with a doublequote character.
/// That is not a valid Windows directory path, so Chrome could not
/// create/open it and silently fell back to using the user's normal,
/// already-logged-in DEFAULT profile directory instead. Because Chrome's
/// single-instance ("singleton") mechanism is scoped per user-data-dir, and
/// the default profile very often already has a running Chrome instance,
/// the new process handed off "open this URL" to that ALREADY-RUNNING
/// instance and exited - and command-line switches such as
/// <c>--proxy-server</c> are only honored on a profile's initial process
/// startup, never on a singleton hand-off. This is what caused BOTH
/// observed symptoms at once: the user's normal logged-in profile/extensions
/// appeared, AND the traffic was not proxied.
/// </para>
/// <para>
/// THE FIX: never manually wrap an argument value in quote characters.
/// Always pass the raw value to <see cref="System.Diagnostics.ProcessStartInfo.ArgumentList"/>
/// and let .NET apply correct escaping exactly once.
/// </para>
/// </remarks>
public static class ChromiumArgumentsBuilder
{
    /// <summary>
    /// Builds the full argument list for launching an isolated, proxy-routed
    /// Chromium browser instance pointed at the local loopback relay.
    /// </summary>
    /// <param name="localRelayPort">The port the local unauthenticated loopback relay (<see cref="ResidentialConnect.Core.Abstractions.ILocalForwardingProxy"/>) is listening on.</param>
    /// <param name="isolatedProfileDirectory">
    /// Absolute path to a dedicated, per-proxy-profile user-data directory.
    /// Must be the RAW path - callers must NEVER wrap this in manual quote
    /// characters; see the class-level remarks for why that corrupts the
    /// value Chrome actually receives.
    /// </param>
    /// <param name="startUrl">Optional URL to navigate to immediately after launch.</param>
    public static IReadOnlyList<string> Build(int localRelayPort, string isolatedProfileDirectory, string? startUrl)
    {
        ArgumentException.ThrowIfNullOrEmpty(isolatedProfileDirectory);

        if (localRelayPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(localRelayPort), localRelayPort, "Local relay port must be a valid TCP port.");
        }

        var arguments = new List<string>
        {
            // Route ALL traffic for this browser instance through the local,
            // unauthenticated loopback relay. This value is safe to pass
            // unquoted - it never contains spaces or quote characters.
            $"--proxy-server=127.0.0.1:{localRelayPort}",

            // Dedicated, isolated profile directory so this launch never
            // touches - or shares the singleton lock of - the user's normal
            // Chrome/Edge profile. CRITICAL: pass the RAW path with no manual
            // quote characters (see class remarks) - ArgumentList applies
            // correct Win32 quoting automatically, including when the path
            // itself contains spaces.
            $"--user-data-dir={isolatedProfileDirectory}",

            // Keep the isolated profile's first run silent and avoid a
            // "set as default browser" prompt in the isolated session.
            "--no-first-run",
            "--no-default-browser-check",

            // Explicitly request a new window, reinforcing that this must be
            // a fresh window in the fresh profile, never a tab handed off to
            // some other already-running Chrome process.
            "--new-window",

            // Defense in depth against Chromium's background/service
            // processes (component updates, background sync, etc.) making
            // network calls outside of the tab we opened - traffic that
            // would not go through our watched local relay.
            "--disable-background-networking",
            "--no-service-autorun",

            // WebRTC's ICE/STUN negotiation opens raw UDP sockets directly to
            // the network interface - it does NOT go through --proxy-server
            // at all, so a page using WebRTC could otherwise reveal the
            // machine's real IP even though every other request is correctly
            // proxied. Forcing "disable_non_proxied_udp" is Chromium's
            // documented policy for preventing exactly this proxy-bypass
            // leak. This is a bug-fix hardening measure (not a new feature):
            // without it, "Chromium cannot silently bypass the relay" would
            // not actually hold.
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        };

        if (!string.IsNullOrWhiteSpace(startUrl))
        {
            arguments.Add(startUrl);
        }

        return arguments;
    }
}
