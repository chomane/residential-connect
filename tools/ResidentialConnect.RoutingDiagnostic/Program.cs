using System.Diagnostics;
using System.Net.Http;
using System.Runtime.Versioning;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Forwarding;
using ResidentialConnect.Proxy.Repository;
using ResidentialConnect.Routing;
using ResidentialConnect.Security.DataProtection;
using ResidentialConnect.Security.Storage;

namespace ResidentialConnect.RoutingDiagnostic;

/// <summary>
/// Headless acceptance test for the Whole Computer / WinDivert reflection
/// fix. See the .csproj file header for the full rationale and usage.
///
/// This intentionally exercises the SAME production classes the WPF app
/// uses (WinDivertSystemTrafficRouter, TransparentForwardingProxy,
/// JsonProxyRepository, FileCredentialStore, DpapiDataProtector) rather than
/// any test double, so a PASS here is evidence about the real app, not just
/// about this tool.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class Program
{
    private const string DefaultTestUrl = "https://1.1.1.1";
    private const string IpEchoUrl = "https://api.ipify.org";
    private const int DefaultTimeoutSeconds = 15;

    private static async Task<int> Main(string[] args)
    {
        // Enable the temporary, verbose routing diagnostics (per-packet
        // tuple/flag/direction logging, counters, CONNECT status, byte
        // counts) in WinDivertSystemTrafficRouter / TransparentForwardingProxy
        // / HttpConnectUpstreamConnector for the duration of this run only -
        // this tool exists specifically to capture that output.
        Environment.SetEnvironmentVariable("RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS", "1");

        Console.WriteLine("=== Residential Connect - Whole Computer routing diagnostic ===");
        Console.WriteLine("This tool automates the exact acceptance test from the");
        Console.WriteLine("2026-09-15 handoff: connect Whole Computer mode, make a real");
        Console.WriteLine("TCP/TLS request from an ordinary HttpClient (no proxy settings");
        Console.WriteLine("configured on it - it must be transparently intercepted), verify");
        Console.WriteLine("it succeeds and egresses via the proxy, then disconnect and");
        Console.WriteLine("verify normal networking is restored.");
        Console.WriteLine();

        var options = DiagnosticOptions.Parse(args);
        if (options is null)
        {
            return 2; // bad arguments; usage already printed
        }

        if (!OperatingSystem.IsWindows())
        {
            WriteResult("PLATFORM", false, "This tool only runs on Windows (WinDivert is a Windows-only kernel driver).");
            return 1;
        }

        if (!IsElevated())
        {
            WriteResult("ELEVATION", false, "Not running as Administrator. Whole Computer mode requires elevation (ISystemTrafficRouter.RequiresElevation = true). Re-run this tool from an elevated PowerShell/cmd.");
            return 1;
        }
        WriteResult("ELEVATION", true, "Running elevated.");

        AppPaths.EnsureDirectoriesExist();
        var logger = new ConsoleAppLogger();

        var protector = new DpapiDataProtector();
        var credentialStore = new FileCredentialStore(AppPaths.CredentialsDirectory, protector);
        var repository = new JsonProxyRepository(AppPaths.ProxiesFilePath, credentialStore, logger);

        var profile = ResolveProfile(repository, options.ProfileId);
        if (profile is null)
        {
            WriteResult("PROFILE", false, options.ProfileId is null
                ? "No proxy profiles found. Add and save at least one proxy in the main app first (Add Proxy -> Test -> Save), then re-run this tool."
                : $"No proxy profile found with id '{options.ProfileId}'.");
            return 1;
        }

        var password = credentialStore.Retrieve(profile.CredentialRef);
        if (string.IsNullOrEmpty(password))
        {
            WriteResult("PROFILE", false, $"Profile '{profile.Name}' has no stored password. Edit it in the main app and re-enter the password, then re-run this tool.");
            return 1;
        }
        WriteResult("PROFILE", true, $"Using profile '{profile.Name}' ({profile.Host}:{profile.Port}, {profile.Protocol}).");

        var stateMarkerPath = Path.Combine(AppPaths.RootDirectory, "routing-diagnostic.marker");
        var stateMarker = new RoutingStateMarker(stateMarkerPath, logger);
        var router = new WinDivertSystemTrafficRouter(
            logger,
            () => new TransparentForwardingProxy(logger),
            stateMarker);

        if (!router.IsSupported)
        {
            WriteResult("ROUTER-SUPPORTED", false, "ISystemTrafficRouter.IsSupported is false even though elevation/platform checks passed above - inspect WinDivertSystemTrafficRouter.IsSupported / the console log above for details (e.g. WinDivert driver files missing next to this executable).");
            return 1;
        }
        WriteResult("ROUTER-SUPPORTED", true, "Router reports supported (Windows + elevated).");

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds * 4));
        var allPassed = true;

        // ---- Baseline: direct request BEFORE enabling routing ----------
        Console.WriteLine();
        Console.WriteLine("--- Step 1: baseline request (routing NOT yet active) ---");
        var baseline = await TryHttpsRequestAsync(options.TestUrl, options.TimeoutSeconds, timeoutCts.Token);
        WriteResult("BASELINE-REQUEST", baseline.Success, baseline.Detail);
        if (!baseline.Success)
        {
            Console.WriteLine("Baseline request itself failed - this indicates a pre-existing network problem unrelated to Whole Computer mode. Fix your network connectivity before re-running this diagnostic.");
            return 1;
        }
        allPassed &= baseline.Success;

        string? baselineIp = null;
        if (!options.SkipIpCheck)
        {
            var baselineIpResult = await TryHttpsRequestAsync(IpEchoUrl, options.TimeoutSeconds, timeoutCts.Token);
            if (baselineIpResult.Success)
            {
                baselineIp = baselineIpResult.ResponseBody?.Trim();
                Console.WriteLine($"    Baseline (direct) egress IP: {baselineIp}");
            }
        }

        // ---- Start Whole Computer routing -------------------------------
        Console.WriteLine();
        Console.WriteLine("--- Step 2: starting Whole Computer routing ---");
        SystemRoutingStatus startStatus;
        try
        {
            startStatus = await router.StartAsync(profile, password, timeoutCts.Token);
        }
        catch (Exception ex)
        {
            WriteResult("ROUTING-START", false, $"StartAsync threw: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }

        var started = startStatus == SystemRoutingStatus.Active;
        WriteResult("ROUTING-START", started, $"Router status after StartAsync: {startStatus}.");
        allPassed &= started;

        if (!started)
        {
            Console.WriteLine("Routing did not reach Active - skipping traffic tests. See the console log above for the specific failure (relay start failure, WinDivert handle open failure, filter compile failure, etc.).");
            return 1;
        }

        try
        {
            // ---- The actual acceptance test: real TCP/TLS through reflection ----
            Console.WriteLine();
            Console.WriteLine($"--- Step 3: request to {options.TestUrl} WHILE Whole Computer mode reports Active ---");
            Console.WriteLine("    (This uses an ordinary HttpClient with NO proxy configured on it at all -");
            Console.WriteLine("     exactly like curl.exe or any other unaware Windows application. If the");
            Console.WriteLine("     WinDivert reflection fix works, the kernel transparently redirects this");
            Console.WriteLine("     connection through the local relay and upstream proxy without this");
            Console.WriteLine("     process's HttpClient knowing anything happened.)");
            var routed = await TryHttpsRequestAsync(options.TestUrl, options.TimeoutSeconds, timeoutCts.Token);
            WriteResult("ROUTED-REQUEST", routed.Success, routed.Detail);
            allPassed &= routed.Success;

            if (!routed.Success)
            {
                Console.WriteLine();
                Console.WriteLine("    DIAGNOSIS HINTS based on the failure mode above:");
                Console.WriteLine("      - Timeout / no response at all  -> reflection is likely not completing");
                Console.WriteLine("        the SYN/SYN-ACK handshake (same symptom as the original bug this fix");
                Console.WriteLine("        targets). Check WinDivertSystemTrafficRouter's forward/return filters");
                Console.WriteLine("        actually matched (enable more verbose logging) and confirm the");
                Console.WriteLine("        process is truly elevated with the WinDivert driver loaded.");
                Console.WriteLine("      - Connection reset shortly after connecting -> matches the checkpoint's");
                Console.WriteLine("        \"ReflectProof\" partial-progress symptom (repeated/garbled relay");
                Console.WriteLine("        response packets, possibly retransmitted SYN-ACKs on the return leg).");
                Console.WriteLine("        Capture a packet trace (Wireshark, loopback + real NIC) during this");
                Console.WriteLine("        exact test run and compare against streamdump.c's expected sequence.");
            }

            if (routed.Success && !options.SkipIpCheck)
            {
                Console.WriteLine();
                Console.WriteLine($"--- Step 4: verifying egress IP actually changed (via {IpEchoUrl}) ---");
                var routedIpResult = await TryHttpsRequestAsync(IpEchoUrl, options.TimeoutSeconds, timeoutCts.Token);
                if (routedIpResult.Success)
                {
                    var routedIp = routedIpResult.ResponseBody?.Trim();
                    var ipChanged = !string.IsNullOrEmpty(routedIp) && !string.Equals(routedIp, baselineIp, StringComparison.Ordinal);
                    WriteResult("EGRESS-IP-CHANGED", ipChanged,
                        ipChanged
                            ? $"Baseline IP was {baselineIp}; routed IP is {routedIp} - traffic is genuinely egressing via the proxy."
                            : $"Baseline IP was {baselineIp}; routed IP is ALSO {routedIp} - traffic is NOT actually going through the proxy (leak), even though the HTTPS request itself succeeded. This is a fail-closed violation and must be investigated before trusting this mode.");
                    allPassed &= ipChanged;
                }
                else
                {
                    WriteResult("EGRESS-IP-CHANGED", false, $"Could not reach {IpEchoUrl} while routed: {routedIpResult.Detail}");
                    allPassed = false;
                }
            }
        }
        finally
        {
            // ---- Always attempt clean disconnect, even if the above failed ----
            Console.WriteLine();
            Console.WriteLine("--- Step 5: stopping Whole Computer routing (cleanup) ---");
            try
            {
                await router.StopAsync(timeoutCts.Token);
                WriteResult("ROUTING-STOP", true, $"Router status after StopAsync: {router.Status}.");
            }
            catch (Exception ex)
            {
                WriteResult("ROUTING-STOP", false, $"StopAsync threw: {ex.GetType().Name}: {ex.Message}");
                allPassed = false;
            }
        }

        // ---- Confirm normal networking is restored --------------------
        Console.WriteLine();
        Console.WriteLine("--- Step 6: confirming normal (direct) networking is restored after disconnect ---");
        var restored = await TryHttpsRequestAsync(options.TestUrl, options.TimeoutSeconds, timeoutCts.Token);
        WriteResult("POST-DISCONNECT-REQUEST", restored.Success, restored.Detail);
        allPassed &= restored.Success;

        Console.WriteLine();
        Console.WriteLine(allPassed
            ? "=== OVERALL RESULT: PASS - Whole Computer mode routed real traffic and cleaned up correctly. ==="
            : "=== OVERALL RESULT: FAIL - see the failed step(s) above. Do NOT consider Whole Computer mode / PR #3 verified. ===");

        return allPassed ? 0 : 1;
    }

    private static ProxyProfile? ResolveProfile(IProxyRepository repository, Guid? explicitId)
    {
        if (explicitId is { } id)
        {
            return repository.GetById(id);
        }

        var selectedId = repository.GetSelectedId();
        if (selectedId is { } sel)
        {
            var selected = repository.GetById(sel);
            if (selected is not null)
            {
                return selected;
            }
        }

        return repository.GetAll().FirstOrDefault();
    }

    private static async Task<RequestResult> TryHttpsRequestAsync(string url, int timeoutSeconds, CancellationToken outerToken)
    {
        using var handler = new HttpClientHandler
        {
            // Explicitly disable any system/environment proxy settings on
            // THIS client - the whole point is to prove kernel-level
            // (WinDivert) redirection works on a client that has no idea
            // any proxy exists, exactly like curl.exe with no --proxy flag
            // or any other ordinary Windows application.
            UseProxy = false,
            Proxy = null
        };
        using var client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token);
            var body = await response.Content.ReadAsStringAsync(linkedCts.Token);
            stopwatch.Stop();
            return new RequestResult(
                true,
                $"{url} -> HTTP {(int)response.StatusCode} in {stopwatch.ElapsedMilliseconds}ms.",
                body);
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new RequestResult(false, $"{url} -> TIMED OUT after {stopwatch.ElapsedMilliseconds}ms (no response within {timeoutSeconds}s).", null);
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            return new RequestResult(false, $"{url} -> FAILED after {stopwatch.ElapsedMilliseconds}ms.{Environment.NewLine}    Full exception chain: {DescribeExceptionChain(ex)}", null);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new RequestResult(false, $"{url} -> unexpected error after {stopwatch.ElapsedMilliseconds}ms.{Environment.NewLine}    Full exception chain: {DescribeExceptionChain(ex)}", null);
        }
    }

    /// <summary>
    /// Renders the full .NET exception chain (the exception plus every
    /// nested <see cref="Exception.InnerException"/>), so a routed-request
    /// TLS/connect failure (e.g. "The SSL connection could not be
    /// established") shows the actual underlying SocketException/Win32
    /// error instead of just the outer wrapper message.
    /// </summary>
    private static string DescribeExceptionChain(Exception ex)
    {
        var parts = new List<string>();
        var current = ex;
        var depth = 0;
        while (current is not null && depth < 10)
        {
            parts.Add($"[{depth}] {current.GetType().FullName}: {current.Message}");
            current = current.InnerException;
            depth++;
        }

        return string.Join(" <-- ", parts);
    }

    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static void WriteResult(string step, bool passed, string detail)
    {
        var marker = passed ? "[PASS]" : "[FAIL]";
        Console.WriteLine($"{marker} {step}: {detail}");
    }

    private sealed record RequestResult(bool Success, string Detail, string? ResponseBody);

    /// <summary>Minimal stdout-based IAppLogger so this tool has no dependency on the WPF client's SimpleFileLogger.</summary>
    private sealed class ConsoleAppLogger : IAppLogger
    {
        public void Log(LogLevel level, string category, string message, Exception? exception = null)
        {
            var scrubbed = ResidentialConnect.Core.Diagnostics.SecretScrubber.Scrub(message);
            Console.WriteLine($"    [{level}] {category}: {scrubbed}{(exception is null ? string.Empty : $" ({exception.GetType().Name}: {exception.Message})")}");
        }
    }

    private sealed class DiagnosticOptions
    {
        public string TestUrl { get; private init; } = DefaultTestUrl;
        public int TimeoutSeconds { get; private init; } = DefaultTimeoutSeconds;
        public bool SkipIpCheck { get; private init; }
        public Guid? ProfileId { get; private init; }

        public static DiagnosticOptions? Parse(string[] args)
        {
            string testUrl = DefaultTestUrl;
            int timeoutSeconds = DefaultTimeoutSeconds;
            bool skipIpCheck = false;
            Guid? profileId = null;

            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--test-url" when i + 1 < args.Length:
                        testUrl = args[++i];
                        break;
                    case "--timeout-seconds" when i + 1 < args.Length && int.TryParse(args[i + 1], out var t):
                        timeoutSeconds = t;
                        i++;
                        break;
                    case "--skip-ip-check":
                        skipIpCheck = true;
                        break;
                    case "--profile-id" when i + 1 < args.Length && Guid.TryParse(args[i + 1], out var pid):
                        profileId = pid;
                        i++;
                        break;
                    case "--help":
                    case "-h":
                        PrintUsage();
                        return null;
                    default:
                        Console.Error.WriteLine($"Unrecognized argument: {args[i]}");
                        PrintUsage();
                        return null;
                }
            }

            return new DiagnosticOptions
            {
                TestUrl = testUrl,
                TimeoutSeconds = timeoutSeconds,
                SkipIpCheck = skipIpCheck,
                ProfileId = profileId
            };
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: ResidentialConnect.RoutingDiagnostic.exe [options]");
            Console.WriteLine("  --test-url <url>          HTTPS URL to request through Whole Computer routing (default: https://1.1.1.1)");
            Console.WriteLine("  --timeout-seconds <n>     Per-request timeout in seconds (default: 15)");
            Console.WriteLine("  --skip-ip-check           Skip the api.ipify.org egress-IP-changed verification");
            Console.WriteLine("  --profile-id <guid>       Use a specific saved proxy profile id instead of the currently selected/first one");
        }
    }
}
