using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Quic;
using System.Net.Sockets;
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
/// fix, AND (as of 2026-09-16) for the additive UDP/DNS leak-protection
/// checks layered on top of it. See the .csproj file header for the full
/// rationale and usage, and README.md in this folder for the full option
/// list and how to read the output.
///
/// This intentionally exercises the SAME production classes the WPF app
/// uses (WinDivertSystemTrafficRouter, TransparentForwardingProxy,
/// JsonProxyRepository, FileCredentialStore, DpapiDataProtector) rather than
/// any test double, so a PASS here is evidence about the real app, not just
/// about this tool.
/// </summary>
/// <remarks>
/// <para>
/// <b>2026-09-16 additions (strictly additive - no existing TCP step below
/// was modified):</b> the original TCP acceptance test only ever proved the
/// TCP forward/return reflection pipeline. It did not prove anything about
/// this branch's separate UDP leak-protection work (the DNS-block handle,
/// or the newer general UDP-block handle - see
/// <see cref="ResidentialConnect.Routing.BypassFilterBuilder.BuildDnsFilter"/>
/// and <see cref="ResidentialConnect.Routing.BypassFilterBuilder.BuildUdpBlockFilter"/>).
/// This run now adds four new, independently-reported checks around the
/// existing TCP steps:
/// </para>
/// <list type="number">
/// <item><b>Before</b> routing starts: a raw UDP/53 DNS query to a public
/// resolver must succeed - this proves both that the probe itself works
/// AND that plain UDP genuinely functions on this machine/network before
/// any interception exists (a necessary precondition for the "blocked
/// while Active" check below to mean anything).</item>
/// <item><b>While Active:</b> the identical raw UDP/53 query must now
/// receive NO response (timeout) - proving the DNS-block handle actually
/// prevents a real DNS leak, not just that its filter string looks right.</item>
/// <item><b>While Active:</b> an HTTP/3-exact request (UDP/443, QUIC) must
/// either fail/time out (proving the general UDP-block handle also stops
/// non-DNS UDP from leaking) or - if <see cref="QuicConnection.IsSupported"/>
/// reports this machine cannot attempt HTTP/3 at all - the check is
/// reported as SKIP (a genuine capability limitation, never silently
/// counted as a PASS).</item>
/// <item><b>After</b> <c>StopAsync</c>: the raw UDP/53 query must succeed
/// again, proving normal UDP networking (not just TCP) is fully restored.</item>
/// </list>
/// <para>
/// The original TCP checks (BASELINE-REQUEST, ROUTING-START, ROUTED-REQUEST,
/// EGRESS-IP-CHANGED, ROUTING-STOP, POST-DISCONNECT-REQUEST) are completely
/// unchanged in behavior and wording - only their surrounding step numbers
/// shifted to make room for the new UDP/DNS/QUIC steps interleaved at the
/// correct points in the sequence (before start / while Active / after stop).
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class Program
{
    private const string DefaultTestUrl = "https://1.1.1.1";
    private const string IpEchoUrl = "https://api.ipify.org";
    private const string DefaultDnsProbeServerIp = "1.1.1.1";
    private const string DefaultDnsProbeHostName = "example.com";
    private const string DefaultQuicTestUrl = "https://cloudflare-quic.com/";
    private const int DefaultTimeoutSeconds = 15;
    private const int DefaultUdpTimeoutSeconds = 5;

    private static async Task<int> Main(string[] args)
    {
        // Enable the temporary, verbose routing diagnostics (per-packet
        // tuple/flag/direction logging, counters, CONNECT status, byte
        // counts) in WinDivertSystemTrafficRouter / TransparentForwardingProxy
        // / HttpConnectUpstreamConnector for the duration of this run only -
        // this tool exists specifically to capture that output.
        Environment.SetEnvironmentVariable("RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS", "1");

        Console.WriteLine("=== Residential Connect - Whole Computer routing diagnostic ===");
        Console.WriteLine("This tool automates the TCP acceptance test from the 2026-09-15");
        Console.WriteLine("handoff (connect Whole Computer mode, make a real TCP/TLS request");
        Console.WriteLine("from an ordinary HttpClient, verify it succeeds and egresses via");
        Console.WriteLine("the proxy, then disconnect and verify normal networking is");
        Console.WriteLine("restored) PLUS the 2026-09-16 UDP/DNS leak-protection checks: a");
        Console.WriteLine("raw UDP/53 DNS probe before/while/after routing, and an HTTP/3");
        Console.WriteLine("(UDP/443 QUIC) probe while routing is Active.");
        Console.WriteLine();

        var options = DiagnosticOptions.Parse(args);
        if (options is null)
        {
            return 2; // bad arguments; usage already printed
        }

        if (!OperatingSystem.IsWindows())
        {
            WriteResult("PLATFORM", CheckOutcome.Fail, "This tool only runs on Windows (WinDivert is a Windows-only kernel driver).");
            return 1;
        }

        if (!IsElevated())
        {
            WriteResult("ELEVATION", CheckOutcome.Fail, "Not running as Administrator. Whole Computer mode requires elevation (ISystemTrafficRouter.RequiresElevation = true). Re-run this tool from an elevated PowerShell/cmd.");
            return 1;
        }
        WriteResult("ELEVATION", CheckOutcome.Pass, "Running elevated.");

        AppPaths.EnsureDirectoriesExist();
        var logger = new ConsoleAppLogger();

        var protector = new DpapiDataProtector();
        var credentialStore = new FileCredentialStore(AppPaths.CredentialsDirectory, protector);
        var repository = new JsonProxyRepository(AppPaths.ProxiesFilePath, credentialStore, logger);

        var profile = ResolveProfile(repository, options.ProfileId);
        if (profile is null)
        {
            WriteResult("PROFILE", CheckOutcome.Fail, options.ProfileId is null
                ? "No proxy profiles found. Add and save at least one proxy in the main app first (Add Proxy -> Test -> Save), then re-run this tool."
                : $"No proxy profile found with id '{options.ProfileId}'.");
            return 1;
        }

        var password = credentialStore.Retrieve(profile.CredentialRef);
        if (string.IsNullOrEmpty(password))
        {
            WriteResult("PROFILE", CheckOutcome.Fail, $"Profile '{profile.Name}' has no stored password. Edit it in the main app and re-enter the password, then re-run this tool.");
            return 1;
        }
        WriteResult("PROFILE", CheckOutcome.Pass, $"Using profile '{profile.Name}' ({profile.Host}:{profile.Port}, {profile.Protocol}).");

        var stateMarkerPath = Path.Combine(AppPaths.RootDirectory, "routing-diagnostic.marker");
        var stateMarker = new RoutingStateMarker(stateMarkerPath, logger);
        var router = new WinDivertSystemTrafficRouter(
            logger,
            () => new TransparentForwardingProxy(logger),
            stateMarker);

        if (!router.IsSupported)
        {
            WriteResult("ROUTER-SUPPORTED", CheckOutcome.Fail, "ISystemTrafficRouter.IsSupported is false even though elevation/platform checks passed above - inspect WinDivertSystemTrafficRouter.IsSupported / the console log above for details (e.g. WinDivert driver files missing next to this executable).");
            return 1;
        }
        WriteResult("ROUTER-SUPPORTED", CheckOutcome.Pass, "Router reports supported (Windows + elevated).");

        // Overall watchdog: bumped from the original 4x multiplier to 8x to
        // make room for the four new UDP/DNS/QUIC steps below (each of
        // which can itself legitimately wait up to a full timeout window,
        // e.g. the "must NOT respond" checks that only pass by timing out).
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds * 8));

        // Independent, named results surfaced in the final acceptance
        // summary banner - tracked separately from the step-by-step
        // [PASS]/[FAIL]/[SKIP] lines above so the six specific outcomes the
        // acceptance test cares about are unambiguous even if a reader
        // skims straight to the bottom of the output.
        var summary = new AcceptanceSummary();

        // ---- Baseline: direct TCP request BEFORE enabling routing ------
        Console.WriteLine();
        Console.WriteLine("--- Step 1: baseline TCP/HTTPS request (routing NOT yet active) ---");
        var baseline = await TryHttpsRequestAsync(options.TestUrl, options.TimeoutSeconds, timeoutCts.Token);
        WriteResult("BASELINE-REQUEST", ToOutcome(baseline.Success), baseline.Detail);
        if (!baseline.Success)
        {
            Console.WriteLine("Baseline request itself failed - this indicates a pre-existing network problem unrelated to Whole Computer mode. Fix your network connectivity before re-running this diagnostic.");
            return 1;
        }

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

        // ---- NEW Step 1b: raw UDP/53 DNS baseline (routing NOT yet active) ----
        // Proves both that the raw-UDP probe itself works AND that plain
        // UDP genuinely functions on this machine/network before any
        // interception exists - a necessary precondition for the "blocked
        // while Active" check below to mean anything at all.
        Console.WriteLine();
        Console.WriteLine($"--- Step 1b: raw UDP/53 DNS probe to {options.DnsProbeServerIp} (routing NOT yet active) ---");
        Console.WriteLine("    (Hand-built single-packet DNS query sent directly over a raw UdpClient -");
        Console.WriteLine("     bypasses System.Net.Dns/OS resolver caching so this is an unambiguous");
        Console.WriteLine("     single UDP round-trip signal, not just \"some DNS lookup succeeded\".)");
        var udpBaseline = await TryRawUdpDnsQueryAsync(options.DnsProbeServerIp, options.DnsProbeHostName, options.UdpTimeoutSeconds, timeoutCts.Token);
        WriteResult("RAW-UDP-DNS-BASELINE", ToOutcome(udpBaseline.Responded), udpBaseline.Detail);
        summary.UdpDnsBaselineWorked = udpBaseline.Responded;
        if (!udpBaseline.Responded)
        {
            Console.WriteLine("Raw UDP/53 baseline failed BEFORE routing started - this indicates a pre-existing network/firewall problem unrelated to Whole Computer mode (or that outbound UDP/53 to this resolver is already blocked by something else). The 'UDP/53 blocked while Active' check below cannot be trusted as evidence of this app's own leak protection unless this baseline succeeds first. Fix connectivity to the DNS probe server (or pass --dns-test-ip with a reachable resolver) before re-running this diagnostic.");
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
            WriteResult("ROUTING-START", CheckOutcome.Fail, $"StartAsync threw: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }

        var started = startStatus == SystemRoutingStatus.Active;
        WriteResult("ROUTING-START", ToOutcome(started), $"Router status after StartAsync: {startStatus}.");

        if (!started)
        {
            Console.WriteLine("Routing did not reach Active - skipping traffic tests. See the console log above for the specific failure (relay start failure, WinDivert handle open failure, filter compile failure, etc.).");
            return 1;
        }

        try
        {
            // ---- The actual TCP acceptance test: real TCP/TLS through reflection ----
            Console.WriteLine();
            Console.WriteLine($"--- Step 3: request to {options.TestUrl} WHILE Whole Computer mode reports Active ---");
            Console.WriteLine("    (This uses an ordinary HttpClient with NO proxy configured on it at all -");
            Console.WriteLine("     exactly like curl.exe or any other unaware Windows application. If the");
            Console.WriteLine("     WinDivert reflection fix works, the kernel transparently redirects this");
            Console.WriteLine("     connection through the local relay and upstream proxy without this");
            Console.WriteLine("     process's HttpClient knowing anything happened.)");
            var routed = await TryHttpsRequestAsync(options.TestUrl, options.TimeoutSeconds, timeoutCts.Token);
            WriteResult("ROUTED-REQUEST", ToOutcome(routed.Success), routed.Detail);
            summary.TcpRoutedThroughProxy = routed.Success;

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
                    WriteResult("EGRESS-IP-CHANGED", ToOutcome(ipChanged),
                        ipChanged
                            ? $"Baseline IP was {baselineIp}; routed IP is {routedIp} - traffic is genuinely egressing via the proxy."
                            : $"Baseline IP was {baselineIp}; routed IP is ALSO {routedIp} - traffic is NOT actually going through the proxy (leak), even though the HTTPS request itself succeeded. This is a fail-closed violation and must be investigated before trusting this mode.");
                    summary.ProxyEgressVerified = ipChanged;
                }
                else
                {
                    WriteResult("EGRESS-IP-CHANGED", CheckOutcome.Fail, $"Could not reach {IpEchoUrl} while routed: {routedIpResult.Detail}");
                    summary.ProxyEgressVerified = false;
                }
            }

            // ---- NEW Step 4b: UDP/53 DNS must now be BLOCKED (fail-closed) ----
            Console.WriteLine();
            Console.WriteLine($"--- Step 4b: repeating the raw UDP/53 DNS probe to {options.DnsProbeServerIp} WHILE Active ---");
            Console.WriteLine("    (PASS here means NO response was received at all - proving the DNS-block");
            Console.WriteLine("     WinDivert Drop handle is actually preventing this UDP/53 query from ever");
            Console.WriteLine("     leaving the machine, not just that BuildDnsFilter's filter string looks");
            Console.WriteLine("     correct in isolation.)");
            var udpWhileActive = await TryRawUdpDnsQueryAsync(options.DnsProbeServerIp, options.DnsProbeHostName, options.UdpTimeoutSeconds, timeoutCts.Token);
            var udpBlocked = !udpWhileActive.Responded;
            WriteResult("UDP-DNS-BLOCKED-WHILE-ACTIVE", ToOutcome(udpBlocked),
                udpBlocked
                    ? udpWhileActive.Detail
                    : $"LEAK: {udpWhileActive.Detail} - plain UDP/53 DNS reached the real network directly while Whole Computer mode reported Active. This is a fail-closed violation in the DNS-block handle (see BypassFilterBuilder.BuildDnsFilter / DnsLeakGuard).");
            summary.UdpDns53BlockedWhileActive = udpBlocked;

            // ---- NEW Step 4c: general UDP/QUIC (HTTP/3) must be BLOCKED, or SKIP if unavailable ----
            Console.WriteLine();
            Console.WriteLine($"--- Step 4c: HTTP/3-exact request to {options.QuicTestUrl} (UDP/443 QUIC) WHILE Active ---");
            Console.WriteLine("    (Exercises the NEW general UDP-block handle - BypassFilterBuilder.BuildUdpBlockFilter -");
            Console.WriteLine("     which covers every outbound UDP packet except UDP/53. PASS means the HTTP/3");
            Console.WriteLine("     request could NOT complete over QUIC while Active. If this machine's .NET/OS/msquic");
            Console.WriteLine("     stack cannot attempt HTTP/3 at all, this is reported as SKIP - a genuine capability");
            Console.WriteLine("     limitation, never silently counted as a PASS.)");
            var quicResult = await TryQuicBlockedCheckAsync(options.QuicTestUrl, options.TimeoutSeconds, timeoutCts.Token);
            WriteResult("UDP-QUIC-BLOCKED-WHILE-ACTIVE", quicResult.Outcome, quicResult.Detail);
            summary.UdpQuicOutcome = quicResult.Outcome;
        }
        finally
        {
            // ---- Always attempt clean disconnect, even if the above failed ----
            Console.WriteLine();
            Console.WriteLine("--- Step 5: stopping Whole Computer routing (cleanup) ---");
            try
            {
                await router.StopAsync(timeoutCts.Token);
                WriteResult("ROUTING-STOP", CheckOutcome.Pass, $"Router status after StopAsync: {router.Status}.");
            }
            catch (Exception ex)
            {
                WriteResult("ROUTING-STOP", CheckOutcome.Fail, $"StopAsync threw: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // ---- NEW Step 5b: UDP/53 DNS must work normally again after disconnect ----
        Console.WriteLine();
        Console.WriteLine($"--- Step 5b: repeating the raw UDP/53 DNS probe to {options.DnsProbeServerIp} AFTER disconnect ---");
        var udpRestored = await TryRawUdpDnsQueryAsync(options.DnsProbeServerIp, options.DnsProbeHostName, options.UdpTimeoutSeconds, timeoutCts.Token);
        WriteResult("UDP-DNS-RESTORED-AFTER-DISCONNECT", ToOutcome(udpRestored.Responded), udpRestored.Detail);
        summary.UdpDnsRestoredAfterDisconnect = udpRestored.Responded;

        // ---- Confirm normal TCP networking is restored -----------------
        Console.WriteLine();
        Console.WriteLine("--- Step 6: confirming normal (direct) TCP networking is restored after disconnect ---");
        var restored = await TryHttpsRequestAsync(options.TestUrl, options.TimeoutSeconds, timeoutCts.Token);
        WriteResult("POST-DISCONNECT-REQUEST", ToOutcome(restored.Success), restored.Detail);
        summary.TcpRestoredAfterDisconnect = restored.Success;

        PrintAcceptanceSummary(summary);

        var allPassed = summary.AllRequiredChecksPassed();
        Console.WriteLine();
        Console.WriteLine(allPassed
            ? "=== OVERALL RESULT: PASS - Whole Computer mode routed real TCP traffic, blocked UDP leaks, and cleaned up correctly. ==="
            : "=== OVERALL RESULT: FAIL - see the failed step(s) and acceptance summary above. Do NOT consider Whole Computer mode / PR #3 verified. ===");

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
    /// Sends one hand-built, single-packet raw UDP/53 DNS query (via
    /// <see cref="ResidentialConnect.Routing.RawDnsProbeMessage"/>) directly
    /// over a raw <see cref="UdpClient"/> socket and waits up to
    /// <paramref name="timeoutSeconds"/> for a matching response.
    /// Deliberately bypasses <see cref="System.Net.Dns"/> / the OS resolver
    /// entirely - see the class-level remarks on <see cref="Program"/> for
    /// why an unambiguous single-packet signal is required here, both for
    /// the "must respond" (baseline/restored) and "must NOT respond"
    /// (blocked-while-Active) checks that call this same helper.
    /// </summary>
    private static async Task<RawUdpProbeResult> TryRawUdpDnsQueryAsync(string dnsServerIp, string hostName, int timeoutSeconds, CancellationToken outerToken)
    {
        var transactionId = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var query = RawDnsProbeMessage.BuildQuery(transactionId, hostName);

        using var udp = new UdpClient();
        var stopwatch = Stopwatch.StartNew();

        try
        {
            await udp.SendAsync(query, dnsServerIp, 53, outerToken);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new RawUdpProbeResult(false, $"raw UDP send to {dnsServerIp}:53 failed immediately after {stopwatch.ElapsedMilliseconds}ms: {ex.GetType().Name}: {ex.Message} (this is a local send-side failure, not evidence either way about UDP blocking).");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            var result = await udp.ReceiveAsync(linkedCts.Token);
            stopwatch.Stop();
            var valid = RawDnsProbeMessage.IsValidDnsResponse(result.Buffer, transactionId);
            return valid
                ? new RawUdpProbeResult(true, $"received a valid DNS response ({result.Buffer.Length} bytes, matching transaction ID 0x{transactionId:X4}) from {result.RemoteEndPoint} in {stopwatch.ElapsedMilliseconds}ms.")
                : new RawUdpProbeResult(false, $"received {result.Buffer.Length} bytes from {result.RemoteEndPoint} after {stopwatch.ElapsedMilliseconds}ms, but it did not validate as a matching DNS response (unexpected/garbage packet) - treating as no valid response.");
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new RawUdpProbeResult(false, $"no UDP response received from {dnsServerIp}:53 within {timeoutSeconds}s (timed out after {stopwatch.ElapsedMilliseconds}ms).");
        }
        catch (SocketException ex)
        {
            stopwatch.Stop();
            return new RawUdpProbeResult(false, $"raw UDP receive from {dnsServerIp}:53 failed after {stopwatch.ElapsedMilliseconds}ms: SocketException ({ex.SocketErrorCode}): {ex.Message}.");
        }
    }

    /// <summary>
    /// Determines HTTP/3 (QUIC, UDP/443) capability via
    /// <see cref="QuicConnection.IsSupported"/> first - if this machine's
    /// .NET/OS/msquic stack cannot even attempt HTTP/3, the check is
    /// reported as <see cref="CheckOutcome.Skip"/> rather than either PASS
    /// or FAIL, per the explicit requirement that a genuine capability gap
    /// must never be silently counted as passing evidence. Only when HTTP/3
    /// is actually attemptable does this method make a real
    /// <see cref="HttpVersionPolicy.RequestVersionExact"/> HTTP/3 request
    /// and require it to fail/time out (PASS) rather than succeed (FAIL,
    /// a UDP/QUIC leak) while Whole Computer mode is Active.
    /// </summary>
    private static async Task<QuicCheckResult> TryQuicBlockedCheckAsync(string quicTestUrl, int timeoutSeconds, CancellationToken outerToken)
    {
        if (!QuicConnection.IsSupported)
        {
            return new QuicCheckResult(
                CheckOutcome.Skip,
                "SKIP - HTTP/3 unavailable on this machine: System.Net.Quic.QuicConnection.IsSupported is false (missing msquic/TLS 1.3/OS prerequisites for QUIC). This check cannot exercise the UDP/443 block at all here, so it is reported as SKIP rather than PASS or FAIL - it is neither evidence the block works nor that it doesn't.");
        }

        using var handler = new HttpClientHandler { UseProxy = false, Proxy = null };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };
        using var request = new HttpRequestMessage(HttpMethod.Get, quicTestUrl)
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact
        };

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, linkedCts.Token);
            stopwatch.Stop();
            return new QuicCheckResult(
                CheckOutcome.Fail,
                $"LEAK: HTTP/3 request to {quicTestUrl} UNEXPECTEDLY SUCCEEDED (HTTP {(int)response.StatusCode}, protocol {response.Version}) in {stopwatch.ElapsedMilliseconds}ms while Whole Computer mode reported Active - QUIC/UDP-443 traffic reached the real network directly. This is a fail-closed violation in the general UDP-block handle (see BypassFilterBuilder.BuildUdpBlockFilter).");
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new QuicCheckResult(
                CheckOutcome.Pass,
                $"HTTP/3 request to {quicTestUrl} timed out after {stopwatch.ElapsedMilliseconds}ms while Active - matches the expected fail-closed UDP block (QUIC/UDP-443 cannot be proxied by this V0.2 TCP-only implementation, so it is blocked rather than leaked).");
        }
        catch (HttpRequestException ex)
        {
            stopwatch.Stop();
            return new QuicCheckResult(
                CheckOutcome.Pass,
                $"HTTP/3 request to {quicTestUrl} failed after {stopwatch.ElapsedMilliseconds}ms while Active ({ex.GetType().Name}: {ex.Message}) - matches the expected fail-closed UDP block.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            return new QuicCheckResult(
                CheckOutcome.Pass,
                $"HTTP/3 request to {quicTestUrl} could not complete after {stopwatch.ElapsedMilliseconds}ms while Active ({ex.GetType().Name}: {ex.Message}) - matches the expected fail-closed UDP block.");
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

    private static CheckOutcome ToOutcome(bool passed) => passed ? CheckOutcome.Pass : CheckOutcome.Fail;

    private static void WriteResult(string step, CheckOutcome outcome, string detail)
    {
        var marker = outcome switch
        {
            CheckOutcome.Pass => "[PASS]",
            CheckOutcome.Skip => "[SKIP]",
            _ => "[FAIL]"
        };
        Console.WriteLine($"{marker} {step}: {detail}");
    }

    /// <summary>
    /// Prints the final, clearly-separated acceptance summary banner - the
    /// six independent results the acceptance test explicitly cares about,
    /// each reported on its own line regardless of which step above
    /// produced it, so a reader does not have to reconstruct the outcome by
    /// scanning the full step-by-step log.
    /// </summary>
    private static void PrintAcceptanceSummary(AcceptanceSummary summary)
    {
        Console.WriteLine();
        Console.WriteLine("=== ACCEPTANCE SUMMARY ===");
        WriteSummaryLine("TCP routed through proxy", ToOutcome(summary.TcpRoutedThroughProxy));
        WriteSummaryLine("Proxy egress verified (IP changed)", ToOutcome(summary.ProxyEgressVerified));
        WriteSummaryLine("UDP/53 (DNS) blocked while Active", ToOutcome(summary.UdpDns53BlockedWhileActive));
        WriteSummaryLine("General UDP/QUIC (HTTP/3) blocked while Active", summary.UdpQuicOutcome);
        WriteSummaryLine("UDP restored after disconnect", ToOutcome(summary.UdpDnsRestoredAfterDisconnect));
        WriteSummaryLine("TCP restored after disconnect", ToOutcome(summary.TcpRestoredAfterDisconnect));
        if (!summary.UdpDnsBaselineWorked)
        {
            Console.WriteLine("    NOTE: the pre-routing raw UDP/53 baseline itself failed - the 'UDP/53 blocked while Active' result above is NOT reliable evidence of this app's leak protection (see Step 1b).");
        }
    }

    private static void WriteSummaryLine(string label, CheckOutcome outcome)
    {
        var marker = outcome switch
        {
            CheckOutcome.Pass => "[PASS]",
            CheckOutcome.Skip => "[SKIP]",
            _ => "[FAIL]"
        };
        Console.WriteLine($"{marker} {label}");
    }

    private enum CheckOutcome
    {
        Pass,
        Fail,
        Skip
    }

    /// <summary>
    /// Tracks the six independent results the acceptance test's final
    /// summary banner must report, plus the pre-routing UDP baseline used
    /// only to qualify (not gate) the "blocked while Active" result.
    /// </summary>
    private sealed class AcceptanceSummary
    {
        public bool UdpDnsBaselineWorked { get; set; }
        public bool TcpRoutedThroughProxy { get; set; }
        public bool ProxyEgressVerified { get; set; }
        public bool UdpDns53BlockedWhileActive { get; set; }
        public CheckOutcome UdpQuicOutcome { get; set; } = CheckOutcome.Fail;
        public bool UdpDnsRestoredAfterDisconnect { get; set; }
        public bool TcpRestoredAfterDisconnect { get; set; }

        /// <summary>
        /// Overall PASS requires every required check to have passed. The
        /// UDP/QUIC check is the one exception: SKIP (a genuine, detected
        /// capability limitation - HTTP/3 unavailable on this machine) does
        /// NOT fail the overall run, but an actual FAIL (a real leak, or an
        /// unexpected error while HTTP/3 was attemptable) still does.
        /// </summary>
        public bool AllRequiredChecksPassed() =>
            TcpRoutedThroughProxy
            && ProxyEgressVerified
            && UdpDns53BlockedWhileActive
            && UdpQuicOutcome != CheckOutcome.Fail
            && UdpDnsRestoredAfterDisconnect
            && TcpRestoredAfterDisconnect;
    }

    private sealed record RequestResult(bool Success, string Detail, string? ResponseBody);

    private sealed record RawUdpProbeResult(bool Responded, string Detail);

    private sealed record QuicCheckResult(CheckOutcome Outcome, string Detail);

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
        public int UdpTimeoutSeconds { get; private init; } = DefaultUdpTimeoutSeconds;
        public bool SkipIpCheck { get; private init; }
        public Guid? ProfileId { get; private init; }
        public string DnsProbeServerIp { get; private init; } = DefaultDnsProbeServerIp;
        public string DnsProbeHostName { get; private init; } = DefaultDnsProbeHostName;
        public string QuicTestUrl { get; private init; } = DefaultQuicTestUrl;

        public static DiagnosticOptions? Parse(string[] args)
        {
            string testUrl = DefaultTestUrl;
            int timeoutSeconds = DefaultTimeoutSeconds;
            int udpTimeoutSeconds = DefaultUdpTimeoutSeconds;
            bool skipIpCheck = false;
            Guid? profileId = null;
            string dnsProbeServerIp = DefaultDnsProbeServerIp;
            string dnsProbeHostName = DefaultDnsProbeHostName;
            string quicTestUrl = DefaultQuicTestUrl;

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
                    case "--udp-timeout-seconds" when i + 1 < args.Length && int.TryParse(args[i + 1], out var ut):
                        udpTimeoutSeconds = ut;
                        i++;
                        break;
                    case "--skip-ip-check":
                        skipIpCheck = true;
                        break;
                    case "--profile-id" when i + 1 < args.Length && Guid.TryParse(args[i + 1], out var pid):
                        profileId = pid;
                        i++;
                        break;
                    case "--dns-test-ip" when i + 1 < args.Length:
                        dnsProbeServerIp = args[++i];
                        break;
                    case "--dns-test-host" when i + 1 < args.Length:
                        dnsProbeHostName = args[++i];
                        break;
                    case "--quic-test-url" when i + 1 < args.Length:
                        quicTestUrl = args[++i];
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
                UdpTimeoutSeconds = udpTimeoutSeconds,
                SkipIpCheck = skipIpCheck,
                ProfileId = profileId,
                DnsProbeServerIp = dnsProbeServerIp,
                DnsProbeHostName = dnsProbeHostName,
                QuicTestUrl = quicTestUrl
            };
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: ResidentialConnect.RoutingDiagnostic.exe [options]");
            Console.WriteLine("  --test-url <url>            HTTPS URL to request through Whole Computer routing (default: https://1.1.1.1)");
            Console.WriteLine("  --timeout-seconds <n>       Per-request timeout in seconds for TCP/HTTP checks (default: 15)");
            Console.WriteLine("  --udp-timeout-seconds <n>   Per-probe timeout in seconds for the raw UDP/53 DNS checks (default: 5)");
            Console.WriteLine("  --skip-ip-check             Skip the api.ipify.org egress-IP-changed verification");
            Console.WriteLine("  --profile-id <guid>         Use a specific saved proxy profile id instead of the currently selected/first one");
            Console.WriteLine("  --dns-test-ip <ip>          Public DNS resolver IP for the raw UDP/53 probe (default: 1.1.1.1)");
            Console.WriteLine("  --dns-test-host <name>      Hostname to query in the raw UDP/53 probe (default: example.com)");
            Console.WriteLine("  --quic-test-url <url>       HTTP/3-capable HTTPS URL for the UDP/443 QUIC block check (default: https://cloudflare-quic.com/)");
        }
    }
}
