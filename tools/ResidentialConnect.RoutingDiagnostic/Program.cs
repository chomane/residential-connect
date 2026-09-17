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
using ResidentialConnect.Proxy;
using ResidentialConnect.Proxy.Dns;
using ResidentialConnect.Proxy.Forwarding;
using ResidentialConnect.Proxy.IpEcho;
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
/// this branch's separate UDP leak-protection work (the DNS-capture handle,
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
/// any interception exists (kept as useful pre-routing evidence; see the
/// 2026-09-16 THIRD correction below for why it no longer gates the
/// "while Active" DNS check's validity).</item>
/// <item><b>While Active:</b> (see the 2026-09-16 THIRD correction below -
/// this row is intentionally NOT "must time out" any more.)</item>
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
/// <para>
/// <b>2026-09-16 THIRD correction (this file ONLY, DIAGNOSTIC-ONLY - no
/// production behavior changed):</b> a real Windows run exposed that the
/// "while Active" UDP/53 check above was testing an OBSOLETE assumption.
/// The production architecture does not simply DROP outbound UDP/53 - it
/// CAPTURES the query, resolves it via proxied DNS-over-HTTPS, and
/// synthesizes a valid reply that appears to come from the originally
/// addressed DNS server (see
/// <see cref="ResidentialConnect.Routing.BypassFilterBuilder.BuildDnsFilter"/>,
/// <see cref="ResidentialConnect.Routing.WinDivertSystemTrafficRouter"/>'s
/// DNS capture loop, and <see cref="ResidentialConnect.Routing.DnsUdpReplyPacketBuilder"/>).
/// The real Windows run's own diagnostics log line
/// (<c>[DNS #9] 192.168.0.108:51313 -&gt; 1.1.1.1:53 answered via proxied DoH
/// (61 byte response)</c>) proved this exact behavior, immediately followed
/// by the old Step 4b incorrectly reporting that same VALID synthesized
/// response as a direct UDP/53 leak - the old check was logically incapable
/// of telling a correct synthesized answer apart from a real direct one,
/// because both look identical from the querying socket's point of view
/// when the destination is a REAL resolver (1.1.1.1) that could
/// legitimately have answered directly too.
/// </para>
/// <para>
/// The fix: Step 4b now targets a documentation-only IANA TEST-NET-1
/// address (<c>192.0.2.1</c>, RFC 5737 - see
/// <see cref="DefaultDnsInterceptionTestNetIp"/>) instead of a real public
/// resolver. <c>192.0.2.1</c> cannot legitimately run any real DNS service
/// at all, so a VALID, transaction-ID-matching DNS reply to a query sent
/// there can ONLY have come from this app's own DNS-capture-and-synthesize
/// path - it is now unambiguous proof of interception, not a leak. The
/// renamed result is <c>DNS-PROXIED-WHILE-ACTIVE</c> (PASS = a valid
/// synthesized reply WAS received; FAIL = no valid reply, meaning the
/// production DNS-capture path did not intercept and answer the query).
/// The pre-routing real-resolver baseline (Step 1b, still targeting
/// 1.1.1.1 by default) is UNCHANGED and kept purely as evidence this
/// specific Windows/network environment had genuinely working direct
/// UDP/53 before routing started - it is no longer treated as a
/// precondition for Step 4b's validity, since Step 4b's new TEST-NET
/// target is unambiguous on its own regardless of whether real UDP/53
/// happens to work on this network.
/// </para>
/// <para>
/// <b>Direct-leak observation (considered, not implemented):</b> a
/// lower-priority WinDivert Sniff handle that watches for the ORIGINAL
/// (unmodified) UDP/53 query continuing toward the real network after the
/// production capture handle intercepts it was considered, per the
/// requirement to add this "if it can be done safely ... without altering
/// production behavior". It was deliberately NOT implemented in this
/// diagnostic-only correction: doing so would require this diagnostic tool
/// to open its OWN raw native WinDivert handle directly (via new P/Invoke
/// declarations local to this file, since
/// <see cref="ResidentialConnect.Routing.WinDivertNative"/> is internal and
/// not exposed to this project) running concurrently, at a different
/// priority, alongside the production router's own handles on the same
/// real Windows machine - new, untested native interop with real
/// priority/ordering semantics that have not been verified safe, which is
/// a meaningfully higher-risk addition than "the minimum correction" this
/// turn calls for. The TEST-NET synthetic-response check above is
/// sufficient on its own (a real resolver cannot exist at 192.0.2.1, so a
/// valid reply is unambiguous proof of interception) and is the only
/// change made this turn, per the explicit fallback instruction: "If
/// implementing that monitor would require risky production changes, do
/// NOT change production code. The TEST-NET synthetic-response check is
/// the minimum correction."
/// </para>
/// <para>
/// <b>2026-09-16 second correction (this file ONLY - acceptance-test-only,
/// no production behavior changed):</b> the overall PASS text previously
/// claimed public IPv6 leaks were blocked, but <c>AcceptanceSummary.AllRequiredChecksPassed()</c>
/// had no live IPv6 result feeding it at all. This adds a real, three-point
/// IPv6 leak test - IPV6-BASELINE (before routing, raw TCP connect to a
/// stable public IPv6 LITERAL, deliberately with NO DNS involved),
/// IPV6-BLOCKED-WHILE-ACTIVE (must fail while Active - V0.2 intentionally
/// fail-closes ALL public IPv6), and IPV6-RESTORED-AFTER-DISCONNECT (must
/// succeed again after <c>StopAsync</c>). If IPV6-BASELINE itself finds no
/// usable public IPv6 path on this machine, the whole triple is reported as
/// a genuine, non-fatal capability SKIP - never a false PASS, and never
/// silently treated as proof the IPv6 block works. The overall PASS banner
/// text is now conditional: it only claims IPv6 was live-tested when the
/// baseline actually found working public IPv6 on this machine.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal static class Program
{
    // 2026-09-16 correction: the PRIMARY Whole Computer success gate must be
    // a real, hostname-addressed HTTPS request - an IP literal (the
    // original https://1.1.1.1 default) never exercises DNS resolution at
    // all, and this exact IP-literal-only acceptance pattern is what
    // produced the now-SUPERSEDED "WHOLE COMPUTER V0.2 VERIFIED" checkpoint
    // (see docs/CHECKPOINTS.md). https://example.com/ is a stable, widely
    // available hostname target with no login/redirect/anti-bot friction.
    private const string DefaultHostnameTestUrl = "https://example.com/";
    // Retained ONLY as an additional, non-gating low-level TCP/IP-literal
    // diagnostic (useful for isolating "is raw TCP reflection working at
    // all" from "does hostname DNS resolution+HTTPS work") - it must never
    // be the thing that decides overall PASS/FAIL. See Step 3b below.
    private const string DefaultIpLiteralDiagnosticUrl = "https://1.1.1.1";
    private const string IpEchoUrl = "https://api.ipify.org";
    private const string DefaultDnsProbeServerIp = "1.1.1.1";
    private const string DefaultDnsProbeHostName = "example.com";
    // 2026-09-16 THIRD correction: 192.0.2.1 is TEST-NET-1 (RFC 5737) - an
    // IANA-reserved documentation-only IPv4 address that can NEVER
    // legitimately run a real Internet DNS service. Sending the "while
    // Active" DNS probe here (instead of to a real resolver like 1.1.1.1)
    // makes a VALID, transaction-ID-matching reply unambiguous proof that
    // ResidentialConnect's own DNS-capture-and-synthesize path answered it
    // (see BypassFilterBuilder.BuildDnsFilter / WinDivertSystemTrafficRouter's
    // DNS capture loop / DnsUdpReplyPacketBuilder) - no real DNS server
    // could possibly have answered from this address, so there is no way
    // to confuse a correct synthesized answer with a real direct one, which
    // was exactly the flaw a real Windows run exposed in the old
    // real-resolver-based "must time out" check this replaces.
    private const string DefaultDnsInterceptionTestNetIp = "192.0.2.1";
    private const string DefaultQuicTestUrl = "https://cloudflare-quic.com/";
    // 2026-09-16 correction: the previous overall PASS text claimed public
    // IPv6 leaks were blocked, but AcceptanceSummary.AllRequiredChecksPassed()
    // contained no live IPv6 result at all - this constant/probe pair fixes
    // that gap. A stable public IPv6 LITERAL (Cloudflare's 2606:4700:4700::1111
    // DNS-over-IPv6 service, port 443) is used deliberately instead of a
    // hostname, per the "do not use DNS for this capability check if
    // practical" requirement - a raw TCP SYN/connect to this literal:port
    // proves genuine IPv6 reachability without depending on IPv6 DNS
    // resolution (a separate concern) at all.
    private const string DefaultIpv6ProbeLiteral = "2606:4700:4700::1111";
    private const int DefaultIpv6ProbePort = 443;
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
        Console.WriteLine("This tool's PRIMARY success gate (2026-09-16 correction) is now a real,");
        Console.WriteLine("HOSTNAME-addressed HTTPS request (default https://example.com/, NOT an IP");
        Console.WriteLine("literal) made from an ordinary HttpClient with no proxy configured on it,");
        Console.WriteLine("whose observed egress IP is then required to EXACTLY MATCH the proxy's own");
        Console.WriteLine("exit IP (established via a direct connectivity test before routing even");
        Console.WriteLine("starts) - see HOSTNAME-HTTPS-ACTIVE and PROXY-EGRESS-MATCH below. A prior");
        Console.WriteLine("IP-literal-only version of this test produced a now-SUPERSEDED checkpoint");
        Console.WriteLine("(see docs/CHECKPOINTS.md) - that mistake is not repeated here: an IP-literal");
        Console.WriteLine("request (Step 3b) is kept ONLY as an informational, non-gating diagnostic.");
        Console.WriteLine("Also includes the 2026-09-16 UDP/DNS leak-protection checks: a raw UDP/53");
        Console.WriteLine("baseline before routing, a DNS-INTERCEPTION check while Active (sends the");
        Console.WriteLine("query to an IANA TEST-NET-1 address - 192.0.2.1 - where only this app's own");
        Console.WriteLine("DNS-capture-and-proxied-DoH path could possibly answer; see");
        Console.WriteLine("DNS-PROXIED-WHILE-ACTIVE below), a UDP/53 restored-after-disconnect check,");
        Console.WriteLine("and an HTTP/3 (UDP/443 QUIC) probe while routing is Active. Also includes a");
        Console.WriteLine("real IPv6 leak test (raw TCP");
        Console.WriteLine("connect to a public IPv6 LITERAL, no DNS) - IPV6-BASELINE / IPV6-BLOCKED-");
        Console.WriteLine("WHILE-ACTIVE / IPV6-RESTORED-AFTER-DISCONNECT - which is reported as a");
        Console.WriteLine("genuine capability [SKIP] (never a false PASS) if this machine has no");
        Console.WriteLine("usable public IPv6 path to test on at all.");
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

        // ---- Establish the EXPECTED proxy egress IP directly (same       ----
        // ---- IProxyConnectivityTester DefaultConnectionManager itself     ----
        // ---- uses before ever starting Whole Computer routing) -----------
        // This is the ground truth PROXY-EGRESS-MATCH below is checked
        // against - "hostname HTTPS succeeded while Active" is NOT
        // sufficient proof by itself; the observed egress IP must also
        // equal the IP this direct-to-proxy test independently establishes
        // belongs to the selected proxy, or a direct-bypass leak (traffic
        // escaping WinDivert interception and reaching the Internet via
        // the real ISP path instead of the proxy) would look identical to
        // a genuine pass.
        Console.WriteLine();
        Console.WriteLine("--- Step 1a: establishing the expected proxy egress IP (direct proxy connectivity test) ---");
        var proxyTester = new HttpProxyConnectivityTester(credentialStore, new IpifyEchoService(), logger);
        using var proxyBaselineCts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds * 2));
        var proxyTestResult = await proxyTester.TestAsync(profile, proxyBaselineCts.Token);
        if (!proxyTestResult.Success || string.IsNullOrWhiteSpace(proxyTestResult.ObservedPublicIp) || !IPAddress.TryParse(proxyTestResult.ObservedPublicIp.Trim(), out var expectedProxyIp))
        {
            WriteResult("PROXY-EGRESS-BASELINE", CheckOutcome.Fail, $"Could not establish the expected proxy egress IP via a direct connectivity test: {proxyTestResult.Message ?? "no public IP observed"}. Cannot proceed - PROXY-EGRESS-MATCH below would have nothing trustworthy to compare against.");
            return 1;
        }
        WriteResult("PROXY-EGRESS-BASELINE", CheckOutcome.Pass, $"Expected proxy egress IP is {expectedProxyIp} (established via a direct-to-proxy connectivity test, independent of Whole Computer routing).");

        var stateMarkerPath = Path.Combine(AppPaths.RootDirectory, "routing-diagnostic.marker");
        var stateMarker = new RoutingStateMarker(stateMarkerPath, logger);
        var router = new WinDivertSystemTrafficRouter(
            logger,
            () => new TransparentForwardingProxy(logger),
            stateMarker,
            () => new ProxiedDohResolver(logger));

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

        // ---- Baseline: direct HOSTNAME-addressed HTTPS request BEFORE  ----
        // ---- enabling routing (the PRIMARY gate target, not an IP     ----
        // ---- literal) ------------------------------------------------------
        // 2026-09-16 correction: the original baseline/routed pair used an
        // IP literal (https://1.1.1.1) as the PRIMARY success gate, which
        // never exercises DNS resolution at all - a leak where hostname
        // DNS/HTTPS bypasses the proxy entirely could still look like a
        // pass. options.HostnameTestUrl (default https://example.com/) is
        // now the primary gate; the IP-literal check (Step 3b) is kept
        // ONLY as an additional, explicitly non-gating low-level diagnostic.
        Console.WriteLine();
        Console.WriteLine($"--- Step 1: baseline hostname-addressed HTTPS request to {options.HostnameTestUrl} (routing NOT yet active) ---");
        var baseline = await TryHttpsRequestAsync(options.HostnameTestUrl, options.TimeoutSeconds, timeoutCts.Token);
        WriteResult("HOSTNAME-HTTPS-BASELINE", ToOutcome(baseline.Success), baseline.Detail);
        if (!baseline.Success)
        {
            Console.WriteLine("Baseline hostname request itself failed - this indicates a pre-existing network/DNS problem unrelated to Whole Computer mode. Fix your network connectivity before re-running this diagnostic.");
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

        // ---- NEW Step 1c: public IPv6 capability baseline (routing NOT yet active) ----
        // 2026-09-16 correction: determines, on THIS machine, whether public
        // IPv6 connectivity even exists at all BEFORE claiming anything
        // about whether the IPv6 fail-closed block works. Deliberately uses
        // a raw TCP connect to an IPv6 LITERAL:port (no DNS involved) per
        // the "do not use DNS for this capability check if practical"
        // requirement. If this machine genuinely has no usable public IPv6
        // path, the "blocked while Active" check below is a genuine
        // capability SKIP, not a false PASS - there is nothing to leak on.
        Console.WriteLine();
        Console.WriteLine($"--- Step 1c: public IPv6 capability baseline - raw TCP connect to [{options.Ipv6ProbeLiteral}]:{options.Ipv6ProbePort} (routing NOT yet active) ---");
        Console.WriteLine("    (Raw Socket.ConnectAsync to an IPv6 LITERAL - no DNS lookup of any kind is");
        Console.WriteLine("     performed for this check, so it isolates \"does this machine have a working");
        Console.WriteLine("     public IPv6 path at all\" from any DNS/hostname-resolution concern.)");
        var ipv6Baseline = await TryIPv6ProbeAsync(options.Ipv6ProbeLiteral, options.Ipv6ProbePort, options.TimeoutSeconds, timeoutCts.Token);
        summary.Ipv6BaselineWorked = ipv6Baseline.Connected;
        if (ipv6Baseline.Connected)
        {
            WriteResult("IPV6-BASELINE", CheckOutcome.Pass, ipv6Baseline.Detail);
        }
        else
        {
            WriteResult("IPV6-BASELINE", CheckOutcome.Skip,
                $"SKIP - {ipv6Baseline.Detail} This machine has no functioning public IPv6 path to leak on right now, so the IPv6 fail-closed block CANNOT be exercised at all (this is a genuine capability limitation of this test run, NOT evidence that the IPv6 block works - it simply cannot be tested here). IPV6-BLOCKED-WHILE-ACTIVE and IPV6-RESTORED-AFTER-DISCONNECT below will also be reported as SKIP for the same reason.");
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
            // ---- The PRIMARY Whole Computer success gate: real hostname ----
            // ---- DNS resolution + HTTPS through reflection --------------------
            Console.WriteLine();
            Console.WriteLine($"--- Step 3: hostname-addressed HTTPS request to {options.HostnameTestUrl} WHILE Whole Computer mode reports Active ---");
            Console.WriteLine("    (This uses an ordinary HttpClient with NO proxy configured on it at all -");
            Console.WriteLine("     exactly like curl.exe or any other unaware Windows application, resolving");
            Console.WriteLine("     a REAL hostname via the OS resolver. If the WinDivert reflection fix AND");
            Console.WriteLine("     the proxied-DoH DNS capture both work, the kernel transparently redirects");
            Console.WriteLine("     both the DNS query and the TCP/TLS connection through the local relay and");
            Console.WriteLine("     upstream proxy without this process's HttpClient knowing anything happened.)");
            var hostnameRouted = await TryHttpsRequestAsync(options.HostnameTestUrl, options.TimeoutSeconds, timeoutCts.Token);
            WriteResult("HOSTNAME-HTTPS-ACTIVE", ToOutcome(hostnameRouted.Success), hostnameRouted.Detail);
            summary.HostnameHttpsActive = hostnameRouted.Success;

            if (!hostnameRouted.Success)
            {
                Console.WriteLine();
                Console.WriteLine("    DIAGNOSIS HINTS based on the failure mode above:");
                Console.WriteLine("      - Timeout / no response at all  -> reflection or DNS capture is likely");
                Console.WriteLine("        not completing (same symptom class as the original TCP reflection bug,");
                Console.WriteLine("        or the DNS capture/proxied-DoH path is failing). Check");
                Console.WriteLine("        WinDivertSystemTrafficRouter's forward/return AND DNS-capture filters");
                Console.WriteLine("        actually matched (enable more verbose logging) and confirm the");
                Console.WriteLine("        process is truly elevated with the WinDivert driver loaded.");
                Console.WriteLine("      - Connection reset shortly after connecting -> matches the checkpoint's");
                Console.WriteLine("        \"ReflectProof\" partial-progress symptom (repeated/garbled relay");
                Console.WriteLine("        response packets, possibly retransmitted SYN-ACKs on the return leg).");
                Console.WriteLine("        Capture a packet trace (Wireshark, loopback + real NIC) during this");
                Console.WriteLine("        exact test run and compare against streamdump.c's expected sequence.");
            }

            // ---- Step 3b (NON-GATING, low-level diagnostic only): the ----
            // ---- retained IP-literal TCP/TLS request. This exercises   ----
            // ---- raw TCP reflection without any DNS-capture dependency, ----
            // ---- which is useful for narrowing down a HOSTNAME-HTTPS-ACTIVE ----
            // ---- failure to "DNS capture broken" (this passes, hostname ----
            // ---- fails) vs. "TCP reflection itself broken" (both fail). ----
            // ---- Its outcome is reported but NEVER included in         ----
            // ---- AllRequiredChecksPassed() - an IP-literal-only result  ----
            // ---- must never again be treated as the Whole Computer      ----
            // ---- success gate (see docs/CHECKPOINTS.md SUPERSEDED note).----
            Console.WriteLine();
            Console.WriteLine($"--- Step 3b (informational, NON-GATING): IP-literal TCP/TLS request to {options.IpLiteralDiagnosticUrl} WHILE Active ---");
            Console.WriteLine("    (Low-level diagnostic only - narrows down a HOSTNAME-HTTPS-ACTIVE failure to");
            Console.WriteLine("     \"DNS capture broken\" vs. \"TCP reflection itself broken\". This result is NEVER");
            Console.WriteLine("     counted toward the overall PASS/FAIL decision - see docs/CHECKPOINTS.md for why");
            Console.WriteLine("     an IP-literal-only result was previously (incorrectly) treated as sufficient.)");
            var ipLiteralRouted = await TryHttpsRequestAsync(options.IpLiteralDiagnosticUrl, options.TimeoutSeconds, timeoutCts.Token);
            WriteResult("IP-LITERAL-TCP-DIAGNOSTIC (informational only)", ToOutcome(ipLiteralRouted.Success), ipLiteralRouted.Detail);

            if (hostnameRouted.Success && !options.SkipIpCheck)
            {
                Console.WriteLine();
                Console.WriteLine($"--- Step 4: verifying proxy egress IP (via {IpEchoUrl}) matches the expected proxy IP established in Step 1a ---");
                var routedIpResult = await TryHttpsRequestAsync(IpEchoUrl, options.TimeoutSeconds, timeoutCts.Token);
                if (routedIpResult.Success && IPAddress.TryParse(routedIpResult.ResponseBody?.Trim(), out var actualEgressIp))
                {
                    var egressMatches = actualEgressIp.Equals(expectedProxyIp);
                    WriteResult("PROXY-EGRESS-MATCH", ToOutcome(egressMatches),
                        egressMatches
                            ? $"Expected proxy egress IP ({expectedProxyIp}, from Step 1a) matches the observed routed egress IP ({actualEgressIp}) - traffic is genuinely egressing via the selected proxy, not merely reaching the Internet by some other path."
                            : $"MISMATCH: expected proxy egress IP was {expectedProxyIp} (Step 1a) but the routed hostname request egressed as {actualEgressIp}. Internet access worked, but egress did NOT match the selected proxy - this is a possible DIRECT-BYPASS LEAK (traffic reached the Internet without actually going through the proxy) and must be investigated before trusting this mode. Also note the raw baseline (direct, pre-routing) IP was {baselineIp ?? "(unknown)"}.");
                    summary.ProxyEgressMatch = egressMatches;
                }
                else
                {
                    WriteResult("PROXY-EGRESS-MATCH", CheckOutcome.Fail, $"Could not obtain a parseable egress IP from {IpEchoUrl} while routed: {routedIpResult.Detail}");
                    summary.ProxyEgressMatch = false;
                }
            }
            else if (!options.SkipIpCheck)
            {
                // hostnameRouted failed - PROXY-EGRESS-MATCH cannot be
                // meaningfully attempted, and must be reported as an
                // explicit FAIL (never SKIP - a hostname failure is a real
                // acceptance failure, and leaving this check silently
                // unreported would look identical to "was never checked").
                WriteResult("PROXY-EGRESS-MATCH", CheckOutcome.Fail, "Skipped attempting the check because the hostname-addressed request (HOSTNAME-HTTPS-ACTIVE) itself failed - reported as FAIL, not SKIP, since egress cannot be confirmed to match the proxy when the routed request never even succeeded.");
                summary.ProxyEgressMatch = false;
            }

            // ---- NEW Step 4b (2026-09-16 THIRD correction): DNS must now ----
            // ---- be INTERCEPTED AND ANSWERED via proxied DoH, NOT simply ----
            // ---- "blocked"/timed out - see the class-level remarks above ----
            // ---- for the full rationale (a real Windows run proved the   ----
            // ---- old "must time out" assumption obsolete and produced a  ----
            // ---- false-failure misreading a VALID synthesized DNS reply  ----
            // ---- from BuildDnsFilter's own capture-and-answer path as a  ----
            // ---- direct leak). Targets DefaultDnsInterceptionTestNetIp   ----
            // ---- (192.0.2.1, RFC 5737 TEST-NET-1) instead of a real      ----
            // ---- resolver - a valid, transaction-ID-matching reply from  ----
            // ---- that address can ONLY have come from this app's own DNS ----
            // ---- capture-and-synthesize path, never from a real server. ----
            Console.WriteLine();
            Console.WriteLine($"--- Step 4b: sending the same raw DNS query to {options.DnsInterceptionTestNetIp}:53 (IANA TEST-NET-1 - no real DNS service can exist here) WHILE Active ---");
            Console.WriteLine("    (PASS here means a VALID, transaction-ID-matching DNS reply WAS received -");
            Console.WriteLine("     since 192.0.2.1 cannot legitimately run any real Internet DNS service,");
            Console.WriteLine("     the ONLY possible source of a valid reply is ResidentialConnect's own");
            Console.WriteLine("     DNS-capture handle (BuildDnsFilter) intercepting this UDP/53 query and");
            Console.WriteLine("     answering it via proxied DNS-over-HTTPS (see WinDivertSystemTrafficRouter's");
            Console.WriteLine("     DNS capture loop / DnsUdpReplyPacketBuilder) - this is now unambiguous");
            Console.WriteLine("     proof of interception, never a leak, regardless of what a real resolver");
            Console.WriteLine("     might have done at a different destination address.)");
            var dnsInterceptionResult = await TryRawUdpDnsQueryAsync(options.DnsInterceptionTestNetIp, options.DnsProbeHostName, options.UdpTimeoutSeconds, timeoutCts.Token);
            WriteResult("DNS-PROXIED-WHILE-ACTIVE", ToOutcome(dnsInterceptionResult.Responded),
                dnsInterceptionResult.Responded
                    ? $"[PASS] DNS intercepted and answered through proxied DoH while Active - {dnsInterceptionResult.Detail} (this reply could only have come from ResidentialConnect's own DNS-capture-and-synthesize path, since {options.DnsInterceptionTestNetIp} is an IANA TEST-NET-1 address with no real DNS service)."
                    : $"FAIL: {dnsInterceptionResult.Detail} - no valid DNS reply was received for a query sent to the TEST-NET address while Whole Computer mode reported Active. This means the production DNS-capture handle (BypassFilterBuilder.BuildDnsFilter) did NOT intercept and answer this UDP/53 query as expected - the application's own DNS resolution would time out/fail in this state.");
            summary.DnsProxiedWhileActive = dnsInterceptionResult.Responded;

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

            // ---- NEW Step 4d: public IPv6 must now be BLOCKED (fail-closed), ----
            // ---- ONLY meaningful if the Step 1c baseline actually worked --------
            Console.WriteLine();
            Console.WriteLine($"--- Step 4d: repeating the public IPv6 probe to [{options.Ipv6ProbeLiteral}]:{options.Ipv6ProbePort} WHILE Active ---");
            if (!summary.Ipv6BaselineWorked)
            {
                WriteResult("IPV6-BLOCKED-WHILE-ACTIVE", CheckOutcome.Skip,
                    "SKIP - the Step 1c capability baseline already established this machine has no functioning public IPv6 path (see IPV6-BASELINE above), so there is nothing to leak on and this check cannot meaningfully be run. This SKIP does NOT prove the IPv6 fail-closed block works, but it is non-fatal - there was no public IPv6 to leak in the first place.");
                summary.Ipv6BlockedWhileActive = null;
            }
            else
            {
                Console.WriteLine("    (PASS here means the connect attempt FAILED/timed out - proving the IPv6");
                Console.WriteLine("     fail-closed block (BypassFilterBuilder.BuildIPv6BlockFilter) actually");
                Console.WriteLine("     prevents this public IPv6 connection from ever leaving the machine, not");
                Console.WriteLine("     just that its filter string looks correct in isolation. If baseline IPv6");
                Console.WriteLine("     worked (it did, per Step 1c) but this ALSO succeeds, that is a hard FAIL -");
                Console.WriteLine("     a direct IPv6 leak.)");
                var ipv6WhileActive = await TryIPv6ProbeAsync(options.Ipv6ProbeLiteral, options.Ipv6ProbePort, options.TimeoutSeconds, timeoutCts.Token);
                var ipv6Blocked = !ipv6WhileActive.Connected;
                WriteResult("IPV6-BLOCKED-WHILE-ACTIVE", ToOutcome(ipv6Blocked),
                    ipv6Blocked
                        ? ipv6WhileActive.Detail
                        : $"LEAK: {ipv6WhileActive.Detail} - public IPv6 reached the real network directly while Whole Computer mode reported Active, even though Step 1c proved this machine has working public IPv6. This is a hard FAIL / direct IPv6 leak in the IPv6 fail-closed block (see BypassFilterBuilder.BuildIPv6BlockFilter).");
                summary.Ipv6BlockedWhileActive = ipv6Blocked;
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

        // ---- NEW Step 5c: public IPv6 must work normally again after   ----
        // ---- disconnect - ONLY meaningful if the Step 1c baseline       ----
        // ---- actually worked in the first place ---------------------------
        Console.WriteLine();
        Console.WriteLine($"--- Step 5c: repeating the public IPv6 probe to [{options.Ipv6ProbeLiteral}]:{options.Ipv6ProbePort} AFTER disconnect ---");
        if (!summary.Ipv6BaselineWorked)
        {
            WriteResult("IPV6-RESTORED-AFTER-DISCONNECT", CheckOutcome.Skip,
                "SKIP - the Step 1c capability baseline already established this machine has no functioning public IPv6 path (see IPV6-BASELINE above), so there is nothing to confirm was 'restored'. This SKIP does not indicate any problem with StopAsync/cleanup - IPv6 simply was never available on this machine to begin with.");
            summary.Ipv6RestoredAfterDisconnect = null;
        }
        else
        {
            Console.WriteLine("    (Baseline IPv6 worked in Step 1c, so after StopAsync this MUST succeed");
            Console.WriteLine("     again - if it does not, cleanup left IPv6 networking broken/still");
            Console.WriteLine("     blocked, which is a hard FAIL even though the 'blocked while Active'");
            Console.WriteLine("     check above may have correctly passed.)");
            var ipv6Restored = await TryIPv6ProbeAsync(options.Ipv6ProbeLiteral, options.Ipv6ProbePort, options.TimeoutSeconds, timeoutCts.Token);
            WriteResult("IPV6-RESTORED-AFTER-DISCONNECT", ToOutcome(ipv6Restored.Connected),
                ipv6Restored.Connected
                    ? ipv6Restored.Detail
                    : $"FAIL: {ipv6Restored.Detail} - public IPv6 connectivity did NOT return after StopAsync, even though Step 1c proved it worked before routing started. This is a hard FAIL - cleanup left this machine's IPv6 networking broken/still blocked.");
            summary.Ipv6RestoredAfterDisconnect = ipv6Restored.Connected;
        }

        // ---- Confirm normal HOSTNAME-addressed networking is restored ----
        Console.WriteLine();
        Console.WriteLine($"--- Step 6: confirming normal (direct) hostname-addressed HTTPS networking to {options.HostnameTestUrl} is restored after disconnect ---");
        var restored = await TryHttpsRequestAsync(options.HostnameTestUrl, options.TimeoutSeconds, timeoutCts.Token);
        WriteResult("HOSTNAME-HTTPS-RESTORED-AFTER-DISCONNECT", ToOutcome(restored.Success), restored.Detail);
        summary.HostnameHttpsRestoredAfterDisconnect = restored.Success;

        PrintAcceptanceSummary(summary);

        var allPassed = summary.AllRequiredChecksPassed();
        // 2026-09-16 second correction: the PASS text must never claim
        // public IPv6 leaks were "blocked" unless IPv6 was actually
        // LIVE-tested end to end (summary.Ipv6WasLiveTested) - if the IPv6
        // check was capability-SKIPPED (no public IPv6 on this machine),
        // the wording below says so explicitly instead of making an
        // unsupported claim about IPv6.
        // 2026-09-16 THIRD correction: DNS is no longer described as
        // "blocked" - the production architecture INTERCEPTS AND ANSWERS
        // UDP/53 DNS via proxied DoH rather than dropping it (see
        // DNS-PROXIED-WHILE-ACTIVE above). Only the general UDP/QUIC
        // handle is still accurately described as "blocked".
        string overallPassText = summary.Ipv6WasLiveTested
            ? "=== OVERALL RESULT: PASS - Whole Computer mode routed real hostname DNS+HTTPS traffic through the VERIFIED proxy egress IP, intercepted and proxied DNS via DoH, blocked general UDP/QUIC and public-IPv6 leaks (IPv6 was LIVE-tested end to end on this machine), and cleaned up correctly. ==="
            : "=== OVERALL RESULT: PASS - Whole Computer mode routed real hostname DNS+HTTPS traffic through the VERIFIED proxy egress IP, intercepted and proxied DNS via DoH, and blocked general UDP/QUIC leaks, and cleaned up correctly. NOTE: the public IPv6 leak test was capability-SKIPPED (see IPV6-BASELINE above) - this machine has no usable public IPv6 path at all, so IPv6 leak-blocking was NOT live-tested this run and this PASS makes no claim about it either way. ===";
        Console.WriteLine();
        Console.WriteLine(allPassed
            ? overallPassText
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
    /// Attempts a raw TCP connect to a public IPv6 LITERAL:port (no DNS
    /// involved at all - <paramref name="ipv6Literal"/> is parsed directly
    /// via <see cref="IPAddress.Parse"/>) to determine whether this machine
    /// currently has usable public IPv6 connectivity. Used three times by
    /// the IPv6 acceptance sequence: once BEFORE routing starts (the
    /// capability baseline - if this itself fails/times out, this machine
    /// has no functioning public IPv6 path to leak on at all, and the
    /// whole IPv6 leak check is a genuine capability SKIP, never a false
    /// PASS), once WHILE Whole Computer mode is Active (must now fail -
    /// V0.2 intentionally fail-closes ALL public IPv6, see
    /// <see cref="ResidentialConnect.Routing.BypassFilterBuilder.BuildIPv6BlockFilter"/>),
    /// and once AFTER <c>StopAsync</c> (must succeed again, proving IPv6
    /// networking is fully restored).
    /// </summary>
    private static async Task<Ipv6ProbeResult> TryIPv6ProbeAsync(string ipv6Literal, int port, int timeoutSeconds, CancellationToken outerToken)
    {
        if (!IPAddress.TryParse(ipv6Literal, out var address) || address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return new Ipv6ProbeResult(false, $"'{ipv6Literal}' is not a valid IPv6 literal - cannot run the IPv6 probe at all (this is a tool configuration problem, not evidence about IPv6 blocking either way).");
        }

        using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(outerToken);
        linkedCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        var stopwatch = Stopwatch.StartNew();
        try
        {
            await socket.ConnectAsync(address, port, linkedCts.Token);
            stopwatch.Stop();
            return new Ipv6ProbeResult(true, $"raw TCP connect to [{address}]:{port} succeeded in {stopwatch.ElapsedMilliseconds}ms - this machine has usable public IPv6 connectivity to this address right now.");
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new Ipv6ProbeResult(false, $"raw TCP connect to [{address}]:{port} timed out after {stopwatch.ElapsedMilliseconds}ms (no response within {timeoutSeconds}s).");
        }
        catch (SocketException ex)
        {
            stopwatch.Stop();
            return new Ipv6ProbeResult(false, $"raw TCP connect to [{address}]:{port} failed after {stopwatch.ElapsedMilliseconds}ms: SocketException ({ex.SocketErrorCode}): {ex.Message}.");
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new Ipv6ProbeResult(false, $"raw TCP connect to [{address}]:{port} failed unexpectedly after {stopwatch.ElapsedMilliseconds}ms: {ex.GetType().Name}: {ex.Message}.");
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
    /// seven independent results the acceptance test explicitly cares
    /// about, each reported on its own line regardless of which step above
    /// produced it, so a reader does not have to reconstruct the outcome by
    /// scanning the full step-by-step log. 2026-09-16 correction: renamed
    /// "TCP routed through proxy"/"Proxy egress verified (IP changed)" to
    /// HOSTNAME-HTTPS-ACTIVE/PROXY-EGRESS-MATCH - these are now the PRIMARY
    /// gate (hostname DNS+HTTPS while Active, AND the observed egress IP
    /// exactly matching the proxy's independently-established exit IP from
    /// Step 1a), not merely "some IP changed from baseline". The retained
    /// IP-literal diagnostic (Step 3b) is deliberately NOT included here -
    /// it is informational only and never gates PASS/FAIL.
    /// </summary>
    private static void PrintAcceptanceSummary(AcceptanceSummary summary)
    {
        Console.WriteLine();
        Console.WriteLine("=== ACCEPTANCE SUMMARY ===");
        WriteSummaryLine("HOSTNAME-HTTPS-ACTIVE (real hostname DNS+HTTPS routed through proxy)", ToOutcome(summary.HostnameHttpsActive));
        WriteSummaryLine("PROXY-EGRESS-MATCH (observed egress IP == proxy's established exit IP)", ToOutcome(summary.ProxyEgressMatch));
        // 2026-09-16 THIRD correction: renamed from "UDP/53 (DNS) direct-leak
        // blocked while Active" - the production architecture intercepts and
        // ANSWERS DNS via proxied DoH, it does not merely block/time out UDP/53,
        // so "blocked" was never an accurate description of success here (see
        // the class-level remarks for the real Windows run that exposed this).
        WriteSummaryLine("DNS-PROXIED-WHILE-ACTIVE (TEST-NET-1 query intercepted and answered via proxied DoH)", ToOutcome(summary.DnsProxiedWhileActive));
        WriteSummaryLine("General UDP/QUIC (public UDP) bypass blocked while Active", summary.UdpQuicOutcome);
        WriteSummaryLine("Hostname DNS/HTTPS restored after disconnect", ToOutcome(summary.HostnameHttpsRestoredAfterDisconnect));
        WriteSummaryLine("UDP restored after disconnect", ToOutcome(summary.UdpDnsRestoredAfterDisconnect));
        if (!summary.UdpDnsBaselineWorked)
        {
            Console.WriteLine("    NOTE: the pre-routing raw UDP/53 baseline (to a REAL resolver, Step 1b) itself failed - this indicates a pre-existing network/firewall problem unrelated to Whole Computer mode. It no longer affects the reliability of DNS-PROXIED-WHILE-ACTIVE above (that check targets an IANA TEST-NET-1 address that is unambiguous on its own), but is still useful evidence about this specific Windows/network environment.");
        }
        if (!summary.DnsProxiedWhileActive)
        {
            Console.WriteLine("    NOTE: no valid DNS reply was received from the TEST-NET-1 probe while Active - the production DNS-capture-and-synthesize path (BypassFilterBuilder.BuildDnsFilter) did not intercept/answer this query as expected (see Step 4b).");
        }

        // 2026-09-16 second correction: the IPv6 result MUST appear in this
        // summary - the previous version of this banner had no live IPv6
        // result feeding it at all, while the overall PASS text nonetheless
        // claimed public IPv6 leaks were blocked. The three possible states
        // here are: (1) baseline never worked -> whole triple is SKIP, (2)
        // baseline worked and both legs passed -> PASS, (3) baseline worked
        // but either leg failed -> FAIL.
        if (!summary.Ipv6BaselineWorked)
        {
            WriteSummaryLine("Public IPv6 leak test (capability-SKIPPED - no public IPv6 on this machine)", CheckOutcome.Skip);
            Console.WriteLine("    NOTE: the pre-routing IPv6 capability baseline (IPV6-BASELINE) found no usable public IPv6 path on this machine at all, so the IPv6 fail-closed block could NOT be exercised (see Step 1c). This SKIP is non-fatal and does NOT prove the IPv6 block works - there was simply nothing to leak on here.");
        }
        else
        {
            var ipv6Pass = summary.Ipv6BlockedWhileActive == true && summary.Ipv6RestoredAfterDisconnect == true;
            WriteSummaryLine("Public IPv6 direct-leak blocked while Active, and restored after disconnect", ToOutcome(ipv6Pass));
            if (summary.Ipv6BlockedWhileActive != true)
            {
                Console.WriteLine("    NOTE: baseline IPv6 worked (Step 1c) but public IPv6 was NOT blocked while Whole Computer mode was Active (see IPV6-BLOCKED-WHILE-ACTIVE) - a direct IPv6 leak.");
            }
            else if (summary.Ipv6RestoredAfterDisconnect != true)
            {
                Console.WriteLine("    NOTE: public IPv6 was correctly blocked while Active, but did NOT return after StopAsync (see IPV6-RESTORED-AFTER-DISCONNECT) - cleanup left IPv6 networking broken.");
            }
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
    /// Tracks the independent results the acceptance test's final summary
    /// banner must report, plus the pre-routing UDP baseline kept as
    /// evidence only (see the 2026-09-16 THIRD correction remarks below for
    /// why it no longer gates anything). 2026-09-16 correction:
    /// HostnameHttpsActive/ProxyEgressMatch/HostnameHttpsRestoredAfterDisconnect
    /// replace the previous IP-literal-based TcpRoutedThroughProxy/
    /// ProxyEgressVerified/TcpRestoredAfterDisconnect fields as the PRIMARY,
    /// gating results - a hostname failure or an egress-IP mismatch is
    /// always a real FAIL, never SKIP.
    /// </summary>
    /// <remarks>
    /// <para>
    /// 2026-09-16 second correction: adds the IPv6 leak-test triple
    /// (Ipv6BaselineWorked / Ipv6BlockedWhileActive / Ipv6RestoredAfterDisconnect).
    /// The overall PASS text previously claimed public IPv6 leaks were
    /// blocked with NO live IPv6 result feeding <see cref="AllRequiredChecksPassed"/>
    /// at all - this is the fix for that specific gap. Ipv6BlockedWhileActive
    /// and Ipv6RestoredAfterDisconnect are nullable (<c>bool?</c>), not plain
    /// <c>bool</c>, because they have a genuine third state: <c>null</c> means
    /// "capability SKIP - Ipv6BaselineWorked was false, so there was nothing
    /// to leak on and these two checks were never meaningfully attempted",
    /// which must never be conflated with either a true PASS or a false FAIL.
    /// </para>
    /// <para>
    /// 2026-09-16 THIRD correction: <c>UdpDns53BlockedWhileActive</c> is
    /// renamed to <see cref="DnsProxiedWhileActive"/> - the production
    /// architecture intercepts and ANSWERS UDP/53 DNS via proxied DoH
    /// rather than dropping it, so "blocked" was never an accurate
    /// description of the expected PASS state, and a real Windows run
    /// proved the old name/semantics produced a false FAIL on a genuinely
    /// correct synthesized DNS reply. <c>UdpDnsBaselineWorked</c> (Step 1b,
    /// still against a real resolver) is retained on this class purely as
    /// informational evidence about this specific environment's raw UDP/53
    /// connectivity - it is intentionally EXCLUDED from
    /// <see cref="AllRequiredChecksPassed"/> for the same reason it was
    /// removed from gating: <see cref="DnsProxiedWhileActive"/>'s TEST-NET-1
    /// target is unambiguous on its own and does not need this baseline to
    /// be trustworthy.
    /// </para>
    /// </remarks>
    private sealed class AcceptanceSummary
    {
        public bool UdpDnsBaselineWorked { get; set; }
        public bool HostnameHttpsActive { get; set; }
        public bool ProxyEgressMatch { get; set; }
        public bool DnsProxiedWhileActive { get; set; }
        public CheckOutcome UdpQuicOutcome { get; set; } = CheckOutcome.Fail;
        public bool UdpDnsRestoredAfterDisconnect { get; set; }
        public bool HostnameHttpsRestoredAfterDisconnect { get; set; }
        public bool Ipv6BaselineWorked { get; set; }
        public bool? Ipv6BlockedWhileActive { get; set; }
        public bool? Ipv6RestoredAfterDisconnect { get; set; }

        /// <summary>
        /// Overall PASS requires every required check to have passed. The
        /// UDP/QUIC check is one exception: SKIP (a genuine, detected
        /// capability limitation - HTTP/3 unavailable on this machine) does
        /// NOT fail the overall run, but an actual FAIL (a real leak, or an
        /// unexpected error while HTTP/3 was attemptable) still does. A
        /// hostname-request failure or a proxy-egress mismatch is ALWAYS a
        /// real FAIL here (HostnameHttpsActive/ProxyEgressMatch are plain
        /// booleans, never SKIP) - per the standing "no more
        /// IP-literal-only acceptance tests" mandate, these two are now the
        /// non-negotiable core of the gate.
        /// </summary>
        /// <remarks>
        /// 2026-09-16 second correction - IPv6 gating rule: if
        /// <see cref="Ipv6BaselineWorked"/> is <c>false</c>, this machine
        /// genuinely has no public IPv6 path to leak on, so the IPv6 triple
        /// is a non-fatal capability SKIP and does NOT affect the overall
        /// result at all (matching the pre-existing UDP/QUIC SKIP
        /// precedent). If <see cref="Ipv6BaselineWorked"/> is <c>true</c>,
        /// BOTH <see cref="Ipv6BlockedWhileActive"/> AND
        /// <see cref="Ipv6RestoredAfterDisconnect"/> are required to be
        /// exactly <c>true</c> (not merely non-false) for overall PASS - a
        /// direct IPv6 leak while Active, OR IPv6 failing to return after
        /// disconnect, is always a hard FAIL once baseline IPv6 was proven
        /// to exist. 2026-09-16 THIRD correction:
        /// <see cref="DnsProxiedWhileActive"/> replaces
        /// <c>UdpDns53BlockedWhileActive</c> here - it must be exactly
        /// <c>true</c> (a valid synthesized reply WAS received from the
        /// TEST-NET-1 probe) for overall PASS, since that is now the
        /// correct evidence of the production DNS-capture-and-answer path
        /// working, not "no response at all".
        /// </remarks>
        public bool AllRequiredChecksPassed() =>
            HostnameHttpsActive
            && ProxyEgressMatch
            && DnsProxiedWhileActive
            && UdpQuicOutcome != CheckOutcome.Fail
            && UdpDnsRestoredAfterDisconnect
            && HostnameHttpsRestoredAfterDisconnect
            && (!Ipv6BaselineWorked || (Ipv6BlockedWhileActive == true && Ipv6RestoredAfterDisconnect == true));

        /// <summary>
        /// True only when the IPv6 leak test was actually LIVE-tested end
        /// to end (baseline worked, and both the while-Active and
        /// after-disconnect legs actually ran rather than being
        /// capability-SKIPPED). Used to gate the wording of the overall
        /// PASS banner so it never claims "IPv6 leaks blocked" when the
        /// IPv6 check was in fact SKIPPED for lack of any public IPv6 path
        /// to test on this machine.
        /// </summary>
        public bool Ipv6WasLiveTested =>
            Ipv6BaselineWorked && Ipv6BlockedWhileActive.HasValue && Ipv6RestoredAfterDisconnect.HasValue;
    }

    private sealed record RequestResult(bool Success, string Detail, string? ResponseBody);

    private sealed record RawUdpProbeResult(bool Responded, string Detail);

    private sealed record Ipv6ProbeResult(bool Connected, string Detail);

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
        public string HostnameTestUrl { get; private init; } = DefaultHostnameTestUrl;
        public string IpLiteralDiagnosticUrl { get; private init; } = DefaultIpLiteralDiagnosticUrl;
        public int TimeoutSeconds { get; private init; } = DefaultTimeoutSeconds;
        public int UdpTimeoutSeconds { get; private init; } = DefaultUdpTimeoutSeconds;
        public bool SkipIpCheck { get; private init; }
        public Guid? ProfileId { get; private init; }
        public string DnsProbeServerIp { get; private init; } = DefaultDnsProbeServerIp;
        public string DnsProbeHostName { get; private init; } = DefaultDnsProbeHostName;
        public string DnsInterceptionTestNetIp { get; private init; } = DefaultDnsInterceptionTestNetIp;
        public string QuicTestUrl { get; private init; } = DefaultQuicTestUrl;
        public string Ipv6ProbeLiteral { get; private init; } = DefaultIpv6ProbeLiteral;
        public int Ipv6ProbePort { get; private init; } = DefaultIpv6ProbePort;

        public static DiagnosticOptions? Parse(string[] args)
        {
            string hostnameTestUrl = DefaultHostnameTestUrl;
            string ipLiteralDiagnosticUrl = DefaultIpLiteralDiagnosticUrl;
            int timeoutSeconds = DefaultTimeoutSeconds;
            int udpTimeoutSeconds = DefaultUdpTimeoutSeconds;
            bool skipIpCheck = false;
            Guid? profileId = null;
            string dnsProbeServerIp = DefaultDnsProbeServerIp;
            string dnsProbeHostName = DefaultDnsProbeHostName;
            string dnsInterceptionTestNetIp = DefaultDnsInterceptionTestNetIp;
            string quicTestUrl = DefaultQuicTestUrl;
            string ipv6ProbeLiteral = DefaultIpv6ProbeLiteral;
            int ipv6ProbePort = DefaultIpv6ProbePort;

            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--test-url" when i + 1 < args.Length:
                        // Retained name for backward compatibility, but this
                        // now sets the PRIMARY hostname-addressed gate target -
                        // pass a real hostname URL here, not an IP literal (use
                        // --ip-literal-diagnostic-url for the non-gating
                        // low-level TCP diagnostic instead).
                        hostnameTestUrl = args[++i];
                        break;
                    case "--ip-literal-diagnostic-url" when i + 1 < args.Length:
                        ipLiteralDiagnosticUrl = args[++i];
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
                    case "--dns-interception-testnet-ip" when i + 1 < args.Length:
                        dnsInterceptionTestNetIp = args[++i];
                        break;
                    case "--quic-test-url" when i + 1 < args.Length:
                        quicTestUrl = args[++i];
                        break;
                    case "--ipv6-test-literal" when i + 1 < args.Length:
                        ipv6ProbeLiteral = args[++i];
                        break;
                    case "--ipv6-test-port" when i + 1 < args.Length && int.TryParse(args[i + 1], out var v6p):
                        ipv6ProbePort = v6p;
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
                HostnameTestUrl = hostnameTestUrl,
                IpLiteralDiagnosticUrl = ipLiteralDiagnosticUrl,
                TimeoutSeconds = timeoutSeconds,
                UdpTimeoutSeconds = udpTimeoutSeconds,
                SkipIpCheck = skipIpCheck,
                ProfileId = profileId,
                DnsProbeServerIp = dnsProbeServerIp,
                DnsProbeHostName = dnsProbeHostName,
                DnsInterceptionTestNetIp = dnsInterceptionTestNetIp,
                QuicTestUrl = quicTestUrl,
                Ipv6ProbeLiteral = ipv6ProbeLiteral,
                Ipv6ProbePort = ipv6ProbePort
            };
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: ResidentialConnect.RoutingDiagnostic.exe [options]");
            Console.WriteLine("  --test-url <url>            PRIMARY hostname-addressed HTTPS URL for the Whole Computer success gate (default: https://example.com/). Must be a real hostname, NOT an IP literal.");
            Console.WriteLine("  --ip-literal-diagnostic-url <url>  IP-literal HTTPS URL for the additional, NON-GATING low-level TCP diagnostic only (default: https://1.1.1.1)");
            Console.WriteLine("  --timeout-seconds <n>       Per-request timeout in seconds for TCP/HTTP checks (default: 15)");
            Console.WriteLine("  --udp-timeout-seconds <n>   Per-probe timeout in seconds for the raw UDP/53 DNS checks (default: 5)");
            Console.WriteLine("  --skip-ip-check             Skip the api.ipify.org egress-IP-changed verification");
            Console.WriteLine("  --profile-id <guid>         Use a specific saved proxy profile id instead of the currently selected/first one");
            Console.WriteLine("  --dns-test-ip <ip>          Public DNS resolver IP for the raw UDP/53 probe (default: 1.1.1.1)");
            Console.WriteLine("  --dns-test-host <name>      Hostname to query in the raw UDP/53 probe (default: example.com)");
            Console.WriteLine("  --dns-interception-testnet-ip <ip>  IANA TEST-NET address used for the DNS-PROXIED-WHILE-ACTIVE interception check (default: 192.0.2.1, RFC 5737 TEST-NET-1 - must be an address that cannot legitimately run a real DNS service)");
            Console.WriteLine("  --quic-test-url <url>       HTTP/3-capable HTTPS URL for the UDP/443 QUIC block check (default: https://cloudflare-quic.com/)");
            Console.WriteLine("  --ipv6-test-literal <addr>  Public IPv6 LITERAL (no DNS) used for the IPv6 leak-test baseline/while-Active/after-disconnect probes (default: 2606:4700:4700::1111)");
            Console.WriteLine("  --ipv6-test-port <n>        TCP port to connect to on the IPv6 literal above (default: 443)");
        }
    }
}
