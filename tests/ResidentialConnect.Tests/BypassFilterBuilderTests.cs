using System.Net;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the pure WinDivert filter-string construction logic - the part
/// of the whole-computer routing design that can be fully verified without a
/// real Windows machine/driver. These assert the exact loop-prevention /
/// self-exclusion clauses required by the product brief ("Residential
/// Connect's own upstream proxy connection must bypass its own interception
/// path"), the DNS leak-protection filters, and (2026-09-16 correction) the
/// full 8-row filter-partition table's mutual-exclusivity guarantees and the
/// De Morgan-only exclusion rule (never a grouped <c>not (...)</c> around a
/// compound expression - see <see cref="BypassFilterBuilder"/> class remarks
/// "Filter-syntax note").
/// </summary>
public class BypassFilterBuilderTests
{
    private const int RelayPort = 34010;

    [Fact]
    public void BuildForwardFilter_ExcludesLoopback_ButNotImpostor_ToPreventReinterceptionLoopsWithoutBlockingTheClientsHandshakeCompletingAck()
    {
        // 2026-09-15 fix: an isolated single-handle "streamdump parity"
        // diagnostic (tools/ResidentialConnect.StreamdumpParity) proved on
        // real Windows hardware that the client's own final ACK completing
        // a reflected TCP handshake is itself captured with Impostor=True -
        // WinDivert's Impostor flag is a flow-provenance marker (this
        // flow's SYN was itself injected), not a "this exact packet was
        // re-sent unchanged" marker. Excluding !impostor here silently
        // discarded that ACK on every single redirected connection, so
        // TransparentForwardingProxy's AcceptTcpClientAsync could never
        // complete. Loop prevention instead relies on direction (this
        // filter requires "outbound"; every packet this router itself
        // reflects is explicitly marked Inbound before re-injection - see
        // BypassFilterBuilder class remarks) plus PacketRedirectPlanner's
        // own flow-table gate - not a blanket impostor exclusion.
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort);

        Assert.Contains("!loopback", filter);
        Assert.DoesNotContain("!impostor", filter);
        Assert.Contains("outbound", filter);
        Assert.Contains("tcp", filter);
    }

    [Fact]
    public void BuildForwardFilter_ExcludesTrafficToTheUpstreamProxyItself()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort);

        Assert.Contains("198.51.100.10", filter);
        Assert.Contains("8080", filter);
        Assert.Contains(" or ", filter);
    }

    [Fact]
    public void BuildForwardFilter_ExcludesTheRelaysOwnSourcePort()
    {
        // Required by the packet-reflection technique: once the local relay
        // starts replying, its own genuinely-outbound reply packets must not
        // be re-captured by the forward filter and misinterpreted as a new
        // application connection attempt - see BypassFilterBuilder remarks.
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort);

        Assert.Contains($"tcp.SrcPort != {RelayPort}", filter);
    }

    [Fact]
    public void BuildForwardFilter_MultipleProxyAddresses_OrsThemTogether()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(
            new[] { IPAddress.Parse("198.51.100.10"), IPAddress.Parse("198.51.100.11") },
            8080,
            RelayPort);

        Assert.Contains("198.51.100.10", filter);
        Assert.Contains("198.51.100.11", filter);
        Assert.Contains(" or ", filter);
        Assert.Contains(" and ", filter);
    }

    [Fact]
    public void BuildForwardFilter_DeduplicatesRepeatedAddresses()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(
            new[] { IPAddress.Parse("198.51.100.10"), IPAddress.Parse("198.51.100.10") },
            8080,
            RelayPort);

        var occurrences = filter.Split("198.51.100.10").Length - 1;
        Assert.Equal(1, occurrences);
    }

    [Fact]
    public void BuildForwardFilter_IgnoresIPv6Addresses_UsesOnlyIPv4()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(
            new[] { IPAddress.Parse("198.51.100.10"), IPAddress.Parse("2001:db8::1") },
            8080,
            RelayPort);

        Assert.Contains("198.51.100.10", filter);
        Assert.DoesNotContain("2001:db8", filter);
    }

    [Fact]
    public void BuildForwardFilter_NoIPv4AddressAtAll_ThrowsRatherThanBuildingAnUnsafeFilter()
    {
        // Fail-closed at the filter-construction level: refusing to build any
        // filter at all is safer than building one with no self-exclusion
        // clause, which could re-intercept the app's own upstream tunnel.
        Assert.Throws<InvalidOperationException>(() =>
            BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("2001:db8::1") }, 8080, RelayPort));
    }

    [Fact]
    public void BuildForwardFilter_EmptyAddressList_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            BypassFilterBuilder.BuildForwardFilter(Array.Empty<IPAddress>(), 8080, RelayPort));
    }

    [Fact]
    public void BuildForwardFilter_IsExplicitlyScopedToIPv4()
    {
        // Explicit ip-scoping (2026-09-16 correction) so a TCP-over-IPv6
        // packet is never captured here - it is exclusively
        // BuildIPv6BlockFilter's responsibility.
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort);

        Assert.Contains(" ip ", $" {filter} ");
    }

    [Fact]
    public void BuildReturnFilter_MatchesTheGivenRelayPort_AndDoesNotRequireLoopback()
    {
        // Under the reflection technique the relay listens on a real local
        // address and its replies are NOT classified "loopback" by
        // WinDivert (the apparent remote peer is a real, non-local address)
        // - requiring "loopback" here (an earlier, broken revision of this
        // filter) would mean it could never match the relay's actual reply
        // traffic at all.
        var filter = BypassFilterBuilder.BuildReturnFilter(54321);

        Assert.Contains("54321", filter);
        Assert.DoesNotContain("loopback", filter);
    }

    [Fact]
    public void BuildReturnFilter_ExcludesImpostorNoLonger_ToAvoidDroppingTheRelaysAckForEstablishedFlowData()
    {
        // 2026-09-16 fix: a real-Windows production diagnostic run showed
        // the client's TLS ClientHello (ACK,PSH, 673-byte payload) was
        // captured and reflected correctly on the FORWARD leg with
        // Impostor=True, but the RETURN leg never captured the relay's own
        // ACK for that data at all (only the earlier SYN,ACK was ever seen
        // on RETURN) - the client then retransmitted the identical
        // ClientHello segment repeatedly, and the upstream tunnel was torn
        // down with zero bytes ever relayed in either direction. This is
        // the same WinDivert flow-provenance Impostor semantics already
        // fixed on the forward filter (see BuildForwardFilter's own fix and
        // class remarks): the relay's ACK for a flow whose SYN-ACK was
        // itself reflected is ALSO tagged Impostor=True, so "!impostor" on
        // this RETURN filter was silently discarding it. An independent,
        // isolated single-handle streamdump-parity test (extended to verify
        // bidirectional established-flow DATA) already proved basic
        // WinDivert reflection itself carries data correctly in both
        // directions, ruling out a fundamental reflection/checksum/ABI
        // problem and pointing squarely at this filter's own "!impostor"
        // clause. Loop prevention continues to rely on this filter's
        // "outbound" requirement (reflected packets are marked Inbound
        // before re-injection) plus "tcp.SrcPort == relayPort" plus
        // PacketRedirectPlanner.PlanReturn's own flow-table gate - not a
        // blanket impostor exclusion.
        var filter = BypassFilterBuilder.BuildReturnFilter(54321);

        Assert.DoesNotContain("!impostor", filter);
        Assert.Contains("outbound", filter);
        Assert.Contains("tcp.SrcPort == 54321", filter);
    }

    [Fact]
    public void BuildDnsFilter_MatchesPlainUdp53_ExcludesLoopbackAndImpostor()
    {
        var filter = BypassFilterBuilder.BuildDnsFilter();

        Assert.Contains("udp", filter);
        Assert.Contains("53", filter);
        Assert.Contains("!loopback", filter);
        Assert.Contains("!impostor", filter);
    }

    [Fact]
    public void BuildDnsFilter_IsExplicitlyScopedToIPv4()
    {
        // 2026-09-16 correction: the IPv4 DNS filter must explicitly include
        // "ip" so it can never match an IPv6 DNS query - see
        // BuildDnsFilterV6_And_BuildDnsFilter_AreMutuallyExclusive below.
        var filter = BypassFilterBuilder.BuildDnsFilter();

        Assert.Equal("outbound and !loopback and !impostor and ip and udp and udp.DstPort == 53", filter);
    }

    [Fact]
    public void BuildDnsFilterV6_MatchesPlainUdp53_ExcludesLoopbackAndImpostor_IsExplicitlyIpv6Scoped()
    {
        var filter = BypassFilterBuilder.BuildDnsFilterV6();

        Assert.Equal("outbound and !loopback and !impostor and ipv6 and udp and udp.DstPort == 53", filter);
    }

    [Fact]
    public void BuildDnsFilterV6_And_BuildDnsFilter_AreMutuallyExclusive()
    {
        // Correction #1 ("Make IPv4/IPv6 DNS filters mutually exclusive"):
        // WinDivert's "ip" and "ipv6" fields are "Is IPv4?"/"Is IPv6?" and a
        // single packet can never satisfy both (confirmed against
        // reqrypt.org/windivert-doc.html s7's field table) - so as long as
        // each filter string contains its own version scope token, no
        // packet can ever match both handles. This test pins that
        // requirement directly in the generated strings, independent of the
        // real native parser (see the WinDivert-native-parser test below
        // for the Windows-only cross-check).
        var v4Filter = BypassFilterBuilder.BuildDnsFilter();
        var v6Filter = BypassFilterBuilder.BuildDnsFilterV6();

        Assert.Contains(" ip ", $" {v4Filter} ");
        Assert.DoesNotContain("ipv6", v4Filter);
        Assert.Contains("ipv6", v6Filter);
    }

    [Fact]
    public void BuildUdpBlockFilter_MatchesOutboundNonLoopbackUdp_ButExcludesPort53()
    {
        // Port 53 is deliberately excluded here so this handle's Drop rule
        // never overlaps the same packet as BuildDnsFilter's own, separate,
        // unchanged Drop handle (see BuildUdpBlockFilter remarks).
        var filter = BypassFilterBuilder.BuildUdpBlockFilter();

        Assert.Contains("outbound", filter);
        Assert.Contains("!loopback", filter);
        Assert.Contains("udp", filter);
        Assert.Contains("udp.DstPort != 53", filter);
    }

    [Fact]
    public void BuildUdpBlockFilter_DoesNotReferenceTcpAtAll()
    {
        // Fail-safe sanity check that this UDP-only filter cannot possibly
        // match/interfere with the verified TCP forward/return handles.
        var filter = BypassFilterBuilder.BuildUdpBlockFilter();

        Assert.DoesNotContain("tcp", filter);
    }

    [Fact]
    public void BuildUdpBlockFilter_IsExplicitlyScopedToIPv4()
    {
        var filter = BypassFilterBuilder.BuildUdpBlockFilter();

        Assert.Contains(" ip ", $" {filter} ");
    }

    // ------------------------------------------------------------------
    // 2026-09-16 correction: LAN/local bypass (IPv4 TCP row + IPv4 UDP
    // rows), IPv6 fail-closed (all protocols except UDP/53), and
    // unsupported-IPv4 protocol fail-closed. One test per row of the
    // authoritative 8-row filter-partition table (correction #9 / #11:
    // "add unit tests for every filter category above before the Windows
    // run"), further corrected the same day for De Morgan-only exclusions
    // and IPv6/DNS mutual-exclusivity.
    // ------------------------------------------------------------------

    [Fact]
    public void BuildForwardFilter_Row_Ipv4PublicTcp_StillCapturedByTheReflectionEngine()
    {
        // "IPv4 public TCP -> proxy/reflection engine": unchanged base
        // behavior - the forward filter still matches ordinary outbound
        // TCP (the LAN exclusion added below only carves out LAN/local
        // destinations, it does not remove public TCP capture).
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort);

        Assert.Contains("outbound", filter);
        Assert.Contains("tcp", filter);
    }

    [Fact]
    public void BuildForwardFilter_Row_Ipv4LanTcp_IsExcludedFromCapture_UntouchedBypass()
    {
        // "IPv4 LAN TCP -> untouched/bypass": the forward filter must
        // exclude every LAN/local range via per-range De Morgan clauses -
        // NEVER a single grouped "not (...)" around a compound OR (that
        // form was rejected by the real WinDivert parser with Win32 error
        // 87 during live Windows testing - see class remarks "Filter-syntax
        // note").
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort);

        Assert.Contains("10.0.0.0", filter);
        Assert.Contains("172.16.0.0", filter);
        Assert.Contains("192.168.0.0", filter);
        Assert.Contains("169.254.0.0", filter);
        Assert.Contains("127.0.0.0", filter);
        Assert.Contains("224.0.0.0", filter);
        Assert.Contains("255.255.255.255", filter);
        AssertNoGroupedNegationOfCompoundExpression(filter);
    }

    [Fact]
    public void BuildDnsFilter_Row_Udp53Ipv4_IsCapturedRegardlessOfLanOrPublicDestination()
    {
        // "UDP/53 (IPv4 OR IPv6) -> intercepted and answered using proxied
        // DoH": the IPv4 DNS filter must NOT exclude LAN destinations -
        // a LAN router acting as the resolver must still be captured,
        // because it's the query CONTENT (hostnames), not the transport
        // destination, that must never leak.
        var filter = BypassFilterBuilder.BuildDnsFilter();

        Assert.Contains("udp.DstPort == 53", filter);
        Assert.DoesNotContain("10.0.0.0", filter);
        Assert.DoesNotContain("192.168.0.0", filter);
    }

    [Fact]
    public void BuildDnsFilterV6_Row_Udp53Ipv6_IsCapturedRegardlessOfLanOrPublicDestination()
    {
        // "UDP/53 (IPv4 OR IPv6) -> intercepted and answered using proxied
        // DoH": same guarantee as BuildDnsFilter, for IPv6 transport - a
        // Windows-configured DNS server may itself be an IPv6 address (LAN
        // ULA or public), and either way it must be captured, never
        // exempted like BuildIPv6BlockFilter's local-range exemption.
        var filter = BypassFilterBuilder.BuildDnsFilterV6();

        Assert.Contains("ipv6", filter);
        Assert.Contains("udp", filter);
        Assert.Contains("udp.DstPort == 53", filter);
        Assert.Contains("outbound", filter);
        Assert.Contains("!loopback", filter);
        Assert.DoesNotContain("fc00::", filter);
        Assert.DoesNotContain("fe80::", filter);
    }

    [Fact]
    public void BuildUdpBlockFilter_Row_Ipv4PublicNonDnsUdp_IsDropped()
    {
        // "IPv4 public non-DNS UDP -> DROP": already covered by the
        // existing BuildUdpBlockFilter_MatchesOutboundNonLoopbackUdp...
        // test above; this test additionally pins the row-to-filter
        // mapping by name per the authoritative partition table.
        var filter = BypassFilterBuilder.BuildUdpBlockFilter();

        Assert.Contains("udp", filter);
        Assert.Contains("udp.DstPort != 53", filter);
    }

    [Fact]
    public void BuildUdpBlockFilter_Row_Ipv4LanNonDnsUdp_IsExemptedAsBypass()
    {
        // "IPv4 LAN non-DNS UDP -> bypass": the general UDP block must
        // exclude the same shared LAN/local destination ranges used by
        // BuildForwardFilter (per-range De Morgan clauses, never a grouped
        // negation), so LAN UDP (mDNS, SSDP/UPnP, LAN game traffic, etc.)
        // is never blocked.
        var filter = BypassFilterBuilder.BuildUdpBlockFilter();

        Assert.Contains("10.0.0.0", filter);
        Assert.Contains("192.168.0.0", filter);
        AssertNoGroupedNegationOfCompoundExpression(filter);
    }

    [Fact]
    public void BuildIPv6BlockFilter_Row_PublicIpv6AllProtocolsExceptDns_IsDropped()
    {
        // "public IPv6, all protocols -> DROP for V0.2" EXCEPT UDP/53
        // (correction #2: the block must not overlap IPv6 DNS/53, which is
        // exclusively BuildDnsFilterV6's responsibility). Must NOT be
        // scoped to (tcp or udp) only - it must match IPv6 regardless of
        // upper-layer protocol (other than the UDP/53 exemption), since
        // V0.2 proxies no IPv6 transport at all.
        var filter = BypassFilterBuilder.BuildIPv6BlockFilter();

        Assert.Contains("outbound", filter);
        Assert.Contains("!loopback", filter);
        Assert.Contains("ipv6", filter);
        Assert.DoesNotContain("tcp", filter);
    }

    [Fact]
    public void BuildIPv6BlockFilter_ExemptsUdp53_SoItNeverOverlapsTheIpv6DnsCaptureHandle()
    {
        // Correction #2: "The public-IPv6 DROP handle must NOT overlap IPv6
        // DNS/53 ... make BuildIPv6BlockFilter() exclude outbound UDP
        // destination port 53." Written as "(!udp or udp.DstPort != 53)" -
        // a parenthesized OR of two negated single-field tests - NOT the
        // simpler-looking "udp.DstPort != 53" alone, because a
        // protocol-specific field test on a non-UDP packet evaluates false
        // ("fails") per WinDivert's own semantics, which would incorrectly
        // exempt every non-UDP IPv6 packet from this block too.
        var filter = BypassFilterBuilder.BuildIPv6BlockFilter();

        Assert.Contains("udp", filter);
        Assert.Contains("udp.DstPort != 53", filter);
        Assert.Contains("!udp", filter);
    }

    [Fact]
    public void BuildIPv6BlockFilter_And_BuildDnsFilterV6_AreMutuallyExclusive()
    {
        // A genuine outbound, non-loopback IPv6 UDP/53 packet must be
        // capturable by BuildDnsFilterV6 and NEVER also match
        // BuildIPv6BlockFilter (both handles are opened at the same
        // NETWORK layer and would otherwise both independently receive a
        // copy of the same packet, causing it to be silently dropped
        // instead of answered via proxied DoH).
        var dnsV6Filter = BypassFilterBuilder.BuildDnsFilterV6();
        var blockV6Filter = BypassFilterBuilder.BuildIPv6BlockFilter();

        // The DNS filter requires udp.DstPort == 53; the block filter's
        // exemption clause requires "!udp or udp.DstPort != 53" - logically
        // the negation of "udp and udp.DstPort == 53" - so no packet can
        // satisfy both simultaneously.
        Assert.Contains("udp.DstPort == 53", dnsV6Filter);
        Assert.Contains("udp.DstPort != 53", blockV6Filter);
        Assert.Contains("!udp", blockV6Filter);
    }

    [Fact]
    public void BuildIPv6BlockFilter_Row_LocalIpv6_IsExemptedAsBypass()
    {
        // "local IPv6 -> bypass": loopback, link-local, ULA/LAN, and
        // multicast ranges must be explicitly excluded from the block via
        // per-range De Morgan clauses - never a grouped negation.
        var filter = BypassFilterBuilder.BuildIPv6BlockFilter();

        Assert.Contains("::1", filter);
        Assert.Contains("fe80::", filter);
        Assert.Contains("fc00::", filter);
        Assert.Contains("ff00::", filter);
        AssertNoGroupedNegationOfCompoundExpression(filter);
    }

    [Fact]
    public void BuildOtherProtocolBlockFilter_Row_UnsupportedPublicIpv4Protocols_IsDropped()
    {
        // "unsupported public IPv4 protocols -> DROP": e.g. ICMP (protocol
        // 1) must be blocked while Whole Computer mode is Active, since
        // V0.2 has no upstream path for any protocol other than TCP/UDP.
        var filter = BypassFilterBuilder.BuildOtherProtocolBlockFilter();

        Assert.Contains("outbound", filter);
        Assert.Contains("!loopback", filter);
        Assert.Contains("ip.Protocol != 6", filter);
        Assert.Contains("ip.Protocol != 17", filter);
    }

    [Fact]
    public void BuildOtherProtocolBlockFilter_LanTrafficOfAnyProtocol_IsExemptedAsBypass()
    {
        // LAN/local traffic of any protocol (e.g. a ping to the local
        // router) remains allowed - only PUBLIC non-TCP/UDP protocols are
        // blocked. Uses per-range De Morgan clauses, never a grouped
        // negation.
        var filter = BypassFilterBuilder.BuildOtherProtocolBlockFilter();

        Assert.Contains("10.0.0.0", filter);
        Assert.Contains("192.168.0.0", filter);
        AssertNoGroupedNegationOfCompoundExpression(filter);
    }

    [Fact]
    public void BuildOtherProtocolBlockFilter_IsExplicitlyScopedToIPv4()
    {
        var filter = BypassFilterBuilder.BuildOtherProtocolBlockFilter();

        Assert.Contains(" ip ", $" {filter} ");
    }

    // ------------------------------------------------------------------
    // Real WinDivert native-parser validation (Windows-only; a documented
    // no-op everywhere else). Per the explicit instruction: "where
    // possible, use WinDivert's filter compilation helper to validate
    // every generated filter string." WinDivertNative is internal to
    // ResidentialConnect.Routing; ResidentialConnect.Tests is granted
    // access via [InternalsVisibleTo] specifically for this purpose - see
    // ResidentialConnect.Routing.csproj.
    // ------------------------------------------------------------------

    public static IEnumerable<object[]> AllGeneratedFilters()
    {
        yield return new object[] { "BuildForwardFilter", BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080, RelayPort) };
        yield return new object[] { "BuildReturnFilter", BypassFilterBuilder.BuildReturnFilter(RelayPort) };
        yield return new object[] { "BuildDnsFilter", BypassFilterBuilder.BuildDnsFilter() };
        yield return new object[] { "BuildDnsFilterV6", BypassFilterBuilder.BuildDnsFilterV6() };
        yield return new object[] { "BuildUdpBlockFilter", BypassFilterBuilder.BuildUdpBlockFilter() };
        yield return new object[] { "BuildIPv6BlockFilter", BypassFilterBuilder.BuildIPv6BlockFilter() };
        yield return new object[] { "BuildOtherProtocolBlockFilter", BypassFilterBuilder.BuildOtherProtocolBlockFilter() };
    }

    [Theory]
    [MemberData(nameof(AllGeneratedFilters))]
    public void GeneratedFilter_CompilesAgainstTheRealWinDivertParser_OnWindows(string filterName, string filter)
    {
        // On non-Windows hosts (this sandbox), WinDivert.dll cannot be
        // loaded at all - this test is a documented, intentional no-op
        // there (see WinDivertSystemTrafficRouterTests for the established
        // pattern of runtime-guarding native-only assertions with
        // OperatingSystem.IsWindows() rather than an OS-conditional Skip
        // attribute, so the test still runs and passes trivially on every
        // CI OS instead of showing as skipped).
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var compiled = WinDivertNative.TryCompileFilter(filter, WinDivertNative.Layer.Network, out var error, out var errorPosition);

        Assert.True(compiled, $"{filterName} failed to compile against the real WinDivert parser: {error} (position {errorPosition}). Filter: \"{filter}\"");
    }

    /// <summary>
    /// Asserts a filter string never contains a grouped negation of a
    /// compound (multi-clause) expression - i.e. never <c>not (X and Y)</c>
    /// or <c>not (X or Y)</c> - per the real-Windows-verified requirement
    /// that WinDivert's parser rejects that shape with Win32 error 87
    /// (ERROR_INVALID_PARAMETER). A bare <c>not X</c> / <c>!X</c> single-test
    /// negation, or a parenthesized OR of two negated single-field tests
    /// used as one term within a larger "and" chain (e.g.
    /// <c>(ip.DstAddr &lt; low or ip.DstAddr &gt; high)</c>), are both fine -
    /// only "not (" or "!(" immediately followed by a compound group is
    /// disallowed.
    /// </summary>
    private static void AssertNoGroupedNegationOfCompoundExpression(string filter)
    {
        Assert.DoesNotContain("not (", filter);
        Assert.DoesNotContain("!(", filter);
    }
}
