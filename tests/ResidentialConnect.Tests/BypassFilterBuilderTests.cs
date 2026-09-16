using System.Net;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the pure WinDivert filter-string construction logic - the part
/// of the whole-computer routing design that can be fully verified without a
/// real Windows machine/driver. These assert the exact loop-prevention /
/// self-exclusion clauses required by the product brief ("Residential
/// Connect's own upstream proxy connection must bypass its own interception
/// path") and the DNS leak-protection filter.
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
    public void BuildDnsFilter_IsUnchangedByTheUdpBlockAddition()
    {
        // Standing instruction: the 2026-09-16 general UDP-block handle must
        // be strictly additive and must never alter the already-verified
        // DNS-block filter string.
        var filter = BypassFilterBuilder.BuildDnsFilter();

        Assert.Equal("outbound and !loopback and !impostor and udp and udp.DstPort == 53", filter);
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
}
