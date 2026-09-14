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
    [Fact]
    public void BuildForwardFilter_ExcludesImpostorAndLoopback_ToPreventReinterceptionLoops()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080);

        Assert.Contains("!loopback", filter);
        Assert.Contains("!impostor", filter);
        Assert.Contains("outbound", filter);
    }

    [Fact]
    public void BuildForwardFilter_ExcludesTrafficToTheUpstreamProxyItself()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("198.51.100.10") }, 8080);

        Assert.Contains("198.51.100.10", filter);
        Assert.Contains("8080", filter);
        Assert.Contains("not (", filter);
    }

    [Fact]
    public void BuildForwardFilter_MultipleProxyAddresses_OrsThemTogether()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(
            new[] { IPAddress.Parse("198.51.100.10"), IPAddress.Parse("198.51.100.11") },
            8080);

        Assert.Contains("198.51.100.10", filter);
        Assert.Contains("198.51.100.11", filter);
        Assert.Contains(" or ", filter);
    }

    [Fact]
    public void BuildForwardFilter_DeduplicatesRepeatedAddresses()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(
            new[] { IPAddress.Parse("198.51.100.10"), IPAddress.Parse("198.51.100.10") },
            8080);

        var occurrences = filter.Split("198.51.100.10").Length - 1;
        Assert.Equal(1, occurrences);
    }

    [Fact]
    public void BuildForwardFilter_IgnoresIPv6Addresses_UsesOnlyIPv4()
    {
        var filter = BypassFilterBuilder.BuildForwardFilter(
            new[] { IPAddress.Parse("198.51.100.10"), IPAddress.Parse("2001:db8::1") },
            8080);

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
            BypassFilterBuilder.BuildForwardFilter(new[] { IPAddress.Parse("2001:db8::1") }, 8080));
    }

    [Fact]
    public void BuildForwardFilter_EmptyAddressList_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            BypassFilterBuilder.BuildForwardFilter(Array.Empty<IPAddress>(), 8080));
    }

    [Fact]
    public void BuildReturnFilter_MatchesLoopbackAndTheGivenRelayPort()
    {
        var filter = BypassFilterBuilder.BuildReturnFilter(54321);

        Assert.Contains("loopback", filter);
        Assert.Contains("54321", filter);
        Assert.DoesNotContain("!loopback", filter);
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
}
