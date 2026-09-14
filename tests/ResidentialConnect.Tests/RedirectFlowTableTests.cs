using System.Net;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="RedirectFlowTable"/> in its
/// <see cref="Core.Abstractions.IOriginalDestinationResolver"/> role (used by
/// <c>TransparentForwardingProxy</c>) plus its cleanup/eviction behavior
/// (used by <c>WinDivertSystemTrafficRouter</c> to bound memory growth).
/// </summary>
public class RedirectFlowTableTests
{
    [Fact]
    public void TryResolve_KnownClientPort_ReturnsRecordedDestination()
    {
        var table = new RedirectFlowTable();
        table.Record(51000, "93.184.216.34", 443);

        var resolved = table.TryResolve(new IPEndPoint(IPAddress.Parse("10.0.0.5"), 51000), out var host, out var port);

        Assert.True(resolved);
        Assert.Equal("93.184.216.34", host);
        Assert.Equal(443, port);
    }

    [Fact]
    public void TryResolve_IsNonDestructive_CanBeCalledMultipleTimesForTheSameFlow()
    {
        // Unlike a single-use NAT table, TransparentForwardingProxy's one
        // lookup must not remove the entry the packet-level router keeps
        // needing for the rest of the flow's lifetime.
        var table = new RedirectFlowTable();
        table.Record(51000, "93.184.216.34", 443);
        var endpoint = new IPEndPoint(IPAddress.Parse("10.0.0.5"), 51000);

        Assert.True(table.TryResolve(endpoint, out _, out _));
        Assert.True(table.TryResolve(endpoint, out _, out _));
    }

    [Fact]
    public void TryResolve_UnknownClientPort_ReturnsFalse_FailClosedFriendly()
    {
        var table = new RedirectFlowTable();

        var resolved = table.TryResolve(new IPEndPoint(IPAddress.Loopback, 12345), out var host, out var port);

        Assert.False(resolved);
        Assert.Equal(string.Empty, host);
        Assert.Equal(0, port);
    }

    [Fact]
    public void Remove_ThenTryResolve_ReturnsFalse()
    {
        var table = new RedirectFlowTable();
        table.Record(51000, "93.184.216.34", 443);

        table.Remove(51000);

        Assert.False(table.TryGetFlow(51000, out _, out _));
    }

    [Fact]
    public void Clear_RemovesAllTrackedFlows()
    {
        var table = new RedirectFlowTable();
        table.Record(51000, "93.184.216.34", 443);
        table.Record(51001, "93.184.216.35", 443);

        table.Clear();

        Assert.False(table.TryGetFlow(51000, out _, out _));
        Assert.False(table.TryGetFlow(51001, out _, out _));
    }

    [Fact]
    public void EvictIdle_DoesNotRemoveRecentlyTouchedFlows()
    {
        var table = new RedirectFlowTable();
        table.Record(51000, "93.184.216.34", 443);
        table.TryGetFlow(51000, out _, out _); // touches LastSeenUtc

        table.EvictIdle();

        Assert.True(table.TryGetFlow(51000, out _, out _));
    }
}
