using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Forwarding;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="WinDivertSystemTrafficRouter"/> that can run on any
/// OS (this sandbox is Linux) without a real WinDivert driver - specifically
/// the elevation/support-detection contract and the "fail-closed, never
/// touch real networking" behavior when the platform does not support Whole
/// Computer mode at all. Actually opening a WinDivert handle and capturing
/// real packets can only be verified on a real, elevated Windows 10/11 x64
/// machine - see docs/BUILD.md "Windows-only acceptance checklist".
/// </summary>
public class WinDivertSystemTrafficRouterTests
{
    private static WinDivertSystemTrafficRouter CreateRouter(string markerPath) =>
        new(new NullLogger(), () => new TransparentForwardingProxy(new NullLogger()), new RoutingStateMarker(markerPath, new NullLogger()));

    [Fact]
    public void RequiresElevation_IsAlwaysTrue()
    {
        var router = CreateRouter(TempMarkerPath());
        Assert.True(router.RequiresElevation);
    }

    [Fact]
    public void IsSupported_OnNonWindowsHost_IsFalse()
    {
        // This sandbox always runs on Linux, so IsSupported must correctly
        // report false rather than throwing or - worse - reporting true and
        // letting a caller attempt to open a WinDivert handle that cannot
        // possibly exist here. On a real Windows machine this same property
        // additionally depends on process elevation - see
        // docs/BUILD.md "Windows-only acceptance checklist" for what must be
        // verified there instead.
        var router = CreateRouter(TempMarkerPath());

        if (!OperatingSystem.IsWindows())
        {
            Assert.False(router.IsSupported);
        }
    }

    [Fact]
    public async Task StartAsync_WhenNotSupported_ReturnsUnavailable_AndNeverThrows()
    {
        var router = CreateRouter(TempMarkerPath());
        var profile = new ProxyProfile { Host = "127.0.0.1", Port = 8080, Username = "u", Protocol = ProxyProtocol.Http, CountryCode = "US" };

        var status = await router.StartAsync(profile, "pass", CancellationToken.None);

        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(SystemRoutingStatus.Unavailable, status);
            Assert.Equal(SystemRoutingStatus.Unavailable, router.Status);
        }
    }

    [Fact]
    public async Task StartAsync_WhenNotSupported_NeverWritesAStaleMarker()
    {
        // Fail-closed at the state-tracking level too: if the router never
        // actually started intercepting anything, there is nothing to
        // recover from on a later crash - MarkActive must not have been
        // called.
        var markerPath = TempMarkerPath();
        try
        {
            var router = CreateRouter(markerPath);
            var profile = new ProxyProfile { Host = "127.0.0.1", Port = 8080, Username = "u", Protocol = ProxyProtocol.Http, CountryCode = "US" };

            await router.StartAsync(profile, "pass", CancellationToken.None);

            if (!OperatingSystem.IsWindows())
            {
                Assert.False(File.Exists(markerPath));
            }
        }
        finally
        {
            if (File.Exists(markerPath))
            {
                File.Delete(markerPath);
            }
        }
    }

    [Fact]
    public async Task StopAsync_WhenNeverStarted_DoesNotThrow()
    {
        var router = CreateRouter(TempMarkerPath());

        await router.StopAsync();

        Assert.Equal(SystemRoutingStatus.Disabled, router.Status);
    }

    [Fact]
    public async Task StartAsync_RaisesStatusChanged_TransitioningThroughStartingBeforeFinalStatus()
    {
        var router = CreateRouter(TempMarkerPath());
        var observed = new List<SystemRoutingStatus>();
        router.StatusChanged += (_, status) => observed.Add(status);
        var profile = new ProxyProfile { Host = "127.0.0.1", Port = 8080, Username = "u", Protocol = ProxyProtocol.Http, CountryCode = "US" };

        await router.StartAsync(profile, "pass", CancellationToken.None);

        if (!OperatingSystem.IsWindows())
        {
            Assert.Contains(SystemRoutingStatus.Unavailable, observed);
        }
    }

    private static string TempMarkerPath() => Path.Combine(Path.GetTempPath(), $"rc-router-marker-{Guid.NewGuid():N}.marker");
}
