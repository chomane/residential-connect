using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="RoutingStateMarker"/> - the crash/force-close
/// recovery mechanism for Whole Computer mode's own on-disk state (see class
/// remarks for exactly what this does and does not need to repair; Windows
/// networking itself is already restored by the OS the instant the owning
/// process exits, for any reason, because WinDivert handle lifetime is tied
/// to process lifetime).
/// </summary>
public class RoutingStateMarkerTests
{
    private static string TempMarkerPath() => Path.Combine(Path.GetTempPath(), $"rc-routing-marker-test-{Guid.NewGuid():N}.marker");

    [Fact]
    public void RecoverFromPreviousSession_NoMarkerFile_ReturnsFalse_DoesNothing()
    {
        var path = TempMarkerPath();
        var marker = new RoutingStateMarker(path, new NullLogger());

        var recovered = marker.RecoverFromPreviousSession();

        Assert.False(recovered);
    }

    [Fact]
    public void MarkActive_ThenRecoverFromPreviousSession_DetectsAndClearsStaleMarker()
    {
        var path = TempMarkerPath();
        try
        {
            var marker = new RoutingStateMarker(path, new NullLogger());
            marker.MarkActive();
            Assert.True(File.Exists(path));

            // Simulate a NEW process instance (a fresh RoutingStateMarker,
            // as App.xaml.cs would construct on next launch) discovering the
            // marker left behind by an unclean previous exit.
            var nextLaunchMarker = new RoutingStateMarker(path, new NullLogger());
            var recovered = nextLaunchMarker.RecoverFromPreviousSession();

            Assert.True(recovered);
            Assert.False(File.Exists(path));
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void MarkActive_ThenClearClean_LeavesNoMarkerBehind_SoNextLaunchFindsNothingToRecover()
    {
        var path = TempMarkerPath();
        try
        {
            var marker = new RoutingStateMarker(path, new NullLogger());
            marker.MarkActive();
            marker.ClearClean();

            Assert.False(File.Exists(path));

            var nextLaunchMarker = new RoutingStateMarker(path, new NullLogger());
            Assert.False(nextLaunchMarker.RecoverFromPreviousSession());
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }

    [Fact]
    public void ClearClean_WhenNoMarkerExists_DoesNotThrow()
    {
        var path = TempMarkerPath();
        var marker = new RoutingStateMarker(path, new NullLogger());

        var exception = Record.Exception(() => marker.ClearClean());

        Assert.Null(exception);
    }
}
