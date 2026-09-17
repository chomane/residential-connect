using ResidentialConnect.Core.Diagnostics;

namespace ResidentialConnect.Routing;

/// <summary>
/// Crash/force-close recovery for Whole Computer mode.
/// </summary>
/// <remarks>
/// <para>
/// <b>What actually needs "recovery" here, precisely:</b> the WinDivert
/// kernel driver's packet interception is tied to the lifetime of the
/// WinDivert handle(s) our process opened
/// (<see cref="WinDivertSystemTrafficRouter"/>). Windows itself guarantees
/// that ALL handles owned by a process are closed by the OS when that
/// process exits for any reason, including a crash or a forced
/// (Task Manager "End Task") termination - there is no scenario where a
/// WinDivert handle survives its owning process. WinDivert's own
/// documentation states the driver auto-installs/uninstalls tied to handle
/// lifetime, so once the OS closes our handle, packet interception itself
/// stops immediately and real networking is already restored - Whole
/// Computer mode cannot leave a "stuck" kernel-level packet filter behind
/// the way, for example, a persistent WFP callout or firewall rule could.
/// </para>
/// <para>
/// What CAN survive an unclean exit, and what this class actually guards
/// against, is purely <b>this application's own on-disk state</b>: a marker
/// file written when routing reaches <see cref="Models.SystemRoutingStatus.Active"/>
/// and normally deleted on a clean <c>StopAsync</c>. If the app is
/// force-closed while that marker is still present, the NEXT launch finds
/// it, logs a clear diagnostic explaining that the previous session did not
/// shut down Whole Computer mode cleanly (even though - per the above -
/// Windows networking itself was never actually left in an intercepted
/// state), and deletes the stale marker so the UI does not incorrectly
/// believe Whole Computer mode is still active from a previous session. This
/// is intentionally a narrow, accurate claim - NOT a claim that this class
/// "fixes broken Windows networking", because there is nothing to fix at the
/// networking level once the owning process is gone.
/// </para>
/// </remarks>
public sealed class RoutingStateMarker
{
    private readonly string _markerFilePath;
    private readonly IAppLogger _logger;

    public RoutingStateMarker(string markerFilePath, IAppLogger logger)
    {
        _markerFilePath = markerFilePath ?? throw new ArgumentNullException(nameof(markerFilePath));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>Writes the marker, called once whole-computer routing reaches Active.</summary>
    public void MarkActive()
    {
        try
        {
            var directory = Path.GetDirectoryName(_markerFilePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(_markerFilePath, $"pid={Environment.ProcessId};startedAtUtc={DateTimeOffset.UtcNow:O}");
        }
        catch (IOException ex)
        {
            _logger.Warning("RoutingStateMarker", $"Could not write routing state marker: {ex.GetType().Name}.");
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.Warning("RoutingStateMarker", $"Could not write routing state marker: {ex.GetType().Name}.");
        }
    }

    /// <summary>Deletes the marker, called on a clean, user-initiated DISCONNECT/StopAsync.</summary>
    public void ClearClean()
    {
        try
        {
            if (File.Exists(_markerFilePath))
            {
                File.Delete(_markerFilePath);
            }
        }
        catch (IOException)
        {
            // Best-effort - a leftover marker only ever causes a one-time,
            // clearly-logged notice on the next launch, never a functional
            // problem (see class remarks).
        }
        catch (UnauthorizedAccessException)
        {
            // Same as above.
        }
    }

    /// <summary>
    /// Call once at application startup, before offering Whole Computer mode
    /// in the UI. If a stale marker from an unclean previous exit is found,
    /// logs a clear diagnostic and removes it. Returns true if a stale
    /// marker was found (purely informational for the caller/UI - Windows
    /// networking itself needs no repair, see class remarks).
    /// </summary>
    public bool RecoverFromPreviousSession()
    {
        try
        {
            if (!File.Exists(_markerFilePath))
            {
                return false;
            }

            var contents = File.ReadAllText(_markerFilePath);
            _logger.Warning(
                "RoutingStateMarker",
                $"Found a Whole Computer routing marker from a previous session that did not shut down cleanly ({contents}). " +
                "Windows networking was already restored automatically by the OS when that process exited (WinDivert's " +
                "interception is tied to the owning process's handle) - clearing the stale marker so the UI starts fresh.");

            File.Delete(_markerFilePath);
            return true;
        }
        catch (IOException ex)
        {
            _logger.Warning("RoutingStateMarker", $"Could not check/clear routing state marker on startup: {ex.GetType().Name}.");
            return false;
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.Warning("RoutingStateMarker", $"Could not check/clear routing state marker on startup: {ex.GetType().Name}.");
            return false;
        }
    }
}
