namespace ResidentialConnect.Core.Diagnostics;

/// <summary>
/// Shared, process-wide monotonic millisecond timestamp source used ONLY by
/// the temporary <c>RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS</c> instrumentation
/// added on 2026-09-15 (see <c>WinDivertSystemTrafficRouter</c>,
/// <c>TransparentForwardingProxy</c>, <c>HttpConnectUpstreamConnector</c>).
/// </summary>
/// <remarks>
/// The whole point of timestamping every diagnostic line with a SINGLE
/// shared clock (rather than, say, a per-class <see cref="System.Diagnostics.Stopwatch"/>
/// each reset at a different moment) is so a human reading one Windows
/// console transcript can directly compare "elapsedMs" across the three
/// different classes/threads involved in one redirected TCP flow - e.g. the
/// exact number of milliseconds between
/// <c>[FORWARD #N] ... flags=[SYN]</c> (captured by the router's dedicated
/// forward thread) and the corresponding
/// <c>[RETURN #M] ... flags=[SYN,ACK]</c> (captured by the router's
/// dedicated return thread) - which is precisely the number needed to
/// confirm or refute the "return capture loop was thread-starved for
/// several seconds" hypothesis raised by the first instrumented run's
/// results (returnCaptures arriving in a late burst just before the
/// routed HTTPS request gave up).
/// <para>
/// Backed by <see cref="Environment.TickCount64"/>: monotonic (immune to
/// system clock changes/NTP adjustments), process-wide, and cheap enough to
/// call on every captured packet without perturbing the very timing this
/// instrumentation exists to measure.
/// </para>
/// </remarks>
public static class DiagnosticClock
{
    private static readonly long StartTicks = Environment.TickCount64;

    /// <summary>Milliseconds elapsed since this process started (approximately - since first use of this class).</summary>
    public static long ElapsedMs => Environment.TickCount64 - StartTicks;
}
