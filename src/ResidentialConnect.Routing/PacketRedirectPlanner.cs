using System.Net;

namespace ResidentialConnect.Routing;

/// <summary>
/// Minimal, immutable snapshot of the fields <see cref="PacketRedirectPlanner"/>
/// needs from a captured TCP/IPv4 packet. Deliberately NOT the real
/// (unsafe-pointer-based) WinDivert parse result, so the redirect DECISION
/// logic can be constructed, exercised, and unit tested with plain,
/// synthetic values on any OS - only <see cref="WinDivertSystemTrafficRouter"/>
/// itself (which reads/writes the real unsafe packet headers and calls into
/// the native WinDivert driver) needs a real Windows machine to verify.
/// </summary>
public readonly record struct CapturedTcpPacket(
    bool IsSyn,
    bool IsAck,
    bool IsFin,
    bool IsRst,
    int SrcPort,
    int DstPort,
    IPAddress DstAddr);

/// <summary>Outcome of evaluating one captured packet against the current flow table / fail-closed state.</summary>
public readonly record struct RedirectDecision(bool ShouldRewrite, IPAddress? NewAddress, int? NewPort)
{
    /// <summary>Never resend this packet - the fail-closed behavior for anything not explicitly redirected.</summary>
    public static readonly RedirectDecision Drop = new(false, null, null);

    public static RedirectDecision Rewrite(IPAddress address, int port) => new(true, address, port);
}

/// <summary>
/// Pure decision logic for whether/how to rewrite a captured packet on the
/// forward (application -&gt; real destination) and return (local relay -&gt;
/// application) legs of a whole-computer-redirected TCP flow. Contains ZERO
/// WinDivert/P-Invoke/native calls - see <see cref="WinDivertSystemTrafficRouter"/>
/// for where these decisions are actually applied to real packet bytes and
/// sent back into the kernel.
/// </summary>
/// <remarks>
/// <b>Fail-closed by construction:</b> every code path that is not an
/// explicit, tracked redirect returns <see cref="RedirectDecision.Drop"/>.
/// In particular, a packet that is neither a brand-new SYN nor part of an
/// already-tracked flow (e.g. a connection that was already established
/// before Whole Computer mode was turned on) is DROPPED rather than resent
/// unmodified - satisfying "packets that would have been redirected are
/// never silently allowed to reach the real network". The trade-off,
/// documented as a known limitation, is that pre-existing connections stall
/// when Whole Computer mode is enabled rather than continuing unprotected.
/// </remarks>
public static class PacketRedirectPlanner
{
    /// <summary>
    /// Plans the forward leg: a packet sent BY the intercepted application
    /// TOWARDS its real (pre-redirect) destination.
    /// </summary>
    public static RedirectDecision PlanForward(
        CapturedTcpPacket packet,
        RedirectFlowTable flowTable,
        IPAddress relayAddress,
        int relayPort,
        bool failClosed)
    {
        ArgumentNullException.ThrowIfNull(flowTable);
        ArgumentNullException.ThrowIfNull(relayAddress);

        if (failClosed)
        {
            // Once the relay/upstream path has faulted, no packet - new or
            // already tracked - may reach the real network. This is the
            // packet-level half of the fail-closed contract described on
            // ISystemTrafficRouter.
            return RedirectDecision.Drop;
        }

        if (packet.IsSyn && !packet.IsAck)
        {
            // A brand-new outbound connection attempt. Record its real,
            // original destination (read directly from the packet's own
            // header - the application/OS already resolved DNS before
            // sending this SYN, so no DNS lookup of our own is needed here)
            // before rewriting it.
            flowTable.Record(packet.SrcPort, packet.DstAddr.ToString(), packet.DstPort);
            return RedirectDecision.Rewrite(relayAddress, relayPort);
        }

        if (flowTable.TryGetFlow(packet.SrcPort, out _, out _))
        {
            if (packet.IsFin || packet.IsRst)
            {
                // Best-effort cleanup: once either side signals close/reset
                // on the forward leg, stop tracking the flow. A generous
                // idle-timeout sweep (see RedirectFlowTable.EvictIdle) is the
                // safety net for any FIN/RST WinDivert's queue happened to
                // drop under load.
                flowTable.Remove(packet.SrcPort);
            }

            return RedirectDecision.Rewrite(relayAddress, relayPort);
        }

        // Not a new SYN and not a tracked flow: most likely a connection
        // that was already established before Whole Computer mode started.
        // Fail closed - see class remarks.
        return RedirectDecision.Drop;
    }

    /// <summary>
    /// Plans the return leg: a reply packet sent BY the local transparent
    /// relay BACK to the intercepted application, which must have its source
    /// address/port rewritten to impersonate the real original destination -
    /// otherwise the application's own TCP stack will not recognize the
    /// reply as belonging to the connection it thinks it opened.
    /// </summary>
    public static RedirectDecision PlanReturn(CapturedTcpPacket packet, RedirectFlowTable flowTable, bool failClosed)
    {
        ArgumentNullException.ThrowIfNull(flowTable);

        if (failClosed)
        {
            return RedirectDecision.Drop;
        }

        if (flowTable.TryGetFlow(packet.DstPort, out var host, out var port) && IPAddress.TryParse(host, out var address))
        {
            if (packet.IsFin || packet.IsRst)
            {
                flowTable.Remove(packet.DstPort);
            }

            return RedirectDecision.Rewrite(address, port);
        }

        // No tracked flow for this local port - not a redirected connection
        // we recognize. Fail closed rather than letting an unrecognized
        // loopback reply travel onward unmodified.
        return RedirectDecision.Drop;
    }
}
