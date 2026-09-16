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
/// <remarks>
/// Includes BOTH source and destination address/port (not just destination)
/// because the correct WinDivert redirect technique is a full 4-tuple
/// <b>reflection</b> (swap source and destination, then re-inject the packet
/// on the INBOUND path) - see <see cref="RedirectDecision"/> remarks for why
/// a partial ("rewrite destination only, keep Outbound") rewrite does not
/// actually work.
/// </remarks>
/// <remarks>
/// <b>2026-09-16 diagnostic-only extension:</b> <see cref="IsPsh"/>,
/// <see cref="SeqNum"/>, <see cref="AckNum"/>, <see cref="Window"/>, and
/// <see cref="PayloadLength"/> were added purely so
/// <see cref="WinDivertSystemTrafficRouter"/>'s per-packet diagnostic log
/// lines (gated behind <c>RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS</c>) can
/// show established-flow data segments (not just the SYN/SYN-ACK/ACK
/// handshake) - specifically to investigate the "upstream CONNECT succeeded
/// but the relayed session immediately ended with zero bytes in both
/// directions" symptom, where the question is whether the client's
/// post-handshake DATA segment (e.g. its TLS ClientHello) is even being
/// captured/reflected by WinDivert at all. All five have defaults and do
/// NOT participate in any decision <see cref="PacketRedirectPlanner"/>
/// makes - they are read-only, log-only fields.
/// </remarks>
public readonly record struct CapturedTcpPacket(
    bool IsSyn,
    bool IsAck,
    bool IsFin,
    bool IsRst,
    IPAddress SrcAddr,
    int SrcPort,
    IPAddress DstAddr,
    int DstPort,
    bool IsPsh = false,
    uint SeqNum = 0,
    uint AckNum = 0,
    int Window = 0,
    int PayloadLength = 0);

/// <summary>
/// Outcome of evaluating one captured packet against the current flow table
/// / fail-closed state.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a full 4-tuple "reflect", not a single-field "rewrite":</b>
/// an earlier revision of this router only rewrote the packet's destination
/// address/port (to a loopback relay address) and re-sent it still marked
/// <c>Outbound</c>. That looks plausible but does not work: Windows only
/// classifies a packet "loopback" when BOTH its source AND destination are
/// local-machine addresses, and a genuinely outbound send to a
/// newly-rewritten destination is subject to the normal TCP/IP stack's
/// path/routing and anti-spoofing checks for an ordinary outbound
/// connection attempt - which is not what actually happens to a real
/// "packet received from the network" and does not correctly establish a
/// new inbound-looking flow. The official, WinDivert-documented technique
/// (used by the upstream <c>streamdump.c</c> example and required for any
/// WinDivert-based transparent proxy) is instead to <b>swap</b> the
/// source and destination address/port and flip the packet's direction
/// flag from <c>Outbound</c> to <c>Inbound</c> before re-injecting it. This
/// makes Windows' own TCP/IP stack believe the packet just arrived over the
/// network from a real peer, so the OS's own stack performs the handshake,
/// retransmission, and ACK/window handling - and, critically, correctly
/// delivers it to whatever process is listening on the (real, non-loopback)
/// local interface address and port the packet now carries as its
/// destination.
/// </para>
/// <para>
/// <b>Forward leg</b> (application -&gt; real destination): before
/// transform, the packet is Src=(ClientRealIP,ClientPort),
/// Dst=(RealDestIP,RealDestPort). After transform it becomes
/// Src=(RealDestIP,ClientPort) [<i>unchanged port, swapped address</i>],
/// Dst=(ClientRealIP,RelayPort), marked Inbound. Windows now delivers this
/// (fake, but well-formed) "packet from RealDestIP" to
/// <c>TransparentForwardingProxy</c>'s listening socket. The relay's
/// <c>accept()</c> reports the remote endpoint as (RealDestIP,ClientPort) -
/// exactly the (host, port) pair <see cref="RedirectFlowTable"/> already
/// keys flows by via the client's port, so
/// <c>IOriginalDestinationResolver</c>/<c>TransparentForwardingProxy</c>
/// need NO changes at all for this fix.
/// </para>
/// <para>
/// <b>Return leg</b> (local relay's own reply -&gt; application): the
/// relay's own TCP stack, believing its peer is (RealDestIP,ClientPort),
/// generates ordinary outbound replies Src=(ClientRealIP,RelayPort),
/// Dst=(RealDestIP,ClientPort). These are reflected back with
/// Src=(RealDestIP,RealDestPort) [<i>RealDestPort restored from the flow
/// table - it is the one piece of information destroyed by the forward
/// rewrite above and only recoverable from the flow table</i>],
/// Dst=(ClientRealIP,ClientPort), marked Inbound - exactly what the
/// original application's own socket is expecting to receive from the real
/// remote server it believes it is talking to.
/// </para>
/// <para>
/// <b>Fail-closed by construction:</b> every code path that is not an
/// explicit, tracked redirect returns <see cref="RedirectDecision.Drop"/>.
/// In particular, a packet that is neither a brand-new SYN nor part of an
/// already-tracked flow (e.g. a connection that was already established
/// before Whole Computer mode was turned on) is DROPPED rather than resent
/// unmodified - satisfying "packets that would have been redirected are
/// never silently allowed to reach the real network". The trade-off,
/// documented as a known limitation, is that pre-existing connections stall
/// when Whole Computer mode is enabled rather than continuing unprotected.
/// </para>
/// </remarks>
public readonly record struct RedirectDecision(
    bool ShouldReflect,
    IPAddress? NewSrcAddr,
    int? NewSrcPort,
    IPAddress? NewDstAddr,
    int? NewDstPort)
{
    /// <summary>Never resend this packet - the fail-closed behavior for anything not explicitly redirected.</summary>
    public static readonly RedirectDecision Drop = new(false, null, null, null, null);

    public static RedirectDecision Reflect(IPAddress newSrcAddr, int newSrcPort, IPAddress newDstAddr, int newDstPort) =>
        new(true, newSrcAddr, newSrcPort, newDstAddr, newDstPort);
}

/// <summary>
/// Pure decision logic for whether/how to reflect a captured packet on the
/// forward (application -&gt; real destination) and return (local relay -&gt;
/// application) legs of a whole-computer-redirected TCP flow. Contains ZERO
/// WinDivert/P-Invoke/native calls - see <see cref="WinDivertSystemTrafficRouter"/>
/// for where these decisions are actually applied to real packet bytes,
/// checksums recalculated, and the result sent back into the kernel with
/// its direction flag flipped.
/// </summary>
public static class PacketRedirectPlanner
{
    /// <summary>
    /// Plans the forward leg: a packet sent BY the intercepted application
    /// TOWARDS its real (pre-redirect) destination.
    /// </summary>
    /// <param name="relayPort">The local port <c>TransparentForwardingProxy</c> is listening on.</param>
    public static RedirectDecision PlanForward(
        CapturedTcpPacket packet,
        RedirectFlowTable flowTable,
        int relayPort,
        bool failClosed)
    {
        ArgumentNullException.ThrowIfNull(flowTable);

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
            // before reflecting it. The client's port (packet.SrcPort) is
            // the key - it stays the same on the wire throughout the
            // reflection, and Windows guarantees it is unique among this
            // machine's own outbound connections at any one time.
            flowTable.Record(packet.SrcPort, packet.DstAddr.ToString(), packet.DstPort);
            return RedirectDecision.Reflect(packet.DstAddr, packet.SrcPort, packet.SrcAddr, relayPort);
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

            // Every subsequent packet of an already-tracked flow gets the
            // identical reflection re-applied - the application's own TCP
            // stack keeps addressing every packet of this connection to the
            // same real destination (packet.DstAddr/packet.DstPort still
            // carry it fresh on every packet), so no flow-table lookup of
            // the destination is even needed here.
            return RedirectDecision.Reflect(packet.DstAddr, packet.SrcPort, packet.SrcAddr, relayPort);
        }

        // Not a new SYN and not a tracked flow: most likely a connection
        // that was already established before Whole Computer mode started.
        // Fail closed - see class remarks.
        return RedirectDecision.Drop;
    }

    /// <summary>
    /// Plans the return leg: a reply packet sent BY the local transparent
    /// relay BACK to the intercepted application, which must be reflected
    /// to impersonate the real original destination - otherwise the
    /// application's own TCP stack will not recognize the reply as
    /// belonging to the connection it thinks it opened.
    /// </summary>
    public static RedirectDecision PlanReturn(CapturedTcpPacket packet, RedirectFlowTable flowTable, bool failClosed)
    {
        ArgumentNullException.ThrowIfNull(flowTable);

        if (failClosed)
        {
            return RedirectDecision.Drop;
        }

        // packet.DstPort here is the CLIENT's port (the relay's own reply is
        // addressed, from the OS's point of view, back to the spoofed real
        // destination at ClientPort - see class remarks) - the same key the
        // forward leg recorded the flow under.
        if (flowTable.TryGetFlow(packet.DstPort, out _, out var originalDestinationPort))
        {
            if (packet.IsFin || packet.IsRst)
            {
                flowTable.Remove(packet.DstPort);
            }

            // packet.DstAddr already IS the real original destination
            // address (that is what the forward leg spoofed the relay's
            // apparent peer to be, and the relay's own reply packet is
            // naturally addressed there) - only the ORIGINAL DESTINATION
            // PORT needs to be recovered from the flow table, since the
            // forward leg overwrote that field with relayPort and nothing
            // on the wire carries the real value forward from there.
            return RedirectDecision.Reflect(packet.DstAddr, originalDestinationPort, packet.SrcAddr, packet.DstPort);
        }

        // No tracked flow for this local port - not a redirected connection
        // we recognize. Fail closed rather than letting an unrecognized
        // reply travel onward unmodified.
        return RedirectDecision.Drop;
    }
}
