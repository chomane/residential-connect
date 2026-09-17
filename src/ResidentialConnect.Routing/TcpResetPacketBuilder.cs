using System.Buffers.Binary;

namespace ResidentialConnect.Routing;

/// <summary>
/// Pure, side-effect-free construction of the forged IPv4 TCP RST+ACK packet
/// used to implement <see cref="RedirectAction.RejectStale"/> - see
/// <see cref="PacketRedirectPlanner"/>'s remarks for when/why that decision
/// is made. Deliberately free of any WinDivert P/Invoke call (or any other
/// native/Windows-only dependency), exactly like <see cref="BypassFilterBuilder"/>,
/// so the byte-for-byte construction can be fully unit tested on any OS in
/// this sandbox - only the actual <c>WinDivertSend</c> call that transmits
/// the resulting bytes requires a real Windows machine.
/// </summary>
/// <remarks>
/// <para>
/// <b>Adapted directly from WinDivert's own official sample</b>
/// <c>examples/netfilter/netfilter.c</c> (fetched in full from
/// <c>https://raw.githubusercontent.com/basil00/WinDivert/master/examples/netfilter/netfilter.c</c>)
/// - per the explicit product instruction "do not invent new RST
/// sequence/ACK rules". The official sample pre-fabricates a minimal,
/// fixed-size IPv4+TCP header buffer once (<c>PacketIpTcpInit</c>: zeroed,
/// <c>Version=4</c>, <c>HdrLength=5</c> (20-byte IPv4 header, no options),
/// <c>Id=htons(0xDEAD)</c>, <c>TTL=64</c>, <c>Protocol=IPPROTO_TCP</c>,
/// <c>ip.Length=htons(sizeof(TCPPACKET))</c>, TCP <c>HdrLength=5</c> (20-byte
/// TCP header, no options), <c>Rst=1</c>, <c>Ack=1</c>) and then, for EACH
/// packet that needs a reset, overwrites only the address/port/seq/ack
/// fields with these EXACT formulas (quoted verbatim from the sample):
/// <code>
/// reset->ip.SrcAddr = ip_header->DstAddr;
/// reset->ip.DstAddr = ip_header->SrcAddr;
/// reset->tcp.SrcPort = tcp_header->DstPort;
/// reset->tcp.DstPort = tcp_header->SrcPort;
/// reset->tcp.SeqNum =
///     (tcp_header->Ack? tcp_header->AckNum: 0);
/// reset->tcp.AckNum =
///     (tcp_header->Syn?
///         htonl(ntohl(tcp_header->SeqNum) + 1):
///         htonl(ntohl(tcp_header->SeqNum) + payload_len));
/// </code>
/// This class is a 1:1 managed-byte-array port of exactly that: no new
/// sequence/acknowledgement derivation logic has been invented, and the
/// pre-fabricated fixed fields (Id=0xDEAD, TTL=64, header lengths, protocol,
/// RST+ACK flags) match the sample's <c>PacketIpTcpInit</c> exactly.
/// </para>
/// <para>
/// <b>Never resets an already-RST or already-FIN packet</b> - the official
/// sample's own guard is <c>if (ip_header != NULL &amp;&amp; !tcp_header->Rst
/// &amp;&amp; !tcp_header->Fin)</c>. <see cref="PacketRedirectPlanner.PlanForward"/>
/// already enforces this one level up (an untracked packet that is itself
/// RST or FIN is hard-<see cref="RedirectAction.Drop"/>ped, never
/// <see cref="RedirectAction.RejectStale"/>), but <see cref="BuildIPv4Reset"/>
/// ALSO throws defensively if ever called for such a packet, so a future
/// caller cannot silently reintroduce the exact bug the sample's guard
/// exists to prevent (generating a reset in response to a reset, an
/// infinite RST/RST loop between two TCP stacks).
/// </para>
/// <para>
/// <b>Byte order:</b> every multi-byte field is written in network
/// (big-endian) order via <see cref="BinaryPrimitives"/>'s
/// <c>WriteXxxBigEndian</c> helpers - matching how
/// <see cref="WinDivertSystemTrafficRouter.CapturePacket"/> already reads
/// the equivalent fields (<c>BinaryPrimitives.ReverseEndianness</c> on a
/// little-endian host is the read-side mirror of writing big-endian
/// directly here).
/// </para>
/// <para>
/// <b>Not a mutation of the captured packet's buffer</b> - exactly like the
/// official sample, which sends a SEPARATE, freshly pre-fabricated
/// <c>TCPPACKET</c> struct rather than editing the captured packet in
/// place. The captured packet may carry a TCP payload (making it larger
/// than 40 bytes); the forged reset never does - it is always exactly
/// <see cref="PacketLength"/> (40) bytes: a bare 20-byte IPv4 header
/// followed by a bare 20-byte TCP header, no options, no payload.
/// </para>
/// </remarks>
public static class TcpResetPacketBuilder
{
    /// <summary>
    /// Total length, in bytes, of the forged packet: a 20-byte IPv4 header
    /// (no options) plus a 20-byte TCP header (no options), with no payload -
    /// exactly <c>sizeof(TCPPACKET)</c> in the official netfilter.c sample.
    /// </summary>
    public const int PacketLength = 40;

    private const byte IPv4VersionAndHeaderLength = 0x45; // Version 4, 20-byte header (5 x 32-bit words)
    private const byte TimeToLive = 64;
    private const byte TcpProtocolNumber = 6;
    private const ushort FixedIpIdentification = 0xDEAD; // matches the sample's htons(0xDEAD)
    private const byte TcpHeaderLengthAndFlagsLowByte = 0x50; // data offset = 5 x 32-bit words (20 bytes), reserved bits 0
    private const byte TcpRstAckFlagsByte = 0x14; // bit2 (RST) | bit4 (ACK) within the TCP flags byte

    /// <summary>
    /// Builds the forged IPv4 TCP RST+ACK packet answering <paramref name="original"/>,
    /// as a same-flow reply (source/destination swapped - this is what the
    /// ORIGINAL packet's sender will receive). The caller is responsible for
    /// recalculating checksums (<c>WinDivertHelperCalcChecksums</c>) and
    /// flipping the WinDivert address direction
    /// (<see cref="WinDivertNative.MarkInbound"/>) before sending - this
    /// method only produces the packet BYTES, exactly like the official
    /// sample separates packet construction from the
    /// <c>WinDivertHelperCalcChecksums</c>/<c>WinDivertSend</c> calls that
    /// follow it.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <paramref name="original"/> is itself RST or FIN-flagged -
    /// see class remarks for why this must never happen (matches the
    /// official sample's own guard).
    /// </exception>
    public static byte[] BuildIPv4Reset(CapturedTcpPacket original)
    {
        if (original.IsRst || original.IsFin)
        {
            throw new InvalidOperationException(
                "Refusing to build a TCP reset in response to an already-RST or already-FIN packet - " +
                "this exact guard is required by WinDivert's own official netfilter.c sample " +
                "(\"if (ip_header != NULL && !tcp_header->Rst && !tcp_header->Fin)\") to avoid an " +
                "infinite RST/RST loop. PacketRedirectPlanner.PlanForward should already have hard-Dropped " +
                "this packet instead of choosing RejectStale for it - this exception indicates that guard " +
                "was bypassed.");
        }

        var buffer = new byte[PacketLength];
        var span = buffer.AsSpan();

        // --- Pre-fabricated fixed IPv4 header fields (PacketIpInit) -------
        buffer[0] = IPv4VersionAndHeaderLength;
        buffer[1] = 0x00; // TOS
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(2, 2), PacketLength); // ip.Length = htons(sizeof(TCPPACKET))
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(4, 2), FixedIpIdentification); // ip.Id = htons(0xDEAD)
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(6, 2), 0); // flags/fragment offset
        buffer[8] = TimeToLive;
        buffer[9] = TcpProtocolNumber;
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(10, 2), 0); // checksum - recalculated by WinDivertHelperCalcChecksums

        // --- Per-packet address swap: reset->ip.SrcAddr = original DstAddr; reset->ip.DstAddr = original SrcAddr ---
        original.DstAddr.GetAddressBytes().CopyTo(buffer, 12);
        original.SrcAddr.GetAddressBytes().CopyTo(buffer, 16);

        // --- Per-packet port swap: reset->tcp.SrcPort = original DstPort; reset->tcp.DstPort = original SrcPort ---
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(20, 2), (ushort)original.DstPort);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(22, 2), (ushort)original.SrcPort);

        // --- Seq/Ack derivation - verbatim netfilter.c formulas ----------
        // reset->tcp.SeqNum = (tcp_header->Ack ? tcp_header->AckNum : 0);
        var seqNum = original.IsAck ? original.AckNum : 0u;
        // reset->tcp.AckNum = (tcp_header->Syn
        //     ? htonl(ntohl(tcp_header->SeqNum) + 1)
        //     : htonl(ntohl(tcp_header->SeqNum) + payload_len));
        var ackNum = original.IsSyn
            ? unchecked(original.SeqNum + 1)
            : unchecked(original.SeqNum + (uint)original.PayloadLength);

        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(24, 4), seqNum);
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(28, 4), ackNum);

        // --- Pre-fabricated fixed TCP header fields (PacketTcpInit: HdrLength=5, Rst=1, Ack=1) ---
        buffer[32] = TcpHeaderLengthAndFlagsLowByte;
        buffer[33] = TcpRstAckFlagsByte;
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(34, 2), 0); // window
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(36, 2), 0); // checksum - recalculated by WinDivertHelperCalcChecksums
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(38, 2), 0); // urgent pointer

        return buffer;
    }
}
