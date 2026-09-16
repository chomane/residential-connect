using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace ResidentialConnect.Routing;

/// <summary>
/// Pure, side-effect-free construction of the synthesized UDP/53 DNS REPLY
/// packet sent back to the application that issued a captured DNS query,
/// after the query's raw bytes were answered via proxied DNS-over-HTTPS -
/// see correction #2/#9 ("UDP/53 (IPv4 OR IPv6) -&gt; intercepted and
/// answered using proxied DoH", "synthesize the reply using the SAME IP
/// family as the captured request"). Deliberately free of any WinDivert
/// P/Invoke call, exactly like <see cref="TcpResetPacketBuilder"/> and
/// <see cref="BypassFilterBuilder"/>, so it is fully unit-testable without a
/// real Windows/WinDivert driver.
/// </summary>
/// <remarks>
/// <para>
/// <b>Raw DNS wire-format preservation:</b> <paramref name="dnsResponsePayload"/>
/// (the exact bytes of the DoH HTTP response body) is copied into the
/// synthesized packet's UDP payload VERBATIM - this class never parses or
/// reconstructs any DNS message field (transaction ID, question/answer
/// records, EDNS options, etc.). This preserves every detail (A/AAAA/CNAME/
/// DNSSEC/EDNS) exactly as the DoH resolver (Cloudflare) returned them,
/// without this application needing to understand or reimplement DNS
/// message semantics at all.
/// </para>
/// <para>
/// <b>Same-IP-family reply:</b> if the captured query was IPv4 (a UDP/53
/// packet sent to an IPv4-addressed configured DNS server), the reply is
/// synthesized as an IPv4 UDP packet; if the captured query was IPv6
/// (correction #2 - "a Windows-configured DNS server may itself be an IPv6
/// address"), the reply is synthesized as an IPv6 UDP packet. This class
/// dispatches on <see cref="CapturedUdpPacket.AddressFamily"/> automatically
/// - the caller never needs to special-case the two families itself beyond
/// choosing which WinDivert handle originally captured the query.
/// </para>
/// <para>
/// <b>Reflection semantics identical to <see cref="TcpResetPacketBuilder"/>:</b>
/// the synthesized reply swaps source and destination exactly like a real
/// DNS server's reply would - <c>reply.Src = original.Dst</c> (the
/// configured DNS server's own address:53) and <c>reply.Dst =
/// original.Src</c> (the application's real address:port that sent the
/// query). The caller (<see cref="WinDivertSystemTrafficRouter"/>) is
/// responsible for marking the WinDivert address <c>Inbound</c>
/// (<see cref="WinDivertNative.MarkInbound"/>) and recalculating checksums
/// (<c>WinDivertHelperCalcChecksums</c>) before sending, exactly like the
/// forged TCP reset - this class only produces the packet BYTES.
/// </para>
/// </remarks>
public static class DnsUdpReplyPacketBuilder
{
    private const byte IPv4VersionAndHeaderLength = 0x45; // Version 4, 20-byte header
    private const byte TimeToLive = 64;
    private const byte UdpProtocolNumber = 17;
    private const ushort FixedIpIdentification = 0xDEAD;
    private const int Ipv4HeaderLength = 20;
    private const int Ipv6HeaderLength = 40;
    private const int UdpHeaderLength = 8;

    /// <summary>
    /// Builds the full synthesized reply packet (IP header + UDP header +
    /// raw DNS payload), in the SAME address family as
    /// <paramref name="original"/>.
    /// </summary>
    public static byte[] BuildReply(CapturedUdpPacket original, byte[] dnsResponsePayload)
    {
        ArgumentNullException.ThrowIfNull(original);
        ArgumentNullException.ThrowIfNull(dnsResponsePayload);

        return original.AddressFamily switch
        {
            AddressFamily.InterNetwork => BuildIPv4Reply(original, dnsResponsePayload),
            AddressFamily.InterNetworkV6 => BuildIPv6Reply(original, dnsResponsePayload),
            _ => throw new NotSupportedException($"Unsupported address family {original.AddressFamily} for a DNS UDP reply."),
        };
    }

    private static byte[] BuildIPv4Reply(CapturedUdpPacket original, byte[] dnsResponsePayload)
    {
        var totalLength = Ipv4HeaderLength + UdpHeaderLength + dnsResponsePayload.Length;
        var buffer = new byte[totalLength];
        var span = buffer.AsSpan();

        // --- IPv4 header ---------------------------------------------------
        buffer[0] = IPv4VersionAndHeaderLength;
        buffer[1] = 0x00; // TOS
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(2, 2), (ushort)totalLength);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(4, 2), FixedIpIdentification);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(6, 2), 0); // flags/fragment offset
        buffer[8] = TimeToLive;
        buffer[9] = UdpProtocolNumber;
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(10, 2), 0); // checksum - recalculated by WinDivertHelperCalcChecksums

        // reply.Src = original.Dst (the configured DNS server); reply.Dst = original.Src (the real application)
        original.DstAddr.GetAddressBytes().CopyTo(buffer, 12);
        original.SrcAddr.GetAddressBytes().CopyTo(buffer, 16);

        WriteUdpHeaderAndPayload(span.Slice(Ipv4HeaderLength), original, dnsResponsePayload);

        return buffer;
    }

    private static byte[] BuildIPv6Reply(CapturedUdpPacket original, byte[] dnsResponsePayload)
    {
        var udpLength = UdpHeaderLength + dnsResponsePayload.Length;
        var totalLength = Ipv6HeaderLength + udpLength;
        var buffer = new byte[totalLength];
        var span = buffer.AsSpan();

        // --- IPv6 fixed header ----------------------------------------------
        // VersionClassFlow: Version=6 in the top 4 bits, traffic class/flow label 0.
        BinaryPrimitives.WriteUInt32BigEndian(span.Slice(0, 4), 0x60000000u);
        BinaryPrimitives.WriteUInt16BigEndian(span.Slice(4, 2), (ushort)udpLength); // PayloadLength
        buffer[6] = UdpProtocolNumber; // NextHeader
        buffer[7] = TimeToLive; // HopLimit

        // reply.Src = original.Dst (the configured DNS server); reply.Dst = original.Src (the real application)
        original.DstAddr.GetAddressBytes().CopyTo(buffer, 8);
        original.SrcAddr.GetAddressBytes().CopyTo(buffer, 24);

        WriteUdpHeaderAndPayload(span.Slice(Ipv6HeaderLength), original, dnsResponsePayload);

        return buffer;
    }

    private static void WriteUdpHeaderAndPayload(Span<byte> udpSpan, CapturedUdpPacket original, byte[] dnsResponsePayload)
    {
        var udpLength = UdpHeaderLength + dnsResponsePayload.Length;

        // reply.SrcPort = original.DstPort (53); reply.DstPort = original.SrcPort (the application's ephemeral port)
        BinaryPrimitives.WriteUInt16BigEndian(udpSpan.Slice(0, 2), (ushort)original.DstPort);
        BinaryPrimitives.WriteUInt16BigEndian(udpSpan.Slice(2, 2), (ushort)original.SrcPort);
        BinaryPrimitives.WriteUInt16BigEndian(udpSpan.Slice(4, 2), (ushort)udpLength);
        BinaryPrimitives.WriteUInt16BigEndian(udpSpan.Slice(6, 2), 0); // checksum - recalculated by WinDivertHelperCalcChecksums

        dnsResponsePayload.CopyTo(udpSpan.Slice(UdpHeaderLength));
    }
}
