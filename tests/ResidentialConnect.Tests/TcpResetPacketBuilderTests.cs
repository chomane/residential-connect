using System.Buffers.Binary;
using System.Net;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the pure, byte-for-byte forged-RST construction adapted from
/// WinDivert's official <c>examples/netfilter/netfilter.c</c> sample - see
/// <see cref="TcpResetPacketBuilder"/> remarks for the exact quoted C
/// algorithm this ports. Every seq/ack derivation case and the RST/FIN
/// guard are covered here since this is the part of "correction #1"
/// (RejectStale) that can be fully verified without a real Windows/WinDivert
/// driver.
/// </summary>
public class TcpResetPacketBuilderTests
{
    private static CapturedTcpPacket MakeTracked(
        bool isSyn = false,
        bool isAck = false,
        bool isFin = false,
        bool isRst = false,
        uint seqNum = 1000,
        uint ackNum = 2000,
        int payloadLength = 0) =>
        new(
            IsSyn: isSyn,
            IsAck: isAck,
            IsFin: isFin,
            IsRst: isRst,
            SrcAddr: IPAddress.Parse("203.0.113.5"),
            SrcPort: 51000,
            DstAddr: IPAddress.Parse("198.51.100.20"),
            DstPort: 443,
            SeqNum: seqNum,
            AckNum: ackNum,
            PayloadLength: payloadLength);

    [Fact]
    public void BuildIPv4Reset_ProducesExactly40Bytes()
    {
        var packet = MakeTracked(isAck: true, payloadLength: 200);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        Assert.Equal(40, reset.Length);
        Assert.Equal(TcpResetPacketBuilder.PacketLength, reset.Length);
    }

    [Fact]
    public void BuildIPv4Reset_SwapsSourceAndDestinationAddresses()
    {
        var packet = MakeTracked(isAck: true, payloadLength: 200);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        // reset->ip.SrcAddr = original DstAddr; reset->ip.DstAddr = original SrcAddr
        var srcAddrBytes = reset.AsSpan(12, 4).ToArray();
        var dstAddrBytes = reset.AsSpan(16, 4).ToArray();

        Assert.Equal(packet.DstAddr.GetAddressBytes(), srcAddrBytes);
        Assert.Equal(packet.SrcAddr.GetAddressBytes(), dstAddrBytes);
    }

    [Fact]
    public void BuildIPv4Reset_SwapsSourceAndDestinationPorts()
    {
        var packet = MakeTracked(isAck: true, payloadLength: 200);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        var srcPort = BinaryPrimitives.ReadUInt16BigEndian(reset.AsSpan(20, 2));
        var dstPort = BinaryPrimitives.ReadUInt16BigEndian(reset.AsSpan(22, 2));

        Assert.Equal((ushort)packet.DstPort, srcPort);
        Assert.Equal((ushort)packet.SrcPort, dstPort);
    }

    [Fact]
    public void BuildIPv4Reset_WhenOriginalIsAckedEstablishedFlowData_SeqNumIsOriginalAckNum()
    {
        // reset->tcp.SeqNum = (tcp_header->Ack ? tcp_header->AckNum : 0);
        var packet = MakeTracked(isAck: true, ackNum: 9999, payloadLength: 200);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        var seqNum = BinaryPrimitives.ReadUInt32BigEndian(reset.AsSpan(24, 4));
        Assert.Equal(9999u, seqNum);
    }

    [Fact]
    public void BuildIPv4Reset_WhenOriginalIsNotAcked_SeqNumIsZero()
    {
        // reset->tcp.SeqNum = (tcp_header->Ack ? tcp_header->AckNum : 0);
        var packet = MakeTracked(isAck: false, isSyn: true, ackNum: 9999, seqNum: 500);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        var seqNum = BinaryPrimitives.ReadUInt32BigEndian(reset.AsSpan(24, 4));
        Assert.Equal(0u, seqNum);
    }

    [Fact]
    public void BuildIPv4Reset_WhenOriginalIsSyn_AckNumIsOriginalSeqNumPlusOne()
    {
        // reset->tcp.AckNum = (tcp_header->Syn ? htonl(ntohl(SeqNum)+1) : ...);
        var packet = MakeTracked(isSyn: true, isAck: false, seqNum: 500, payloadLength: 0);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        var ackNum = BinaryPrimitives.ReadUInt32BigEndian(reset.AsSpan(28, 4));
        Assert.Equal(501u, ackNum);
    }

    [Fact]
    public void BuildIPv4Reset_WhenOriginalIsNotSyn_AckNumIsOriginalSeqNumPlusPayloadLength()
    {
        // reset->tcp.AckNum = (tcp_header->Syn ? ... : htonl(ntohl(SeqNum)+payload_len));
        var packet = MakeTracked(isSyn: false, isAck: true, seqNum: 1000, payloadLength: 250);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        var ackNum = BinaryPrimitives.ReadUInt32BigEndian(reset.AsSpan(28, 4));
        Assert.Equal(1250u, ackNum);
    }

    [Fact]
    public void BuildIPv4Reset_WhenOriginalIsNotSynAndHasZeroPayload_AckNumEqualsOriginalSeqNum()
    {
        var packet = MakeTracked(isSyn: false, isAck: true, seqNum: 4242, payloadLength: 0);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        var ackNum = BinaryPrimitives.ReadUInt32BigEndian(reset.AsSpan(28, 4));
        Assert.Equal(4242u, ackNum);
    }

    [Fact]
    public void BuildIPv4Reset_SetsRstAndAckFlags_MatchingTheOfficialSamplesPreFabricatedFlags()
    {
        var packet = MakeTracked(isAck: true, payloadLength: 100);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        // TCP flags occupy the low byte at offset 33 (offset 32 is the data
        // offset/reserved high byte). RST=bit2 (0x04), ACK=bit4 (0x10).
        var flagsByte = reset[33];
        Assert.Equal(0x14, flagsByte);
        Assert.NotEqual(0, flagsByte & 0x04); // RST set
        Assert.NotEqual(0, flagsByte & 0x10); // ACK set
        Assert.Equal(0, flagsByte & 0x02); // SYN not set
        Assert.Equal(0, flagsByte & 0x01); // FIN not set
    }

    [Fact]
    public void BuildIPv4Reset_SetsIPv4VersionAndProtocolFields_MatchingTheOfficialSamplesFixedHeader()
    {
        var packet = MakeTracked(isAck: true, payloadLength: 100);
        var reset = TcpResetPacketBuilder.BuildIPv4Reset(packet);

        // Version(4)/HeaderLength(5 words = 20 bytes) packed into byte 0.
        Assert.Equal(0x45, reset[0]);
        // ip.Protocol = IPPROTO_TCP (6), at offset 9.
        Assert.Equal(6, reset[9]);
        // ip.Length = htons(sizeof(TCPPACKET)) = 40, at offset 2-3.
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(reset.AsSpan(2, 2));
        Assert.Equal(40, totalLength);
        // ip.Id = htons(0xDEAD), at offset 4-5.
        var id = BinaryPrimitives.ReadUInt16BigEndian(reset.AsSpan(4, 2));
        Assert.Equal(0xDEAD, id);
        // ip.TTL = 64, at offset 8.
        Assert.Equal(64, reset[8]);
    }

    [Fact]
    public void BuildIPv4Reset_ThrowsRatherThanRespondingToAnAlreadyRstPacket()
    {
        // Matches netfilter.c's own guard: "!tcp_header->Rst && !tcp_header->Fin".
        var packet = MakeTracked(isRst: true);

        Assert.Throws<InvalidOperationException>(() => TcpResetPacketBuilder.BuildIPv4Reset(packet));
    }

    [Fact]
    public void BuildIPv4Reset_ThrowsRatherThanRespondingToAnAlreadyFinPacket()
    {
        var packet = MakeTracked(isFin: true, isAck: true);

        Assert.Throws<InvalidOperationException>(() => TcpResetPacketBuilder.BuildIPv4Reset(packet));
    }

    [Fact]
    public void BuildIPv4Reset_DoesNotIncludeAnyPayloadBytes_AlwaysExactly40BytesRegardlessOfOriginalPayloadLength()
    {
        // Unlike the captured packet (which may carry a large TCP payload),
        // the forged reset is a bare 40-byte IPv4+TCP header pair, matching
        // the official sample's separate, minimal TCPPACKET struct.
        var smallPayload = MakeTracked(isAck: true, payloadLength: 1);
        var largePayload = MakeTracked(isAck: true, payloadLength: 1400);

        Assert.Equal(40, TcpResetPacketBuilder.BuildIPv4Reset(smallPayload).Length);
        Assert.Equal(40, TcpResetPacketBuilder.BuildIPv4Reset(largePayload).Length);
    }
}
