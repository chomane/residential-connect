using System.Net;
using System.Net.Sockets;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="DnsUdpReplyPacketBuilder"/> - the pure IPv4/IPv6 DNS
/// UDP reply packet construction used by the proxied-DoH DNS capture path
/// (correction #2/#4/#9). Pins byte-for-byte the address/port swap, fixed
/// header fields, and payload placement - the same testing approach already
/// used for <see cref="TcpResetPacketBuilder"/>.
/// </summary>
public class DnsUdpReplyPacketBuilderTests
{
    private static CapturedUdpPacket MakeIPv4Query(byte[]? payload = null) => new(
        AddressFamily.InterNetwork,
        SrcAddr: IPAddress.Parse("192.168.1.50"),
        SrcPort: 54321,
        DstAddr: IPAddress.Parse("8.8.8.8"),
        DstPort: 53,
        Payload: payload ?? new byte[] { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

    private static CapturedUdpPacket MakeIPv6Query(byte[]? payload = null) => new(
        AddressFamily.InterNetworkV6,
        SrcAddr: IPAddress.Parse("fe80::1"),
        SrcPort: 54321,
        DstAddr: IPAddress.Parse("2606:4700:4700::1111"),
        DstPort: 53,
        Payload: payload ?? new byte[] { 0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01 });

    [Fact]
    public void BuildReply_IPv4_SwapsSourceAndDestination()
    {
        var query = MakeIPv4Query();
        var dnsResponse = new byte[] { 0xAA, 0xBB, 0x81, 0x80 };

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        // IPv4 header: SrcAddr at byte 12, DstAddr at byte 16.
        var replySrc = new IPAddress(packet[12..16]);
        var replyDst = new IPAddress(packet[16..20]);
        Assert.Equal(query.DstAddr, replySrc);
        Assert.Equal(query.SrcAddr, replyDst);
    }

    [Fact]
    public void BuildReply_IPv4_SwapsSourceAndDestinationPorts()
    {
        var query = MakeIPv4Query();
        var dnsResponse = new byte[] { 0xAA, 0xBB };

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        // UDP header starts right after the 20-byte IPv4 header.
        var replySrcPort = (packet[20] << 8) | packet[21];
        var replyDstPort = (packet[22] << 8) | packet[23];
        Assert.Equal(53, replySrcPort);
        Assert.Equal(54321, replyDstPort);
    }

    [Fact]
    public void BuildReply_IPv4_EmbedsThePayloadVerbatim()
    {
        var query = MakeIPv4Query();
        var dnsResponse = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02 };

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        // 20-byte IPv4 header + 8-byte UDP header = 28-byte offset.
        var embeddedPayload = packet[28..];
        Assert.Equal(dnsResponse, embeddedPayload);
    }

    [Fact]
    public void BuildReply_IPv4_TotalLengthIsHeadersPlusPayload()
    {
        var query = MakeIPv4Query();
        var dnsResponse = new byte[100];

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        Assert.Equal(20 + 8 + 100, packet.Length);
    }

    [Fact]
    public void BuildReply_IPv4_SetsVersion4AndUdpProtocolNumber()
    {
        var query = MakeIPv4Query();
        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, new byte[] { 0x01 });

        Assert.Equal(0x45, packet[0]); // version 4, 20-byte header
        Assert.Equal(17, packet[9]); // protocol = UDP
    }

    [Fact]
    public void BuildReply_IPv6_SwapsSourceAndDestination()
    {
        var query = MakeIPv6Query();
        var dnsResponse = new byte[] { 0x01, 0x02 };

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        // IPv6 fixed header: SrcAddr at byte 8 (16 bytes), DstAddr at byte 24 (16 bytes).
        var replySrc = new IPAddress(packet[8..24]);
        var replyDst = new IPAddress(packet[24..40]);
        Assert.Equal(query.DstAddr, replySrc);
        Assert.Equal(query.SrcAddr, replyDst);
    }

    [Fact]
    public void BuildReply_IPv6_SwapsSourceAndDestinationPorts()
    {
        var query = MakeIPv6Query();
        var dnsResponse = new byte[] { 0x01 };

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        // UDP header starts right after the fixed 40-byte IPv6 header.
        var replySrcPort = (packet[40] << 8) | packet[41];
        var replyDstPort = (packet[42] << 8) | packet[43];
        Assert.Equal(53, replySrcPort);
        Assert.Equal(54321, replyDstPort);
    }

    [Fact]
    public void BuildReply_IPv6_EmbedsThePayloadVerbatim()
    {
        var query = MakeIPv6Query();
        var dnsResponse = new byte[] { 0x11, 0x22, 0x33 };

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        // 40-byte IPv6 header + 8-byte UDP header = 48-byte offset.
        Assert.Equal(dnsResponse, packet[48..]);
    }

    [Fact]
    public void BuildReply_IPv6_SetsVersion6AndUdpNextHeader()
    {
        var query = MakeIPv6Query();
        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, new byte[] { 0x01 });

        Assert.Equal(0x60, packet[0] & 0xF0); // top nibble = version 6
        Assert.Equal(17, packet[6]); // NextHeader = UDP
    }

    [Fact]
    public void BuildReply_IPv6_TotalLengthIsFixedHeaderPlusUdpPlusPayload()
    {
        var query = MakeIPv6Query();
        var dnsResponse = new byte[50];

        var packet = DnsUdpReplyPacketBuilder.BuildReply(query, dnsResponse);

        Assert.Equal(40 + 8 + 50, packet.Length);
    }

    [Fact]
    public void BuildReply_UnsupportedAddressFamily_Throws()
    {
        var query = new CapturedUdpPacket(
            AddressFamily.AppleTalk,
            IPAddress.Loopback,
            1,
            IPAddress.Loopback,
            53,
            Array.Empty<byte>());

        Assert.Throws<NotSupportedException>(() => DnsUdpReplyPacketBuilder.BuildReply(query, new byte[] { 1 }));
    }

    [Fact]
    public void BuildReply_NullOriginal_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => DnsUdpReplyPacketBuilder.BuildReply(null!, new byte[] { 1 }));
    }

    [Fact]
    public void BuildReply_NullPayload_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => DnsUdpReplyPacketBuilder.BuildReply(MakeIPv4Query(), null!));
    }
}
