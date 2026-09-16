using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the pure raw-DNS-probe query/response helper used by
/// <c>tools/ResidentialConnect.RoutingDiagnostic</c>'s new UDP/53
/// leak-protection acceptance checks. No network I/O, no Windows
/// dependency - these run on any OS, exactly like
/// <see cref="BypassFilterBuilderTests"/>.
/// </summary>
public class RawDnsProbeMessageTests
{
    [Fact]
    public void BuildQuery_EncodesTransactionIdInFirstTwoBytes()
    {
        var query = RawDnsProbeMessage.BuildQuery(0x1234, "example.com");

        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);
    }

    [Fact]
    public void BuildQuery_SetsRecursionDesiredStandardQueryFlags()
    {
        var query = RawDnsProbeMessage.BuildQuery(1, "example.com");

        // QR=0, Opcode=0000, AA=0, TC=0, RD=1 -> 0x01
        Assert.Equal(0x01, query[2]);
        Assert.Equal(0x00, query[3]);
    }

    [Fact]
    public void BuildQuery_SetsExactlyOneQuestionAndZeroOtherCounts()
    {
        var query = RawDnsProbeMessage.BuildQuery(1, "example.com");

        Assert.Equal(0x00, query[4]);
        Assert.Equal(0x01, query[5]); // QDCOUNT = 1
        Assert.Equal(0x00, query[6]);
        Assert.Equal(0x00, query[7]); // ANCOUNT = 0
        Assert.Equal(0x00, query[8]);
        Assert.Equal(0x00, query[9]); // NSCOUNT = 0
        Assert.Equal(0x00, query[10]);
        Assert.Equal(0x00, query[11]); // ARCOUNT = 0
    }

    [Fact]
    public void BuildQuery_EncodesLabelsWithLengthPrefixesAndRootTerminator()
    {
        var query = RawDnsProbeMessage.BuildQuery(1, "a.bc");

        // 12-byte header, then: 0x01 'a' 0x02 'b' 'c' 0x00 (root) then QTYPE/QCLASS
        Assert.Equal(0x01, query[12]);
        Assert.Equal((byte)'a', query[13]);
        Assert.Equal(0x02, query[14]);
        Assert.Equal((byte)'b', query[15]);
        Assert.Equal((byte)'c', query[16]);
        Assert.Equal(0x00, query[17]); // root label terminator
        Assert.Equal(0x00, query[18]);
        Assert.Equal(0x01, query[19]); // QTYPE = A
        Assert.Equal(0x00, query[20]);
        Assert.Equal(0x01, query[21]); // QCLASS = IN
        Assert.Equal(22, query.Length);
    }

    [Fact]
    public void BuildQuery_EmptyHostName_Throws()
    {
        Assert.Throws<ArgumentException>(() => RawDnsProbeMessage.BuildQuery(1, string.Empty));
    }

    [Fact]
    public void IsValidDnsResponse_NullData_ReturnsFalse()
    {
        Assert.False(RawDnsProbeMessage.IsValidDnsResponse(null, 1));
    }

    [Fact]
    public void IsValidDnsResponse_TooShort_ReturnsFalse()
    {
        Assert.False(RawDnsProbeMessage.IsValidDnsResponse(new byte[] { 0x00, 0x01, 0x81 }, 1));
    }

    [Fact]
    public void IsValidDnsResponse_MismatchedTransactionId_ReturnsFalse()
    {
        var response = MakeResponseHeader(id: 0x0002, qr: true, opcode: 0);
        Assert.False(RawDnsProbeMessage.IsValidDnsResponse(response, expectedTransactionId: 0x0001));
    }

    [Fact]
    public void IsValidDnsResponse_QrBitNotSet_ReturnsFalse()
    {
        // A packet that looks like another outbound QUERY (QR=0), not a
        // response - must not be mistaken for a real answer.
        var notAResponse = MakeResponseHeader(id: 0x0042, qr: false, opcode: 0);
        Assert.False(RawDnsProbeMessage.IsValidDnsResponse(notAResponse, expectedTransactionId: 0x0042));
    }

    [Fact]
    public void IsValidDnsResponse_NonStandardOpcode_ReturnsFalse()
    {
        var weirdOpcode = MakeResponseHeader(id: 0x0042, qr: true, opcode: 5);
        Assert.False(RawDnsProbeMessage.IsValidDnsResponse(weirdOpcode, expectedTransactionId: 0x0042));
    }

    [Fact]
    public void IsValidDnsResponse_MatchingIdQrSetStandardOpcode_ReturnsTrue()
    {
        var goodResponse = MakeResponseHeader(id: 0x0042, qr: true, opcode: 0);
        Assert.True(RawDnsProbeMessage.IsValidDnsResponse(goodResponse, expectedTransactionId: 0x0042));
    }

    [Fact]
    public void IsValidDnsResponse_AcceptsNxDomainOrServFailResponseCodes()
    {
        // Deliberate: even an error RCODE still proves a real DNS server
        // received and answered the UDP datagram - that is all this
        // leak-protection probe needs to prove.
        var nxdomain = MakeResponseHeader(id: 7, qr: true, opcode: 0, rcode: 3);
        Assert.True(RawDnsProbeMessage.IsValidDnsResponse(nxdomain, expectedTransactionId: 7));
    }

    private static byte[] MakeResponseHeader(ushort id, bool qr, int opcode, int rcode = 0)
    {
        var buffer = new byte[12];
        buffer[0] = (byte)(id >> 8);
        buffer[1] = (byte)id;
        var flagsHigh = 0;
        if (qr)
        {
            flagsHigh |= 0x80;
        }

        flagsHigh |= (opcode & 0x0F) << 3;
        buffer[2] = (byte)flagsHigh;
        buffer[3] = (byte)(rcode & 0x0F);
        return buffer;
    }
}
