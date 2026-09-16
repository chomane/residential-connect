using System.Text;

namespace ResidentialConnect.Routing;

/// <summary>
/// Pure, allocation-simple helper for constructing and validating a minimal
/// raw DNS query/response pair over UDP. This class performs NO network I/O
/// itself - it exists specifically so <c>tools/ResidentialConnect.RoutingDiagnostic</c>
/// can independently prove UDP/53 leak protection end-to-end:
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a hand-rolled raw query instead of <see cref="System.Net.Dns"/>:</b>
/// the whole point of this probe is to send a real UDP/53 packet and observe
/// whether ANY response arrives at the socket level - <see cref="System.Net.Dns"/>
/// (and the OS resolver it wraps) may cache results, retry over multiple
/// transports, or otherwise obscure whether the specific UDP round-trip
/// actually happened. A raw, single-shot UDP datagram built and parsed here
/// gives the diagnostic tool an unambiguous, single-packet signal: either a
/// syntactically valid DNS response with the matching transaction ID comes
/// back on this exact socket, or it does not.
/// </para>
/// <para>
/// <b>Why this lives in <c>ResidentialConnect.Routing</c> (not the tool
/// project) and does no I/O:</b> keeping the query-building/response-parsing
/// logic pure and side-effect-free makes it fully unit-testable from
/// <c>tests/ResidentialConnect.Tests</c> without a real network, a real
/// Windows machine, or WinDivert - unlike the actual socket send/receive
/// (owned by the diagnostic tool itself, which is Windows-only per the rest
/// of Whole Computer mode). This is purely additive: it does not read from
/// or modify <see cref="BypassFilterBuilder"/>, <see cref="DnsLeakGuard"/>,
/// or any other already-verified file.
/// </para>
/// </remarks>
public static class RawDnsProbeMessage
{
    private const int HeaderLength = 12;

    /// <summary>
    /// Builds a minimal, standard (recursion-desired) DNS query for an A
    /// record for <paramref name="hostName"/>, tagged with
    /// <paramref name="transactionId"/> so the caller can later match a
    /// response to this exact query with <see cref="IsValidDnsResponse"/>.
    /// </summary>
    public static byte[] BuildQuery(ushort transactionId, string hostName)
    {
        ArgumentException.ThrowIfNullOrEmpty(hostName);

        var labels = hostName.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length == 0)
        {
            throw new ArgumentException("hostName must contain at least one non-empty label.", nameof(hostName));
        }

        var questionLength = labels.Sum(label => 1 + Encoding.ASCII.GetByteCount(label)) + 1 + 4;
        var buffer = new byte[HeaderLength + questionLength];

        // --- Header (RFC 1035 ss4.1.1) ---
        buffer[0] = (byte)(transactionId >> 8);
        buffer[1] = (byte)transactionId;
        buffer[2] = 0x01; // QR=0 (query), Opcode=0 (standard), AA=0, TC=0, RD=1 (recursion desired)
        buffer[3] = 0x00; // RA/Z/RCODE all 0 on a query
        buffer[4] = 0x00; buffer[5] = 0x01; // QDCOUNT = 1
        buffer[6] = 0x00; buffer[7] = 0x00; // ANCOUNT = 0
        buffer[8] = 0x00; buffer[9] = 0x00; // NSCOUNT = 0
        buffer[10] = 0x00; buffer[11] = 0x00; // ARCOUNT = 0

        // --- Question section ---
        var offset = HeaderLength;
        foreach (var label in labels)
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            buffer[offset++] = (byte)labelBytes.Length;
            labelBytes.CopyTo(buffer, offset);
            offset += labelBytes.Length;
        }

        buffer[offset++] = 0x00; // root label terminator
        buffer[offset++] = 0x00; buffer[offset++] = 0x01; // QTYPE = A (1)
        buffer[offset++] = 0x00; buffer[offset++] = 0x01; // QCLASS = IN (1)

        return buffer;
    }

    /// <summary>
    /// Returns true only if <paramref name="data"/> is at least large enough
    /// to contain a DNS header, its transaction ID matches
    /// <paramref name="expectedTransactionId"/>, its QR bit marks it as a
    /// response (not another query), and its Opcode is the standard-query
    /// value this probe always sends. Deliberately does NOT require RCODE
    /// == 0 (NOERROR) - even an NXDOMAIN/SERVFAIL response is still proof
    /// that a real DNS server on the far end received the UDP datagram and
    /// replied, which is the only thing this leak-protection probe cares
    /// about; it is not asserting the queried name actually resolves.
    /// </summary>
    public static bool IsValidDnsResponse(byte[]? data, ushort expectedTransactionId)
    {
        if (data is null || data.Length < HeaderLength)
        {
            return false;
        }

        var responseId = (ushort)((data[0] << 8) | data[1]);
        if (responseId != expectedTransactionId)
        {
            return false;
        }

        var flagsHigh = data[2];
        var isResponse = (flagsHigh & 0x80) != 0; // QR bit
        var opcode = (flagsHigh >> 3) & 0x0F;

        return isResponse && opcode == 0;
    }
}
