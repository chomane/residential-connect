using System.Net;
using System.Net.Sockets;

namespace ResidentialConnect.Routing;

/// <summary>
/// Minimal, immutable snapshot of a captured outbound UDP/53 (DNS) packet -
/// the UDP counterpart of <see cref="CapturedTcpPacket"/>, used by the
/// DNS-over-HTTPS capture path (correction #2/#4/#9: "UDP/53 (IPv4 OR IPv6)
/// -&gt; intercepted and answered using proxied DoH"). Deliberately carries
/// the RAW DNS wire-format payload bytes verbatim, never parsed - see
/// <see cref="DnsUdpReplyPacketBuilder"/> remarks for why preserving the
/// original bytes untouched (rather than manually parsing/reconstructing
/// the DNS message) is the deliberate design choice.
/// </summary>
public sealed record CapturedUdpPacket(
    AddressFamily AddressFamily,
    IPAddress SrcAddr,
    int SrcPort,
    IPAddress DstAddr,
    int DstPort,
    byte[] Payload);
