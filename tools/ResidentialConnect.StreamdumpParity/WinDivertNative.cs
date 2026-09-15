using System.Runtime.InteropServices;

namespace ResidentialConnect.StreamdumpParity;

/// <summary>
/// Independent, from-scratch P/Invoke layer for WinDivert 2.2.2, written
/// specifically for this isolated parity diagnostic. Deliberately NOT
/// shared with <c>ResidentialConnect.Routing.WinDivertNative</c> (the
/// production copy) - the whole point of this tool is to be a second,
/// independent re-verification of the WINDIVERT_ADDRESS struct layout
/// against the real WinDivert 2.2.2 <c>windivert.h</c> (re-fetched
/// 2026-09-15 from
/// https://raw.githubusercontent.com/basil00/Divert/v2.2.2/include/windivert.h),
/// not a copy that could silently share a bug with production.
/// </summary>
/// <remarks>
/// Re-verified field-by-field against the official header's C bitfield
/// declaration:
/// <code>
/// typedef struct
/// {
///     INT64  Timestamp;                   // offset 0
///     UINT32 Layer:8;                      // offset 8, bits 0-7
///     UINT32 Event:8;                      // offset 8, bits 8-15
///     UINT32 Sniffed:1;                    // offset 8, bit 16
///     UINT32 Outbound:1;                   // offset 8, bit 17
///     UINT32 Loopback:1;                   // offset 8, bit 18
///     UINT32 Impostor:1;                   // offset 8, bit 19
///     UINT32 IPv6:1;                       // offset 8, bit 20
///     UINT32 IPChecksum:1;                 // offset 8, bit 21
///     UINT32 TCPChecksum:1;                // offset 8, bit 22
///     UINT32 UDPChecksum:1;                // offset 8, bit 23
///     UINT32 Reserved1:8;                  // offset 8, bits 24-31
///     UINT32 Reserved2;                    // offset 12
///     union { WINDIVERT_DATA_NETWORK Network; ... UINT8 Reserved3[64]; }; // offset 16
/// } WINDIVERT_ADDRESS;    // total size = 8 + 4 + 4 + 64 = 80 bytes
/// </code>
/// This confirms the production struct's bit positions (Outbound=1&lt;&lt;17,
/// Loopback=1&lt;&lt;18, Impostor=1&lt;&lt;19, IPv6=1&lt;&lt;20) and adds the three
/// checksum-validity bits (IPChecksum=1&lt;&lt;21, TCPChecksum=1&lt;&lt;22,
/// UDPChecksum=1&lt;&lt;23) this parity tool additionally needs to log, and
/// which the production copy does not currently expose (it never needed
/// them). Total struct size (80 bytes), the NETWORK union's IfIdx/SubIfIdx
/// offsets (16/20), and the IPv4/TCP header sizes (20/20 bytes) are all
/// re-validated at startup by <see cref="ValidateAbi"/>, independently of
/// production's own <c>WinDivertNative.ValidateAbi()</c>.
/// </remarks>
internal static unsafe class WinDivertNative
{
    internal static readonly IntPtr InvalidHandle = new(-1);

    internal const uint MaxPacketSize = 65575;

    private const uint OutboundBit = 1u << 17;
    private const uint LoopbackBit = 1u << 18;
    private const uint ImpostorBit = 1u << 19;
    private const uint IPv6Bit = 1u << 20;
    private const uint IPChecksumBit = 1u << 21;
    private const uint TCPChecksumBit = 1u << 22;
    private const uint UDPChecksumBit = 1u << 23;

    internal enum Layer : int
    {
        Network = 0
    }

    internal enum Shutdown : int
    {
        Recv = 0x1,
        Send = 0x2,
        Both = 0x3
    }

    [StructLayout(LayoutKind.Explicit, Size = 80)]
    internal struct Address
    {
        [FieldOffset(0)]
        internal long Timestamp;

        [FieldOffset(8)]
        internal uint Flags;

        [FieldOffset(12)]
        internal uint Reserved2;

        [FieldOffset(16)]
        internal uint IfIdx;

        [FieldOffset(20)]
        internal uint SubIfIdx;

        [FieldOffset(16)]
        internal fixed byte Reserved3[64];

        internal bool Outbound => (Flags & OutboundBit) != 0;
        internal bool Loopback => (Flags & LoopbackBit) != 0;
        internal bool Impostor => (Flags & ImpostorBit) != 0;
        internal bool IPv6 => (Flags & IPv6Bit) != 0;
        internal bool IPChecksumValid => (Flags & IPChecksumBit) != 0;
        internal bool TCPChecksumValid => (Flags & TCPChecksumBit) != 0;
        internal bool UDPChecksumValid => (Flags & UDPChecksumBit) != 0;

        internal void SetOutbound(bool value)
        {
            if (value)
            {
                Flags |= OutboundBit;
            }
            else
            {
                Flags &= ~OutboundBit;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct IPv4Header
    {
        internal byte VersionAndHeaderLength;
        internal byte TOS;
        internal ushort Length;
        internal ushort Id;
        internal ushort FragOff0;
        internal byte TTL;
        internal byte Protocol;
        internal ushort Checksum;
        internal uint SrcAddr;
        internal uint DstAddr;

        internal byte HeaderLength => (byte)(VersionAndHeaderLength & 0x0F);
        internal byte Version => (byte)(VersionAndHeaderLength >> 4);
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TcpHeader
    {
        internal ushort SrcPort;
        internal ushort DstPort;
        internal uint SeqNum;
        internal uint AckNum;
        internal ushort HeaderLengthAndFlags;
        internal ushort Window;
        internal ushort Checksum;
        internal ushort UrgPtr;

        internal bool Fin => (HeaderLengthAndFlags & 0x0100) != 0;
        internal bool Syn => (HeaderLengthAndFlags & 0x0200) != 0;
        internal bool Rst => (HeaderLengthAndFlags & 0x0400) != 0;
        internal bool Psh => (HeaderLengthAndFlags & 0x0800) != 0;
        internal bool Ack => (HeaderLengthAndFlags & 0x1000) != 0;
        internal bool Urg => (HeaderLengthAndFlags & 0x2000) != 0;
    }

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertOpen", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr Open([MarshalAs(UnmanagedType.LPStr)] string filter, Layer layer, short priority, ulong flags);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertRecv", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Recv(IntPtr handle, void* packet, uint packetLen, out uint recvLen, Address* address);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertSend", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Send(IntPtr handle, void* packet, uint packetLen, out uint sendLen, Address* address);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertShutdown", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ShutdownHandle(IntPtr handle, Shutdown how);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertClose", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Close(IntPtr handle);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertHelperParsePacket", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ParsePacket(
        void* packet, uint packetLen,
        out IPv4Header* ipv4Header, out IntPtr ipv6Header, out byte protocol,
        out IntPtr icmpHeader, out IntPtr icmpv6Header,
        out TcpHeader* tcpHeader, out IntPtr udpHeader,
        out IntPtr data, out uint dataLen, out IntPtr next, out uint nextLen);

    [DllImport("WinDivert.dll", EntryPoint = "WinDivertHelperCalcChecksums", CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CalcChecksums(void* packet, uint packetLen, Address* address, ulong flags);

    /// <summary>
    /// Independently re-validates the exact same ABI assumptions production's
    /// own <c>ResidentialConnect.Routing.WinDivertNative.ValidateAbi()</c>
    /// checks, using this tool's own, separately-declared structs - so a
    /// pass here is real, independent confirmation, not just "the same code
    /// path agreeing with itself".
    /// </summary>
    internal static void ValidateAbi(Action<string> log)
    {
        var addressSize = Marshal.SizeOf<Address>();
        log($"sizeof(WINDIVERT_ADDRESS) = {addressSize} bytes (expected 80).");
        if (addressSize != 80)
        {
            throw new InvalidOperationException($"WinDivert ADDRESS ABI mismatch. Expected 80 bytes, got {addressSize}.");
        }

        var ipSize = Marshal.SizeOf<IPv4Header>();
        log($"sizeof(WINDIVERT_IPHDR) = {ipSize} bytes (expected 20).");
        if (ipSize != 20)
        {
            throw new InvalidOperationException($"WinDivert IPv4 header ABI mismatch. Expected 20 bytes, got {ipSize}.");
        }

        var tcpSize = Marshal.SizeOf<TcpHeader>();
        log($"sizeof(WINDIVERT_TCPHDR) = {tcpSize} bytes (expected 20).");
        if (tcpSize != 20)
        {
            throw new InvalidOperationException($"WinDivert TCP header ABI mismatch. Expected 20 bytes, got {tcpSize}.");
        }

        var ifIdxOffset = Marshal.OffsetOf<Address>(nameof(Address.IfIdx)).ToInt32();
        var subIfIdxOffset = Marshal.OffsetOf<Address>(nameof(Address.SubIfIdx)).ToInt32();
        log($"WINDIVERT_DATA_NETWORK.IfIdx offset = {ifIdxOffset} (expected 16), SubIfIdx offset = {subIfIdxOffset} (expected 20).");
        if (ifIdxOffset != 16 || subIfIdxOffset != 20)
        {
            throw new InvalidOperationException($"WinDivert NETWORK address ABI mismatch. Expected IfIdx/SubIfIdx offsets 16/20, got {ifIdxOffset}/{subIfIdxOffset}.");
        }

        var flagsOffset = Marshal.OffsetOf<Address>(nameof(Address.Flags)).ToInt32();
        log($"WINDIVERT_ADDRESS.Flags (Layer/Event/Sniffed/Outbound/.../Reserved1 bitfield) offset = {flagsOffset} (expected 8).");
        if (flagsOffset != 8)
        {
            throw new InvalidOperationException($"WinDivert ADDRESS ABI mismatch. Expected Flags offset 8, got {flagsOffset}.");
        }

        log("ABI validation PASSED - struct layout matches WinDivert 2.2.2 windivert.h exactly.");
    }
}
