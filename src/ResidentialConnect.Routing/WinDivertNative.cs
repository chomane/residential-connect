using System.Runtime.InteropServices;

namespace ResidentialConnect.Routing;

/// <summary>
/// Minimal, direct P/Invoke interop for the official WinDivert 2.2.2 native
/// API (<c>WinDivert.dll</c>/<c>WinDivert64.sys</c>, shipped unmodified by
/// the <c>Native.WinDivert</c> NuGet package).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why direct P/Invoke instead of a managed wrapper package:</b> an
/// earlier revision of this router used the <c>Aigio.WinDivertSharp</c>
/// managed wrapper, whose <c>WinDivertAddress</c> struct is only 24 bytes.
/// WinDivert 2.2.2's real <c>WINDIVERT_ADDRESS</c> is 80 bytes. Passing a
/// 24-byte buffer to a native API that writes 80 bytes corrupts adjacent
/// managed memory on every single <c>WinDivertRecv</c>/<c>WinDivertSend</c>
/// call - a credible root cause of the <c>coreclr.dll</c> access-violation
/// crashes observed during live Windows testing. This file's <see cref="Address"/>
/// struct is laid out to match the official 80-byte <c>WINDIVERT_ADDRESS</c>
/// exactly (validated at runtime by <see cref="ValidateAbi"/>, called once
/// before any handle is opened). Do not reintroduce
/// <c>Aigio.WinDivertSharp</c> or any other third-party WinDivert wrapper
/// without re-verifying its address-struct size against whatever WinDivert
/// native version is actually bundled.
/// </para>
/// <para>
/// <b>TCP/IP header fields are network (big-endian) byte order.</b> Ports
/// read from <see cref="TcpHeader.SrcPort"/>/<see cref="TcpHeader.DstPort"/>
/// must be byte-swapped to host order before use in managed code, and
/// swapped back before writing a rewritten port back into the packet - see
/// <c>WinDivertSystemTrafficRouter.NativePortToHost</c>/<c>HostPortToNative</c>.
/// </para>
/// </remarks>
internal static unsafe class WinDivertNative
{
    internal static readonly IntPtr InvalidHandle = new(-1);

    internal const uint MaxPacketSize = 65575;

    /// <summary>Bit position of the <c>Outbound</c> flag within <see cref="Address.Flags"/> (see WINDIVERT_ADDRESS: Layer:8, Event:8, Sniffed:1, Outbound:1, ...).</summary>
    private const uint OutboundBit = 1u << 17;

    internal enum Layer : int
    {
        Network = 0,
        NetworkForward = 1,
        Flow = 2,
        Socket = 3,
        Reflect = 4
    }

    [Flags]
    internal enum OpenFlags : ulong
    {
        None = 0,
        Sniff = 0x0001,
        Drop = 0x0002,
        RecvOnly = 0x0004,
        SendOnly = 0x0008,
        NoInstall = 0x0010,
        Fragments = 0x0020
    }

    internal enum Shutdown : int
    {
        Recv = 0x1,
        Send = 0x2,
        Both = 0x3
    }

    /// <summary>
    /// WINDIVERT_PARAM identifiers for <see cref="SetParam"/>. Only the two
    /// used by this router are declared. See remarks on
    /// <see cref="SetParam"/> for why <c>QueueLength</c>/<c>QueueTime</c> are
    /// tuned up from their defaults.
    /// </summary>
    internal enum Param : int
    {
        QueueLength = 0,
        QueueTime = 1,
        QueueSize = 2,
        VersionMajor = 3,
        VersionMinor = 4
    }

    /// <summary>
    /// Exact 80-byte WINDIVERT_ADDRESS layout used by WinDivert 2.2.2.
    ///
    /// Offset  0: INT64 Timestamp
    /// Offset  8: 32-bit Layer/Event/flag bitfield
    /// Offset 12: UINT32 Reserved2
    /// Offset 16: 64-byte layer-specific union
    ///
    /// At NETWORK layer the first 8 bytes of the union are:
    /// UINT32 IfIdx, UINT32 SubIfIdx.
    /// </summary>
    [StructLayout(LayoutKind.Explicit, Size = 80)]
    internal struct Address
    {
        [FieldOffset(0)]
        internal long Timestamp;

        // Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1,
        // Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1,
        // UDPChecksum:1, Reserved1:8.
        [FieldOffset(8)]
        internal uint Flags;

        [FieldOffset(12)]
        internal uint Reserved2;

        // WINDIVERT_DATA_NETWORK begins at offset 16.
        [FieldOffset(16)]
        internal uint IfIdx;

        [FieldOffset(20)]
        internal uint SubIfIdx;

        // Force the complete 64-byte union to exist through offset 79.
        [FieldOffset(16)]
        internal fixed byte Reserved3[64];

        internal bool Outbound => (Flags & OutboundBit) != 0;

        internal bool Loopback => (Flags & (1u << 18)) != 0;

        internal bool Impostor => (Flags & (1u << 19)) != 0;

        internal bool IPv6 => (Flags & (1u << 20)) != 0;
    }

    /// <summary>
    /// Clears the <c>Outbound</c> bit so a captured (genuinely outbound)
    /// packet is re-injected as an INBOUND packet - the core of WinDivert's
    /// official transparent-proxy "reflection" pattern (see
    /// <c>WinDivertSystemTrafficRouter</c> remarks and the upstream
    /// <c>streamdump.c</c> sample). Re-injecting with the direction
    /// unchanged (the V0.2.0 bug this router previously shipped with) makes
    /// Windows treat the rewritten packet as an ordinary outbound send to
    /// the new destination, which for a real (non-loopback-consistent)
    /// source/destination combination is silently dropped by the TCP/IP
    /// stack's anti-spoofing checks - explaining the observed
    /// timeout/connection-reset symptoms.
    /// </summary>
    internal static void MarkInbound(Address* address)
    {
        address->Flags &= ~OutboundBit;
    }

    /// <summary>
    /// Raw IPv4 header layout.
    ///
    /// The first byte contains HdrLength in the low nibble and Version in the
    /// high nibble. We do not use C# bitfields; HeaderLength/Version expose
    /// those values safely.
    /// </summary>
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

    /// <summary>
    /// Raw TCP header layout.
    ///
    /// WinDivert's native TCP bitfields occupy the 16-bit value at offset 12.
    /// We expose the flags through masks instead of relying on C# bitfield
    /// layout.
    /// </summary>
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

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertOpen",
        CallingConvention = CallingConvention.Cdecl,
        CharSet = CharSet.Ansi,
        SetLastError = true)]
    internal static extern IntPtr Open(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        Layer layer,
        short priority,
        ulong flags);

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertRecv",
        CallingConvention = CallingConvention.Cdecl,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Recv(
        IntPtr handle,
        void* packet,
        uint packetLen,
        out uint recvLen,
        Address* address);

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertSend",
        CallingConvention = CallingConvention.Cdecl,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Send(
        IntPtr handle,
        void* packet,
        uint packetLen,
        out uint sendLen,
        Address* address);

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertShutdown",
        CallingConvention = CallingConvention.Cdecl,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ShutdownHandle(
        IntPtr handle,
        Shutdown how);

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertClose",
        CallingConvention = CallingConvention.Cdecl,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Close(IntPtr handle);

    /// <summary>
    /// Sets a per-handle WinDivert queue parameter
    /// (<c>WinDivertSetParam</c>). Used to raise <see cref="Param.QueueLength"/>
    /// and <see cref="Param.QueueTime"/> above their (fairly small) defaults
    /// - see <c>WinDivertSystemTrafficRouter</c>'s remarks on why the
    /// capture loops must be serviced by dedicated OS threads AND why the
    /// driver-side queue itself is given extra headroom as a second,
    /// independent safety margin against the same "packet captured but not
    /// read in time gets silently dropped" failure mode.
    /// </summary>
    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertSetParam",
        CallingConvention = CallingConvention.Cdecl,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetParam(IntPtr handle, Param param, ulong value);

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertHelperParsePacket",
        CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ParsePacket(
        void* packet,
        uint packetLen,
        out IPv4Header* ipv4Header,
        out IntPtr ipv6Header,
        out byte protocol,
        out IntPtr icmpHeader,
        out IntPtr icmpv6Header,
        out TcpHeader* tcpHeader,
        out IntPtr udpHeader,
        out IntPtr data,
        out uint dataLen,
        out IntPtr next,
        out uint nextLen);

    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertHelperCalcChecksums",
        CallingConvention = CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CalcChecksums(
        void* packet,
        uint packetLen,
        Address* address,
        ulong flags);

    /// <summary>
    /// Compiles and validates a WinDivert filter without opening a
    /// WinDivert handle or starting packet interception.
    ///
    /// The object buffer is optional in the native API. Passing null
    /// performs syntax/semantic validation only.
    /// </summary>
    [DllImport(
        "WinDivert.dll",
        EntryPoint = "WinDivertHelperCompileFilter",
        CallingConvention = CallingConvention.Cdecl,
        CharSet = CharSet.Ansi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CompileFilterNative(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        Layer layer,
        IntPtr obj,
        uint objLen,
        out IntPtr errorStr,
        out uint errorPos);

    /// <summary>
    /// Validates a WinDivert filter and returns the native parser error
    /// information if validation fails.
    /// </summary>
    internal static bool TryCompileFilter(
        string filter,
        Layer layer,
        out string? error,
        out uint errorPosition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filter);

        var result = CompileFilterNative(
            filter,
            layer,
            IntPtr.Zero,
            0,
            out var errorPtr,
            out errorPosition);

        if (result)
        {
            error = null;
            errorPosition = 0;
            return true;
        }

        error = errorPtr == IntPtr.Zero
            ? "Unknown WinDivert filter error."
            : Marshal.PtrToStringAnsi(errorPtr);

        return false;
    }

    /// <summary>
    /// Verifies the ABI assumptions that matter most before native packet
    /// capture is ever started.
    /// </summary>
    internal static void ValidateAbi()
    {
        var addressSize = Marshal.SizeOf<Address>();
        if (addressSize != 80)
        {
            throw new InvalidOperationException(
                $"WinDivert ADDRESS ABI mismatch. Expected 80 bytes for WinDivert 2.2.2, got {addressSize}.");
        }

        var ipSize = Marshal.SizeOf<IPv4Header>();
        if (ipSize != 20)
        {
            throw new InvalidOperationException(
                $"WinDivert IPv4 header ABI mismatch. Expected 20 bytes, got {ipSize}.");
        }

        var tcpSize = Marshal.SizeOf<TcpHeader>();
        if (tcpSize != 20)
        {
            throw new InvalidOperationException(
                $"WinDivert TCP header ABI mismatch. Expected 20 bytes, got {tcpSize}.");
        }

        var ifIdxOffset = Marshal.OffsetOf<Address>(nameof(Address.IfIdx)).ToInt32();
        var subIfIdxOffset = Marshal.OffsetOf<Address>(nameof(Address.SubIfIdx)).ToInt32();

        if (ifIdxOffset != 16 || subIfIdxOffset != 20)
        {
            throw new InvalidOperationException(
                $"WinDivert NETWORK address ABI mismatch. Expected IfIdx/SubIfIdx offsets 16/20, got {ifIdxOffset}/{subIfIdxOffset}.");
        }
    }
}
