using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ResidentialConnect.StreamdumpParity;

/// <summary>
/// Minimal, ISOLATED "streamdump parity" diagnostic (2026-09-15). See
/// README.md in this folder for the full rationale, and this project's
/// .csproj header comment for why it deliberately does not reference any
/// production Residential Connect code.
///
/// Goal: determine whether the OFFICIAL WinDivert streamdump.c single-handle
/// reflection algorithm (https://github.com/basil00/Divert -
/// examples/streamdump/streamdump.c, re-fetched 2026-09-15 and reproduced
/// almost verbatim here, adapted only to (a) restrict the filter to ONE
/// specific target flow instead of blanket ports, and (b) add extensive
/// per-packet diagnostic logging) can reliably establish a real TCP 3-way
/// handshake with a LOCAL listening socket on THIS Windows machine, driven
/// by a real outbound connection attempt this same process makes - entirely
/// independent of Residential Connect's own production two-handle
/// (forward+return) / flow-table / relay / HTTP-CONNECT architecture.
///
/// If this test's handshake completes quickly and reliably (no multi-second
/// delay before a SYN-ACK is seen), that points the finger squarely at
/// something specific to production's two-handle/flow-table/relay-CONNECT
/// architecture. If this test ALSO exhibits the same "first N SYNs ignored,
/// Nth retransmit finally gets a SYN-ACK" symptom, the bug is almost
/// certainly in address metadata (Network.IfIdx/SubIfIdx), checksum
/// handling, the P/Invoke ABI, or how Windows Filtering Platform itself is
/// treating these reflected packets on this specific machine/NIC - not in
/// anything Residential Connect's proxy/relay layer does.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class Program
{
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static long _forwardCount;
    private static long _returnCount;
    private static long _reinjectedCount;
    private static long _sendFailureCount;

    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine("=== Residential Connect - STREAMDUMP PARITY diagnostic (isolated, single WinDivert handle) ===");
        Console.WriteLine("This tool is INDEPENDENT of production Whole Computer routing (no flow table, no relay,");
        Console.WriteLine("no HTTP CONNECT, no DNS handle). It reproduces the official streamdump.c single-handle");
        Console.WriteLine("reflection algorithm for exactly ONE target flow, to determine whether basic WinDivert");
        Console.WriteLine("reflection can reliably complete a real TCP handshake on this machine at all.");
        Console.WriteLine();

        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("[FAIL] PLATFORM: This tool only runs on Windows.");
            return 1;
        }

        if (!IsElevated())
        {
            Console.WriteLine("[FAIL] ELEVATION: Not running as Administrator. WinDivert requires elevation.");
            return 1;
        }
        Console.WriteLine("[PASS] ELEVATION: Running elevated.");

        var options = Options.Parse(args);
        if (options is null)
        {
            return 2;
        }

        // ---- Independent ABI re-verification (separate from production) ----
        Console.WriteLine();
        Console.WriteLine("--- Independent WINDIVERT_ADDRESS ABI re-verification ---");
        try
        {
            WinDivertNative.ValidateAbi(line => Console.WriteLine($"    {line}"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FAIL] ABI-VALIDATION: {ex.Message}");
            return 1;
        }
        Console.WriteLine("[PASS] ABI-VALIDATION: WINDIVERT_ADDRESS/IPv4/TCP struct layouts confirmed against windivert.h.");

        // ---- Resolve target ----
        Console.WriteLine();
        Console.WriteLine($"--- Resolving target {options.TargetHost}:{options.TargetPort} ---");
        var addresses = await Dns.GetHostAddressesAsync(options.TargetHost);
        var targetIp = Array.Find(addresses, a => a.AddressFamily == AddressFamily.InterNetwork);
        if (targetIp is null)
        {
            Console.WriteLine($"[FAIL] DNS: Could not resolve an IPv4 address for '{options.TargetHost}'.");
            return 1;
        }
        Console.WriteLine($"    Target IPv4: {targetIp}:{options.TargetPort}");

        // ---- Start the LOCAL listener ("PROXY" in streamdump terms) --------
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        var localPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        Console.WriteLine($"    Local listener ('PROXY' role) bound to 0.0.0.0:{localPort}.");

        var listenerCts = new CancellationTokenSource();
        var acceptedTcs = new TaskCompletionSource<IPEndPoint?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var acceptTask = AcceptLoopAsync(listener, acceptedTcs, listenerCts.Token);

        // ---- Build the filter: ONLY this one target flow + the local port --
        // Deliberately narrower than streamdump.c's own filter (which
        // matches by PORT NUMBER ALONE, capturing every flow that happens to
        // share that port) - restricted here by IP address too, per the
        // explicit instruction to capture nothing but this one target flow
        // plus the local relay port, so the console log is not polluted by
        // unrelated background traffic on this machine.
        var filter =
            $"tcp and ((ip.DstAddr == {targetIp} and tcp.DstPort == {options.TargetPort}) or " +
            $"(ip.SrcAddr == {targetIp} and tcp.SrcPort == {options.TargetPort}) or " +
            $"tcp.DstPort == {localPort} or tcp.SrcPort == {localPort})";
        Console.WriteLine($"    WinDivert filter: \"{filter}\"");

        // ---- Open ONE WinDivert NETWORK handle, exactly like streamdump.c --
        var handle = WinDivertNative.Open(filter, WinDivertNative.Layer.Network, 0, 0);
        if (handle == WinDivertNative.InvalidHandle || handle == IntPtr.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            Console.WriteLine($"[FAIL] WINDIVERT-OPEN: Failed to open the WinDivert handle (Win32 error {err}).");
            listenerCts.Cancel();
            listener.Stop();
            return 1;
        }
        Console.WriteLine("[PASS] WINDIVERT-OPEN: Single NETWORK-layer handle opened successfully.");

        // ---- Dedicated thread for the capture loop (lesson learned from --
        // the production ThreadPool-starvation investigation - even though
        // this test only expects one flow, a dedicated thread costs nothing
        // and removes any doubt that scheduling affects THIS result).
        var captureCts = new CancellationTokenSource();
        var captureThread = new Thread(() => CaptureLoop(handle, targetIp, options.TargetPort, localPort, captureCts.Token))
        {
            IsBackground = true,
            Name = "RC-Parity-Capture",
            Priority = ThreadPriority.AboveNormal
        };
        captureThread.Start();

        // Give the capture loop and listener a brief moment to be fully
        // ready before generating the real outbound SYN.
        await Task.Delay(250);

        // ---- The actual trigger: a REAL outbound TCP connect attempt -------
        // Exactly what generates a genuine outbound SYN for the capture loop
        // to reflect - no browser/curl/external tool needed, fully
        // self-contained, mirroring how ResidentialConnect.RoutingDiagnostic
        // triggers production's forward path.
        Console.WriteLine();
        Console.WriteLine($"--- Issuing a real outbound TCP connect() to {targetIp}:{options.TargetPort} at t={Clock.ElapsedMilliseconds}ms ---");
        Console.WriteLine("    (This connection is expected to be reflected into the local listener above -");
        Console.WriteLine("     it will never actually reach the real target. We only care whether/when the");
        Console.WriteLine("     3-way TCP handshake completes, not about any application-layer protocol.)");

        var connectSw = Stopwatch.StartNew();
        bool connected;
        string connectDetail;
        using var probeClient = new TcpClient();
        try
        {
            using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(options.TimeoutSeconds));
            await probeClient.ConnectAsync(targetIp, options.TargetPort, connectCts.Token);
            connectSw.Stop();
            connected = true;
            connectDetail = $"connect() SUCCEEDED after {connectSw.ElapsedMilliseconds}ms (local endpoint {probeClient.Client.LocalEndPoint}).";
        }
        catch (OperationCanceledException)
        {
            connectSw.Stop();
            connected = false;
            connectDetail = $"connect() TIMED OUT after {connectSw.ElapsedMilliseconds}ms (no handshake completion within {options.TimeoutSeconds}s).";
        }
        catch (Exception ex)
        {
            connectSw.Stop();
            connected = false;
            connectDetail = $"connect() FAILED after {connectSw.ElapsedMilliseconds}ms: {DescribeExceptionChain(ex)}";
        }

        Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] {connectDetail}");

        // Give a short grace period for the listener's own Accept to observe
        // the completed handshake and for any trailing FIN/RST to be logged.
        var acceptedEndpoint = await Task.WhenAny(acceptedTcs.Task, Task.Delay(TimeSpan.FromSeconds(3)))
            .ContinueWith(_ => acceptedTcs.Task.IsCompletedSuccessfully ? acceptedTcs.Task.Result : null);

        await Task.Delay(1000);

        // ---- Tear down ------------------------------------------------------
        captureCts.Cancel();
        WinDivertNative.ShutdownHandle(handle, WinDivertNative.Shutdown.Recv);
        captureThread.Join(TimeSpan.FromSeconds(5));
        WinDivertNative.Close(handle);
        listenerCts.Cancel();
        listener.Stop();
        try { await acceptTask; } catch { /* expected on cancel */ }

        Console.WriteLine();
        Console.WriteLine("--- Summary ---");
        Console.WriteLine($"    forwardCaptures={Interlocked.Read(ref _forwardCount)}, returnCaptures={Interlocked.Read(ref _returnCount)}, reinjected={Interlocked.Read(ref _reinjectedCount)}, sendFailures={Interlocked.Read(ref _sendFailureCount)}");
        Console.WriteLine($"    Local listener accepted a connection: {(acceptedEndpoint is not null ? $"YES, apparent peer {acceptedEndpoint}" : "NO")}");
        Console.WriteLine($"    connect() outcome: {connectDetail}");

        var pass = connected && acceptedEndpoint is not null;
        Console.WriteLine();
        Console.WriteLine(pass
            ? "=== OVERALL RESULT: PASS - single-handle streamdump-style reflection established a real TCP handshake. ==="
            : "=== OVERALL RESULT: FAIL - the handshake did not complete (or took the whole timeout) even with the minimal, isolated, official-algorithm single-handle test. ===");
        Console.WriteLine();
        Console.WriteLine(pass
            ? "    INTERPRETATION: since basic WinDivert reflection works fine in isolation, the bug is most"
            : "    INTERPRETATION: since even this minimal, single-handle, flow-table-free, relay-free test");
        Console.WriteLine(pass
            ? "    likely specific to Residential Connect's own two-handle/flow-table/relay/CONNECT"
            : "    reproduces the failure, focus next on address metadata (Network.IfIdx/SubIfIdx), checksum");
        Console.WriteLine(pass
            ? "    architecture, not to the fundamental reflection technique itself."
            : "    flags, the P/Invoke ABI, or how Windows Filtering Platform/this NIC treats reflected");
        if (!pass)
        {
            Console.WriteLine("    packets on this specific machine - NOT the proxy/relay layer.");
        }

        return pass ? 0 : 1;
    }

    private static async Task AcceptLoopAsync(TcpListener listener, TaskCompletionSource<IPEndPoint?> firstAccepted, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                var peer = (IPEndPoint?)client.Client.RemoteEndPoint;
                Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] [LOCAL-LISTENER] Accepted a connection - apparent peer (should look like the real target): {peer}");
                firstAccepted.TrySetResult(peer);
                // Nothing further to do - this test only proves the 3-way
                // handshake completes; it deliberately does not relay any
                // application-layer bytes (no HTTP CONNECT, no proxy).
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static unsafe void CaptureLoop(IntPtr handle, IPAddress targetIp, int targetPort, int localPort, CancellationToken cancellationToken)
    {
        var buffer = GC.AllocateUninitializedArray<byte>((int)WinDivertNative.MaxPacketSize, pinned: true);

        fixed (byte* packetBuffer = buffer)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                WinDivertNative.Address address = default;

                if (!WinDivertNative.Recv(handle, packetBuffer, WinDivertNative.MaxPacketSize, out var recvLen, &address))
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    var recvError = Marshal.GetLastWin32Error();
                    Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] WinDivertRecv FAILED (Win32 error {recvError}).");
                    continue;
                }

                if (recvLen == 0 || recvLen > WinDivertNative.MaxPacketSize)
                {
                    continue;
                }

                ProcessPacket(handle, packetBuffer, recvLen, &address, targetIp, targetPort, localPort);
            }
        }
    }

    private static unsafe void ProcessPacket(
        IntPtr handle, byte* packetBuffer, uint recvLen, WinDivertNative.Address* address,
        IPAddress targetIp, int targetPort, int localPort)
    {
        var result = WinDivertNative.ParsePacket(
            packetBuffer, recvLen,
            out var ip, out _, out var protocol, out _, out _,
            out var tcp, out _, out _, out _, out _, out _);

        if (!result || ip == null || tcp == null || ip->Version != 4 || protocol != 6)
        {
            return;
        }

        var isForward = address->Outbound; // will be re-checked precisely below, this is just for counting
        if (isForward) Interlocked.Increment(ref _forwardCount); else Interlocked.Increment(ref _returnCount);

        var srcAddr = NativeIpv4ToIPAddress(ip->SrcAddr);
        var dstAddr = NativeIpv4ToIPAddress(ip->DstAddr);
        var srcPort = NativePortToHost(tcp->SrcPort);
        var dstPort = NativePortToHost(tcp->DstPort);
        var seq = BinaryPrimitives.ReverseEndianness(tcp->SeqNum);
        var ack = BinaryPrimitives.ReverseEndianness(tcp->AckNum);
        var beforeIpChecksum = ip->Checksum;
        var beforeTcpChecksum = tcp->Checksum;

        Console.WriteLine(
            $"    [t={Clock.ElapsedMilliseconds}ms] CAPTURED {srcAddr}:{srcPort} -> {dstAddr}:{dstPort} " +
            $"flags=[{DescribeFlags(tcp)}] seq={seq} ack={ack} " +
            $"Outbound={address->Outbound} Loopback={address->Loopback} Impostor={address->Impostor} " +
            $"IPChecksumValid={address->IPChecksumValid} TCPChecksumValid={address->TCPChecksumValid} " +
            $"IfIdx={address->IfIdx} SubIfIdx={address->SubIfIdx} " +
            $"ipChecksumBefore=0x{beforeIpChecksum:X4} tcpChecksumBefore=0x{beforeTcpChecksum:X4}");

        // --- EXACT official streamdump.c reflection algorithm -------------
        // (see https://github.com/basil00/Divert examples/streamdump/streamdump.c,
        // re-fetched 2026-09-15; "port" = targetPort, "proxy_port" = localPort;
        // no ALT_PORT redirect branch here - out of scope for this parity
        // test, which only cares about the PORT<->PROXY reflection pair).
        var reflected = false;
        if (address->Outbound)
        {
            if (tcp->DstPort == HostPortToNative(targetPort) && ip->DstAddr == IPAddressToNativeIpv4(targetIp))
            {
                // Reflect: PORT ---> PROXY (identical to streamdump.c)
                var dstAddrNative = ip->DstAddr;
                tcp->DstPort = HostPortToNative(localPort);
                ip->DstAddr = ip->SrcAddr;
                ip->SrcAddr = dstAddrNative;
                address->SetOutbound(false);
                reflected = true;
            }
            else if (tcp->SrcPort == HostPortToNative(localPort))
            {
                // Reflect: PROXY ---> PORT (identical to streamdump.c)
                var dstAddrNative = ip->DstAddr;
                tcp->SrcPort = HostPortToNative(targetPort);
                ip->DstAddr = ip->SrcAddr;
                ip->SrcAddr = dstAddrNative;
                address->SetOutbound(false);
                reflected = true;
            }
        }

        if (!reflected)
        {
            // Not one of the two reflection cases streamdump.c handles for
            // this pair (e.g. an already-inbound packet WinDivert re-offered,
            // or a packet that matched the filter for some other reason) -
            // streamdump.c's own main loop falls through to WinDivertSend
            // UNCONDITIONALLY for every captured packet, including ones that
            // matched neither branch (it has no separate "drop" path at all
            // for the single-flow case). We reproduce that exactly: WinDivert
            // itself already made the capture decision via the filter, and
            // any packet not matching one of the two branches above is
            // resent completely UNMODIFIED, exactly as-is - this is the
            // official algorithm's own behavior, not a Residential Connect
            // fail-closed design (this isolated tool intentionally has no
            // fail-closed policy of its own).
            Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] (no reflection case matched - resending UNMODIFIED, exactly like streamdump.c's fall-through.)");
        }
        else
        {
            var newSrc = NativeIpv4ToIPAddress(ip->SrcAddr);
            var newDst = NativeIpv4ToIPAddress(ip->DstAddr);
            var newSrcPort = NativePortToHost(tcp->SrcPort);
            var newDstPort = NativePortToHost(tcp->DstPort);
            Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] REFLECTED -> {newSrc}:{newSrcPort} -> {newDst}:{newDstPort} Outbound={address->Outbound}");
        }

        if (!WinDivertNative.CalcChecksums(packetBuffer, recvLen, address, 0))
        {
            var checksumError = Marshal.GetLastWin32Error();
            Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] WinDivertHelperCalcChecksums FAILED (Win32 error {checksumError}).");
            return;
        }

        var afterIpChecksum = ip->Checksum;
        var afterTcpChecksum = tcp->Checksum;
        Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] ipChecksumAfter=0x{afterIpChecksum:X4} tcpChecksumAfter=0x{afterTcpChecksum:X4}");

        if (!WinDivertNative.Send(handle, packetBuffer, recvLen, out _, address))
        {
            var sendError = Marshal.GetLastWin32Error();
            Interlocked.Increment(ref _sendFailureCount);
            Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] WinDivertSend FAILED (Win32 error {sendError}).");
            return;
        }

        Interlocked.Increment(ref _reinjectedCount);
        Console.WriteLine($"    [t={Clock.ElapsedMilliseconds}ms] WinDivertSend OK (reinjected).");
    }

    private static unsafe string DescribeFlags(WinDivertNative.TcpHeader* tcp)
    {
        var flags = new List<string>(4);
        if (tcp->Syn) flags.Add("SYN");
        if (tcp->Ack) flags.Add("ACK");
        if (tcp->Fin) flags.Add("FIN");
        if (tcp->Rst) flags.Add("RST");
        return flags.Count == 0 ? "-" : string.Join(",", flags);
    }

    private static string DescribeExceptionChain(Exception ex)
    {
        var parts = new List<string>();
        var current = ex;
        var depth = 0;
        while (current is not null && depth < 10)
        {
            parts.Add($"[{depth}] {current.GetType().FullName}: {current.Message}");
            current = current.InnerException;
            depth++;
        }
        return string.Join(" <-- ", parts);
    }

    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static int NativePortToHost(ushort nativePort) => BinaryPrimitives.ReverseEndianness(nativePort);

    private static ushort HostPortToNative(int hostPort) => BinaryPrimitives.ReverseEndianness((ushort)hostPort);

    private static IPAddress NativeIpv4ToIPAddress(uint nativeAddress) => new(BitConverter.GetBytes(nativeAddress));

    private static uint IPAddressToNativeIpv4(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes(), 0);

    private sealed class Options
    {
        public string TargetHost { get; private init; } = "1.1.1.1";
        public int TargetPort { get; private init; } = 443;
        public int TimeoutSeconds { get; private init; } = 15;

        public static Options? Parse(string[] args)
        {
            var opts = new Options();
            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--target-host" when i + 1 < args.Length:
                        opts = new Options { TargetHost = args[++i], TargetPort = opts.TargetPort, TimeoutSeconds = opts.TimeoutSeconds };
                        break;
                    case "--target-port" when i + 1 < args.Length && int.TryParse(args[i + 1], out var p):
                        opts = new Options { TargetHost = opts.TargetHost, TargetPort = p, TimeoutSeconds = opts.TimeoutSeconds };
                        i++;
                        break;
                    case "--timeout-seconds" when i + 1 < args.Length && int.TryParse(args[i + 1], out var t):
                        opts = new Options { TargetHost = opts.TargetHost, TargetPort = opts.TargetPort, TimeoutSeconds = t };
                        i++;
                        break;
                    case "--help":
                    case "-h":
                        Console.WriteLine("usage: ResidentialConnect.StreamdumpParity [--target-host HOST] [--target-port PORT] [--timeout-seconds N]");
                        return null;
                    default:
                        Console.Error.WriteLine($"Unrecognized argument: {args[i]}");
                        return null;
                }
            }

            return opts;
        }
    }
}
