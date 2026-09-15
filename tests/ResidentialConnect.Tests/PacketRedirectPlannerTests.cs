using System.Net;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the pure packet-redirect decision logic used by
/// <c>WinDivertSystemTrafficRouter</c>. These exercise the exact fail-closed,
/// NAT-tracking, and full-4-tuple-REFLECTION behavior the product requires
/// WITHOUT needing a real WinDivert handle/Windows kernel - only the actual
/// native packet capture/injection calls require a real Windows machine to
/// verify (see docs/BUILD.md "Windows-only acceptance checklist").
/// </summary>
public class PacketRedirectPlannerTests
{
    private const string ClientAddr = "10.0.0.5";
    private const int ClientPort = 50000;
    private const string RealDestAddr = "93.184.216.34";
    private const int RealDestPort = 443;
    private const int RelayPort = 9000;

    private static CapturedTcpPacket Syn(int srcPort = ClientPort, string srcAddr = ClientAddr, int dstPort = RealDestPort, string dstAddr = RealDestAddr) =>
        new(IsSyn: true, IsAck: false, IsFin: false, IsRst: false, SrcAddr: IPAddress.Parse(srcAddr), SrcPort: srcPort, DstAddr: IPAddress.Parse(dstAddr), DstPort: dstPort);

    private static CapturedTcpPacket Data(int srcPort, string srcAddr, int dstPort, string dstAddr, bool fin = false, bool rst = false) =>
        new(IsSyn: false, IsAck: true, IsFin: fin, IsRst: rst, SrcAddr: IPAddress.Parse(srcAddr), SrcPort: srcPort, DstAddr: IPAddress.Parse(dstAddr), DstPort: dstPort);

    [Fact]
    public void PlanForward_NewSyn_RecordsFlowAndReflectsToRelay()
    {
        var flowTable = new RedirectFlowTable();
        var syn = Syn();

        var decision = PacketRedirectPlanner.PlanForward(syn, flowTable, RelayPort, failClosed: false);

        Assert.True(decision.ShouldReflect);
        // Reflection: new source = real destination address, with the
        // CLIENT'S OWN port unchanged; new destination = the client's real
        // address, with the RELAY's port.
        Assert.Equal(IPAddress.Parse(RealDestAddr), decision.NewSrcAddr);
        Assert.Equal(ClientPort, decision.NewSrcPort);
        Assert.Equal(IPAddress.Parse(ClientAddr), decision.NewDstAddr);
        Assert.Equal(RelayPort, decision.NewDstPort);

        Assert.True(flowTable.TryGetFlow(ClientPort, out var host, out var port));
        Assert.Equal(RealDestAddr, host);
        Assert.Equal(RealDestPort, port);
    }

    [Fact]
    public void PlanForward_SubsequentPacketOfTrackedFlow_KeepsReflecting()
    {
        var flowTable = new RedirectFlowTable();
        PacketRedirectPlanner.PlanForward(Syn(), flowTable, RelayPort, failClosed: false);

        var followUp = Data(ClientPort, ClientAddr, RealDestPort, RealDestAddr);
        var decision = PacketRedirectPlanner.PlanForward(followUp, flowTable, RelayPort, failClosed: false);

        Assert.True(decision.ShouldReflect);
        Assert.Equal(RelayPort, decision.NewDstPort);
        Assert.Equal(IPAddress.Parse(ClientAddr), decision.NewDstAddr);
    }

    [Fact]
    public void PlanForward_UntrackedNonSynPacket_FailsClosed()
    {
        // A connection that was already established BEFORE Whole Computer
        // mode was turned on - the product requirement is that this must
        // never be silently allowed through unmodified.
        var flowTable = new RedirectFlowTable();
        var decision = PacketRedirectPlanner.PlanForward(Data(60000, ClientAddr, RealDestPort, RealDestAddr), flowTable, RelayPort, failClosed: false);

        Assert.False(decision.ShouldReflect);
    }

    [Fact]
    public void PlanForward_WhenFailClosed_DropsEvenABrandNewSyn()
    {
        var flowTable = new RedirectFlowTable();
        var decision = PacketRedirectPlanner.PlanForward(Syn(), flowTable, RelayPort, failClosed: true);

        Assert.False(decision.ShouldReflect);
        // And crucially, it must not have been recorded either - no new
        // flows are established while fail-closed.
        Assert.False(flowTable.TryGetFlow(ClientPort, out _, out _));
    }

    [Fact]
    public void PlanForward_FinPacket_RemovesTrackedFlow()
    {
        var flowTable = new RedirectFlowTable();
        PacketRedirectPlanner.PlanForward(Syn(), flowTable, RelayPort, failClosed: false);

        PacketRedirectPlanner.PlanForward(Data(ClientPort, ClientAddr, RealDestPort, RealDestAddr, fin: true), flowTable, RelayPort, failClosed: false);

        Assert.False(flowTable.TryGetFlow(ClientPort, out _, out _));
    }

    [Fact]
    public void PlanReturn_TrackedFlow_ReflectsToImpersonateOriginalDestination()
    {
        var flowTable = new RedirectFlowTable();
        flowTable.Record(ClientPort, RealDestAddr, RealDestPort);

        // Return packet: relay's own reply. Its own local address is the
        // client's real address (that's what it bound to / is being
        // addressed as after the forward reflection), source port is the
        // relay's port, and its destination is the apparent remote peer
        // (RealDestAddr:ClientPort) established during the forward leg.
        var returnPacket = Data(RelayPort, ClientAddr, ClientPort, RealDestAddr);
        var decision = PacketRedirectPlanner.PlanReturn(returnPacket, flowTable, failClosed: false);

        Assert.True(decision.ShouldReflect);
        // Reflected source must impersonate the REAL destination the
        // application believes it is talking to: same address the packet
        // already carried as its destination, but with the ORIGINAL
        // destination port recovered from the flow table (the forward leg
        // overwrote that field with the relay's own port on the wire).
        Assert.Equal(IPAddress.Parse(RealDestAddr), decision.NewSrcAddr);
        Assert.Equal(RealDestPort, decision.NewSrcPort);
        Assert.Equal(IPAddress.Parse(ClientAddr), decision.NewDstAddr);
        Assert.Equal(ClientPort, decision.NewDstPort);
    }

    [Fact]
    public void PlanReturn_UntrackedFlow_FailsClosed()
    {
        var flowTable = new RedirectFlowTable();
        var decision = PacketRedirectPlanner.PlanReturn(Data(RelayPort, ClientAddr, 60000, RealDestAddr), flowTable, failClosed: false);

        Assert.False(decision.ShouldReflect);
    }

    [Fact]
    public void PlanReturn_WhenFailClosed_DropsEvenATrackedFlow()
    {
        var flowTable = new RedirectFlowTable();
        flowTable.Record(ClientPort, RealDestAddr, RealDestPort);

        var decision = PacketRedirectPlanner.PlanReturn(Data(RelayPort, ClientAddr, ClientPort, RealDestAddr), flowTable, failClosed: true);

        Assert.False(decision.ShouldReflect);
    }

    [Fact]
    public void PlanReturn_FinPacket_RemovesTrackedFlow()
    {
        var flowTable = new RedirectFlowTable();
        flowTable.Record(ClientPort, RealDestAddr, RealDestPort);

        PacketRedirectPlanner.PlanReturn(Data(RelayPort, ClientAddr, ClientPort, RealDestAddr, fin: true), flowTable, failClosed: false);

        Assert.False(flowTable.TryGetFlow(ClientPort, out _, out _));
    }
}
