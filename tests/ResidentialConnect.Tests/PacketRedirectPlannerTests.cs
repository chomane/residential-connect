using System.Net;
using ResidentialConnect.Routing;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for the pure packet-redirect decision logic used by
/// <c>WinDivertSystemTrafficRouter</c>. These exercise the exact fail-closed
/// and NAT-tracking behavior the product requires WITHOUT needing a real
/// WinDivert handle/Windows kernel - only the actual native packet
/// capture/injection calls require a real Windows machine to verify (see
/// docs/BUILD.md "Windows-only acceptance checklist").
/// </summary>
public class PacketRedirectPlannerTests
{
    private static CapturedTcpPacket Syn(int srcPort, int dstPort, string dstAddr) =>
        new(IsSyn: true, IsAck: false, IsFin: false, IsRst: false, SrcPort: srcPort, DstPort: dstPort, DstAddr: IPAddress.Parse(dstAddr));

    private static CapturedTcpPacket Data(int srcPort, int dstPort, string dstAddr, bool fin = false, bool rst = false) =>
        new(IsSyn: false, IsAck: true, IsFin: fin, IsRst: rst, SrcPort: srcPort, DstPort: dstPort, DstAddr: IPAddress.Parse(dstAddr));

    [Fact]
    public void PlanForward_NewSyn_RecordsFlowAndRewritesToRelay()
    {
        var flowTable = new RedirectFlowTable();
        var syn = Syn(50000, 443, "93.184.216.34");

        var decision = PacketRedirectPlanner.PlanForward(syn, flowTable, IPAddress.Loopback, 9000, failClosed: false);

        Assert.True(decision.ShouldRewrite);
        Assert.Equal(IPAddress.Loopback, decision.NewAddress);
        Assert.Equal(9000, decision.NewPort);
        Assert.True(flowTable.TryGetFlow(50000, out var host, out var port));
        Assert.Equal("93.184.216.34", host);
        Assert.Equal(443, port);
    }

    [Fact]
    public void PlanForward_SubsequentPacketOfTrackedFlow_KeepsRewriting()
    {
        var flowTable = new RedirectFlowTable();
        PacketRedirectPlanner.PlanForward(Syn(50000, 443, "93.184.216.34"), flowTable, IPAddress.Loopback, 9000, failClosed: false);

        var followUp = Data(50000, 443, "93.184.216.34");
        var decision = PacketRedirectPlanner.PlanForward(followUp, flowTable, IPAddress.Loopback, 9000, failClosed: false);

        Assert.True(decision.ShouldRewrite);
        Assert.Equal(9000, decision.NewPort);
    }

    [Fact]
    public void PlanForward_UntrackedNonSynPacket_FailsClosed()
    {
        // A connection that was already established BEFORE Whole Computer
        // mode was turned on - the product requirement is that this must
        // never be silently allowed through unmodified.
        var flowTable = new RedirectFlowTable();
        var decision = PacketRedirectPlanner.PlanForward(Data(60000, 443, "93.184.216.34"), flowTable, IPAddress.Loopback, 9000, failClosed: false);

        Assert.False(decision.ShouldRewrite);
    }

    [Fact]
    public void PlanForward_WhenFailClosed_DropsEvenABrandNewSyn()
    {
        var flowTable = new RedirectFlowTable();
        var decision = PacketRedirectPlanner.PlanForward(Syn(50000, 443, "93.184.216.34"), flowTable, IPAddress.Loopback, 9000, failClosed: true);

        Assert.False(decision.ShouldRewrite);
        // And crucially, it must not have been recorded either - no new
        // flows are established while fail-closed.
        Assert.False(flowTable.TryGetFlow(50000, out _, out _));
    }

    [Fact]
    public void PlanForward_FinPacket_RemovesTrackedFlow()
    {
        var flowTable = new RedirectFlowTable();
        PacketRedirectPlanner.PlanForward(Syn(50000, 443, "93.184.216.34"), flowTable, IPAddress.Loopback, 9000, failClosed: false);

        PacketRedirectPlanner.PlanForward(Data(50000, 443, "93.184.216.34", fin: true), flowTable, IPAddress.Loopback, 9000, failClosed: false);

        Assert.False(flowTable.TryGetFlow(50000, out _, out _));
    }

    [Fact]
    public void PlanReturn_TrackedFlow_RewritesSourceToImpersonateOriginalDestination()
    {
        var flowTable = new RedirectFlowTable();
        flowTable.Record(50000, "93.184.216.34", 443);

        // Return packet: relay -> application. Its destination port is the
        // application's client port (50000); the rewrite must set the
        // SOURCE to impersonate the real destination.
        var returnPacket = Data(9000, 50000, "127.0.0.1");
        var decision = PacketRedirectPlanner.PlanReturn(returnPacket, flowTable, failClosed: false);

        Assert.True(decision.ShouldRewrite);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), decision.NewAddress);
        Assert.Equal(443, decision.NewPort);
    }

    [Fact]
    public void PlanReturn_UntrackedFlow_FailsClosed()
    {
        var flowTable = new RedirectFlowTable();
        var decision = PacketRedirectPlanner.PlanReturn(Data(9000, 60000, "127.0.0.1"), flowTable, failClosed: false);

        Assert.False(decision.ShouldRewrite);
    }

    [Fact]
    public void PlanReturn_WhenFailClosed_DropsEvenATrackedFlow()
    {
        var flowTable = new RedirectFlowTable();
        flowTable.Record(50000, "93.184.216.34", 443);

        var decision = PacketRedirectPlanner.PlanReturn(Data(9000, 50000, "127.0.0.1"), flowTable, failClosed: true);

        Assert.False(decision.ShouldRewrite);
    }

    [Fact]
    public void PlanReturn_FinPacket_RemovesTrackedFlow()
    {
        var flowTable = new RedirectFlowTable();
        flowTable.Record(50000, "93.184.216.34", 443);

        PacketRedirectPlanner.PlanReturn(Data(9000, 50000, "127.0.0.1", fin: true), flowTable, failClosed: false);

        Assert.False(flowTable.TryGetFlow(50000, out _, out _));
    }
}
