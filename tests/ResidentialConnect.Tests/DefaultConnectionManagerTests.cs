using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy;

namespace ResidentialConnect.Tests;

/// <summary>
/// Tests for <see cref="DefaultConnectionManager"/>'s V0.2 mode-aware
/// orchestration: mode switching, fail-closed propagation of routing
/// failures into <see cref="ConnectionState"/>, DISCONNECT cleanup, and -
/// critically - proof that <see cref="ConnectionMode.BrowserOnly"/> NEVER
/// touches <see cref="ResidentialConnect.Core.Abstractions.ISystemTrafficRouter"/>
/// at all, preserving V0.1 behavior exactly.
/// </summary>
public class DefaultConnectionManagerTests
{
    private static ProxyProfile MakeProfile() => new()
    {
        Host = "proxy.example.com",
        Port = 8080,
        Username = "user",
        CredentialRef = "cred-1",
        Protocol = ProxyProtocol.Http,
        CountryCode = "US"
    };

    [Fact]
    public async Task ConnectAsync_BrowserOnly_NeverCallsTheTrafficRouter()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.BrowserOnly);

        Assert.Equal(ConnectionStatus.Connected, state.Status);
        Assert.Equal(ConnectionMode.BrowserOnly, state.Mode);
        Assert.Equal(SystemRoutingStatus.Disabled, state.RoutingStatus);
        Assert.Equal(0, router.StartCallCount);
    }

    [Fact]
    public async Task ConnectAsync_DefaultMode_IsBrowserOnly()
    {
        // Regression guard for "existing callers get exactly V0.1 behavior" -
        // omitting the mode argument entirely must behave identically to
        // explicitly passing BrowserOnly.
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);

        var state = await manager.ConnectAsync(MakeProfile());

        Assert.Equal(ConnectionMode.BrowserOnly, state.Mode);
        Assert.Equal(0, router.StartCallCount);
    }

    [Fact]
    public async Task ConnectAsync_ProxyTestFails_NeverAttemptsWholeComputerRouting()
    {
        var tester = new FakeProxyConnectivityTester { NextResult = ProxyTestResult.Failed(ProxyTestFailureReason.AuthenticationFailed, "bad creds") };
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Error, state.Status);
        Assert.Equal(0, router.StartCallCount);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_StartsRouterWithTheResolvedPassword()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t-pass");
        var router = new FakeSystemTrafficRouter();
        var verifier = new FakeWholeComputerConnectivityVerifier();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, verifier);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Connected, state.Status);
        Assert.Equal(ConnectionMode.WholeComputer, state.Mode);
        Assert.Equal(SystemRoutingStatus.Active, state.RoutingStatus);
        Assert.Equal(1, router.StartCallCount);
        Assert.Equal("s3cr3t-pass", router.LastPassword);
        Assert.Equal(1, verifier.VerifyCallCount);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_VerificationSucceeds_ReportsConnectedWithVerifiedPublicIp()
    {
        // The reported PublicIp must come from the VERIFICATION call (the
        // one that actually proved traffic flows end-to-end through the
        // now-Active routing), not merely from the earlier direct-to-proxy
        // connectivity test.
        var tester = new FakeProxyConnectivityTester { NextResult = ProxyTestResult.Successful("198.51.100.1", TimeSpan.FromMilliseconds(10)) };
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var verifier = new FakeWholeComputerConnectivityVerifier { NextResult = WholeComputerVerificationResult.Successful("203.0.113.42") };
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, verifier);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Connected, state.Status);
        Assert.Equal("203.0.113.42", state.PublicIp);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_VerificationFails_ReportsErrorAndRollsRoutingBack()
    {
        // Core fail-closed contract for the verification step: if a real,
        // hostname-addressed request does not actually route through Whole
        // Computer mode, the UI must NEVER be told Connected, and routing
        // must be stopped (rolled back) rather than left Active while the
        // user is told something failed.
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var verifier = new FakeWholeComputerConnectivityVerifier
        {
            NextResult = WholeComputerVerificationResult.Failed("Whole Computer routing could not carry a real hostname-addressed HTTPS request. Routing has been rolled back.")
        };
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, verifier);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Error, state.Status);
        Assert.Equal(SystemRoutingStatus.Unavailable, state.RoutingStatus);
        Assert.Equal(1, router.StartCallCount);
        Assert.Equal(1, router.StopCallCount);
        Assert.Contains("rolled back", state.StatusMessage);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_VerificationFails_NeverLeavesTheUIInConnectedState()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var verifier = new FakeWholeComputerConnectivityVerifier { NextResult = WholeComputerVerificationResult.Failed("timed out") };
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, verifier);

        await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.NotEqual(ConnectionStatus.Connected, manager.CurrentState.Status);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_VerifierThrows_TreatsAsFailedVerificationAndRollsBack()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, new ThrowingWholeComputerConnectivityVerifier());

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Error, state.Status);
        Assert.Equal(1, router.StopCallCount);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_RouterUnavailable_ReportsErrorAndNeverClaimsConnected()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter { NextStartResult = SystemRoutingStatus.Unavailable };
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        // Fail-closed at the UX level too: Whole Computer must never silently
        // report "Connected" while actually only proxying the (nonexistent,
        // in this mode) browser - it must surface the routing failure.
        Assert.Equal(ConnectionStatus.Error, state.Status);
        Assert.Equal(SystemRoutingStatus.Unavailable, state.RoutingStatus);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_RouterNotSupported_NeverCallsStartAsync()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter { IsSupported = false };
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Error, state.Status);
        Assert.Equal(SystemRoutingStatus.Unavailable, state.RoutingStatus);
        Assert.Equal(0, router.StartCallCount);
    }

    [Fact]
    public async Task ConnectAsync_WholeComputer_NoRouterConfigured_ReportsUnavailable()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), trafficRouter: null);

        var state = await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        Assert.Equal(ConnectionStatus.Error, state.Status);
        Assert.Equal(SystemRoutingStatus.Unavailable, state.RoutingStatus);
    }

    [Fact]
    public async Task DisconnectAsync_WholeComputer_StopsTheRouter()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, new FakeWholeComputerConnectivityVerifier());
        await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        await manager.DisconnectAsync();

        Assert.Equal(1, router.StopCallCount);
        Assert.Equal(ConnectionStatus.Ready, manager.CurrentState.Status);
    }

    [Fact]
    public async Task DisconnectAsync_BrowserOnly_NeverCallsRouterStopAsync()
    {
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);
        await manager.ConnectAsync(MakeProfile(), ConnectionMode.BrowserOnly);

        await manager.DisconnectAsync();

        // StopAsync is harmless to call, but asserting 0 calls here pins
        // down that BrowserOnly's DISCONNECT path is unchanged from V0.1 and
        // never depends on the router being in any particular state.
        Assert.Equal(0, router.StopCallCount);
    }

    [Fact]
    public async Task RouterFailsClosedAfterConnect_PropagatesIntoConnectionStateViaStateChanged()
    {
        // Simulates the upstream relay/tunnel faulting WHILE Whole Computer
        // mode is already Active (e.g. the residential proxy connection
        // drops) - DefaultConnectionManager must surface this into
        // ConnectionState (and fire StateChanged) rather than continuing to
        // silently report "Connected" while traffic is actually being
        // dropped fail-closed at the routing layer.
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router, new FakeWholeComputerConnectivityVerifier());
        await manager.ConnectAsync(MakeProfile(), ConnectionMode.WholeComputer);

        ConnectionState? observed = null;
        manager.StateChanged += (_, state) => observed = state;

        router.SimulateFailClosed();

        Assert.NotNull(observed);
        Assert.Equal(SystemRoutingStatus.FailedClosed, observed!.RoutingStatus);
        Assert.Equal(ConnectionStatus.Error, observed.Status);
        Assert.Equal(SystemRoutingStatus.FailedClosed, manager.CurrentState.RoutingStatus);
    }

    [Fact]
    public async Task RouterStatusChanged_WhileInBrowserOnlyMode_IsIgnored()
    {
        // Defensive test: a router subscribed from a PREVIOUS Whole Computer
        // session (or a stray event) must never corrupt BrowserOnly state.
        var tester = new FakeProxyConnectivityTester();
        var credentialStore = new InMemoryCredentialStore();
        credentialStore.Save("cred-1", "s3cr3t");
        var router = new FakeSystemTrafficRouter();
        var manager = new DefaultConnectionManager(tester, credentialStore, new NullLogger(), router);
        await manager.ConnectAsync(MakeProfile(), ConnectionMode.BrowserOnly);

        router.SimulateFailClosed();

        Assert.Equal(ConnectionMode.BrowserOnly, manager.CurrentState.Mode);
        Assert.Equal(ConnectionStatus.Connected, manager.CurrentState.Status);
    }
}
