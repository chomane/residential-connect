using System.Diagnostics;
using ResidentialConnect.Browser;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Tests;

public sealed class BrowserLifecycleTests : IDisposable
{
    private readonly string _profiles = Path.Combine(Path.GetTempPath(), "rc-browser-tests-" + Guid.NewGuid().ToString("N"));
    private readonly List<Process> _processes = new();
    private readonly ProxyProfile _profile = new() { CredentialRef = "test-only" };

    private ChromiumBrowserLauncher Launcher(Func<ILocalForwardingProxy> relay, Func<ProcessStartInfo, Process?>? start = null)
    {
        var credentials = new InMemoryCredentialStore();
        credentials.Save(_profile.CredentialRef, "test-only");
        return new ChromiumBrowserLauncher(new Provider(), credentials, relay, new NullLogger(),
            start ?? (_ => StartProcess()), _profiles);
    }

    private Process StartProcess()
    {
        var info = new ProcessStartInfo
        {
            FileName = OperatingSystem.IsWindows() ? "powershell.exe" : "/bin/sleep",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in OperatingSystem.IsWindows()
            ? new[] { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 120" }
            : new[] { "120" })
            info.ArgumentList.Add(arg);
        var process = Process.Start(info)!;
        // Keep a separate handle for assertions after the launcher disposes its handle.
        _processes.Add(Process.GetProcessById(process.Id));
        return process;
    }

    [Fact]
    public async Task Disconnect_StopsAllOwnedBrowsersAndRelays_PreservesUnownedProcessAndProfile()
    {
        using var unrelated = StartProcess();
        var relays = new List<Relay>();
        var launcher = Launcher(() => { var relay = new Relay(); relays.Add(relay); return relay; });
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        var profileFile = Path.Combine(_profiles, _profile.Id.ToString("N"), "persistent-data");
        await File.WriteAllTextAsync(profileFile, "keep");
        await Task.WhenAll(launcher.DisconnectAllAsync(), launcher.DisconnectAllAsync());
        await launcher.DisconnectAllAsync();
        Assert.False(unrelated.HasExited);
        Assert.All(_processes.Skip(1), process => Assert.True(process.HasExited));
        Assert.All(relays, relay => { Assert.Equal(1, relay.Stops); Assert.Equal(1, relay.Disposals); });
        Assert.Equal("keep", await File.ReadAllTextAsync(profileFile));
    }

    [Fact]
    public async Task Disconnect_KillsOwnedChildProcessTree()
    {
        if (!OperatingSystem.IsWindows()) return;
        Directory.CreateDirectory(_profiles);
        var childFile = Path.Combine(_profiles, "child.pid");
        var launcher = Launcher(() => new Relay(), _ =>
        {
            var script = "$child = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 120'; " +
                "[IO.File]::WriteAllText('" + childFile.Replace("'", "''") + "', [string]$child.Id); Start-Sleep -Seconds 120";
            var info = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true };
            info.ArgumentList.Add("-NoProfile");
            info.ArgumentList.Add("-EncodedCommand");
            info.ArgumentList.Add(Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script)));
            var process = Process.Start(info)!;
            _processes.Add(Process.GetProcessById(process.Id));
            return process;
        });
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (!File.Exists(childFile)) await Task.Delay(50, timeout.Token);
        var childId = int.Parse(await File.ReadAllTextAsync(childFile, timeout.Token));
        var child = Process.GetProcessById(childId);
        _processes.Add(child);
        await launcher.DisconnectAllAsync();
        await child.WaitForExitAsync(timeout.Token);
        Assert.All(_processes, process => Assert.True(process.HasExited));
    }

    [Fact]
    public async Task Disconnect_ToleratesBrowserAlreadyClosed_AndCanLaunchAgain()
    {
        var relays = new List<Relay>();
        var launcher = Launcher(() => { var relay = new Relay(); relays.Add(relay); return relay; });
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        _processes[0].Kill(entireProcessTree: true);
        await _processes[0].WaitForExitAsync();
        Assert.Equal(0, relays[0].Stops);
        await launcher.DisconnectAllAsync();
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        await launcher.DisconnectAllAsync();
        Assert.All(relays, relay => Assert.Equal(1, relay.Disposals));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedProcessStart_CleansPartialRelay(bool throws)
    {
        var relay = new Relay();
        var launcher = Launcher(() => relay, _ => throws ? throw new IOException("test") : null);
        Assert.False((await launcher.LaunchAsync(_profile)).Success);
        await launcher.DisconnectAllAsync();
        Assert.Equal(1, relay.Stops);
        Assert.Equal(1, relay.Disposals);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedRelayStart_IsCleaned_WithoutLaunching(bool throws)
    {
        var relay = new Relay { FailStart = throws, Healthy = false };
        var launcher = Launcher(() => relay, _ => throw new Xunit.Sdk.XunitException("Must not launch"));
        Assert.False((await launcher.LaunchAsync(_profile)).Success);
        Assert.Equal(1, relay.Stops);
        Assert.Equal(1, relay.Disposals);
    }

    [Fact]
    public async Task Disconnect_WaitsForInflightLaunch_AndForRelayStop()
    {
        var relay = new Relay { StartGate = new(), StopGate = new() };
        var launcher = Launcher(() => relay);
        var launch = launcher.LaunchAsync(_profile);
        await relay.Started.Task;
        var disconnect = launcher.DisconnectAllAsync();
        Assert.False(disconnect.IsCompleted);
        relay.StartGate.SetResult();
        Assert.True((await launch).Success);
        await relay.Stopping.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(disconnect.IsCompleted);
        Assert.True(_processes[0].HasExited);
        relay.StopGate.SetResult();
        await disconnect.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(1, relay.Disposals);
    }

    [Fact]
    public async Task CancellationAfterRelayStart_CleansPartialSession()
    {
        using var cancellation = new CancellationTokenSource();
        var relay = new Relay { StartGate = new() };
        var launcher = Launcher(() => relay);
        var launch = launcher.LaunchAsync(_profile, cancellationToken: cancellation.Token);
        await relay.Started.Task;
        cancellation.Cancel();
        relay.StartGate.SetResult();
        Assert.False((await launch).Success);
        Assert.Empty(_processes);
        Assert.Equal(1, relay.Disposals);
    }

    [Fact]
    public async Task CanceledDisconnect_DoesNotForgetSessions()
    {
        var relay = new Relay();
        var launcher = Launcher(() => relay);
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => launcher.DisconnectAllAsync(cancellation.Token));
        Assert.False(_processes[0].HasExited);
        await launcher.DisconnectAllAsync();
        Assert.True(_processes[0].HasExited);
        Assert.Equal(1, relay.Disposals);
    }

    [Fact]
    public async Task StopFailure_DoesNotPreventDisposalOrOtherSessionCleanup()
    {
        var first = new Relay { FailStop = true };
        var second = new Relay();
        var queue = new Queue<Relay>(new[] { first, second });
        var launcher = Launcher(() => queue.Dequeue());
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        Assert.True((await launcher.LaunchAsync(_profile)).Success);
        await Assert.ThrowsAsync<AggregateException>(() => launcher.DisconnectAllAsync());
        Assert.All(_processes, process => Assert.True(process.HasExited));
        Assert.Equal(1, first.Disposals);
        Assert.Equal(1, second.Disposals);
        await launcher.DisconnectAllAsync();
    }

    public void Dispose()
    {
        foreach (var process in _processes)
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); process.WaitForExit(); }
            process.Dispose();
        }
        if (Directory.Exists(_profiles)) Directory.Delete(_profiles, recursive: true);
    }

    private sealed class Provider : IBrowserProvider
    {
        public string ProviderName => "Test";
        public string FindExecutable() => "test-browser";
    }

    private sealed class Relay : ILocalForwardingProxy
    {
        public bool Healthy = true, FailStart, FailStop;
        public TaskCompletionSource? StartGate, StopGate;
        public TaskCompletionSource Started = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Stopping = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Stops, Disposals;
        public bool IsRunning { get; private set; }
        public int? Port { get; private set; }
        public async Task<int> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default)
        {
            Started.TrySetResult();
            if (StartGate is not null) await StartGate.Task;
            if (FailStart) throw new IOException("test relay start failure");
            IsRunning = Healthy;
            Port = 12345;
            return Port.Value;
        }
        public async Task StopAsync()
        {
            Stops++;
            IsRunning = false;
            Port = null;
            Stopping.TrySetResult();
            if (StopGate is not null) await StopGate.Task;
            if (FailStop) throw new IOException("test relay stop failure");
        }
        public void Dispose() => Disposals++;
    }
}
