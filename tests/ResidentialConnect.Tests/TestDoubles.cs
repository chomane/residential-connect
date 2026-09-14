using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Security.DataProtection;

namespace ResidentialConnect.Tests;

/// <summary>Cross-platform fake for IDataProtector (reversible XOR, test-only, NOT secure) so FileCredentialStore can be unit tested without real DPAPI (Windows-only).</summary>
public sealed class FakeReversibleProtector : IDataProtector
{
    private static readonly byte[] Key = { 0x5A, 0x3C, 0x91, 0x77 };

    public byte[] Protect(byte[] plaintext) => Xor(plaintext);
    public byte[] Unprotect(byte[] ciphertext) => Xor(ciphertext);

    private static byte[] Xor(byte[] data)
    {
        var result = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ Key[i % Key.Length]);
        }
        return result;
    }
}

public sealed class InMemoryCredentialStore : ICredentialStore
{
    private readonly Dictionary<string, string> _store = new();

    public string Save(string key, string secret) { _store[key] = secret; return key; }
    public string? Retrieve(string key) => _store.TryGetValue(key, out var v) ? v : null;
    public void Delete(string key) => _store.Remove(key);
    public bool Exists(string key) => _store.ContainsKey(key);
}

public sealed class InMemoryProxyRepository : IProxyRepository
{
    private readonly List<ProxyProfile> _profiles = new();
    private Guid? _selected;

    public IReadOnlyList<ProxyProfile> GetAll() => _profiles.Select(p => p.Clone()).ToList();
    public ProxyProfile? GetById(Guid id) => _profiles.FirstOrDefault(p => p.Id == id)?.Clone();
    public ProxyProfile Add(ProxyProfile profile) { _profiles.Add(profile.Clone()); return profile; }
    public void Update(ProxyProfile profile)
    {
        var idx = _profiles.FindIndex(p => p.Id == profile.Id);
        if (idx < 0) throw new InvalidOperationException("Not found");
        _profiles[idx] = profile.Clone();
    }
    public void Delete(Guid id) => _profiles.RemoveAll(p => p.Id == id);
    public void SetSelected(Guid? id) => _selected = id;
    public Guid? GetSelectedId() => _selected;
}

public sealed class NullLogger : IAppLogger
{
    public void Log(LogLevel level, string category, string message, Exception? exception = null) { }
}

/// <summary>Scriptable fake IProxyConnectivityTester so DefaultConnectionManager's mode-aware CONNECT flow can be tested without a real network call.</summary>
public sealed class FakeProxyConnectivityTester : IProxyConnectivityTester
{
    public ProxyTestResult NextResult { get; set; } = ProxyTestResult.Successful("203.0.113.9", TimeSpan.FromMilliseconds(42));

    public Task<ProxyTestResult> TestAsync(ProxyProfile profile, CancellationToken cancellationToken = default) => Task.FromResult(NextResult);
}

/// <summary>
/// Scriptable fake ISystemTrafficRouter used to test DefaultConnectionManager's
/// Whole Computer orchestration (start/stop calls, fail-closed status
/// propagation, mode-gated bypass of the router entirely for Browser Only)
/// without needing a real WinDivert handle/Windows kernel.
/// </summary>
public sealed class FakeSystemTrafficRouter : ISystemTrafficRouter
{
    public bool IsSupported { get; set; } = true;
    public bool RequiresElevation => true;
    public SystemRoutingStatus Status { get; private set; } = SystemRoutingStatus.Disabled;
    public event EventHandler<SystemRoutingStatus>? StatusChanged;

    public SystemRoutingStatus NextStartResult { get; set; } = SystemRoutingStatus.Active;
    public int StartCallCount { get; private set; }
    public int StopCallCount { get; private set; }
    public string? LastPassword { get; private set; }

    public Task<SystemRoutingStatus> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default)
    {
        StartCallCount++;
        LastPassword = password;
        Status = NextStartResult;
        StatusChanged?.Invoke(this, Status);
        return Task.FromResult(Status);
    }

    public Task StopAsync(CancellationToken cancellationToken = default)
    {
        StopCallCount++;
        Status = SystemRoutingStatus.Disabled;
        StatusChanged?.Invoke(this, Status);
        return Task.CompletedTask;
    }

    /// <summary>Test hook to simulate an asynchronous fail-closed transition while already Active (e.g. the relay faulted).</summary>
    public void SimulateFailClosed()
    {
        Status = SystemRoutingStatus.FailedClosed;
        StatusChanged?.Invoke(this, Status);
    }
}

/// <summary>
/// Adds throw-on-start scripting to the existing <see cref="FakeSystemTrafficRouter"/>
/// contract via extension-friendly properties would require modifying the
/// sealed class above; instead, ConnectionManagerModeTests uses
/// <see cref="FakeSystemTrafficRouter"/> directly (see its
/// <c>NextStartResult</c>/<c>LastPassword</c> members above) and a small
/// dedicated throwing fake for the one "StartAsync throws" scenario.
/// </summary>
public sealed class ThrowingSystemTrafficRouter : ISystemTrafficRouter
{
    public bool IsSupported => true;
    public bool RequiresElevation => true;
    public SystemRoutingStatus Status => SystemRoutingStatus.Disabled;
    public event EventHandler<SystemRoutingStatus>? StatusChanged { add { } remove { } }

    public Task<SystemRoutingStatus> StartAsync(ProxyProfile profile, string password, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("Simulated unexpected failure.");

    public Task StopAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
}
