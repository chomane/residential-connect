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
