using System.Text.Json;
using System.Text.Json.Serialization;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Proxy.Repository;

/// <summary>
/// <see cref="IProxyRepository"/> implementation backed by a single local
/// JSON file. Only non-secret fields are ever written to this file - see
/// <see cref="ProxyProfile.CredentialRef"/> - so the file is safe to include
/// in backups, screenshots, or (accidentally) source control without
/// leaking any proxy password.
/// </summary>
public sealed class JsonProxyRepository : IProxyRepository
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _filePath;
    private readonly ICredentialStore _credentialStore;
    private readonly IAppLogger _logger;
    private readonly object _lock = new();

    private List<ProxyProfile> _profiles;
    private Guid? _selectedId;

    public JsonProxyRepository(string filePath, ICredentialStore credentialStore, IAppLogger logger)
    {
        _filePath = filePath ?? throw new ArgumentNullException(nameof(filePath));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        var loaded = Load();
        _profiles = loaded.Profiles;
        _selectedId = loaded.SelectedId;
    }

    public IReadOnlyList<ProxyProfile> GetAll()
    {
        lock (_lock)
        {
            return _profiles.Select(p => p.Clone()).ToList();
        }
    }

    public ProxyProfile? GetById(Guid id)
    {
        lock (_lock)
        {
            return _profiles.FirstOrDefault(p => p.Id == id)?.Clone();
        }
    }

    public ProxyProfile Add(ProxyProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        lock (_lock)
        {
            if (profile.Id == Guid.Empty)
            {
                profile.Id = Guid.NewGuid();
            }

            _profiles.Add(profile.Clone());
            Persist();
            _logger.Info("ProxyRepository", $"Added proxy profile '{profile.Name}' ({profile.Id}).");
            return profile;
        }
    }

    public void Update(ProxyProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        lock (_lock)
        {
            var index = _profiles.FindIndex(p => p.Id == profile.Id);
            if (index < 0)
            {
                throw new InvalidOperationException($"Proxy profile with id '{profile.Id}' was not found.");
            }

            _profiles[index] = profile.Clone();
            Persist();
            _logger.Info("ProxyRepository", $"Updated proxy profile '{profile.Name}' ({profile.Id}).");
        }
    }

    public void Delete(Guid id)
    {
        lock (_lock)
        {
            var existing = _profiles.FirstOrDefault(p => p.Id == id);
            if (existing is null)
            {
                return;
            }

            _profiles.RemoveAll(p => p.Id == id);

            if (!string.IsNullOrEmpty(existing.CredentialRef))
            {
                _credentialStore.Delete(existing.CredentialRef);
            }

            if (_selectedId == id)
            {
                _selectedId = null;
            }

            Persist();
            _logger.Info("ProxyRepository", $"Deleted proxy profile '{existing.Name}' ({id}).");
        }
    }

    public void SetSelected(Guid? id)
    {
        lock (_lock)
        {
            _selectedId = id;
            Persist();
        }
    }

    public Guid? GetSelectedId()
    {
        lock (_lock)
        {
            return _selectedId;
        }
    }

    private (List<ProxyProfile> Profiles, Guid? SelectedId) Load()
    {
        if (!File.Exists(_filePath))
        {
            return (new List<ProxyProfile>(), null);
        }

        try
        {
            var json = File.ReadAllText(_filePath);
            var document = JsonSerializer.Deserialize<PersistedDocument>(json, SerializerOptions);
            return (document?.Profiles ?? new List<ProxyProfile>(), document?.SelectedId);
        }
        catch (Exception ex)
        {
            _logger.Error("ProxyRepository", "Failed to load proxies.json; starting with an empty proxy list.", ex);
            return (new List<ProxyProfile>(), null);
        }
    }

    private void Persist()
    {
        var directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var document = new PersistedDocument
        {
            Profiles = _profiles,
            SelectedId = _selectedId
        };

        var json = JsonSerializer.Serialize(document, SerializerOptions);

        // Write to a temp file then move, to avoid corrupting the store if the
        // process is killed mid-write.
        var tempPath = _filePath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, _filePath, overwrite: true);
    }

    private sealed class PersistedDocument
    {
        public List<ProxyProfile> Profiles { get; set; } = new();
        public Guid? SelectedId { get; set; }
    }
}
