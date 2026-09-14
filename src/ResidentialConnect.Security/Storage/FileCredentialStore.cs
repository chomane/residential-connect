using System.Text;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Security.DataProtection;

namespace ResidentialConnect.Security.Storage;

/// <summary>
/// <see cref="ICredentialStore"/> implementation that stores one encrypted
/// file per secret under the application's local app-data folder. Each file
/// contains only DPAPI-protected ciphertext (see <see cref="IDataProtector"/>)
/// - never plaintext. The key passed in by callers becomes the file name
/// (sanitized), and is itself just an opaque GUID-based identifier generated
/// by <see cref="Save"/>, so it carries no information about the proxy it
/// belongs to.
/// </summary>
public sealed class FileCredentialStore : ICredentialStore
{
    private readonly string _storageDirectory;
    private readonly IDataProtector _protector;

    public FileCredentialStore(string storageDirectory, IDataProtector protector)
    {
        _storageDirectory = storageDirectory ?? throw new ArgumentNullException(nameof(storageDirectory));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        Directory.CreateDirectory(_storageDirectory);
    }

    public string Save(string key, string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        ArgumentNullException.ThrowIfNull(secret);

        var path = PathFor(key);
        var plaintextBytes = Encoding.UTF8.GetBytes(secret);
        try
        {
            var ciphertext = _protector.Protect(plaintextBytes);
            File.WriteAllBytes(path, ciphertext);
        }
        finally
        {
            Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
        }

        return key;
    }

    public string? Retrieve(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var path = PathFor(key);
        if (!File.Exists(path))
        {
            return null;
        }

        var ciphertext = File.ReadAllBytes(path);
        var plaintextBytes = _protector.Unprotect(ciphertext);
        try
        {
            return Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
        }
    }

    public void Delete(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var path = PathFor(key);
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    public bool Exists(string key)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        return File.Exists(PathFor(key));
    }

    private string PathFor(string key)
    {
        // Keys are always generated internally as GUIDs (see CredentialKeyFactory),
        // but sanitize defensively in case a caller passes something unexpected.
        var safe = new string(key.Where(c => char.IsLetterOrDigit(c) || c is '-' or '_').ToArray());
        if (safe.Length == 0)
        {
            throw new ArgumentException("Credential key resolves to an empty file name.", nameof(key));
        }

        return Path.Combine(_storageDirectory, safe + ".cred");
    }
}
