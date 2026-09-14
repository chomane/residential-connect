namespace ResidentialConnect.Core.Abstractions;

/// <summary>
/// Secure storage for proxy passwords and any other secret material.
/// Implementations MUST NOT persist secrets in plaintext and MUST NOT log
/// secret values. On Windows this is backed by DPAPI (via
/// ResidentialConnect.Security). A reference/key (not the password) is what
/// gets stored inside <see cref="Models.ProxyProfile.CredentialRef"/>.
/// </summary>
public interface ICredentialStore
{
    /// <summary>
    /// Encrypts and persists <paramref name="secret"/> under a newly
    /// generated or supplied <paramref name="key"/>, returning the key to
    /// store on the owning model.
    /// </summary>
    string Save(string key, string secret);

    /// <summary>Decrypts and returns the secret stored under <paramref name="key"/>, or null if not found.</summary>
    string? Retrieve(string key);

    /// <summary>Removes any secret stored under <paramref name="key"/>. No-op if absent.</summary>
    void Delete(string key);

    /// <summary>True if a secret is currently stored under <paramref name="key"/>.</summary>
    bool Exists(string key);
}
