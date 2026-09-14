namespace ResidentialConnect.Security.DataProtection;

/// <summary>
/// Thin abstraction over the OS-native data protection primitive used to
/// encrypt secret bytes at rest. Kept separate from
/// <c>ICredentialStore</c> so the higher-level storage/key-management logic
/// in <see cref="Storage.FileCredentialStore"/> can be unit tested on any
/// platform (including this Linux build sandbox) using a fake protector,
/// while production Windows builds use <see cref="DpapiDataProtector"/>.
/// </summary>
public interface IDataProtector
{
    /// <summary>Encrypts <paramref name="plaintext"/>, scoped so only the current Windows user can decrypt it.</summary>
    byte[] Protect(byte[] plaintext);

    /// <summary>Decrypts data previously produced by <see cref="Protect"/>.</summary>
    byte[] Unprotect(byte[] ciphertext);
}
