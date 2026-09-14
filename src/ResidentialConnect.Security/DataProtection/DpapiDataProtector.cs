using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ResidentialConnect.Security.DataProtection;

/// <summary>
/// Windows-native secret encryption using DPAPI
/// (<see cref="ProtectedData"/>), scoped to the current Windows user
/// (<see cref="DataProtectionScope.CurrentUser"/>). This means encrypted
/// proxy passwords are unreadable by any other Windows account on the same
/// machine and cannot be decrypted at all on a different machine - exactly
/// the guarantee we need to keep secrets out of source control and safe on
/// disk without asking the user to manage a master password.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiDataProtector : IDataProtector
{
    // Static, non-secret "entropy" that binds ciphertext to this application
    // specifically, so another app that also uses DPAPI for the same user
    // cannot cross-decrypt our secrets. This value is NOT a secret and is
    // safe to keep in source control - DPAPI's actual security comes from
    // the Windows user's protected master key, not from this entropy.
    private static readonly byte[] Entropy =
        "ResidentialConnect.Security.v1"u8.ToArray();

    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);
    }

    public byte[] Unprotect(byte[] ciphertext)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        return ProtectedData.Unprotect(ciphertext, Entropy, DataProtectionScope.CurrentUser);
    }
}
