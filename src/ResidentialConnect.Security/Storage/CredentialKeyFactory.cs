namespace ResidentialConnect.Security.Storage;

/// <summary>Generates opaque, non-guessable credential keys used as <see cref="Core.Models.ProxyProfile.CredentialRef"/>.</summary>
public static class CredentialKeyFactory
{
    public static string NewKey() => "cred_" + Guid.NewGuid().ToString("N");
}
