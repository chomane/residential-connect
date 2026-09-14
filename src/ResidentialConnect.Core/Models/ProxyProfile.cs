namespace ResidentialConnect.Core.Models;

/// <summary>
/// A single configured proxy endpoint (in V0.1: a Webshare Dedicated Static
/// Residential proxy). This model intentionally holds NO secret material -
/// the password is stored separately and only referenced by
/// <see cref="CredentialRef"/>, which resolves through the Security layer
/// (Windows DPAPI / Credential Manager). This guarantees passwords can never
/// accidentally be serialized into the proxy list JSON file that lives next
/// to the app data (and could otherwise end up copied, screenshotted, or
/// committed to source control).
/// </summary>
public sealed class ProxyProfile
{
    /// <summary>Stable identifier for this profile, generated locally. Never sent anywhere.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>User-facing friendly name, e.g. "US - New York - Residential #1".</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Proxy host name or IP address, e.g. "p.webshare.io" or "142.x.x.x".</summary>
    public string Host { get; set; } = string.Empty;

    /// <summary>Proxy TCP port.</summary>
    public int Port { get; set; }

    /// <summary>Proxy username (not secret by itself, but never logged together with the password).</summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Opaque reference used to look up the encrypted password via
    /// <c>ICredentialStore</c>. This is a key name, never the password itself.
    /// </summary>
    public string CredentialRef { get; set; } = string.Empty;

    /// <summary>Wire protocol to use when connecting to this proxy.</summary>
    public ProxyProtocol Protocol { get; set; } = ProxyProtocol.Http;

    /// <summary>ISO-3166 alpha-2 country code, e.g. "US".</summary>
    public string CountryCode { get; set; } = string.Empty;

    /// <summary>Human readable country name, e.g. "United States".</summary>
    public string CountryName { get; set; } = string.Empty;

    /// <summary>City label as provided by the proxy provider, e.g. "New York".</summary>
    public string City { get; set; } = string.Empty;

    /// <summary>When this profile was added, for diagnostics/sorting purposes only.</summary>
    public DateTimeOffset CreatedAtUtc { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Result of the most recent health/connectivity test, if any.</summary>
    public ProxyTestResult? LastTestResult { get; set; }

    /// <summary>
    /// Returns a copy of this profile with all fields duplicated (used by the
    /// edit dialog so cancel does not mutate the original in-memory instance).
    /// </summary>
    public ProxyProfile Clone() => new()
    {
        Id = Id,
        Name = Name,
        Host = Host,
        Port = Port,
        Username = Username,
        CredentialRef = CredentialRef,
        Protocol = Protocol,
        CountryCode = CountryCode,
        CountryName = CountryName,
        City = City,
        CreatedAtUtc = CreatedAtUtc,
        LastTestResult = LastTestResult
    };

    public override string ToString() => string.IsNullOrWhiteSpace(Name)
        ? $"{Host}:{Port}"
        : Name;
}
