using System.Text.RegularExpressions;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Core.Common;

/// <summary>Result of validating a <see cref="ProxyProfile"/> plus its plaintext password (pre-encryption).</summary>
public sealed class ValidationResult
{
    public bool IsValid => Errors.Count == 0;

    public IReadOnlyList<string> Errors { get; }

    public ValidationResult(IReadOnlyList<string> errors) => Errors = errors;

    public static readonly ValidationResult Ok = new(Array.Empty<string>());
}

/// <summary>
/// Centralized validation rules for proxy configuration, shared by the
/// "Add/Edit Proxy" UI, CSV import, and unit tests, so all three enforce
/// identical rules.
/// </summary>
public static partial class ProxyValidation
{
    public const int MinPort = 1;
    public const int MaxPort = 65535;

    [GeneratedRegex(@"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", RegexOptions.Compiled)]
    private static partial Regex HostnamePattern();

    public static ValidationResult Validate(ProxyProfile profile, string? plaintextPassword)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(profile.Host))
        {
            errors.Add("Host/IP is required.");
        }
        else if (!IsValidHost(profile.Host))
        {
            errors.Add($"'{profile.Host}' is not a valid hostname or IP address.");
        }

        if (profile.Port < MinPort || profile.Port > MaxPort)
        {
            errors.Add($"Port must be between {MinPort} and {MaxPort}.");
        }

        if (string.IsNullOrWhiteSpace(profile.Username))
        {
            errors.Add("Username is required.");
        }

        if (string.IsNullOrEmpty(plaintextPassword))
        {
            errors.Add("Password is required.");
        }

        if (string.IsNullOrWhiteSpace(profile.CountryCode) && string.IsNullOrWhiteSpace(profile.CountryName))
        {
            errors.Add("Country is required.");
        }

        return errors.Count == 0 ? ValidationResult.Ok : new ValidationResult(errors);
    }

    public static bool IsValidHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        if (System.Net.IPAddress.TryParse(host, out _))
        {
            return true;
        }

        return host.Length <= 253 && HostnamePattern().IsMatch(host);
    }

    public static bool IsValidPort(int port) => port is >= MinPort and <= MaxPort;
}
