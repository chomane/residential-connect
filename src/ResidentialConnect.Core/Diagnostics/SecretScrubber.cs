using System.Text.RegularExpressions;

namespace ResidentialConnect.Core.Diagnostics;

/// <summary>
/// Best-effort defense-in-depth helper that redacts values that look like
/// credentials/secrets before they are written to a log sink. This is a
/// SAFETY NET, not the primary control - the primary control is that no
/// layer ever passes a raw password/secret into a log call in the first
/// place (passwords are never even loaded into memory outside of the moment
/// they're needed for an auth handshake).
/// </summary>
public static partial class SecretScrubber
{
    private const string Redacted = "***REDACTED***";

    // Matches key=value / key: value pairs for common secret-ish key names.
    [GeneratedRegex(
        "(?i)(password|passwd|pwd|secret|api[_-]?key|token|authorization)\\s*[:=]\\s*[^\\s,;]+",
        RegexOptions.Compiled)]
    private static partial Regex SecretKeyValuePattern();

    // Matches "user:password@host" style userinfo in URIs.
    [GeneratedRegex(@"://([^/\s:@]+):([^/\s@]+)@", RegexOptions.Compiled)]
    private static partial Regex UriUserInfoPattern();

    /// <summary>Redacts any substring in <paramref name="message"/> that looks like a credential.</summary>
    public static string Scrub(string? message)
    {
        if (string.IsNullOrEmpty(message))
        {
            return message ?? string.Empty;
        }

        var result = SecretKeyValuePattern().Replace(message, match =>
        {
            var separatorIndex = match.Value.IndexOfAny(new[] { ':', '=' });
            var key = separatorIndex >= 0 ? match.Value[..(separatorIndex + 1)] : match.Value;
            return $"{key}{Redacted}";
        });

        result = UriUserInfoPattern().Replace(result, $"://{Redacted}:{Redacted}@");

        return result;
    }
}
