namespace ResidentialConnect.Core.Common;

/// <summary>
/// Tiny built-in lookup from ISO-3166-1 alpha-2 country codes to display
/// name and flag emoji. This is intentionally NOT a network call - it exists
/// purely so the main screen can show a flag/name immediately for whatever
/// country code a proxy profile carries, without any backend dependency.
/// Unknown codes degrade gracefully (globe emoji + the raw code as the name).
/// </summary>
public static class CountryCatalog
{
    /// <summary>
    /// Converts an ISO-3166-1 alpha-2 code (e.g. "US") into its flag emoji
    /// (e.g. "🇺🇸") using Unicode regional indicator symbols. Works for any
    /// valid two-letter code, not just the ones in <see cref="KnownNames"/>.
    /// </summary>
    public static string ToFlagEmoji(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || countryCode.Length != 2)
        {
            return "🌐";
        }

        var code = countryCode.ToUpperInvariant();
        if (code[0] is < 'A' or > 'Z' || code[1] is < 'A' or > 'Z')
        {
            return "🌐";
        }

        const int regionalIndicatorBase = 0x1F1E6; // 'A' regional indicator
        var first = char.ConvertFromUtf32(regionalIndicatorBase + (code[0] - 'A'));
        var second = char.ConvertFromUtf32(regionalIndicatorBase + (code[1] - 'A'));
        return first + second;
    }

    private static readonly IReadOnlyDictionary<string, string> KnownNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["US"] = "United States",
        ["GB"] = "United Kingdom",
        ["CA"] = "Canada",
        ["DE"] = "Germany",
        ["FR"] = "France",
        ["NL"] = "Netherlands",
        ["AU"] = "Australia",
        ["JP"] = "Japan",
        ["SG"] = "Singapore",
        ["BR"] = "Brazil",
        ["IN"] = "India",
        ["ES"] = "Spain",
        ["IT"] = "Italy",
        ["SE"] = "Sweden",
        ["PL"] = "Poland",
        ["MX"] = "Mexico",
    };

    public static string GetName(string? countryCode, string? fallback = null)
    {
        if (!string.IsNullOrWhiteSpace(countryCode) && KnownNames.TryGetValue(countryCode, out var name))
        {
            return name;
        }

        return !string.IsNullOrWhiteSpace(fallback) ? fallback! : countryCode ?? "Unknown";
    }
}
