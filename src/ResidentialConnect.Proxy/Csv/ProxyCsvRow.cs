namespace ResidentialConnect.Proxy.Csv;

/// <summary>One parsed line of a proxy import CSV, before validation/persistence.</summary>
public sealed class ProxyCsvRow
{
    public int LineNumber { get; init; }
    public string Ip { get; init; } = string.Empty;
    public string Port { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;
    public string Password { get; init; } = string.Empty;
    public string Country { get; init; } = string.Empty;
    public string City { get; init; } = string.Empty;
}

/// <summary>Result of importing a single CSV row.</summary>
public sealed class ProxyCsvImportRowResult
{
    public int LineNumber { get; init; }
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public Guid? CreatedProfileId { get; init; }

    public static ProxyCsvImportRowResult Ok(int lineNumber, Guid profileId) =>
        new() { LineNumber = lineNumber, Success = true, CreatedProfileId = profileId };

    public static ProxyCsvImportRowResult Failed(int lineNumber, string error) =>
        new() { LineNumber = lineNumber, Success = false, ErrorMessage = error };
}

/// <summary>Aggregate result of a full CSV import operation.</summary>
public sealed class ProxyCsvImportResult
{
    public IReadOnlyList<ProxyCsvImportRowResult> Rows { get; init; } = Array.Empty<ProxyCsvImportRowResult>();

    public int SuccessCount => Rows.Count(r => r.Success);
    public int FailureCount => Rows.Count(r => !r.Success);
    public int TotalCount => Rows.Count;
}
