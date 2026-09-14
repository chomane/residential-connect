using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Security.Storage;

namespace ResidentialConnect.Proxy.Csv;

/// <summary>
/// Turns parsed <see cref="ProxyCsvRow"/> entries into persisted
/// <see cref="ProxyProfile"/> records: validates each row, stores its
/// password via <see cref="ICredentialStore"/> (never in the repository's
/// JSON file), and adds the profile via <see cref="IProxyRepository"/>.
/// A failure on one row does not abort the whole import - every row gets an
/// independent result so the caller can show a clear per-line summary.
/// </summary>
public sealed class ProxyCsvImporter
{
    private readonly IProxyRepository _repository;
    private readonly ICredentialStore _credentialStore;
    private readonly IAppLogger _logger;

    public ProxyCsvImporter(IProxyRepository repository, ICredentialStore credentialStore, IAppLogger logger)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _credentialStore = credentialStore ?? throw new ArgumentNullException(nameof(credentialStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public ProxyCsvImportResult Import(string csvContent, ProxyProtocol protocol = ProxyProtocol.Http)
    {
        var rows = ProxyCsvParser.Parse(csvContent);
        var results = new List<ProxyCsvImportRowResult>(rows.Count);

        foreach (var row in rows)
        {
            results.Add(ImportRow(row, protocol));
        }

        _logger.Info("ProxyCsvImporter", $"Import finished: {results.Count(r => r.Success)}/{results.Count} rows succeeded.");
        return new ProxyCsvImportResult { Rows = results };
    }

    private ProxyCsvImportRowResult ImportRow(ProxyCsvRow row, ProxyProtocol protocol)
    {
        if (string.IsNullOrWhiteSpace(row.Ip))
        {
            return ProxyCsvImportRowResult.Failed(row.LineNumber, "Missing IP/host.");
        }

        if (!int.TryParse(row.Port, out var port) || !ProxyValidation.IsValidPort(port))
        {
            return ProxyCsvImportRowResult.Failed(row.LineNumber, $"Invalid port '{row.Port}'.");
        }

        if (string.IsNullOrWhiteSpace(row.Username))
        {
            return ProxyCsvImportRowResult.Failed(row.LineNumber, "Missing username.");
        }

        if (string.IsNullOrEmpty(row.Password))
        {
            return ProxyCsvImportRowResult.Failed(row.LineNumber, "Missing password.");
        }

        var countryCode = NormalizeCountryCode(row.Country);

        var profile = new ProxyProfile
        {
            Host = row.Ip.Trim(),
            Port = port,
            Username = row.Username.Trim(),
            Protocol = protocol,
            CountryCode = countryCode,
            CountryName = CountryCatalog.GetName(countryCode, row.Country.Trim()),
            City = row.City.Trim(),
        };
        profile.Name = string.IsNullOrWhiteSpace(profile.City)
            ? $"{profile.CountryName} - {profile.Host}"
            : $"{profile.CountryName} - {profile.City}";

        var validation = ProxyValidation.Validate(profile, row.Password);
        if (!validation.IsValid)
        {
            return ProxyCsvImportRowResult.Failed(row.LineNumber, string.Join(" ", validation.Errors));
        }

        try
        {
            var credentialKey = CredentialKeyFactory.NewKey();
            _credentialStore.Save(credentialKey, row.Password);
            profile.CredentialRef = credentialKey;

            var added = _repository.Add(profile);
            return ProxyCsvImportRowResult.Ok(row.LineNumber, added.Id);
        }
        catch (Exception ex)
        {
            _logger.Error("ProxyCsvImporter", $"Failed to import row {row.LineNumber}.", ex);
            return ProxyCsvImportRowResult.Failed(row.LineNumber, "Internal error while saving this proxy.");
        }
    }

    private static string NormalizeCountryCode(string country)
    {
        var trimmed = country.Trim();
        if (trimmed.Length == 2)
        {
            return trimmed.ToUpperInvariant();
        }

        // Best-effort: many exports use full country names; without a full
        // ISO lookup table we fall back to storing the name as-is in
        // CountryName and leave CountryCode blank (flag renders as a globe).
        return string.Empty;
    }
}
