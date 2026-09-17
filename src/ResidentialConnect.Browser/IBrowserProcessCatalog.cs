using System.Diagnostics;

namespace ResidentialConnect.Browser;

/// <summary>Returned process handles belong to the caller and must be disposed.</summary>
internal interface IBrowserProcessCatalog
{
    IReadOnlyList<BrowserProcessCandidate> GetProcesses();
}

internal sealed record BrowserProcessCandidate(Process Process, string Name, string? CommandLine);
