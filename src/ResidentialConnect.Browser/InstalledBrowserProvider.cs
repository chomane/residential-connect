using System.Runtime.Versioning;

namespace ResidentialConnect.Browser;

/// <summary>
/// V0.1 TEMPORARY implementation: locates an already-installed Chrome or
/// Edge executable via common Windows install paths. Documented as a
/// stop-gap in README/ARCHITECTURE - a future release should replace this
/// with a provider that ships/manages its own bundled Chromium build so the
/// app does not depend on what the user happens to have installed.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class InstalledBrowserProvider : IBrowserProvider
{
    public string ProviderName => "Installed Chrome/Edge (temporary V0.1 provider)";

    private static readonly string[] CandidatePaths =
    {
        @"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
        @"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
        @"%LocalAppData%\Google\Chrome\Application\chrome.exe",
        @"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
        @"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    };

    public string? FindExecutable()
    {
        foreach (var candidate in CandidatePaths)
        {
            var expanded = Environment.ExpandEnvironmentVariables(candidate);
            if (File.Exists(expanded))
            {
                return expanded;
            }
        }

        return null;
    }
}
