namespace ResidentialConnect.Core.Common;

/// <summary>
/// Centralized, single source of truth for where the application stores its
/// local data (%LOCALAPPDATA%\ResidentialConnect on Windows). Kept in Core so
/// every layer (Security, Proxy, Client) agrees on the same folder without
/// duplicating the logic.
/// </summary>
public static class AppPaths
{
    private const string AppFolderName = "ResidentialConnect";

    /// <summary>Root folder for all local application data.</summary>
    public static string RootDirectory
    {
        get
        {
            var baseDir = Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolderOption.Create);

            // Environment.SpecialFolder.LocalApplicationData can resolve to an
            // empty string on some non-Windows CI hosts; fall back to a temp
            // directory so cross-platform unit tests/builds still work.
            if (string.IsNullOrWhiteSpace(baseDir))
            {
                baseDir = Path.Combine(Path.GetTempPath(), "ResidentialConnectFallback");
            }

            return Path.Combine(baseDir, AppFolderName);
        }
    }

    public static string CredentialsDirectory => Path.Combine(RootDirectory, "Credentials");

    public static string ProxiesFilePath => Path.Combine(RootDirectory, "proxies.json");

    public static string LogsDirectory => Path.Combine(RootDirectory, "Logs");

    public static string BrowserProfilesDirectory => Path.Combine(RootDirectory, "BrowserProfiles");

    public static void EnsureDirectoriesExist()
    {
        Directory.CreateDirectory(RootDirectory);
        Directory.CreateDirectory(CredentialsDirectory);
        Directory.CreateDirectory(LogsDirectory);
        Directory.CreateDirectory(BrowserProfilesDirectory);
    }
}
