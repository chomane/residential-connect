using ResidentialConnect.Browser;

namespace ResidentialConnect.Tests;

public sealed class ChromiumProfileOwnershipTests
{
    private const string Profile = @"C:\Managed Profiles\abc";

    [Theory]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=\"C:\\Managed Profiles\\abc\"", true)]
    [InlineData("msedge.exe", "msedge.exe \"--user-data-dir=C:/managed profiles/ABC/\"", true)]
    [InlineData("CHROMIUM.EXE", "chromium.exe --user-data-dir \"C:\\Managed Profiles\\x\\..\\abc\"", true)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=\"C:\\Managed Profiles\\abc-other\"", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=\"C:\\Managed Profiles\\abc\\child\"", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=\"C:\\Managed Profiles\"", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=\"D:\\Managed Profiles\\abc\"", false)]
    [InlineData("chrome.exe", "chrome.exe --other=\"C:\\Managed Profiles\\abc\"", false)]
    [InlineData("chrome.exe", "chrome.exe --url=\"https://example.test/--user-data-dir=C:/Managed Profiles/abc\"", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=abc", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=\"C:\\Managed Profiles\\abc\" --user-data-dir=C:\\Other", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir=", false)]
    [InlineData("chrome.exe", "chrome.exe --user-data-dir", false)]
    [InlineData("chrome.exe", "chrome.exe -- --user-data-dir=\"C:\\Managed Profiles\\abc\"", false)]
    [InlineData("chrome.exe", null, false)]
    [InlineData("chrome.exe", "", false)]
    [InlineData("not-chrome.exe", "not-chrome.exe --user-data-dir=\"C:\\Managed Profiles\\abc\"", false)]
    public void ExactArgumentMatch_ProtectsOtherProfiles(string name, string? commandLine, bool expected)
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal(expected, ChromiumProfileOwnership.Matches(name, commandLine, Profile));
    }

    [DesktopWmiFact]
    public void WindowsCatalog_CanEnumerateAndDisposeWithoutTerminatingAnything()
    {
        if (!OperatingSystem.IsWindows()) return;
        var candidates = new WindowsBrowserProcessCatalog().GetProcesses();
        foreach (var candidate in candidates) candidate.Process.Dispose();
    }
}

/// <summary>Run explicitly from an unrestricted Windows desktop test session.</summary>
public sealed class DesktopWmiFactAttribute : FactAttribute
{
    public DesktopWmiFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("RESIDENTIALCONNECT_TEST_WMI") != "1")
            Skip = "Requires Windows desktop WMI access; set RESIDENTIALCONNECT_TEST_WMI=1 outside the sandbox.";
    }
}
