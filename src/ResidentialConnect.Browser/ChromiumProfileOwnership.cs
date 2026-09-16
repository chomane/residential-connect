using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ResidentialConnect.Browser;

/// <summary>Checks a complete argument value, never a command-line substring.</summary>
[SupportedOSPlatform("windows")]
internal static class ChromiumProfileOwnership
{
    internal static bool Matches(string name, string? commandLine, string profilePath)
    {
        if (!(name.Equals("chrome.exe", StringComparison.OrdinalIgnoreCase) ||
              name.Equals("msedge.exe", StringComparison.OrdinalIgnoreCase) ||
              name.Equals("chromium.exe", StringComparison.OrdinalIgnoreCase)) ||
            string.IsNullOrWhiteSpace(commandLine))
            return false;

        var argv = CommandLineToArgvW(commandLine, out var count);
        if (argv == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            string? value = null;
            for (var i = 1; i < count; i++)
            {
                var arg = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size))!;
                if (arg == "--") break;
                const string flag = "--user-data-dir";
                string? candidate = null;
                if (arg.StartsWith(flag + "=", StringComparison.Ordinal))
                    candidate = arg[(flag.Length + 1)..];
                else if (arg == flag && i + 1 < count)
                    candidate = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, ++i * IntPtr.Size));
                if (candidate is null) continue;
                // Ambiguous duplicate switches are not evidence of ownership.
                if (value is not null) return false;
                value = candidate;
            }
            var normalized = Normalize(value);
            return normalized is not null && string.Equals(normalized, Normalize(profilePath), StringComparison.OrdinalIgnoreCase);
        }
        finally { LocalFree(argv); }
    }

    private static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        path = path.Replace('/', '\\');
        if (!Path.IsPathFullyQualified(path)) return null;
        try { return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argc);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
