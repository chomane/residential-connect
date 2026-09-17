using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;

namespace ResidentialConnect.Browser;

/// <summary>WMI metadata plus a retained process handle guards against PID reuse.</summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsBrowserProcessCatalog : IBrowserProcessCatalog
{
    public IReadOnlyList<BrowserProcessCandidate> GetProcesses()
    {
        var candidates = new List<BrowserProcessCandidate>();
        try
        {
            using var query = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine, CreationDate FROM Win32_Process " +
                "WHERE Name = 'chrome.exe' OR Name = 'msedge.exe' OR Name = 'chromium.exe'");
            query.Options.Timeout = TimeSpan.FromSeconds(10);
            using var results = query.Get();
            foreach (ManagementObject row in results)
            {
                using (row)
                {
                    Process? process = null;
                    try
                    {
                        if (row["CommandLine"] is not string commandLine || row["CreationDate"] is not string created)
                            continue;
                        process = Process.GetProcessById(Convert.ToInt32(row["ProcessId"]));
                        _ = process.Handle; // Hold the OS identity until cleanup completes.
                        var expected = ManagementDateTimeConverter.ToDateTime(created).ToUniversalTime();
                        // WMI's DMTF date has microsecond precision; Process.StartTime has 100ns precision.
                        if (process.HasExited || process.StartTime.ToUniversalTime().Ticks / 10 != expected.Ticks / 10)
                            continue;
                        candidates.Add(new BrowserProcessCandidate(process, (string)row["Name"], commandLine));
                        process = null; // Ownership transferred to the caller.
                    }
                    catch (ArgumentException) { /* Exited before opening its handle. */ }
                    catch (InvalidOperationException) { /* Exited during inspection. */ }
                    catch (Win32Exception ex) when (ex.NativeErrorCode == 87) { /* No longer exists. */ }
                    finally { process?.Dispose(); }
                }
            }
            return candidates;
        }
        catch
        {
            foreach (var candidate in candidates) candidate.Process.Dispose();
            throw; // Do not report Ready when ownership enumeration failed.
        }
    }
}
