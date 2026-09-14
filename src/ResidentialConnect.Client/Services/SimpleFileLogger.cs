using System.IO;
using ResidentialConnect.Core.Diagnostics;

namespace ResidentialConnect.Client.Services;

/// <summary>Minimal <see cref="IAppLogger"/> writing timestamped, scrubbed lines to a local log file.</summary>
public sealed class SimpleFileLogger : IAppLogger
{
    private readonly string _logFilePath;
    private readonly object _lock = new();

    public SimpleFileLogger(string logFilePath)
    {
        _logFilePath = logFilePath;
        Directory.CreateDirectory(Path.GetDirectoryName(logFilePath)!);
    }

    public void Log(LogLevel level, string category, string message, Exception? exception = null)
    {
        var scrubbed = SecretScrubber.Scrub(message);
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {category}: {scrubbed}";
        if (exception is not null)
        {
            line += $" | Exception: {exception.GetType().Name}: {SecretScrubber.Scrub(exception.Message)}";
        }

        lock (_lock)
        {
            File.AppendAllText(_logFilePath, line + Environment.NewLine);
        }
    }
}
