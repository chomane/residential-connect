namespace ResidentialConnect.Core.Diagnostics;

/// <summary>Severity of a diagnostic log entry.</summary>
public enum LogLevel
{
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3
}

/// <summary>
/// Minimal structured logger abstraction used across all layers. The
/// contract itself does not prevent a caller from passing a secret in
/// <c>message</c>; callers MUST use <see cref="Diagnostics.SecretScrubber"/>
/// helpers (or simply never interpolate secret values) when constructing log
/// messages. See <c>docs/ARCHITECTURE.md</c> "Logging & secret hygiene".
/// </summary>
public interface IAppLogger
{
    void Log(LogLevel level, string category, string message, Exception? exception = null);

    void Debug(string category, string message) => Log(LogLevel.Debug, category, message);
    void Info(string category, string message) => Log(LogLevel.Info, category, message);
    void Warning(string category, string message) => Log(LogLevel.Warning, category, message);
    void Error(string category, string message, Exception? exception = null) => Log(LogLevel.Error, category, message, exception);
}
