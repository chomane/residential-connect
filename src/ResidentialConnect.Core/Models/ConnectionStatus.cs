namespace ResidentialConnect.Core.Models;

/// <summary>State machine for the main window's connection indicator.</summary>
public enum ConnectionStatus
{
    Ready = 0,
    Connecting = 1,
    Connected = 2,
    Disconnecting = 3,
    Error = 4
}

/// <summary>
/// Snapshot of the current connection state exposed by
/// <c>IConnectionManager</c> to the UI layer. Immutable so the UI can safely
/// bind to it without worrying about torn reads across threads.
/// </summary>
public sealed class ConnectionState
{
    public ConnectionStatus Status { get; init; } = ConnectionStatus.Ready;
    public ProxyProfile? ActiveProxy { get; init; }
    public string? PublicIp { get; init; }
    public TimeSpan? Latency { get; init; }
    public string? StatusMessage { get; init; }

    public static readonly ConnectionState Idle = new() { Status = ConnectionStatus.Ready, StatusMessage = "Ready" };
}
