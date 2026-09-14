using System.Collections.Concurrent;
using System.Net;
using ResidentialConnect.Core.Abstractions;

namespace ResidentialConnect.Routing;

/// <summary>
/// Tracks every outbound TCP flow <see cref="WinDivertSystemTrafficRouter"/>
/// has decided to redirect through the local transparent relay, for the
/// FULL lifetime of that flow - not just at connection-establishment time.
/// </summary>
/// <remarks>
/// <para>
/// This is the single most important piece of "NAT" state in the whole
/// V0.2 design, and the reason a naive "rewrite the SYN only" WinDivert
/// implementation would not actually work: rewriting one packet's
/// destination does not change what destination the ORIGINAL application's
/// socket believes it is talking to. Windows's own TCP/IP stack keeps
/// generating every subsequent packet for that socket (ACKs, data, FIN)
/// addressed to the application's original, real destination - so
/// <see cref="WinDivertSystemTrafficRouter"/> must look up and re-apply the
/// SAME destination rewrite to every outbound packet of a redirected flow
/// (keyed by the flow's local/client TCP port, which the application's
/// socket keeps using for the life of the connection), and must also
/// rewrite the RETURN path (the local relay's replies) so their source
/// address:port is changed BACK to impersonate the real original
/// destination - otherwise the application's own socket will reject the
/// reply as not matching any connection it is expecting. Both directions
/// key off the same client port (read from different header fields
/// depending on direction) and share one entry in this table.
/// </para>
/// <para>
/// Entries are removed deterministically when a FIN or RST is observed in
/// either direction of the flow (<see cref="Touch"/> callers pass this in),
/// with a generous idle-timeout sweep (<see cref="EvictIdle"/>) as a safety
/// net for flows whose closing packet WinDivert's queue happened to drop
/// (the official docs note captured packets "may be dropped" if not
/// serviced quickly enough) so the table cannot grow without bound.
/// </para>
/// <para>
/// Implements <see cref="IOriginalDestinationResolver"/> as a non-destructive
/// peek (NOT single-use) specifically because <c>TransparentForwardingProxy</c>
/// needs the same entry this class already keeps alive for the packet-level
/// rewrite loop - removing it on first read would cause every packet after
/// the very first one to silently stop being redirected (a fail-OPEN leak).
/// </para>
/// </remarks>
public sealed class RedirectFlowTable : IOriginalDestinationResolver
{
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(15);

    private sealed class Flow
    {
        public required string Host { get; init; }
        public required int Port { get; init; }
        public DateTimeOffset LastSeenUtc { get; set; }
    }

    private readonly ConcurrentDictionary<int, Flow> _byClientPort = new();

    /// <summary>Records a newly-redirected flow (called once, when the original outbound SYN is intercepted).</summary>
    public void Record(int clientPort, string originalHost, int originalPort)
    {
        _byClientPort[clientPort] = new Flow
        {
            Host = originalHost,
            Port = originalPort,
            LastSeenUtc = DateTimeOffset.UtcNow
        };
    }

    /// <summary>
    /// Non-destructive lookup used on every packet of an already-redirected
    /// flow (both directions). Refreshes the idle timer so long-lived, busy
    /// connections (e.g. an open Telegram session) are never evicted while
    /// still actively exchanging packets.
    /// </summary>
    public bool TryGetFlow(int clientPort, out string host, out int port)
    {
        if (_byClientPort.TryGetValue(clientPort, out var flow))
        {
            flow.LastSeenUtc = DateTimeOffset.UtcNow;
            host = flow.Host;
            port = flow.Port;
            return true;
        }

        host = string.Empty;
        port = 0;
        return false;
    }

    /// <summary>Explicitly removes a flow, called when a FIN or RST is observed for it (in either direction).</summary>
    public void Remove(int clientPort) => _byClientPort.TryRemove(clientPort, out _);

    /// <summary>Removes every flow whose <see cref="IdleTimeout"/> has elapsed since it was last touched.</summary>
    public void EvictIdle()
    {
        var cutoff = DateTimeOffset.UtcNow - IdleTimeout;
        foreach (var kvp in _byClientPort)
        {
            if (kvp.Value.LastSeenUtc < cutoff)
            {
                _byClientPort.TryRemove(kvp.Key, out _);
            }
        }
    }

    /// <summary>Removes every tracked flow. Called on router stop so no stale mapping survives a DISCONNECT/reconnect cycle.</summary>
    public void Clear() => _byClientPort.Clear();

    /// <inheritdoc />
    /// <remarks>
    /// Used by <c>TransparentForwardingProxy</c> exactly once per accepted
    /// connection, to learn where to open the upstream tunnel. Deliberately
    /// non-destructive (see class remarks) - the entry stays alive for the
    /// packet-level router to keep rewriting subsequent packets of the same
    /// flow for its entire duration.
    /// </remarks>
    public bool TryResolve(IPEndPoint clientEndpoint, out string host, out int port)
    {
        ArgumentNullException.ThrowIfNull(clientEndpoint);
        return TryGetFlow(clientEndpoint.Port, out host, out port);
    }
}
