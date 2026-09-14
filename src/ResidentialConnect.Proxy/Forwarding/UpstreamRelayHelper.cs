using System.Net.Sockets;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>
/// Shared byte-splicing helper used by both <see cref="LocalForwardingProxy"/>
/// (V0.1, loopback-only, HTTP-CONNECT-from-the-client semantics) and
/// <see cref="TransparentForwardingProxy"/> (V0.2, whole-computer,
/// kernel-redirected raw TCP semantics). Extracted so both relays share
/// exactly one, already-tested bidirectional copy implementation rather than
/// duplicating it.
/// </summary>
internal static class UpstreamRelayHelper
{
    public static async Task RelayBidirectionalAsync(NetworkStream a, NetworkStream b, CancellationToken cancellationToken)
    {
        var t1 = CopyAsync(a, b, cancellationToken);
        var t2 = CopyAsync(b, a, cancellationToken);
        await Task.WhenAny(t1, t2).ConfigureAwait(false);
    }

    private static async Task CopyAsync(NetworkStream from, NetworkStream to, CancellationToken cancellationToken)
    {
        try
        {
            await from.CopyToAsync(to, 81920, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Connection closed by either side - normal end-of-session.
        }
    }
}
