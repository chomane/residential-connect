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
/// <remarks>
/// <para>
/// <b>2026-09-16 code-inspection note (diagnostic investigation only - NO
/// behavior change made here):</b> per the explicit instruction to inspect,
/// not blindly "fix", this method for the "upstream CONNECT succeeded but
/// the session immediately ended with zero bytes in both directions"
/// symptom, here is exactly what <see cref="RelayBidirectionalAsync"/> does:
/// it starts BOTH copy pumps (<see cref="CopyAsync"/>) concurrently, then
/// <c>await</c>s <c>Task.WhenAny(t1, t2)</c> and returns as soon as
/// EITHER ONE of the two tasks completes - it does not wait for the other
/// pump, does not cancel the other pump's <see cref="CancellationToken"/>
/// itself, and does not dispose anything itself. The still-running pump
/// keeps running (its <c>ReadAsync</c>/<c>WriteAsync</c> calls remain
/// in-flight) until whatever the CALLER does next - in
/// <see cref="TransparentForwardingProxy.HandleClientAsync"/>, the
/// immediately following statement is the end of the enclosing
/// <c>using (upstream)</c> block, which disposes <c>upstream</c> (and the
/// method then returns out of the outer <c>using var _ = localClient;</c>,
/// disposing <c>localClient</c> too) - so the other, still-in-flight pump's
/// stream(s) get disposed out from under it a moment later, which is what
/// actually tears down BOTH directions once ONE of them completes. This is
/// the STANDARD "whichever direction closes first ends the whole
/// connection" bidirectional-relay pattern (the same pattern
/// <c>LocalForwardingProxy</c> already used successfully for V0.1's
/// working OPEN BROWSER path) - it is not, by itself, a bug: a real HTTPS
/// request is expected to eventually see one direction EOF (usually the
/// server closing after its response) and the whole tunnel correctly ends
/// at that point. The diagnostic question this method's behavior raises for
/// the CURRENT symptom is therefore not "does WhenAny work correctly" but
/// "which direction's pump reported EOF/exception FIRST, how quickly after
/// the upstream tunnel was established, and did the app->upstream direction
/// ever see any bytes from <see cref="TransparentForwardingProxy"/>'s local
/// stream at all before that happened" - exactly what
/// <see cref="TransparentForwardingProxy"/>'s new
/// <c>RelayBidirectionalWithDiagnosticsAsync</c> diagnostic-only variant
/// (used only when <c>RESIDENTIALCONNECT_ROUTING_DIAGNOSTICS=1</c>) now logs
/// explicitly, per direction. This production method
/// (<see cref="RelayBidirectionalAsync"/>) itself is UNCHANGED by this
/// investigation.
/// </para>
/// </remarks>
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
