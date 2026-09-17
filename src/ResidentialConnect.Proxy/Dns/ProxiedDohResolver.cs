using System.Net;
using System.Net.Http;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Forwarding;

namespace ResidentialConnect.Proxy.Dns;

/// <summary>
/// Default <see cref="IDohResolver"/>: answers raw DNS wire-format queries
/// via RFC 8484 DNS-over-HTTPS (POST, <c>application/dns-message</c>) against
/// Cloudflare's <c>cloudflare-dns.com</c> resolver, reached ENTIRELY through
/// the residential proxy via a single, session-scoped <see cref="HttpClient"/>
/// whose <see cref="SocketsHttpHandler.ConnectCallback"/> dials the upstream
/// tunnel itself (<see cref="IUpstreamConnector"/>) instead of ever letting
/// <see cref="HttpClient"/>/<see cref="System.Net.Sockets.Socket"/> perform
/// its own TCP connect or DNS resolution.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why <see cref="SocketsHttpHandler.ConnectCallback"/>, not
/// <c>HttpClientHandler.Proxy</c>:</b> <see cref="HttpProxyConnectivityTester"/>
/// (the V0.1 connectivity check) uses an ordinary <c>IWebProxy</c> - simple,
/// but it means .NET's own HTTP stack performs the CONNECT handshake and
/// (for a SOCKS5 profile) would not work at all, since
/// <see cref="System.Net.Http.HttpClientHandler.Proxy"/> only understands
/// HTTP(S) proxies, not SOCKS5. <see cref="ConnectCallback"/> instead hands
/// control of the raw TRANSPORT connection to this class, which reuses the
/// EXACT SAME <see cref="IUpstreamConnector"/> abstraction (and both its
/// concrete HTTP CONNECT / SOCKS5 implementations)
/// <see cref="Forwarding.TransparentForwardingProxy"/> already uses and
/// already has tests for - <see cref="System.Net.Http.SocketsHttpHandler"/>
/// then layers its own TLS (for the <c>https://cloudflare-dns.com</c> URL)
/// directly on top of the returned <see cref="System.IO.Stream"/>, exactly
/// as if it had opened the TCP connection itself.
/// </para>
/// <para>
/// <b>Never resolves <c>cloudflare-dns.com</c> locally:</b> the callback
/// passes <c>context.DnsEndPoint.Host</c>/<c>.Port</c> STRAIGHT to
/// <see cref="IUpstreamConnector.ConnectAsync"/> as the CONNECT/SOCKS5
/// target - the connector's own implementations either forward the
/// hostname to the upstream HTTP proxy as-is (CONNECT
/// <c>cloudflare-dns.com:443</c>) or, for SOCKS5, use ATYP domain-name
/// addressing (see <see cref="Socks5UpstreamConnector"/>) so the RESIDENTIAL
/// PROXY's own exit node resolves the hostname - never this process's own
/// <see cref="System.Net.Dns"/>. This is the entire point of proxying DNS at
/// all: if this class itself called <see cref="System.Net.Dns.GetHostAddressesAsync(string)"/>
/// for <c>cloudflare-dns.com</c>, that lookup would go out over the user's
/// REAL local network - exactly the leak Whole Computer mode's UDP/53
/// interception exists to close, just moved one level up.
/// </para>
/// <para>
/// <b>Session-scoped <see cref="HttpClient"/>:</b> constructed once, in
/// <see cref="Configure"/>, and reused for every <see cref="ResolveAsync"/>
/// call for the life of the Whole Computer session -
/// <see cref="System.Net.Http.SocketsHttpHandler"/>'s own connection pooling
/// then keeps the TLS connection to <c>cloudflare-dns.com</c> warm across
/// queries instead of paying a fresh TCP+TLS+proxy-tunnel handshake for
/// every single DNS lookup.
/// </para>
/// </remarks>
public sealed class ProxiedDohResolver : IDohResolver
{
    private const string DohEndpoint = "https://cloudflare-dns.com/dns-query";
    private const string DnsMessageContentType = "application/dns-message";

    private readonly IAppLogger _logger;
    private HttpClient? _httpClient;
    private IUpstreamConnector? _connector;

    private readonly string _dohEndpointOverride;

    public ProxiedDohResolver(IAppLogger logger) : this(logger, DohEndpoint)
    {
    }

    /// <summary>
    /// Test-only seam letting a test point this resolver at a local fake
    /// DoH server's URL instead of the real <c>cloudflare-dns.com</c>
    /// endpoint, so <see cref="Configure"/>'s
    /// <see cref="IUpstreamConnector"/>-based tunneling can be exercised
    /// end-to-end without a real network call - see
    /// <c>ProxiedDohResolverTests</c>.
    /// </summary>
    internal ProxiedDohResolver(IAppLogger logger, string dohEndpointOverride)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _dohEndpointOverride = dohEndpointOverride ?? throw new ArgumentNullException(nameof(dohEndpointOverride));
    }

    public void Configure(ProxyProfile profile, string password, IPAddress pinnedProxyAddress)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentException.ThrowIfNullOrEmpty(password);
        ArgumentNullException.ThrowIfNull(pinnedProxyAddress);

        if (_httpClient is not null)
        {
            throw new InvalidOperationException("ProxiedDohResolver.Configure must only be called once per Whole Computer session.");
        }

        // Dial the pinned IPv4 literal, never profile.Host - exactly the
        // same "exact dialed IP == exact excluded IP" invariant
        // WinDivertSystemTrafficRouter/TransparentForwardingProxy already
        // enforce for the ordinary TCP forward path (see
        // ITransparentForwardingProxy.StartAsync's pinnedProxyAddress
        // remarks).
        var pinnedProxyHost = pinnedProxyAddress.ToString();
        _connector = profile.Protocol switch
        {
            ProxyProtocol.Http => new HttpConnectUpstreamConnector(pinnedProxyHost, profile.Port, profile.Username, password, _logger),
            ProxyProtocol.Socks5 => new Socks5UpstreamConnector(pinnedProxyHost, profile.Port, profile.Username, password),
            _ => throw new NotSupportedException($"Protocol {profile.Protocol} not supported by the proxied DoH resolver.")
        };

        var handler = new SocketsHttpHandler
        {
            // The default .NET behavior (opening a real Socket and, for a
            // hostname target, resolving it via the local OS resolver) is
            // completely bypassed here - see class remarks "Never resolves
            // cloudflare-dns.com locally".
            ConnectCallback = async (context, cancellationToken) =>
            {
                var upstream = await _connector.ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                return upstream.GetStream();
            },
            // A single persistent connection is exactly what "session-scoped,
            // reused for every query" (class remarks) means in
            // SocketsHttpHandler terms - no reason to ever open a second
            // concurrent tunnel to the same DoH endpoint for this resolver.
            MaxConnectionsPerServer = 4,
            PooledConnectionLifetime = TimeSpan.FromMinutes(10)
        };

        _httpClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
        };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ResidentialConnect/0.2-DoH");
    }

    public async Task<byte[]> ResolveAsync(byte[] dnsQueryPayload, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dnsQueryPayload);

        if (_httpClient is null)
        {
            throw new InvalidOperationException("ProxiedDohResolver.Configure must be called before ResolveAsync.");
        }

        using var content = new ByteArrayContent(dnsQueryPayload);
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(DnsMessageContentType);

        using var request = new HttpRequestMessage(HttpMethod.Post, _dohEndpointOverride) { Content = content };
        request.Headers.Accept.ParseAdd(DnsMessageContentType);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
        _httpClient = null;
    }
}
