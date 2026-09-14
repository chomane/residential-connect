using System.Net.Sockets;
using System.Text;

namespace ResidentialConnect.Proxy.Forwarding;

/// <summary>Result of reading one HTTP request's start-line + headers from a raw socket stream.</summary>
public sealed class RawHttpRequest
{
    public required string Method { get; init; }
    public required string Target { get; init; }
    public required string HttpVersion { get; init; }
    public required IReadOnlyList<string> HeaderLines { get; init; }

    /// <summary>The exact bytes read for the request line + headers (including the trailing blank line), for byte-exact forwarding.</summary>
    public required byte[] RawHeaderBytes { get; init; }

    public string? GetHeader(string name)
    {
        foreach (var line in HeaderLines)
        {
            var idx = line.IndexOf(':');
            if (idx > 0 && string.Equals(line[..idx].Trim(), name, StringComparison.OrdinalIgnoreCase))
            {
                return line[(idx + 1)..].Trim();
            }
        }

        return null;
    }
}

/// <summary>
/// Reads exactly the bytes belonging to an HTTP request's start-line and
/// header block from a <see cref="NetworkStream"/> - byte for byte, so
/// whatever comes after (a request body, or raw TLS bytes for a CONNECT
/// tunnel) is left completely untouched in the stream for the caller to
/// relay verbatim. A plain <see cref="StreamReader"/> cannot be used here
/// because its internal buffering would consume/lose those following bytes.
/// </summary>
public static class RawHttpRequestReader
{
    private const int MaxHeaderBytes = 32 * 1024;

    public static async Task<RawHttpRequest?> ReadAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>(1024);
        var single = new byte[1];

        while (true)
        {
            var read = await stream.ReadAsync(single, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return null; // connection closed before a full request arrived
            }

            buffer.Add(single[0]);

            if (buffer.Count >= 4 &&
                buffer[^4] == (byte)'\r' && buffer[^3] == (byte)'\n' &&
                buffer[^2] == (byte)'\r' && buffer[^1] == (byte)'\n')
            {
                break;
            }

            if (buffer.Count > MaxHeaderBytes)
            {
                throw new InvalidOperationException("HTTP request header block exceeded the maximum allowed size.");
            }
        }

        var rawBytes = buffer.ToArray();
        var text = Encoding.ASCII.GetString(rawBytes);
        var lines = text.Split("\r\n", StringSplitOptions.None);

        var requestLine = lines[0].Split(' ', 3);
        if (requestLine.Length != 3)
        {
            throw new InvalidOperationException($"Malformed HTTP request line: '{lines[0]}'.");
        }

        var headerLines = lines.Skip(1).Where(l => l.Length > 0).ToList();

        return new RawHttpRequest
        {
            Method = requestLine[0],
            Target = requestLine[1],
            HttpVersion = requestLine[2],
            HeaderLines = headerLines,
            RawHeaderBytes = rawBytes
        };
    }
}
