using System.Text;

namespace ResidentialConnect.Proxy.Csv;

/// <summary>
/// Parses the Webshare-style proxy import CSV format:
/// <c>IP,Port,Username,Password,Country,City</c> (one proxy per line, no
/// header line required - a header is auto-detected and skipped if present).
/// Supports basic double-quoted fields so values containing commas (e.g. some
/// city names) can still be imported correctly.
/// </summary>
public static class ProxyCsvParser
{
    private static readonly string[] HeaderTokens = { "ip", "host", "port", "username", "user", "password", "pass", "country", "city" };

    public static IReadOnlyList<ProxyCsvRow> Parse(string csvContent)
    {
        ArgumentNullException.ThrowIfNull(csvContent);

        var rows = new List<ProxyCsvRow>();
        using var reader = new StringReader(csvContent);
        string? line;
        var lineNumber = 0;
        var firstDataLine = true;

        while ((line = reader.ReadLine()) is not null)
        {
            lineNumber++;
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var fields = SplitCsvLine(line);

            if (firstDataLine && LooksLikeHeader(fields))
            {
                firstDataLine = false;
                continue;
            }

            firstDataLine = false;

            rows.Add(new ProxyCsvRow
            {
                LineNumber = lineNumber,
                Ip = GetField(fields, 0),
                Port = GetField(fields, 1),
                Username = GetField(fields, 2),
                Password = GetField(fields, 3),
                Country = GetField(fields, 4),
                City = GetField(fields, 5)
            });
        }

        return rows;
    }

    private static string GetField(IReadOnlyList<string> fields, int index) =>
        index < fields.Count ? fields[index].Trim() : string.Empty;

    private static bool LooksLikeHeader(IReadOnlyList<string> fields) =>
        fields.Count > 0 && fields.Any(f => HeaderTokens.Contains(f.Trim().ToLowerInvariant()));

    private static List<string> SplitCsvLine(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];

            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    current.Append(c);
                }
            }
            else
            {
                if (c == '"')
                {
                    inQuotes = true;
                }
                else if (c == ',')
                {
                    fields.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }
        }

        fields.Add(current.ToString());
        return fields;
    }
}
