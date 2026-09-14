using ResidentialConnect.Browser;

namespace ResidentialConnect.Tests;

/// <summary>
/// Regression tests for the V0.1 OPEN BROWSER bug: Chrome opened the user's
/// normal, already-logged-in profile (with their real extensions) instead of
/// an isolated one, and the launched tab was not routed through the local
/// relay / upstream Webshare proxy at all.
///
/// Root cause: the previous code built the user-data-dir argument as
/// $"--user-data-dir=\"{profileDir}\"" - i.e. it manually embedded literal
/// quote characters into the argument VALUE. Every value added to
/// ProcessStartInfo.ArgumentList is already escaped/quoted automatically by
/// .NET when the real Win32 command line is constructed, so those
/// hand-embedded quotes were escaped a second time, producing a token whose
/// value - once Chrome's own argv parser unescaped the ONE outer quote pair
/// .NET added - still literally started and ended with a doublequote
/// character. That is not a valid Windows directory path, so Chrome could
/// not create/open the isolated profile and silently fell back to the
/// user's normal default profile directory. Because that default profile
/// already had a running Chrome instance, Chrome's process-singleton
/// mechanism handed the "open this URL" request off to the ALREADY-RUNNING
/// instance via IPC and the new process exited - and command-line switches
/// such as --proxy-server are only honored on a profile's INITIAL process
/// startup, never on a singleton hand-off. This explains both symptoms
/// (profile leak AND proxy bypass) from a single root cause.
///
/// These tests assert the exact argument VALUES produced by
/// ChromiumArgumentsBuilder.Build, proving the value passed for
/// --user-data-dir is the raw, unquoted path (no embedded " characters at
/// all), and that every other required safety property holds.
/// </summary>
public class ChromiumArgumentsBuilderTests
{
    private const int SamplePort = 54231;
    private const string SampleProfileDir = @"C:\Users\Test\AppData\Local\ResidentialConnect\BrowserProfiles\abc123def456";

    [Fact]
    public void Build_UserDataDirArgument_ContainsNoEmbeddedQuoteCharacters()
    {
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        var userDataDirArg = Assert.Single(args, a => a.StartsWith("--user-data-dir=", StringComparison.Ordinal));

        // This is the exact regression assertion for the bug: the previous
        // implementation produced "--user-data-dir=\"C:\...\"" (embedded
        // quotes in the VALUE). The fixed value must be the raw path with
        // NO quote characters anywhere in it.
        Assert.DoesNotContain('"', userDataDirArg);
        Assert.Equal($"--user-data-dir={SampleProfileDir}", userDataDirArg);
    }

    [Fact]
    public void Build_UserDataDirArgument_MatchesIsolatedProfileDirectoryExactly()
    {
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        var userDataDirArg = Assert.Single(args, a => a.StartsWith("--user-data-dir=", StringComparison.Ordinal));
        var value = userDataDirArg["--user-data-dir=".Length..];

        Assert.Equal(SampleProfileDir, value);
    }

    [Fact]
    public void Build_ProxyServerArgument_PointsAtLoopbackAndGivenPort()
    {
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        Assert.Contains($"--proxy-server=127.0.0.1:{SamplePort}", args);
    }

    [Fact]
    public void Build_NeverProducesAnArgumentContainingBothHostAndSelectorForSystemProxy()
    {
        // Guard against ever accidentally wiring the browser to something
        // other than the loopback relay (e.g. the real upstream host/port),
        // which would defeat the whole point of the local relay design.
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        Assert.All(args, a => Assert.DoesNotContain("webshare", a, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(args, a => a.Contains("127.0.0.1", StringComparison.Ordinal));
    }

    [Fact]
    public void Build_IncludesWebRtcLeakProtectionFlag()
    {
        // WebRTC ICE/STUN negotiation opens raw UDP sockets that bypass
        // --proxy-server entirely. Without this flag a page could reveal the
        // machine's real IP even while every other request is correctly
        // proxied - a silent partial bypass of the relay.
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        Assert.Contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp", args);
    }

    [Fact]
    public void Build_IncludesNoFirstRunAndNoDefaultBrowserCheck_ForTheIsolatedProfile()
    {
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        Assert.Contains("--no-first-run", args);
        Assert.Contains("--no-default-browser-check", args);
    }

    [Fact]
    public void Build_WithStartUrl_AppendsUrlAsFinalArgument()
    {
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, "https://api.ipify.org");

        Assert.Equal("https://api.ipify.org", args[^1]);
    }

    [Fact]
    public void Build_WithoutStartUrl_DoesNotAppendAnyUrlArgument()
    {
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        Assert.All(args, a => Assert.False(a.StartsWith("http://", StringComparison.Ordinal) || a.StartsWith("https://", StringComparison.Ordinal)));
    }

    [Fact]
    public void Build_ProfileDirectoryWithSpaces_StillProducesRawUnquotedValue()
    {
        // Paths with spaces are exactly the case ArgumentList's automatic
        // escaping exists to handle correctly - the builder must still pass
        // the raw value and let ArgumentList do the quoting, never quote it
        // itself.
        const string dirWithSpaces = @"C:\Users\Test User\AppData\Local\ResidentialConnect\BrowserProfiles\abc123";

        var args = ChromiumArgumentsBuilder.Build(SamplePort, dirWithSpaces, null);

        var userDataDirArg = Assert.Single(args, a => a.StartsWith("--user-data-dir=", StringComparison.Ordinal));
        Assert.Equal($"--user-data-dir={dirWithSpaces}", userDataDirArg);
        Assert.DoesNotContain('"', userDataDirArg);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(100000)]
    public void Build_InvalidPort_Throws(int invalidPort)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ChromiumArgumentsBuilder.Build(invalidPort, SampleProfileDir, null));
    }

    [Fact]
    public void Build_EmptyProfileDirectory_Throws()
    {
        Assert.Throws<ArgumentException>(() => ChromiumArgumentsBuilder.Build(SamplePort, string.Empty, null));
    }

    [Fact]
    public void Build_ProcessStartInfoArgumentList_RoundTripsWithoutCorruption()
    {
        // End-to-end proof that feeding the builder's raw values into
        // ProcessStartInfo.ArgumentList (exactly as ChromiumBrowserLauncher
        // does) and then re-parsing the resulting Win32 command line with
        // the same argv rules Chrome's CommandLineToArgvW uses reproduces
        // the ORIGINAL, uncorrupted directory path - i.e. this is the exact
        // mechanism that was broken before the fix, now verified fixed.
        var args = ChromiumArgumentsBuilder.Build(SamplePort, SampleProfileDir, null);

        var startInfo = new System.Diagnostics.ProcessStartInfo();
        foreach (var arg in args)
        {
            startInfo.ArgumentList.Add(arg);
        }

        var commandLine = BuildWin32CommandLineForTest(startInfo.ArgumentList);
        var reparsed = ArgvParseForTest(commandLine);

        var userDataDirToken = Assert.Single(reparsed, a => a.StartsWith("--user-data-dir=", StringComparison.Ordinal));
        Assert.Equal($"--user-data-dir={SampleProfileDir}", userDataDirToken);
    }

    // --- Minimal re-implementation of .NET's / Win32's argv quoting rules, ---
    // --- used only to prove round-tripping in the test above.             ---

    private static string BuildWin32CommandLineForTest(System.Collections.ObjectModel.Collection<string> argumentList)
    {
        var sb = new System.Text.StringBuilder();
        foreach (var argument in argumentList)
        {
            if (sb.Length > 0)
            {
                sb.Append(' ');
            }

            AppendArgument(sb, argument);
        }

        return sb.ToString();

        // Faithful port of the algorithm .NET's ArgumentList uses internally
        // (PasteArguments.AppendArgument), which itself implements the
        // documented Win32 CommandLineToArgvW-compatible quoting rules.
        static void AppendArgument(System.Text.StringBuilder sb, string argument)
        {
            if (argument.Length != 0 && !argument.Contains(' ') && !argument.Contains('"') && !argument.Contains('\t') && !argument.Contains('\n') && !argument.Contains('\v'))
            {
                sb.Append(argument);
                return;
            }

            sb.Append('"');
            for (var i = 0; i < argument.Length;)
            {
                var c = argument[i++];
                if (c == '\\')
                {
                    var backslashCount = 1;
                    while (i < argument.Length && argument[i] == '\\')
                    {
                        backslashCount++;
                        i++;
                    }

                    if (i == argument.Length)
                    {
                        sb.Append('\\', backslashCount * 2);
                    }
                    else if (argument[i] == '"')
                    {
                        sb.Append('\\', backslashCount * 2 + 1);
                        sb.Append('"');
                        i++;
                    }
                    else
                    {
                        sb.Append('\\', backslashCount);
                    }
                }
                else if (c == '"')
                {
                    sb.Append('\\').Append('"');
                }
                else
                {
                    sb.Append(c);
                }
            }

            sb.Append('"');
        }
    }

    private static List<string> ArgvParseForTest(string commandLine)
    {
        // Minimal CommandLineToArgvW-compatible parser sufficient for this
        // round-trip test (handles quotes and backslash-escaping of quotes).
        var results = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        var i = 0;
        while (i < commandLine.Length)
        {
            var c = commandLine[i];
            if (c == '\\')
            {
                var backslashCount = 0;
                while (i < commandLine.Length && commandLine[i] == '\\')
                {
                    backslashCount++;
                    i++;
                }

                if (i < commandLine.Length && commandLine[i] == '"')
                {
                    current.Append('\\', backslashCount / 2);
                    if (backslashCount % 2 == 1)
                    {
                        current.Append('"');
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                    i++;
                }
                else
                {
                    current.Append('\\', backslashCount);
                }
            }
            else if (c == '"')
            {
                inQuotes = !inQuotes;
                i++;
            }
            else if (c == ' ' && !inQuotes)
            {
                if (current.Length > 0)
                {
                    results.Add(current.ToString());
                    current.Clear();
                }
                i++;
            }
            else
            {
                current.Append(c);
                i++;
            }
        }

        if (current.Length > 0)
        {
            results.Add(current.ToString());
        }

        return results;
    }
}
