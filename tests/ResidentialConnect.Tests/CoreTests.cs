using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Diagnostics;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Csv;
using ResidentialConnect.Security.DataProtection;
using ResidentialConnect.Security.Storage;

namespace ResidentialConnect.Tests;

public class ProxyValidationTests
{
    [Fact]
    public void Validate_ValidProfile_ReturnsOk()
    {
        var profile = new ProxyProfile { Host = "1.2.3.4", Port = 8080, Username = "u", CountryCode = "US" };
        var result = ProxyValidation.Validate(profile, "pass");
        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(70000)]
    public void Validate_InvalidPort_Fails(int port)
    {
        var profile = new ProxyProfile { Host = "1.2.3.4", Port = port, Username = "u", CountryCode = "US" };
        var result = ProxyValidation.Validate(profile, "pass");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_MissingPassword_Fails()
    {
        var profile = new ProxyProfile { Host = "1.2.3.4", Port = 8080, Username = "u", CountryCode = "US" };
        var result = ProxyValidation.Validate(profile, "");
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Password"));
    }

    [Fact]
    public void Validate_InvalidHost_Fails()
    {
        var profile = new ProxyProfile { Host = "not a host!!", Port = 8080, Username = "u", CountryCode = "US" };
        var result = ProxyValidation.Validate(profile, "pass");
        Assert.False(result.IsValid);
    }

    [Fact]
    public void Validate_MissingCountry_Fails()
    {
        var profile = new ProxyProfile { Host = "1.2.3.4", Port = 8080, Username = "u" };
        var result = ProxyValidation.Validate(profile, "pass");
        Assert.False(result.IsValid);
    }
}

public class ProxyCsvParserTests
{
    [Fact]
    public void Parse_ValidCsv_ReturnsRows()
    {
        var csv = "1.2.3.4,8080,user1,pass1,US,New York\n5.6.7.8,1080,user2,pass2,GB,London";
        var rows = ProxyCsvParser.Parse(csv);
        Assert.Equal(2, rows.Count);
        Assert.Equal("1.2.3.4", rows[0].Ip);
        Assert.Equal("8080", rows[0].Port);
        Assert.Equal("New York", rows[0].City);
    }

    [Fact]
    public void Parse_SkipsHeaderRow()
    {
        var csv = "IP,Port,Username,Password,Country,City\n1.2.3.4,8080,user1,pass1,US,New York";
        var rows = ProxyCsvParser.Parse(csv);
        Assert.Single(rows);
        Assert.Equal("1.2.3.4", rows[0].Ip);
    }

    [Fact]
    public void Parse_IgnoresBlankLines()
    {
        var csv = "1.2.3.4,8080,u,p,US,NY\n\n5.6.7.8,1080,u2,p2,GB,London\n";
        var rows = ProxyCsvParser.Parse(csv);
        Assert.Equal(2, rows.Count);
    }
}

public class ProxyCsvImporterTests
{
    private static (ProxyCsvImporter importer, InMemoryProxyRepository repo, InMemoryCredentialStore creds) CreateImporter()
    {
        var repo = new InMemoryProxyRepository();
        var creds = new InMemoryCredentialStore();
        var logger = new NullLogger();
        return (new ProxyCsvImporter(repo, creds, logger), repo, creds);
    }

    [Fact]
    public void Import_ValidRows_CreatesProfilesAndStoresCredentialsSeparately()
    {
        var (importer, repo, creds) = CreateImporter();
        var csv = "1.2.3.4,8080,user1,secretpass1,US,New York";

        var result = importer.Import(csv);

        Assert.Equal(1, result.SuccessCount);
        var profile = repo.GetAll().Single();
        Assert.Equal("1.2.3.4", profile.Host);
        Assert.NotEqual("secretpass1", profile.CredentialRef); // credential ref is a key, not the password
        Assert.Equal("secretpass1", creds.Retrieve(profile.CredentialRef));
    }

    [Fact]
    public void Import_InvalidPort_FailsThatRowOnly()
    {
        var (importer, repo, _) = CreateImporter();
        var csv = "1.2.3.4,notaport,user1,pass1,US,New York\n5.6.7.8,1080,user2,pass2,GB,London";

        var result = importer.Import(csv);

        Assert.Equal(1, result.SuccessCount);
        Assert.Equal(1, result.FailureCount);
        Assert.Single(repo.GetAll());
    }

    [Fact]
    public void Import_MissingPassword_Fails()
    {
        var (importer, _, _) = CreateImporter();
        var csv = "1.2.3.4,8080,user1,,US,New York";

        var result = importer.Import(csv);

        Assert.Equal(0, result.SuccessCount);
        Assert.Equal(1, result.FailureCount);
    }
}

public class CredentialEncryptionTests
{
    [Fact]
    public void SaveAndRetrieve_RoundTrips()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rc-cred-test-" + Guid.NewGuid());
        var store = new FileCredentialStore(dir, new FakeReversibleProtector());
        try
        {
            var key = store.Save("cred_test", "my-secret-password");
            var retrieved = store.Retrieve(key);
            Assert.Equal("my-secret-password", retrieved);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void StoredFile_NeverContainsPlaintextPassword()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rc-cred-test-" + Guid.NewGuid());
        var store = new FileCredentialStore(dir, new FakeReversibleProtector());
        try
        {
            const string secret = "SuperSecretWebshareP@ssw0rd";
            var key = store.Save("cred_test2", secret);
            var filePath = Directory.GetFiles(dir).Single();
            var rawBytes = File.ReadAllBytes(filePath);
            var rawText = System.Text.Encoding.UTF8.GetString(rawBytes);
            Assert.DoesNotContain(secret, rawText);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Retrieve_MissingKey_ReturnsNull()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rc-cred-test-" + Guid.NewGuid());
        var store = new FileCredentialStore(dir, new FakeReversibleProtector());
        try
        {
            Assert.Null(store.Retrieve("does_not_exist"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Delete_RemovesSecret()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rc-cred-test-" + Guid.NewGuid());
        var store = new FileCredentialStore(dir, new FakeReversibleProtector());
        try
        {
            var key = store.Save("cred_test3", "value");
            store.Delete(key);
            Assert.False(store.Exists(key));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

public class ProxyTestResultTests
{
    [Fact]
    public void Successful_SetsExpectedFields()
    {
        var result = ProxyTestResult.Successful("1.2.3.4", TimeSpan.FromMilliseconds(120));
        Assert.True(result.Success);
        Assert.Equal("1.2.3.4", result.ObservedPublicIp);
        Assert.Equal(ProxyTestFailureReason.None, result.FailureReason);
    }

    [Fact]
    public void Failed_SetsExpectedFields()
    {
        var result = ProxyTestResult.Failed(ProxyTestFailureReason.AuthenticationFailed, "bad creds");
        Assert.False(result.Success);
        Assert.Equal(ProxyTestFailureReason.AuthenticationFailed, result.FailureReason);
        Assert.Equal("bad creds", result.Message);
    }
}

public class SecretScrubberTests
{
    [Fact]
    public void Scrub_RedactsPasswordKeyValue()
    {
        var scrubbed = SecretScrubber.Scrub("password=SuperSecret123 was used");
        Assert.DoesNotContain("SuperSecret123", scrubbed);
    }

    [Fact]
    public void Scrub_RedactsUriUserInfo()
    {
        var scrubbed = SecretScrubber.Scrub("Connecting to http://myuser:myPass1@proxy.example.com:8080/");
        Assert.DoesNotContain("myPass1", scrubbed);
        Assert.DoesNotContain("myuser", scrubbed);
    }
}
