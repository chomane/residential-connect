using System.Windows;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Client;

public partial class AddEditProxyWindow : Window
{
    public ProxyProfile Profile { get; private set; } = new();
    public string Password { get; private set; } = string.Empty;
    public bool Saved { get; private set; }

    public AddEditProxyWindow(ProxyProfile? existing = null)
    {
        InitializeComponent();
        if (existing is not null)
        {
            Profile = existing.Clone();
            NameBox.Text = Profile.Name;
            HostBox.Text = Profile.Host;
            PortBox.Text = Profile.Port.ToString();
            UsernameBox.Text = Profile.Username;
            ProtocolBox.SelectedIndex = Profile.Protocol == ProxyProtocol.Socks5 ? 1 : 0;
            CountryCodeBox.Text = Profile.CountryCode;
            CityBox.Text = Profile.City;
        }
    }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        var countryCode = CountryCodeBox.Text.Trim().ToUpperInvariant();
        Profile.Name = string.IsNullOrWhiteSpace(NameBox.Text) ? $"{countryCode} - {HostBox.Text}" : NameBox.Text.Trim();
        Profile.Host = HostBox.Text.Trim();
        _ = int.TryParse(PortBox.Text.Trim(), out var port);
        Profile.Port = port;
        Profile.Username = UsernameBox.Text.Trim();
        Profile.Protocol = ProtocolBox.SelectedIndex == 1 ? ProxyProtocol.Socks5 : ProxyProtocol.Http;
        Profile.CountryCode = countryCode;
        Profile.CountryName = CountryCatalog.GetName(countryCode);
        Profile.City = CityBox.Text.Trim();

        var password = PasswordBox.Password;
        var validation = ProxyValidation.Validate(Profile, password);
        if (!validation.IsValid)
        {
            ErrorText.Text = string.Join(" ", validation.Errors);
            return;
        }

        Password = password;
        Saved = true;
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        Saved = false;
        DialogResult = false;
        Close();
    }
}
