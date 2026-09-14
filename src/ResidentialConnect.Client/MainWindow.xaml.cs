using System.Windows;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Client;

/// <summary>
/// Main screen: shows the selected proxy's country/city/flag, connection
/// status, current public IP, latency, and exposes CONNECT/DISCONNECT and
/// OPEN BROWSER. All heavy lifting (proxy testing, browser launching) is
/// delegated to the Core abstractions injected via <see cref="App"/>'s
/// composition root, keeping this code-behind a thin presentation layer.
/// </summary>
public partial class MainWindow : Window
{
    private readonly IProxyRepository _repository;
    private readonly IConnectionManager _connectionManager;
    private readonly IBrowserLauncher _browserLauncher;

    private ProxyProfile? _selectedProfile;

    public MainWindow(IProxyRepository repository, IConnectionManager connectionManager, IBrowserLauncher browserLauncher)
    {
        InitializeComponent();
        _repository = repository;
        _connectionManager = connectionManager;
        _browserLauncher = browserLauncher;

        _connectionManager.StateChanged += (_, state) => Dispatcher.Invoke(() => RenderState(state));

        ReloadProxies();
    }

    private void ReloadProxies()
    {
        var proxies = _repository.GetAll();
        ProxyComboBox.ItemsSource = proxies;

        var selectedId = _repository.GetSelectedId();
        _selectedProfile = proxies.FirstOrDefault(p => p.Id == selectedId) ?? proxies.FirstOrDefault();
        ProxyComboBox.SelectedItem = _selectedProfile;
        RenderSelectedProfile();
    }

    private void RenderSelectedProfile()
    {
        if (_selectedProfile is null)
        {
            CountryText.Text = "NO PROXY CONFIGURED";
            CityText.Text = "Add a proxy in Settings to get started.";
            FlagText.Text = "🌐";
            ConnectButton.IsEnabled = false;
            return;
        }

        FlagText.Text = CountryCatalog.ToFlagEmoji(_selectedProfile.CountryCode);
        CountryText.Text = _selectedProfile.CountryName.ToUpperInvariant();
        CityText.Text = _selectedProfile.City;
        ConnectButton.IsEnabled = true;
    }

    private void RenderState(ConnectionState state)
    {
        StatusText.Text = $"Status: {state.StatusMessage}";
        IpText.Text = state.PublicIp ?? "—";
        LatencyText.Text = state.Latency.HasValue ? $"{state.Latency.Value.TotalMilliseconds:0} ms" : "—";

        ConnectButton.Content = state.Status == ConnectionStatus.Connected ? "DISCONNECT" : "CONNECT";
        ConnectButton.IsEnabled = state.Status is not (ConnectionStatus.Connecting or ConnectionStatus.Disconnecting);
        OpenBrowserButton.IsEnabled = state.Status == ConnectionStatus.Connected;
    }

    private async void ConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (_connectionManager.CurrentState.Status == ConnectionStatus.Connected)
        {
            await _connectionManager.DisconnectAsync();
            return;
        }

        if (_selectedProfile is null)
        {
            MessageBox.Show(this, "Please add and select a proxy first (Settings / Manage Proxies).", "No proxy selected");
            return;
        }

        await _connectionManager.ConnectAsync(_selectedProfile);
    }

    private async void OpenBrowserButton_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedProfile is null)
        {
            return;
        }

        var result = await _browserLauncher.LaunchAsync(_selectedProfile, "https://api.ipify.org?format=json");
        if (!result.Success)
        {
            MessageBox.Show(this, result.Message ?? "Failed to open browser.", "Open Browser Failed");
        }
    }

    private void ManageProxiesButton_Click(object sender, RoutedEventArgs e)
    {
        var window = new ManageProxiesWindow(_repository) { Owner = this };
        window.ShowDialog();
        ReloadProxies();
    }

    private void ProxyComboBox_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        _selectedProfile = ProxyComboBox.SelectedItem as ProxyProfile;
        if (_selectedProfile is not null)
        {
            _repository.SetSelected(_selectedProfile.Id);
        }

        RenderSelectedProfile();
    }
}
