using System.Windows;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Common;
using ResidentialConnect.Core.Models;

namespace ResidentialConnect.Client;

/// <summary>
/// Main screen: shows the selected proxy's country/city/flag, connection
/// status, current public IP, latency, and exposes the Browser Only / Whole
/// Computer mode selector plus CONNECT/DISCONNECT and OPEN BROWSER. All heavy
/// lifting (proxy testing, browser launching, whole-computer routing) is
/// delegated to the Core abstractions injected via <see cref="App"/>'s
/// composition root, keeping this code-behind a thin presentation layer.
/// </summary>
public partial class MainWindow : Window
{
    private readonly IProxyRepository _repository;
    private readonly IConnectionManager _connectionManager;
    private readonly IBrowserLauncher _browserLauncher;
    private readonly ISystemTrafficRouter? _trafficRouter;

    private ProxyProfile? _selectedProfile;

    public MainWindow(
        IProxyRepository repository,
        IConnectionManager connectionManager,
        IBrowserLauncher browserLauncher,
        ISystemTrafficRouter? trafficRouter = null)
    {
        InitializeComponent();
        _repository = repository;
        _connectionManager = connectionManager;
        _browserLauncher = browserLauncher;
        _trafficRouter = trafficRouter;

        _connectionManager.StateChanged += (_, state) => Dispatcher.Invoke(() => RenderState(state));

        ReloadProxies();
        UpdateModeHint();
    }

    private ConnectionMode SelectedMode => WholeComputerRadio.IsChecked == true
        ? ConnectionMode.WholeComputer
        : ConnectionMode.BrowserOnly;

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

        // Lock the mode selector while a connection is active/in-flight -
        // switching modes mid-session is not supported; the user must
        // DISCONNECT first (see docs/ARCHITECTURE.md "Mode switching").
        var modeLocked = state.Status is ConnectionStatus.Connected or ConnectionStatus.Connecting or ConnectionStatus.Disconnecting;
        BrowserOnlyRadio.IsEnabled = !modeLocked;
        WholeComputerRadio.IsEnabled = !modeLocked && (_trafficRouter?.IsSupported ?? false);

        if (state.Mode == ConnectionMode.WholeComputer && state.RoutingStatus == SystemRoutingStatus.FailedClosed)
        {
            ModeHintText.Text = "Whole Computer routing failed - traffic is being BLOCKED (fail-closed), not sent over your real connection. Disconnect and try again.";
        }
        else
        {
            UpdateModeHint();
        }
    }

    private void ModeRadio_Checked(object sender, RoutedEventArgs e)
    {
        UpdateModeHint();
    }

    private void UpdateModeHint()
    {
        if (ModeHintText is null)
        {
            // Fires once during InitializeComponent, before the field
            // assignment in the constructor completes - nothing to update yet.
            return;
        }

        if (SelectedMode != ConnectionMode.WholeComputer)
        {
            ModeHintText.Text = "";
            return;
        }

        if (_trafficRouter is null || !_trafficRouter.IsSupported)
        {
            ModeHintText.Text = "Whole Computer mode requires running Residential Connect as Administrator on Windows.";
        }
        else
        {
            ModeHintText.Text = "Whole Computer mode routes ALL TCP applications (e.g. Telegram Desktop) through the selected proxy. TCP only - plain UDP (e.g. games, some DNS) is not proxied; DNS queries are blocked rather than leaked.";
        }
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

        var mode = SelectedMode;
        if (mode == ConnectionMode.WholeComputer && (_trafficRouter is null || !_trafficRouter.IsSupported))
        {
            MessageBox.Show(
                this,
                "Whole Computer mode requires running Residential Connect as Administrator on Windows. Restart the app elevated, or use Browser Only mode.",
                "Whole Computer mode unavailable");
            return;
        }

        await _connectionManager.ConnectAsync(_selectedProfile, mode);
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
