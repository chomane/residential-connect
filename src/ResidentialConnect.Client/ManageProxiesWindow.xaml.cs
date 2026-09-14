using System.Windows;
using Microsoft.Win32;
using ResidentialConnect.Core.Abstractions;
using ResidentialConnect.Core.Models;
using ResidentialConnect.Proxy.Csv;
using ResidentialConnect.Proxy;
using ResidentialConnect.Security.Storage;

namespace ResidentialConnect.Client;

/// <summary>Add/Edit/Delete/Select/Test/Import UI for proxy profiles, backed by IProxyRepository.</summary>
public partial class ManageProxiesWindow : Window
{
    private readonly IProxyRepository _repository;
    private readonly ICredentialStore _credentialStore;
    private readonly IProxyConnectivityTester _tester;

    public ManageProxiesWindow(IProxyRepository repository)
    {
        InitializeComponent();
        _repository = repository;
        _credentialStore = App.Services.CredentialStore;
        _tester = App.Services.ConnectivityTester;
        Reload();
    }

    private void Reload() => ProxyGrid.ItemsSource = _repository.GetAll();

    private ProxyProfile? Selected => ProxyGrid.SelectedItem as ProxyProfile;

    private void ProxyGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) { }

    private void AddProxy_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new AddEditProxyWindow { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Saved)
        {
            var key = CredentialKeyFactory.NewKey();
            _credentialStore.Save(key, dialog.Password);
            dialog.Profile.CredentialRef = key;
            _repository.Add(dialog.Profile);
            Reload();
        }
    }

    private void EditProxy_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is null) return;
        var dialog = new AddEditProxyWindow(Selected) { Owner = this };
        if (dialog.ShowDialog() == true && dialog.Saved)
        {
            if (!string.IsNullOrEmpty(dialog.Password))
            {
                var key = string.IsNullOrEmpty(dialog.Profile.CredentialRef) ? CredentialKeyFactory.NewKey() : dialog.Profile.CredentialRef;
                _credentialStore.Save(key, dialog.Password);
                dialog.Profile.CredentialRef = key;
            }
            _repository.Update(dialog.Profile);
            Reload();
        }
    }

    private void DeleteProxy_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is null) return;
        if (MessageBox.Show(this, $"Delete '{Selected.Name}'?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
        {
            _repository.Delete(Selected.Id);
            Reload();
        }
    }

    private void SelectProxy_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is null) return;
        _repository.SetSelected(Selected.Id);
        StatusMessage.Text = $"Selected '{Selected.Name}'.";
    }

    private async void TestProxy_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is null) return;
        StatusMessage.Text = "Testing...";
        var result = await _tester.TestAsync(Selected);
        StatusMessage.Text = result.Success
            ? $"OK: {result.ObservedPublicIp} ({result.Latency?.TotalMilliseconds:0}ms)"
            : $"Failed: {result.Message}";
    }

    private void ImportCsv_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*" };
        if (dialog.ShowDialog(this) == true)
        {
            var importer = new ProxyCsvImporter(_repository, _credentialStore, App.Services.Logger);
            var content = System.IO.File.ReadAllText(dialog.FileName);
            var result = importer.Import(content);
            StatusMessage.Text = $"Imported {result.SuccessCount}/{result.TotalCount} proxies.";
            Reload();
        }
    }
}
