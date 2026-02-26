using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetCapture.Models;
using NetCapture.Services;

namespace NetCapture.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly PacketCaptureService _captureService;
    private readonly object _packetsLock = new();

    [ObservableProperty]
    private ObservableCollection<CapturedPacket> _packets = new();

    [ObservableProperty]
    private CapturedPacket? _selectedPacket;

    [ObservableProperty]
    private ObservableCollection<NetworkInterfaceInfo> _networkInterfaces = new();

    [ObservableProperty]
    private NetworkInterfaceInfo? _selectedInterface;

    [ObservableProperty]
    private string _filterText = string.Empty;

    [ObservableProperty]
    private bool _isCapturing;

    [ObservableProperty]
    private int _packetCount;

    [ObservableProperty]
    private string _statusText = "Ready";

    private ICollectionView? _filteredView;
    public ICollectionView? FilteredPackets
    {
        get => _filteredView;
        private set => SetProperty(ref _filteredView, value);
    }

    public MainViewModel()
    {
        _captureService = new PacketCaptureService();
        _captureService.PacketArrived += OnPacketArrived;

        BindingOperations.EnableCollectionSynchronization(Packets, _packetsLock);
        SetupFilteredView();
        LoadInterfaces();
    }

    private void SetupFilteredView()
    {
        FilteredPackets = CollectionViewSource.GetDefaultView(Packets);
        FilteredPackets.Filter = PacketFilter;
    }

    private bool PacketFilter(object obj)
    {
        if (string.IsNullOrWhiteSpace(FilterText)) return true;
        if (obj is not CapturedPacket packet) return false;

        var filter = FilterText.Trim().ToLowerInvariant();

        if (packet.Protocol.Equals(filter, StringComparison.OrdinalIgnoreCase))
            return true;

        if (packet.Source.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
            packet.Destination.Contains(filter, StringComparison.OrdinalIgnoreCase))
            return true;

        if (packet.Info.Contains(filter, StringComparison.OrdinalIgnoreCase))
            return true;

        if (packet.Number.ToString().Contains(filter))
            return true;

        return false;
    }

    partial void OnFilterTextChanged(string value)
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            FilteredPackets?.Refresh();
        });
    }

    private void LoadInterfaces()
    {
        try
        {
            var interfaces = PacketCaptureService.GetNetworkInterfaces();
            foreach (var iface in interfaces)
            {
                NetworkInterfaces.Add(iface);
            }

            if (NetworkInterfaces.Count > 0)
                SelectedInterface = NetworkInterfaces[0];
        }
        catch (Exception ex)
        {
            StatusText = $"Error loading interfaces: {ex.Message}";
        }
    }

    [RelayCommand]
    private void StartCapture()
    {
        if (SelectedInterface == null)
        {
            StatusText = "Please select a network interface";
            return;
        }

        try
        {
            _captureService.StartCapture(SelectedInterface.IpAddress);
            IsCapturing = true;
            StatusText = $"Capturing on {SelectedInterface.Description} ({SelectedInterface.IpAddress})...";
        }
        catch (Exception ex)
        {
            IsCapturing = false;
            StatusText = $"Error: {ex.Message}. Run as Administrator!";
        }
    }

    [RelayCommand]
    private void StopCapture()
    {
        try
        {
            _captureService.StopCapture();
            IsCapturing = false;
            StatusText = $"Capture stopped. {PacketCount} packets captured.";
        }
        catch (Exception ex)
        {
            StatusText = $"Error stopping capture: {ex.Message}";
        }
    }

    [RelayCommand]
    private void ClearCapture()
    {
        if (IsCapturing)
            StopCapture();

        Application.Current?.Dispatcher.Invoke(() =>
        {
            lock (_packetsLock)
            {
                Packets.Clear();
            }
            PacketCount = 0;
            SelectedPacket = null;
            StatusText = "Cleared";
        });
    }

    private void OnPacketArrived(CapturedPacket packet)
    {
        Application.Current?.Dispatcher.BeginInvoke(() =>
        {
            lock (_packetsLock)
            {
                Packets.Add(packet);
            }
            PacketCount = Packets.Count;
        });
    }

    public void Dispose()
    {
        _captureService.Dispose();
    }
}
