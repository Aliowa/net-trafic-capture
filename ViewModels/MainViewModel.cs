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
    private bool _captureBlocked;

    [ObservableProperty]
    private ObservableCollection<CapturedPacket> _packets = new();

    [ObservableProperty]
    private CapturedPacket? _selectedPacket;

    [ObservableProperty]
    private ObservableCollection<NetworkInterfaceInfo> _networkInterfaces = new();

    [ObservableProperty]
    private NetworkInterfaceInfo? _selectedInterface;

    [ObservableProperty] private string _filterNo          = string.Empty;
    [ObservableProperty] private string _filterTime        = string.Empty;
    [ObservableProperty] private string _filterSource      = string.Empty;
    [ObservableProperty] private string _filterDestination = string.Empty;
    [ObservableProperty] private string _filterProtocol    = string.Empty;
    [ObservableProperty] private string _filterLength      = string.Empty;
    [ObservableProperty] private string _filterInfo        = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartCaptureCommand))]
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
        if (obj is not CapturedPacket packet) return false;

        if (!string.IsNullOrWhiteSpace(FilterNo) &&
            !packet.Number.ToString().Contains(FilterNo.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterTime) &&
            !packet.TimestampFormatted.Contains(FilterTime.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterSource) &&
            !packet.Source.Contains(FilterSource.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterDestination) &&
            !packet.Destination.Contains(FilterDestination.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterProtocol) &&
            !packet.Protocol.Contains(FilterProtocol.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterLength) &&
            !packet.Length.ToString().Contains(FilterLength.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(FilterInfo) &&
            !packet.Info.Contains(FilterInfo.Trim(), StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }

    private void RefreshFilter() =>
        Application.Current?.Dispatcher.Invoke(() => FilteredPackets?.Refresh());

    partial void OnFilterNoChanged(string value)          => RefreshFilter();
    partial void OnFilterTimeChanged(string value)        => RefreshFilter();
    partial void OnFilterSourceChanged(string value)      => RefreshFilter();
    partial void OnFilterDestinationChanged(string value) => RefreshFilter();
    partial void OnFilterProtocolChanged(string value)    => RefreshFilter();
    partial void OnFilterLengthChanged(string value)      => RefreshFilter();
    partial void OnFilterInfoChanged(string value)        => RefreshFilter();

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

    [RelayCommand(CanExecute = nameof(CanStartCapture))]
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
        catch (Exception)
        {
            IsCapturing = false;
            _captureBlocked = true;
            StartCaptureCommand.NotifyCanExecuteChanged();
            StatusText = "⚠ Access denied — restart the application as Administrator";
        }
    }

    private bool CanStartCapture() => !IsCapturing && !_captureBlocked;

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
            _captureBlocked = false;
            StartCaptureCommand.NotifyCanExecuteChanged();
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
