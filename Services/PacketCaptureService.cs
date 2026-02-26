using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetCapture.Models;

namespace NetCapture.Services;

public class PacketCaptureService : IDisposable
{
    private Socket? _socket;
    private bool _isCapturing;
    private int _packetNumber;
    private CancellationTokenSource? _cts;
    private Thread? _captureThread;

    public event Action<CapturedPacket>? PacketArrived;
    public bool IsCapturing => _isCapturing;

    /// <summary>
    /// Returns all active network interfaces with IPv4 addresses.
    /// </summary>
    public static List<NetworkInterfaceInfo> GetNetworkInterfaces()
    {
        var result = new List<NetworkInterfaceInfo>();

        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up)
                continue;

            var ipProps = ni.GetIPProperties();
            foreach (var addr in ipProps.UnicastAddresses)
            {
                if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                {
                    result.Add(new NetworkInterfaceInfo
                    {
                        Name = ni.Name,
                        Description = ni.Description,
                        IpAddress = addr.Address,
                        InterfaceType = ni.NetworkInterfaceType.ToString()
                    });
                    break; // one IPv4 per interface is enough
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Start capturing packets on the specified IP address using raw sockets + SIO_RCVALL.
    /// </summary>
    public void StartCapture(IPAddress bindAddress)
    {
        if (_isCapturing) return;

        _packetNumber = 0;
        _isCapturing = true;
        _cts = new CancellationTokenSource();

        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        _socket.Bind(new IPEndPoint(bindAddress, 0));

        // SIO_RCVALL — enable promiscuous mode to receive ALL IP packets on this interface
        // Value 1 = RCVALL_ON
        _socket.IOControl(IOControlCode.ReceiveAll, BitConverter.GetBytes(1), null);
        _socket.ReceiveBufferSize = 1024 * 1024; // 1MB buffer

        _captureThread = new Thread(CaptureLoop)
        {
            IsBackground = true,
            Name = "PacketCaptureThread"
        };
        _captureThread.Start();
    }

    public void StopCapture()
    {
        if (!_isCapturing) return;
        _isCapturing = false;

        _cts?.Cancel();

        try { _socket?.Close(); } catch { }
        try { _socket?.Dispose(); } catch { }

        _socket = null;
        _cts = null;
    }

    private void CaptureLoop()
    {
        var buffer = new byte[65535];

        while (_isCapturing && _socket != null)
        {
            try
            {
                if (_cts?.IsCancellationRequested == true)
                    break;

                // Check if data is available with a timeout so we can check cancellation
                if (!_socket.Poll(500_000, SelectMode.SelectRead)) // 500ms timeout
                    continue;

                int bytesRead = _socket.Receive(buffer, 0, buffer.Length, SocketFlags.None);
                if (bytesRead > 0)
                {
                    var data = new byte[bytesRead];
                    Buffer.BlockCopy(buffer, 0, data, 0, bytesRead);

                    _packetNumber++;
                    var packet = PacketParser.Parse(data, _packetNumber, DateTime.Now);
                    PacketArrived?.Invoke(packet);
                }
            }
            catch (SocketException)
            {
                break; // Socket was closed
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch
            {
                // Skip malformed packets
            }
        }
    }

    public void Dispose()
    {
        StopCapture();
    }
}

public class NetworkInterfaceInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IPAddress IpAddress { get; set; } = IPAddress.None;
    public string InterfaceType { get; set; } = string.Empty;

    public override string ToString() => $"{Description} ({IpAddress})";
}
