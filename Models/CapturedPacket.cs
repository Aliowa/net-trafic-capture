using System.Collections.ObjectModel;

namespace NetCapture.Models;

public class CapturedPacket
{
    public int Number { get; set; }
    public DateTime Timestamp { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public int Length { get; set; }
    public string Info { get; set; } = string.Empty;
    public byte[] RawData { get; set; } = Array.Empty<byte>();
    public ObservableCollection<PacketDetailNode> DetailNodes { get; set; } = new();

    public string TimestampFormatted => Timestamp.ToString("HH:mm:ss.ffffff");
}
