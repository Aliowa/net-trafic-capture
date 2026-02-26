using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace NetCapture.Converters;

public class ProtocolColorConverter : IValueConverter
{
    // Wireshark-inspired color scheme
    private static readonly Dictionary<string, (Color Background, Color Foreground)> ProtocolColors = new()
    {
        { "TCP",    (Color.FromRgb(231, 230, 255), Color.FromRgb(40, 40, 80)) },
        { "HTTP",   (Color.FromRgb(228, 255, 199), Color.FromRgb(30, 60, 30)) },
        { "TLS",    (Color.FromRgb(210, 235, 255), Color.FromRgb(30, 50, 80)) },
        { "UDP",    (Color.FromRgb(218, 238, 255), Color.FromRgb(30, 50, 80)) },
        { "DNS",    (Color.FromRgb(218, 238, 255), Color.FromRgb(30, 50, 80)) },
        { "ARP",    (Color.FromRgb(250, 240, 215), Color.FromRgb(80, 60, 20)) },
        { "ICMP",   (Color.FromRgb(252, 224, 255), Color.FromRgb(80, 30, 80)) },
        { "ICMPv6", (Color.FromRgb(252, 224, 255), Color.FromRgb(80, 30, 80)) },
    };

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var protocol = value as string ?? "";
        var isBackground = parameter as string == "Background";

        if (ProtocolColors.TryGetValue(protocol, out var colors))
        {
            var c = isBackground ? colors.Background : colors.Foreground;
            return new SolidColorBrush(c);
        }

        return isBackground
            ? new SolidColorBrush(Color.FromRgb(255, 255, 255))
            : new SolidColorBrush(Color.FromRgb(40, 40, 40));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
