using System.Globalization;
using System.Text;
using System.Windows.Data;

namespace NetCapture.Converters;

public class HexDumpConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not byte[] data || data.Length == 0)
            return string.Empty;

        var sb = new StringBuilder();
        int bytesPerLine = 16;

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            // Offset
            sb.Append($"{i:X8}  ");

            // Hex bytes
            for (int j = 0; j < bytesPerLine; j++)
            {
                if (j == 8) sb.Append(' ');

                if (i + j < data.Length)
                    sb.Append($"{data[i + j]:X2} ");
                else
                    sb.Append("   ");
            }

            sb.Append(" ");

            // ASCII
            for (int j = 0; j < bytesPerLine; j++)
            {
                if (i + j < data.Length)
                {
                    byte b = data[i + j];
                    sb.Append(b >= 0x20 && b <= 0x7E ? (char)b : '.');
                }
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
