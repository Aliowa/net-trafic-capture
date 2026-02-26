using System.Collections.ObjectModel;

namespace NetCapture.Models;

public class PacketDetailNode
{
    public string Label { get; set; } = string.Empty;
    public ObservableCollection<PacketDetailNode> Children { get; set; } = new();

    public PacketDetailNode() { }

    public PacketDetailNode(string label)
    {
        Label = label;
    }

    public PacketDetailNode(string label, IEnumerable<PacketDetailNode> children)
    {
        Label = label;
        Children = new ObservableCollection<PacketDetailNode>(children);
    }
}
