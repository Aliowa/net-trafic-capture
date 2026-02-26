using System.Collections.ObjectModel;
using System.Net;
using System.Text;
using NetCapture.Models;

namespace NetCapture.Services;

/// <summary>
/// Manual IP packet parser — parses raw IP datagrams without any external libraries.
/// Supports: IPv4, TCP, UDP, ICMP, DNS (over UDP), basic HTTP/TLS detection.
/// </summary>
public static class PacketParser
{
    public static CapturedPacket Parse(byte[] rawData, int packetNumber, DateTime timestamp)
    {
        var packet = new CapturedPacket
        {
            Number = packetNumber,
            Timestamp = timestamp,
            Length = rawData.Length,
            RawData = rawData
        };

        try
        {
            ParseIpPacket(rawData, packet);
        }
        catch
        {
            packet.Protocol = "UNKNOWN";
            packet.Info = $"{rawData.Length} bytes captured";
        }

        return packet;
    }

    private static void ParseIpPacket(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 20) { packet.Protocol = "UNKNOWN"; return; }

        int version = (data[0] >> 4) & 0xF;

        if (version == 4)
            ParseIPv4(data, packet);
        else if (version == 6)
            ParseIPv6(data, packet);
        else
        {
            packet.Protocol = "UNKNOWN";
            packet.Info = $"Unknown IP version {version}";
        }
    }

    private static void ParseIPv4(byte[] data, CapturedPacket packet)
    {
        int headerLength = (data[0] & 0x0F) * 4;
        if (data.Length < headerLength) return;

        int totalLength = (data[2] << 8) | data[3];
        int identification = (data[4] << 8) | data[5];
        int flagsAndOffset = (data[6] << 8) | data[7];
        int ttl = data[8];
        int protocol = data[9];
        int headerChecksum = (data[10] << 8) | data[11];

        var srcIp = new IPAddress(new ReadOnlySpan<byte>(data, 12, 4));
        var dstIp = new IPAddress(new ReadOnlySpan<byte>(data, 16, 4));

        packet.Source = srcIp.ToString();
        packet.Destination = dstIp.ToString();

        // IP detail node
        var ipNode = new PacketDetailNode($"Internet Protocol Version 4, Src: {srcIp}, Dst: {dstIp}");
        ipNode.Children.Add(new PacketDetailNode($"Version: 4"));
        ipNode.Children.Add(new PacketDetailNode($"Header Length: {headerLength} bytes"));
        ipNode.Children.Add(new PacketDetailNode($"Differentiated Services: 0x{data[1]:X2}"));
        ipNode.Children.Add(new PacketDetailNode($"Total Length: {totalLength}"));
        ipNode.Children.Add(new PacketDetailNode($"Identification: 0x{identification:X4} ({identification})"));

        int flags = (flagsAndOffset >> 13) & 0x7;
        int fragmentOffset = flagsAndOffset & 0x1FFF;
        ipNode.Children.Add(new PacketDetailNode($"Flags: 0x{flags:X1} (DF={(flags & 0x2) != 0}, MF={(flags & 0x1) != 0})"));
        ipNode.Children.Add(new PacketDetailNode($"Fragment Offset: {fragmentOffset}"));
        ipNode.Children.Add(new PacketDetailNode($"Time to Live: {ttl}"));
        ipNode.Children.Add(new PacketDetailNode($"Protocol: {GetProtocolName(protocol)} ({protocol})"));
        ipNode.Children.Add(new PacketDetailNode($"Header Checksum: 0x{headerChecksum:X4}"));
        ipNode.Children.Add(new PacketDetailNode($"Source Address: {srcIp}"));
        ipNode.Children.Add(new PacketDetailNode($"Destination Address: {dstIp}"));
        packet.DetailNodes.Add(ipNode);

        // Parse transport layer
        var payload = data.AsSpan(headerLength);
        switch (protocol)
        {
            case 6:  ParseTcp(payload.ToArray(), packet); break;
            case 17: ParseUdp(payload.ToArray(), packet); break;
            case 1:  ParseIcmp(payload.ToArray(), packet); break;
            case 2:  ParseIgmp(payload.ToArray(), packet); break;
            default:
                packet.Protocol = GetProtocolName(protocol);
                packet.Info = $"{packet.Length} bytes, Protocol: {protocol}";
                break;
        }
    }

    private static void ParseIPv6(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 40) return;

        int trafficClass = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
        int flowLabel = ((data[1] & 0x0F) << 16) | (data[2] << 8) | data[3];
        int payloadLength = (data[4] << 8) | data[5];
        int nextHeader = data[6];
        int hopLimit = data[7];

        var srcIp = new IPAddress(new ReadOnlySpan<byte>(data, 8, 16));
        var dstIp = new IPAddress(new ReadOnlySpan<byte>(data, 24, 16));

        packet.Source = srcIp.ToString();
        packet.Destination = dstIp.ToString();

        var ipNode = new PacketDetailNode($"Internet Protocol Version 6, Src: {srcIp}, Dst: {dstIp}");
        ipNode.Children.Add(new PacketDetailNode($"Version: 6"));
        ipNode.Children.Add(new PacketDetailNode($"Traffic Class: 0x{trafficClass:X2}"));
        ipNode.Children.Add(new PacketDetailNode($"Flow Label: 0x{flowLabel:X5}"));
        ipNode.Children.Add(new PacketDetailNode($"Payload Length: {payloadLength}"));
        ipNode.Children.Add(new PacketDetailNode($"Next Header: {GetProtocolName(nextHeader)} ({nextHeader})"));
        ipNode.Children.Add(new PacketDetailNode($"Hop Limit: {hopLimit}"));
        ipNode.Children.Add(new PacketDetailNode($"Source Address: {srcIp}"));
        ipNode.Children.Add(new PacketDetailNode($"Destination Address: {dstIp}"));
        packet.DetailNodes.Add(ipNode);

        var payload = data.AsSpan(40);
        switch (nextHeader)
        {
            case 6:  ParseTcp(payload.ToArray(), packet); break;
            case 17: ParseUdp(payload.ToArray(), packet); break;
            case 58: ParseIcmpV6(payload.ToArray(), packet); break;
            default:
                packet.Protocol = GetProtocolName(nextHeader);
                packet.Info = $"{packet.Length} bytes";
                break;
        }
    }

    private static void ParseTcp(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 20) return;

        int srcPort = (data[0] << 8) | data[1];
        int dstPort = (data[2] << 8) | data[3];
        uint seqNum = (uint)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
        uint ackNum = (uint)((data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11]);
        int dataOffset = ((data[12] >> 4) & 0xF) * 4;
        int flagsByte = ((data[12] & 0x01) << 8) | data[13];
        int windowSize = (data[14] << 8) | data[15];
        int checksum = (data[16] << 8) | data[17];
        int urgentPointer = (data[18] << 8) | data[19];

        // Parse flags
        bool fin = (flagsByte & 0x01) != 0;
        bool syn = (flagsByte & 0x02) != 0;
        bool rst = (flagsByte & 0x04) != 0;
        bool psh = (flagsByte & 0x08) != 0;
        bool ack = (flagsByte & 0x10) != 0;
        bool urg = (flagsByte & 0x20) != 0;
        bool ece = (flagsByte & 0x40) != 0;
        bool cwr = (flagsByte & 0x80) != 0;

        var flagsList = new List<string>();
        if (syn) flagsList.Add("SYN");
        if (ack) flagsList.Add("ACK");
        if (fin) flagsList.Add("FIN");
        if (rst) flagsList.Add("RST");
        if (psh) flagsList.Add("PSH");
        if (urg) flagsList.Add("URG");
        if (ece) flagsList.Add("ECE");
        if (cwr) flagsList.Add("CWR");
        string flags = flagsList.Count > 0 ? string.Join(", ", flagsList) : "None";

        int payloadLen = data.Length - dataOffset;
        if (payloadLen < 0) payloadLen = 0;

        packet.Protocol = "TCP";
        packet.Info = $"{srcPort} → {dstPort} [{flags}] Seq={seqNum} Ack={ackNum} Win={windowSize} Len={payloadLen}";

        var tcpNode = new PacketDetailNode($"Transmission Control Protocol, Src Port: {srcPort}, Dst Port: {dstPort}");
        tcpNode.Children.Add(new PacketDetailNode($"Source Port: {srcPort}"));
        tcpNode.Children.Add(new PacketDetailNode($"Destination Port: {dstPort}"));
        tcpNode.Children.Add(new PacketDetailNode($"Sequence Number: {seqNum}"));
        tcpNode.Children.Add(new PacketDetailNode($"Acknowledgment Number: {ackNum}"));
        tcpNode.Children.Add(new PacketDetailNode($"Header Length: {dataOffset} bytes"));
        tcpNode.Children.Add(new PacketDetailNode($"Flags: 0x{flagsByte:X3} ({flags})"));
        tcpNode.Children.Add(new PacketDetailNode($"Window Size: {windowSize}"));
        tcpNode.Children.Add(new PacketDetailNode($"Checksum: 0x{checksum:X4}"));
        tcpNode.Children.Add(new PacketDetailNode($"Urgent Pointer: {urgentPointer}"));
        if (payloadLen > 0)
            tcpNode.Children.Add(new PacketDetailNode($"Payload: {payloadLen} bytes"));
        packet.DetailNodes.Add(tcpNode);

        // Application layer detection
        if (payloadLen > 0 && dataOffset < data.Length)
        {
            var payload = data.AsSpan(dataOffset);
            DetectApplicationProtocol(payload.ToArray(), srcPort, dstPort, packet);
        }
    }

    private static void ParseUdp(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 8) return;

        int srcPort = (data[0] << 8) | data[1];
        int dstPort = (data[2] << 8) | data[3];
        int length = (data[4] << 8) | data[5];
        int checksum = (data[6] << 8) | data[7];

        packet.Protocol = "UDP";
        packet.Info = $"{srcPort} → {dstPort} Len={length}";

        var udpNode = new PacketDetailNode($"User Datagram Protocol, Src Port: {srcPort}, Dst Port: {dstPort}");
        udpNode.Children.Add(new PacketDetailNode($"Source Port: {srcPort}"));
        udpNode.Children.Add(new PacketDetailNode($"Destination Port: {dstPort}"));
        udpNode.Children.Add(new PacketDetailNode($"Length: {length}"));
        udpNode.Children.Add(new PacketDetailNode($"Checksum: 0x{checksum:X4}"));
        packet.DetailNodes.Add(udpNode);

        // DNS detection on port 53
        if ((srcPort == 53 || dstPort == 53) && data.Length > 20)
        {
            ParseDns(data.AsSpan(8).ToArray(), packet);
        }
        // DHCP on ports 67/68
        else if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68)
        {
            packet.Protocol = "DHCP";
            packet.Info = $"DHCP {(dstPort == 67 ? "Request" : "Reply")} {srcPort} → {dstPort}";
        }
        // mDNS on port 5353
        else if (srcPort == 5353 || dstPort == 5353)
        {
            packet.Protocol = "MDNS";
            if (data.Length > 20)
                ParseDns(data.AsSpan(8).ToArray(), packet, "MDNS");
        }
        // SSDP on port 1900
        else if (srcPort == 1900 || dstPort == 1900)
        {
            packet.Protocol = "SSDP";
            if (data.Length > 8)
            {
                var payloadStr = Encoding.ASCII.GetString(data, 8, Math.Min(data.Length - 8, 100));
                var firstLine = payloadStr.Split('\n')[0].Trim();
                packet.Info = firstLine;
            }
        }
    }

    private static void ParseIcmp(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 8) return;

        int type = data[0];
        int code = data[1];
        int checksum = (data[2] << 8) | data[3];
        int identifier = (data[4] << 8) | data[5];
        int sequence = (data[6] << 8) | data[7];

        packet.Protocol = "ICMP";
        string typeStr = type switch
        {
            0 => "Echo Reply",
            3 => "Destination Unreachable",
            4 => "Source Quench",
            5 => "Redirect",
            8 => "Echo Request",
            11 => "Time Exceeded",
            12 => "Parameter Problem",
            13 => "Timestamp Request",
            14 => "Timestamp Reply",
            _ => $"Type {type}"
        };

        packet.Info = $"{typeStr} (type={type}, code={code}), id={identifier}, seq={sequence}";

        var icmpNode = new PacketDetailNode($"Internet Control Message Protocol");
        icmpNode.Children.Add(new PacketDetailNode($"Type: {type} ({typeStr})"));
        icmpNode.Children.Add(new PacketDetailNode($"Code: {code}"));
        icmpNode.Children.Add(new PacketDetailNode($"Checksum: 0x{checksum:X4}"));
        icmpNode.Children.Add(new PacketDetailNode($"Identifier: {identifier} (0x{identifier:X4})"));
        icmpNode.Children.Add(new PacketDetailNode($"Sequence Number: {sequence}"));
        if (data.Length > 8)
            icmpNode.Children.Add(new PacketDetailNode($"Data: {data.Length - 8} bytes"));
        packet.DetailNodes.Add(icmpNode);
    }

    private static void ParseIcmpV6(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 4) return;

        int type = data[0];
        int code = data[1];
        int checksum = (data[2] << 8) | data[3];

        packet.Protocol = "ICMPv6";
        string typeStr = type switch
        {
            1 => "Destination Unreachable",
            2 => "Packet Too Big",
            3 => "Time Exceeded",
            128 => "Echo Request",
            129 => "Echo Reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => "Neighbor Solicitation",
            136 => "Neighbor Advertisement",
            _ => $"Type {type}"
        };

        packet.Info = $"{typeStr} (type={type}, code={code})";

        var icmpNode = new PacketDetailNode($"Internet Control Message Protocol v6");
        icmpNode.Children.Add(new PacketDetailNode($"Type: {type} ({typeStr})"));
        icmpNode.Children.Add(new PacketDetailNode($"Code: {code}"));
        icmpNode.Children.Add(new PacketDetailNode($"Checksum: 0x{checksum:X4}"));
        packet.DetailNodes.Add(icmpNode);
    }

    private static void ParseIgmp(byte[] data, CapturedPacket packet)
    {
        if (data.Length < 8) return;

        int type = data[0];
        packet.Protocol = "IGMP";

        string typeStr = type switch
        {
            0x11 => "Membership Query",
            0x12 => "IGMPv1 Membership Report",
            0x16 => "IGMPv2 Membership Report",
            0x17 => "Leave Group",
            0x22 => "IGMPv3 Membership Report",
            _ => $"Type 0x{type:X2}"
        };

        if (data.Length >= 8)
        {
            var groupAddr = new IPAddress(new ReadOnlySpan<byte>(data, 4, 4));
            packet.Info = $"{typeStr}, Group: {groupAddr}";
        }
        else
        {
            packet.Info = typeStr;
        }

        var igmpNode = new PacketDetailNode($"Internet Group Management Protocol");
        igmpNode.Children.Add(new PacketDetailNode($"Type: 0x{type:X2} ({typeStr})"));
        igmpNode.Children.Add(new PacketDetailNode($"Max Response Time: {data[1] * 100}ms"));
        if (data.Length >= 8)
        {
            var groupAddr = new IPAddress(new ReadOnlySpan<byte>(data, 4, 4));
            igmpNode.Children.Add(new PacketDetailNode($"Group Address: {groupAddr}"));
        }
        packet.DetailNodes.Add(igmpNode);
    }

    private static void ParseDns(byte[] data, CapturedPacket packet, string protocolName = "DNS")
    {
        if (data.Length < 12) return;

        int transactionId = (data[0] << 8) | data[1];
        int flags = (data[2] << 8) | data[3];
        bool isResponse = (flags & 0x8000) != 0;
        int questionCount = (data[4] << 8) | data[5];
        int answerCount = (data[6] << 8) | data[7];
        int authorityCount = (data[8] << 8) | data[9];
        int additionalCount = (data[10] << 8) | data[11];

        var queryName = ParseDnsName(data, 12);
        var typeStr = isResponse ? "response" : "query";

        packet.Protocol = protocolName;
        packet.Info = $"Standard query {typeStr} 0x{transactionId:X4} {queryName}";

        var dnsNode = new PacketDetailNode($"Domain Name System ({typeStr})");
        dnsNode.Children.Add(new PacketDetailNode($"Transaction ID: 0x{transactionId:X4}"));
        dnsNode.Children.Add(new PacketDetailNode($"Flags: 0x{flags:X4} ({typeStr})"));
        dnsNode.Children.Add(new PacketDetailNode($"Questions: {questionCount}"));
        dnsNode.Children.Add(new PacketDetailNode($"Answer RRs: {answerCount}"));
        dnsNode.Children.Add(new PacketDetailNode($"Authority RRs: {authorityCount}"));
        dnsNode.Children.Add(new PacketDetailNode($"Additional RRs: {additionalCount}"));
        if (!string.IsNullOrEmpty(queryName))
            dnsNode.Children.Add(new PacketDetailNode($"Name: {queryName}"));
        packet.DetailNodes.Add(dnsNode);
    }

    private static void DetectApplicationProtocol(byte[] payload, int srcPort, int dstPort, CapturedPacket packet)
    {
        // HTTP detection
        var text = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 10));
        if (text.StartsWith("GET ") || text.StartsWith("POST ") || text.StartsWith("PUT ") ||
            text.StartsWith("DELETE ") || text.StartsWith("HEAD ") || text.StartsWith("PATCH ") ||
            text.StartsWith("OPTIONS ") || text.StartsWith("HTTP/"))
        {
            packet.Protocol = "HTTP";
            var fullText = Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 200));
            var firstLine = fullText.Split('\n')[0].Trim();
            packet.Info = firstLine;

            var httpNode = new PacketDetailNode($"Hypertext Transfer Protocol");
            httpNode.Children.Add(new PacketDetailNode(firstLine));
            if (fullText.Contains("Host: "))
            {
                var hostLine = fullText.Split('\n').FirstOrDefault(l => l.Trim().StartsWith("Host:"));
                if (hostLine != null)
                    httpNode.Children.Add(new PacketDetailNode(hostLine.Trim()));
            }
            packet.DetailNodes.Add(httpNode);
            return;
        }

        // TLS detection
        if (payload.Length > 5)
        {
            byte contentType = payload[0];
            if (contentType >= 20 && contentType <= 23)
            {
                byte majorVersion = payload[1];
                byte minorVersion = payload[2];

                if ((majorVersion == 3 && minorVersion <= 4) || majorVersion == 254)
                {
                    packet.Protocol = "TLS";
                    var tlsType = contentType switch
                    {
                        20 => "Change Cipher Spec",
                        21 => "Alert",
                        22 => "Handshake",
                        23 => "Application Data",
                        _ => "Unknown"
                    };

                    string versionStr = (majorVersion, minorVersion) switch
                    {
                        (3, 0) => "SSL 3.0",
                        (3, 1) => "TLS 1.0",
                        (3, 2) => "TLS 1.1",
                        (3, 3) => "TLS 1.2",
                        (3, 4) => "TLS 1.3",
                        _ => $"Unknown ({majorVersion}.{minorVersion})"
                    };

                    int recordLen = (payload[3] << 8) | payload[4];
                    packet.Info = $"{versionStr} {tlsType}, Length {recordLen}";

                    var tlsNode = new PacketDetailNode($"Transport Layer Security");
                    tlsNode.Children.Add(new PacketDetailNode($"Content Type: {tlsType} ({contentType})"));
                    tlsNode.Children.Add(new PacketDetailNode($"Version: {versionStr}"));
                    tlsNode.Children.Add(new PacketDetailNode($"Length: {recordLen}"));

                    // Parse TLS Handshake details
                    if (contentType == 22 && payload.Length > 9)
                    {
                        byte handshakeType = payload[5];
                        string hsTypeStr = handshakeType switch
                        {
                            1 => "Client Hello",
                            2 => "Server Hello",
                            11 => "Certificate",
                            12 => "Server Key Exchange",
                            14 => "Server Hello Done",
                            16 => "Client Key Exchange",
                            _ => $"Type {handshakeType}"
                        };
                        tlsNode.Children.Add(new PacketDetailNode($"Handshake Type: {hsTypeStr} ({handshakeType})"));
                        packet.Info = $"{versionStr} Handshake: {hsTypeStr}";
                    }

                    packet.DetailNodes.Add(tlsNode);
                    return;
                }
            }
        }
    }

    private static string ParseDnsName(byte[] data, int offset)
    {
        var parts = new List<string>();
        int pos = offset;
        int maxLen = Math.Min(data.Length, offset + 255);
        int jumps = 0;

        while (pos < maxLen && jumps < 10)
        {
            if (pos >= data.Length) break;
            int len = data[pos];
            if (len == 0) break;

            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= data.Length) break;
                int pointer = ((len & 0x3F) << 8) | data[pos + 1];
                var suffix = ParseDnsName(data, pointer);
                if (!string.IsNullOrEmpty(suffix))
                    parts.Add(suffix);
                jumps++;
                break;
            }

            pos++;
            if (pos + len > data.Length) break;
            parts.Add(Encoding.ASCII.GetString(data, pos, len));
            pos += len;
        }

        return string.Join(".", parts);
    }

    private static string GetProtocolName(int protocol) => protocol switch
    {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        41 => "IPv6",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => $"Proto-{protocol}"
    };
}
