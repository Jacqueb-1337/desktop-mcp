using System;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;

// Stores only the public network locator. WireGuard and gateway trust credentials
// are separate and must be provisioned through an authenticated enrollment flow.
internal sealed class GatewayEndpoint
{
    internal const int DefaultUdpPort = 51820;
    internal const string FileName = "gateway-endpoint.json";
    internal readonly string Host;
    internal readonly int UdpPort;

    internal GatewayEndpoint(string host, int udpPort)
    {
        Host = host;
        UdpPort = udpPort;
    }

    internal static GatewayEndpoint Parse(string raw)
    {
        if (raw == null) throw new ArgumentException("Enter the gateway IP address or hostname.");
        string value = raw.Trim();
        if (value.Length == 0 || value.Length > 260 ||
            value.IndexOfAny(new char[] { '/', '\\', '@', '#', '?', '\r', '\n', '\t', ' ' }) >= 0)
            throw new ArgumentException("Enter only a valid IP address or DNS hostname, optionally followed by :port.");

        string host = value;
        int port = DefaultUdpPort;
        string portPart = null;
        if (value.StartsWith("[", StringComparison.Ordinal))
        {
            int close = value.IndexOf(']');
            if (close <= 1) throw new ArgumentException("Invalid bracketed IPv6 address.");
            host = value.Substring(1, close - 1);
            string after = value.Substring(close + 1);
            if (after.Length > 0)
            {
                if (!after.StartsWith(":", StringComparison.Ordinal))
                    throw new ArgumentException("Invalid port after IPv6 address.");
                portPart = after.Substring(1);
            }
            IPAddress parsed;
            if (!IPAddress.TryParse(host, out parsed) ||
                parsed.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                throw new ArgumentException("Invalid IPv6 address.");
        }
        else
        {
            int colon = value.LastIndexOf(':');
            if (colon >= 0 && value.IndexOf(':') == colon)
            {
                host = value.Substring(0, colon);
                portPart = value.Substring(colon + 1);
            }
            // Unbracketed IPv6 is accepted only when it parses as a complete address.
        }

        if (portPart != null && (!Int32.TryParse(portPart, out port) || port < 1 || port > 65535))
            throw new ArgumentException("Gateway UDP port must be between 1 and 65535.");

        IPAddress address;
        if (IPAddress.TryParse(host, out address))
        {
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
                IPAddress.IsLoopback(address) || address.IsIPv6Multicast)
                throw new ArgumentException("Choose a reachable gateway address, not loopback or an unspecified address.");
            host = address.ToString();
        }
        else
        {
            if (Uri.CheckHostName(host) != UriHostNameType.Dns || host.Length > 253 ||
                host.StartsWith("-", StringComparison.Ordinal) ||
                host.EndsWith("-", StringComparison.Ordinal) ||
                host.IndexOf("..", StringComparison.Ordinal) >= 0)
                throw new ArgumentException("Invalid gateway hostname.");
            host = host.ToLowerInvariant().TrimEnd('.');
        }
        return new GatewayEndpoint(host, port);
    }

    internal string Display
    {
        get
        {
            return (Host.IndexOf(':') >= 0 ? "[" + Host + "]" : Host) + ":" + UdpPort;
        }
    }

    internal static GatewayEndpoint Load(string privateStateDir)
    {
        string path = Path.Combine(privateStateDir, FileName);
        if (!File.Exists(path)) return null;
        var info = new FileInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0 || info.Length > 4096)
            throw new InvalidDataException("Saved gateway endpoint is invalid.");
        var data = new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string, object>>(File.ReadAllText(path));
        if (data == null || !data.ContainsKey("version") ||
            Convert.ToInt32(data["version"]) != 1 || !data.ContainsKey("host") || !data.ContainsKey("udp_port"))
            throw new InvalidDataException("Saved gateway configuration has an unsupported format.");
        string savedHost = Convert.ToString(data["host"]);
        string savedHostAndPort = (savedHost.IndexOf(':') >= 0 ? "[" + savedHost + "]" : savedHost) + ":" + Convert.ToString(data["udp_port"]);
        var endpoint = Parse(savedHostAndPort);
        return endpoint;
    }

    internal void SaveNew(string privateStateDir)
    {
        if (!Directory.Exists(privateStateDir))
            throw new DirectoryNotFoundException("Private Desktop MCP state must exist before saving its gateway endpoint.");
        string path = Path.Combine(privateStateDir, FileName);
        var content = new JavaScriptSerializer().Serialize(new { version = 1, host = Host, udp_port = UdpPort });
        using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var writer = new StreamWriter(file))
            writer.Write(content);
    }

    internal static GatewayEndpoint Prompt()
    {
        using (var dialog = new Form
        {
            Text = "Desktop MCP gateway",
            Width = 535,
            Height = 215,
            StartPosition = FormStartPosition.CenterScreen,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false
        })
        {
            var intro = new Label {
                Left = 14, Top = 14, Width = 490, Height = 39,
                Text = "Enter the public IP address or DNS hostname of your gateway. This setting is saved and reused on future updates."
            };
            var input = new TextBox { Left = 14, Top = 60, Width = 490, Text = "" };
            var hint = new Label { Left = 14, Top = 90, Width = 490, Height = 23,
                Text = "Example: 203.0.113.10:51820 (UDP port defaults to 51820)" };
            var next = new Button { Left = 310, Top = 124, Width = 95, Text = "Continue" };
            var cancel = new Button { Left = 412, Top = 124, Width = 95,
                Text = "Cancel", DialogResult = DialogResult.Cancel };
            GatewayEndpoint chosen = null;
            next.Click += (sender, args) => {
                try { chosen = Parse(input.Text); dialog.DialogResult = DialogResult.OK; dialog.Close(); }
                catch (ArgumentException error) { MessageBox.Show(error.Message, "Gateway address", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            };
            dialog.Controls.AddRange(new Control[] { intro, input, hint, next, cancel });
            dialog.AcceptButton = next;
            dialog.CancelButton = cancel;
            input.Select();
            return dialog.ShowDialog() == DialogResult.OK ? chosen : null;
        }
    }
}
