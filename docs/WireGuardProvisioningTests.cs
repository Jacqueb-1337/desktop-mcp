using System;
using System.Linq;
using System.Text;

internal static class WireGuardProvisioningTests
{
    private static void Check(bool condition, string title)
    {
        if (!condition) throw new Exception(title);
    }

    private static void Reject(Action action, string title)
    {
        try { action(); }
        catch (ArgumentException) { return; }
        throw new Exception("Expected validation failure: " + title);
    }

    private static string Key(int offset)
    {
        byte[] key = new byte[32];
        for (int i = 0; i < key.Length; i++) key[i] = (byte)(i + offset);
        return Convert.ToBase64String(key);
    }

    public static void Main()
    {
        var ep = GatewayEndpoint.Parse("gateway.example.org:51820");
        var own = Key(1);
        var server = Key(25);
        string config = WireGuardProvisioning.BuildTunnelConfig(
            ep, own, server, "10.93.42.2", "10.93.42.1");
        Check(config.Contains("Endpoint = gateway.example.org:51820"), "Correct public UDP endpoint");
        Check(config.Contains("Address = 10.93.42.2/32"), "Strict private client address");
        Check(config.Contains("AllowedIPs = 10.93.42.1/32"), "Only gateway accessible");
        Check(config.Contains("PublicKey = " + server), "Pinned server identity");
        Check(config.Contains("PrivateKey = " + own), "Private key in restricted config");
        Check(!config.Contains("0.0.0.0/0") && !config.Contains("DNS ="), "Never routes general traffic");
        Reject(() => WireGuardProvisioning.BuildTunnelConfig(ep, own, server, "10.93.42.1", "10.93.42.1"), "Identical addresses");
        Reject(() => WireGuardProvisioning.BuildTunnelConfig(ep, own, server, "127.0.0.1", "10.93.42.1"), "Loopback");
        Reject(() => WireGuardProvisioning.BuildTunnelConfig(ep, own, server, "10.93.42.2", "239.0.0.1"), "Multicast");
        Reject(() => WireGuardProvisioning.BuildTunnelConfig(ep, own, "", "10.93.42.2", "10.93.42.1"), "Missing server key");
        Reject(() => WireGuardProvisioning.BuildTunnelConfig(ep, own, "wireguard", "10.93.42.2", "10.93.42.1"), "Malformed server key");
        Reject(() => WireGuardProvisioning.BuildTunnelConfig(ep, new string('A',44), server, "10.93.42.2", "10.93.42.1"), "Invalid private key");
        Console.WriteLine("PASS: narrow WireGuard route, pinned peer, address/key validation.");
    }
}
