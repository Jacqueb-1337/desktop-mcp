using System;
using System.IO;

internal static class GatewayEndpointTests
{
    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
    }

    private static void Reject(string text)
    {
        try
        {
            GatewayEndpoint.Parse(text);
        }
        catch (ArgumentException) { return; }
        throw new Exception("Should reject endpoint: " + text);
    }

    public static void Main()
    {
        Assert(GatewayEndpoint.Parse("203.0.113.10").Display == "203.0.113.10:51820", "Default port");
        Assert(GatewayEndpoint.Parse("nas.example.org:51515").Display == "nas.example.org:51515", "DNS port");
        Assert(GatewayEndpoint.Parse("[2001:db8::5]:51820").Display == "[2001:db8::5]:51820", "IPv6 port");
        Reject("");
        Reject("127.0.0.1");
        Reject("0.0.0.0");
        Reject("localhost/path");
        Reject("203.0.113.10:0");
        Reject("nas.example.org:65536");
        Reject("server.example.com;rm");
        Reject("myhost@evil.test");

        string temp = Path.Combine(Path.GetTempPath(), "DesktopMCP-endpoint-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var selected = GatewayEndpoint.Parse("203.0.113.10:51820");
            selected.SaveNew(temp);
            var first = GatewayEndpoint.Load(temp);
            var second = GatewayEndpoint.Load(temp);
            Assert(first != null && first.Display == "203.0.113.10:51820", "Saved setting");
            Assert(second != null && second.Display == first.Display, "Upgrade reuse");
            bool overwriteRejected = false;
            try { GatewayEndpoint.Parse("another.example.org").SaveNew(temp); }
            catch (IOException) { overwriteRejected = true; }
            Assert(overwriteRejected, "Existing gateway should not be replaced");
            string data = File.ReadAllText(Path.Combine(temp, GatewayEndpoint.FileName));
            Assert(data.Contains("203.0.113.10"), "Persisted JSON");
            Assert(!data.Contains("private_key") && !data.Contains("token"), "No credentials in endpoint");
            Console.WriteLine("PASS: address validation, persistence, reload, no overwrite.");
        }
        finally { Directory.Delete(temp, true); }
    }
}
