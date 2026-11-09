using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

// Assumes the official, signed WireGuard Windows tools have been installed.
// Gateway identity must be confirmed independently. The public endpoint alone
// never authorizes a peer or defines trust.
internal static class WireGuardProvisioning
{
    internal const string TunnelName = "DesktopMCP";
    internal const string ConfigName = "DesktopMCP.conf";
    internal const string PeerPrivateFile = "peer-private.key";
    internal const string PeerPublicFile = "peer-public.key";

    internal static string ValidateKey(string input)
    {
        string key = (input ?? "").Trim();
        if (key.Length != 44 || !Regex.IsMatch(key, @"\A[A-Za-z0-9+/]{43}=\z"))
            throw new ArgumentException("WireGuard requires a 32-byte base64 public or private key.");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(key); }
        catch (FormatException) { throw new ArgumentException("Invalid WireGuard key encoding."); }
        if (bytes.Length != 32) throw new ArgumentException("Invalid WireGuard key size.");
        bool nonzero = false;
        foreach (byte value in bytes) nonzero |= value != 0;
        if (!nonzero) throw new ArgumentException("An all-zero WireGuard key is invalid.");
        return key;
    }

    internal static IPAddress ValidateAddress(string text)
    {
        IPAddress ip;
        if (!IPAddress.TryParse(text, out ip) ||
            ip.AddressFamily != AddressFamily.InterNetwork ||
            ip.Equals(IPAddress.Any) || IPAddress.IsLoopback(ip) ||
            ip.IsIPv6Multicast || ip.GetAddressBytes()[0] >= 224)
            throw new ArgumentException("The WireGuard private tunnel address must be an IPv4 unicast address.");
        return ip;
    }

    internal static string BuildTunnelConfig(
        GatewayEndpoint endpoint, string clientPrivateKey, string serverPublicKey,
        string clientTunnelAddress, string serverTunnelAddress)
    {
        if (endpoint == null) throw new ArgumentNullException("endpoint");
        string client = ValidateKey(clientPrivateKey);
        string server = ValidateKey(serverPublicKey);
        IPAddress own = ValidateAddress(clientTunnelAddress);
        IPAddress remote = ValidateAddress(serverTunnelAddress);
        if (own.Equals(remote))
            throw new ArgumentException("Client and gateway tunnel addresses must be different.");
        string address = endpoint.Display;
        // A narrow /32 is required: never route the owner's normal traffic
        // through this tunnel or make the Windows PC a general VPN gateway.
        return "[Interface]\r\n" +
               "PrivateKey = " + client + "\r\n" +
               "Address = " + own + "/32\r\n\r\n" +
               "[Peer]\r\n" +
               "PublicKey = " + server + "\r\n" +
               "AllowedIPs = " + remote + "/32\r\n" +
               "Endpoint = " + address + "\r\n" +
               "PersistentKeepalive = 25\r\n";
    }

    internal static void SecureDirectory(string directory)
    {
        string full = Path.GetFullPath(directory);
        if (Directory.Exists(full))
        {
            if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Refusing a redirected WireGuard state folder.");
            // Verify no non-administrator has write access, including through
            // inherited ACLs. Never alter or replace an unsafe existing folder.
            DirectorySecurity existing = Directory.GetAccessControl(full);
            foreach (FileSystemAccessRule entry in existing.GetAccessRules(
                true, true, typeof(SecurityIdentifier)))
            {
                if (entry.AccessControlType != AccessControlType.Allow) continue;
                string sid = entry.IdentityReference.Value;
                if (sid == "S-1-5-18" || sid == "S-1-5-32-544") continue;
                const FileSystemRights danger = FileSystemRights.Write |
                    FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles |
                    FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
                if ((entry.FileSystemRights & danger) != 0)
                    throw new UnauthorizedAccessException("Untrusted write access to protected WireGuard state.");
            }
            return;
        }
        DirectorySecurity security = new DirectorySecurity();
        security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        security.SetAccessRuleProtection(true, false);
        foreach (SecurityIdentifier sid in new [] {
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(sid,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        Directory.CreateDirectory(full, security);
    }

    // This returns only the peer PUBLIC key; the private key is never used as
    // a process argument, put into user settings, or printed by the installer.
    // Existing keys are preserved. Only a local elevated installer may call it.
    internal static string GenerateOrReadPeer(string wireguardExe, string privateDirectory)
    {
        SecureDirectory(privateDirectory);
        string privatePath = Path.Combine(privateDirectory, PeerPrivateFile);
        string publicPath = Path.Combine(privateDirectory, PeerPublicFile);
        if (File.Exists(privatePath) != File.Exists(publicPath))
            throw new InvalidDataException("Incomplete WireGuard peer state. Refusing to replace its identity.");
        if (File.Exists(privatePath))
        {
            string publicKey = ValidateKey(File.ReadAllText(publicPath));
            ValidateKey(File.ReadAllText(privatePath));
            return publicKey;
        }
        string wg = Path.Combine(Path.GetDirectoryName(wireguardExe), "wg.exe");
        if (!File.Exists(wg) || !File.Exists(wireguardExe))
            throw new FileNotFoundException("Official WireGuard Windows tools are required.");
        string secret = RunWg(wg, "genkey", null);
        secret = ValidateKey(secret);
        string publicResult = ValidateKey(RunWg(wg, "pubkey", secret + "\n"));
        try
        {
            WriteNew(privatePath, secret + "\n");
            WriteNew(publicPath, publicResult + "\n");
        }
        catch
        {
            // Never silently generate a different key on partial failure.
            throw;
        }
        return publicResult;
    }

    internal static void SaveNewTunnelConfig(string path, string configuration)
    {
        if (File.Exists(path))
            throw new IOException("Existing WireGuard tunnel is preserved. Explicit reprovisioning is required.");
        string dir = Path.GetDirectoryName(Path.GetFullPath(path));
        SecureDirectory(dir);
        WriteNew(path, configuration);
    }

    private static void WriteNew(string path, string contents)
    {
        using (FileStream file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (StreamWriter writer = new StreamWriter(file, new UTF8Encoding(false)))
            writer.Write(contents);
    }

    private static string RunWg(string executable, string operation, string stdin)
    {
        ProcessStartInfo info = new ProcessStartInfo(executable, operation) {
            UseShellExecute = false,
            RedirectStandardInput = stdin != null,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using (Process process = Process.Start(info))
        {
            if (process == null) throw new IOException("Cannot launch WireGuard tools.");
            if (stdin != null) { process.StandardInput.Write(stdin); process.StandardInput.Close(); }
            string stdout = process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            if (!process.WaitForExit(10000)) {
                process.Kill();
                throw new TimeoutException("WireGuard tool did not exit.");
            }
            if (process.ExitCode != 0)
                throw new IOException("WireGuard key generation failed.");
            return stdout.Trim();
        }
    }
}
