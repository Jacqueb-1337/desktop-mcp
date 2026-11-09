using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.ServiceProcess;

// Invoked only through the administrator-approved protected service installer.
// Deliberately limited to the Desktop MCP tunnel and a single /32 gateway route.
internal static class WireGuardTunnelInstaller
{
    internal const string ServiceName = "WireGuardTunnel$DesktopMCP";
    internal const string TunnelGateway = "10.93.42.1";
    private static string Quote(string input) { return "\"" + input.Replace("\"", "") + "\""; }

    internal static string EmbeddedGatewayPublicKey()
    {
        using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream("gateway-wg-public"))
        {
            if(stream==null)throw new InvalidOperationException("Verified WireGuard gateway identity was not packaged.");
            if(stream.Length==0||stream.Length>200)throw new InvalidDataException("Invalid server public key resource.");
            using(var reader=new StreamReader(stream))
                return WireGuardProvisioning.ValidateKey(reader.ReadToEnd().Trim());
        }
    }

    internal static bool TunnelServiceExists()
    {
        foreach(var item in ServiceController.GetServices())
        {
            using(item)
                if(item.ServiceName==ServiceName)return true;
        }
        return false;
    }

    private static void StartTunnel(string wireguardExecutable, string config)
    {
        var info=new ProcessStartInfo(wireguardExecutable,"/installtunnelservice " + Quote(config))
        { UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true };
        using(var process=Process.Start(info))
        {
            if(process==null)throw new IOException("Windows WireGuard executable did not start.");
            string stdout=process.StandardOutput.ReadToEnd();
            string stderr=process.StandardError.ReadToEnd();
            if(!process.WaitForExit(60000))
            {
                try{process.Kill();}catch{}
                throw new System.TimeoutException("WireGuard tunnel installation timed out.");
            }
            if(process.ExitCode!=0)
                throw new IOException("WireGuard tunnel service installation failed (" + process.ExitCode + ").");
        }
    }

    internal static string EnsureTunnel(string sourceUserState, string protectedDataRoot)
    {
        GatewayEndpoint publicEndpoint=GatewayEndpoint.Load(sourceUserState);
        if(publicEndpoint==null)
            throw new InvalidOperationException("Missing gateway address. Complete first-run gateway setup.");
        string codePath=Path.Combine(sourceUserState,"connection-code.txt");
        if(!File.Exists(codePath))throw new InvalidOperationException("Missing Desktop MCP pairing code.");
        string dm1=GatewayPeerIdentity.ValidateDm1(File.ReadAllText(codePath));
        string wireguardExe=Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"WireGuard","wireguard.exe");
        if(!File.Exists(wireguardExe))
            throw new FileNotFoundException("WireGuard is not installed; install the signed bundled MSI first.");

        string trustedServerKey=EmbeddedGatewayPublicKey();
        string keyFolder=Path.Combine(protectedDataRoot,"WireGuard");
        string publicPeerKey=WireGuardProvisioning.GenerateOrReadPeer(wireguardExe,keyFolder);
        string privatePeerKey=File.ReadAllText(Path.Combine(keyFolder,WireGuardProvisioning.PeerPrivateFile)).Trim();

        string clientIp=GatewayPeerIdentity.ClientAddress(dm1);
        string config=WireGuardProvisioning.BuildTunnelConfig(
            publicEndpoint,privatePeerKey,trustedServerKey,clientIp,TunnelGateway);
        string configPath=Path.Combine(keyFolder,WireGuardProvisioning.ConfigName);

        if(File.Exists(configPath))
        {
            // Never silently replace a tunnel, existing peer, or a manually
            // configured route while updating the Desktop MCP binaries.
            if(!String.Equals(File.ReadAllText(configPath),config,StringComparison.Ordinal))
                throw new InvalidOperationException("Existing WireGuard configuration differs. Explicit owner reprovisioning is required.");
        }
        else if(!TunnelServiceExists())
        {
            WireGuardProvisioning.SaveNewTunnelConfig(configPath,config);
        }
        if(!TunnelServiceExists())StartTunnel(wireguardExe,configPath);

        // Only public data is copied back to the owning user's state.
        string published=Path.Combine(sourceUserState,"public-wireguard-key.txt");
        if(File.Exists(published) &&
            !String.Equals(File.ReadAllText(published).Trim(),publicPeerKey,StringComparison.Ordinal))
            throw new InvalidOperationException("The existing public WireGuard identity does not match the installed tunnel.");
        if(!File.Exists(published))File.WriteAllText(published,publicPeerKey + "\n");
        return GatewayPeerIdentity.RegistrationCode(dm1,publicPeerKey);
    }
}
