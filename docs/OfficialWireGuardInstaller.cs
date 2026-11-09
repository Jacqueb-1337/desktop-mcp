using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

// The official WireGuard MSI is verified at build time and checked against
// a known digest before the local owner's UAC-approved installer can run it.
internal static class OfficialWireGuardInstaller
{
    private const string ApprovedMsiSha256 =
        "7BFED60AD61B785C914B38B61555A975488E1D3EC472DBFB2FCDF498FCA75242";

    internal static void EnsureInstalled(string protectedFolder)
    {
        string destination=Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "WireGuard","wireguard.exe");
        if(File.Exists(destination))return;
        string path=Path.Combine(protectedFolder,
            "WireGuardBootstrap-"+Guid.NewGuid().ToString("N")+".msi");
        using(var resource=Assembly.GetExecutingAssembly().GetManifestResourceStream("wireguard-installer"))
        {
            if(resource==null||resource.Length<100000||resource.Length>33554432)
                throw new InvalidOperationException("Signed WireGuard MSI was not included in the installer.");
            using(var data=new MemoryStream())
            {
                resource.CopyTo(data);
                byte[] bytes=data.ToArray();
                using(var sha=SHA256.Create())
                {
                    var hash=BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","");
                    if(!String.Equals(hash,ApprovedMsiSha256,StringComparison.Ordinal))
                        throw new InvalidOperationException("Bundled WireGuard MSI did not match its approved digest.");
                }
                using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))
                {
                    file.Write(bytes,0,bytes.Length);
                    file.Flush(true);
                }
            }
        }
        try
        {
            string msiexec=Path.Combine(Environment.SystemDirectory,"msiexec.exe");
            var start=new ProcessStartInfo(msiexec,
                "/i \"" + path.Replace("\"","") + "\" /qn /norestart"){
                UseShellExecute=false,CreateNoWindow=true
            };
            using(var process=Process.Start(start))
            {
                if(process==null)throw new IOException("Cannot start Windows Installer.");
                if(!process.WaitForExit(180000))
                {
                    try{process.Kill();}catch{}
                    throw new TimeoutException("WireGuard MSI installation timed out.");
                }
                if(process.ExitCode!=0 && process.ExitCode!=3010)
                    throw new IOException("Official WireGuard MSI installation failed (" + process.ExitCode + ").");
            }
            if(!File.Exists(destination))
                throw new IOException("WireGuard executable not found after MSI installation.");
        }
        finally {if(File.Exists(path))File.Delete(path);}
    }
}
