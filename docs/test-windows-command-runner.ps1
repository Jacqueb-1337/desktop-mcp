# Exercise the helper's Windows job and result protocol in a disposable,
# unelevated process. The real entry point still requires UAC and confirmation.
$ErrorActionPreference='Stop'
$fixture=Join-Path $env:TEMP ('DesktopMCP-command-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
try {
    $source=Join-Path $fixture 'Smoke.cs'
    @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Web.Script.Serialization;

public static class CommandSmoke
{
    public static int Main(string[] args)
    {
        if (args.Length == 1)
        {
            using (var client = new TcpClient("127.0.0.1", int.Parse(args[0])))
            using (var stream = client.GetStream())
            using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
            {
                var request = new WindowsCommandRunner.Request {
                    command = "Write-Output 'desktop-mcp-command-smoke'; exit 7",
                    workspace = Environment.CurrentDirectory
                };
                typeof(WindowsCommandRunner).GetMethod("Execute", BindingFlags.Static | BindingFlags.NonPublic)
                    .Invoke(null, new object[] { request, client.Client, stream, writer, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 20 });
            }
            return 0;
        }
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
                ((IPEndPoint)listener.LocalEndpoint).Port.ToString()) {
                UseShellExecute = false, CreateNoWindow = true
            };
            using (var process = Process.Start(start))
            {
                try
                {
                    var accept = listener.AcceptTcpClientAsync();
                    if (!accept.Wait(5000)) throw new Exception("Worker never connected");
                    using (var peer = accept.Result)
                    using (var stream = peer.GetStream())
                    using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
                    {
                        stream.ReadTimeout = 22000;
                        int size = reader.ReadInt32();
                        if (size <= 0 || size > 10000) throw new Exception("Unexpected result length");
                        var result = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(
                            Encoding.UTF8.GetString(reader.ReadBytes(size)));
                        if ((int)result["exit_code"] != 7 ||
                            ((string)result["stdout"]).Trim() != "desktop-mcp-command-smoke" ||
                            (bool)result["truncated"])
                            throw new Exception("Unexpected PowerShell exit code or output");
                        Console.WriteLine("Windows job ran the disposable PowerShell command and returned stdout and exit code");
                    }
                }
                finally { if (!process.WaitForExit(3000)) { process.Kill(); process.WaitForExit(); } }
            }
        }
        finally { listener.Stop(); }
        return 0;
    }
}
'@ | Set-Content -LiteralPath $source -Encoding Ascii
    $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $exe=Join-Path $fixture 'smoke.exe'
    & $compiler /nologo /target:exe /platform:x64 /main:CommandSmoke /warnaserror+ /reference:System.Web.Extensions.dll "/out:$exe" $source (Join-Path $PSScriptRoot 'WindowsCommandRunner.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Command execution test build failed' }
    & $exe
    if ($LASTEXITCODE -ne 0) { throw 'Command execution test failed' }
} finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force
}
