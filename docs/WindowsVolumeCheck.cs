using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyTitle("Desktop MCP Windows volume check")]
[assembly: AssemblyProduct("Desktop MCP")]

internal static class WindowsVolumeCheck
{
    const uint ReadAccess = 0x80000000;
    const uint ShareReadWrite = 3;
    const uint OpenExisting = 3;
    const uint IsVolumeDirty = 0x00090078;
    const uint VolumeIsDirty = 1;

    static int Main(string[] args)
    {
        ushort port;
        long expires;
        if (args.Length != 3 ||
            !UInt16.TryParse(args[0], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port == 0 ||
            !Regex.IsMatch(args[1], @"\A[a-f0-9]{64}\z") ||
            !Int64.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out expires))
            return 2;
        if (!ValidDeadline(expires))
            return 3;
        using (var identity = WindowsIdentity.GetCurrent())
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                return 5;

        try
        {
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                client.SendTimeout = 3000;
                client.ReceiveTimeout = 3000;
                client.Connect(IPAddress.Loopback, port);
                using (var stream = client.GetStream())
                {
                    var proof = Encoding.ASCII.GetBytes(args[1]);
                    stream.Write(proof, 0, proof.Length);
                    if (stream.ReadByte() != 1 || !ValidDeadline(expires))
                        return 3;
                    stream.WriteByte(VolumeStatus());
                }
            }
            return 0;
        }
        catch (SocketException) { return 4; }
        catch (IOException) { return 4; }
    }

    static bool ValidDeadline(long expires)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return now < expires && expires - now <= 120;
    }

    static byte VolumeStatus()
    {
        string root = Path.GetPathRoot(Environment.SystemDirectory);
        if (root == null || !Regex.IsMatch(root, @"\A[A-Za-z]:\\\z"))
            return 2;
        using (var volume = CreateFile(@"\\.\" + root.Substring(0, 2), ReadAccess,
            ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero))
        {
            uint flags, written;
            if (volume.IsInvalid || !DeviceIoControl(volume, IsVolumeDirty, IntPtr.Zero, 0,
                out flags, sizeof(uint), out written, IntPtr.Zero) || written != sizeof(uint))
                return 2;
            return (flags & VolumeIsDirty) == 0 ? (byte)0 : (byte)1;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle handle, uint code, IntPtr input,
        uint inputSize, out uint output, uint outputSize, out uint written, IntPtr overlapped);
}
