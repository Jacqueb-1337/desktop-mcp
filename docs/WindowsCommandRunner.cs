using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyTitle("Desktop MCP elevated PowerShell")]
[assembly: AssemblyProduct("Desktop MCP")]

internal static class WindowsCommandRunner
{
    const int MaxOutput = 6000;
    const int MaxRequest = 16384;

    [STAThread]
    static int Main(string[] args)
    {
        ushort port;
        long expires;
        if (args.Length != 3 ||
            !UInt16.TryParse(args[0], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port == 0 ||
            !Regex.IsMatch(args[1], @"\A[a-f0-9]{64}\z") ||
            !Int64.TryParse(args[2], NumberStyles.None, CultureInfo.InvariantCulture, out expires))
            return 2;
        if (!ValidDeadline(expires)) return 3;
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
                using (var reader = new BinaryReader(stream, Encoding.UTF8, true))
                using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
                {
                    writer.Write(Encoding.ASCII.GetBytes(args[1]));
                    writer.Flush();
                    if (reader.ReadByte() != 1 || !ValidDeadline(expires)) return 3;
                    int size = reader.ReadInt32();
                    if (size <= 0 || size > MaxRequest) return 2;
                    var bytes = reader.ReadBytes(size);
                    if (bytes.Length != size) return 2;
                    var request = new JavaScriptSerializer().Deserialize<Request>(new UTF8Encoding(false, true).GetString(bytes));
                    if (request == null || String.IsNullOrWhiteSpace(request.command) ||
                        request.command.Length > 2000 || request.command.IndexOf('\0') >= 0 ||
                        String.IsNullOrEmpty(request.workspace) || !Directory.Exists(request.workspace))
                        return 2;

                    // This confirmation comes from the protected, elevated
                    // executable. The desktop agent cannot click it for the owner.
                    if (!ConfirmCommand(request, client.Client, expires) || !ValidDeadline(expires))
                    {
                        WriteResult(writer, new { error = "ADMIN_COMMAND_DECLINED_OR_EXPIRED" });
                        return 3;
                    }
                    return Execute(request, client.Client, stream, writer, expires);
                }
            }
        }
        catch (Exception) { return 4; }
    }

    static bool ConfirmCommand(Request request, Socket socket, long expires)
    {
        using (var form = new Form { Text = "Approve elevated PowerShell", Width = 680, Height = 420,
            StartPosition = FormStartPosition.CenterScreen, TopMost = true, MinimizeBox = false, MaximizeBox = false })
        {
            var location = new Label { Left = 12, Top = 12, Width = 620, Text = "Working folder: " + request.workspace };
            var command = new TextBox { Left = 12, Top = 42, Width = 635, Height = 290, Multiline = true,
                ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Text = request.command };
            var run = new Button { Left = 414, Top = 342, Width = 110, Text = "Run elevated", DialogResult = DialogResult.Yes };
            var cancel = new Button { Left = 534, Top = 342, Width = 110, Text = "Deny", DialogResult = DialogResult.No };
            form.CancelButton = cancel;
            form.Controls.AddRange(new Control[] { location, command, run, cancel });
            form.Shown += (sender, args) => cancel.Focus();
            using (var timer = new Timer { Interval = 250 })
            {
                timer.Tick += (sender, args) => {
                    if (!ValidDeadline(expires) || (socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0))
                        form.DialogResult = DialogResult.No;
                };
                timer.Start();
                return form.ShowDialog() == DialogResult.Yes;
            }
        }
    }

    static int Execute(Request request, Socket socket, NetworkStream stream, BinaryWriter writer, long expires)
    {
        using (var job = CreateJobObject(IntPtr.Zero, null))
        {
            var limits = new JobLimits();
            limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
            // Join before starting PowerShell so it inherits the job from its first instruction.
            if (job.IsInvalid || !SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(typeof(JobLimits))) ||
                !AssignProcessToJobObject(job, GetCurrentProcess()))
            {
                WriteResult(writer, new { error = "ADMIN_COMMAND_JOB_UNAVAILABLE" });
                return 4;
            }

            // EOF or unexpected control data cancels the job. Successful
            // execution writes the result before the job handle is closed.
            stream.ReadTimeout = -1;
            Task.Run(() => {
                try { stream.ReadByte(); }
                catch (IOException) {}
                TerminateJobObject(job, 3);
            });

            var shell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            var args = "-NoLogo -NoProfile -NonInteractive -EncodedCommand " +
                Convert.ToBase64String(Encoding.Unicode.GetBytes(request.command));
            var info = new ProcessStartInfo(shell, args) { WorkingDirectory = request.workspace,
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true };
            if (!ValidDeadline(expires) || (socket.Poll(0, SelectMode.SelectRead) && socket.Available == 0)) return 3;
            using (var process = Process.Start(info))
            {
                process.StandardInput.Close();
                var stdout = Capture(process.StandardOutput);
                var stderr = Capture(process.StandardError);
                int milliseconds = (int)Math.Max(0, Math.Min(120000, (expires - DateTimeOffset.UtcNow.ToUnixTimeSeconds()) * 1000));
                var timer = Stopwatch.StartNew();
                if (!process.WaitForExit(milliseconds) ||
                    !Task.WaitAll(new Task[] { stdout, stderr }, Math.Max(0, milliseconds - (int)timer.ElapsedMilliseconds)) ||
                    !ValidDeadline(expires))
                {
                    WriteResult(writer, new { error = "ADMIN_COMMAND_EXPIRED" });
                    return 3;
                }
                WriteResult(writer, new { exit_code = process.ExitCode, stdout = stdout.Result.text,
                    stderr = stderr.Result.text, truncated = stdout.Result.truncated || stderr.Result.truncated });
                return 0;
            }
        }
    }

    static void WriteResult(BinaryWriter writer, object result)
    {
        var bytes = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(result));
        writer.Write(bytes.Length);
        writer.Write(bytes);
        writer.Flush();
    }

    static async Task<Captured> Capture(StreamReader reader)
    {
        var output = new StringBuilder();
        var buffer = new char[1024];
        bool truncated = false;
        int read;
        while ((read = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            int keep = Math.Min(read, MaxOutput - output.Length);
            output.Append(buffer, 0, keep);
            truncated |= keep < read;
        }
        return new Captured { text = output.ToString(), truncated = truncated };
    }

    static bool ValidDeadline(long expires)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return now < expires && expires - now <= 120;
    }

    public sealed class Request { public string command { get; set; } public string workspace { get; set; } }
    sealed class Captured { public string text; public bool truncated; }

    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimits
    {
        public long perProcessTime, perJobTime;
        public uint flags;
        public UIntPtr minWorkingSet, maxWorkingSet;
        public uint activeProcesses;
        public UIntPtr affinity;
        public uint priorityClass, schedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters { public ulong reads, writes, other, readBytes, writeBytes, otherBytes; }

    [StructLayout(LayoutKind.Sequential)]
    struct JobLimits
    {
        public BasicLimits basic;
        public IoCounters io;
        public UIntPtr processMemoryLimit, jobMemoryLimit, peakProcessMemory, peakJobMemory;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass, ref JobLimits limits, int size);
    [DllImport("kernel32.dll")]
    static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);
    [DllImport("kernel32.dll")]
    static extern bool TerminateJobObject(SafeFileHandle job, uint code);
}
