using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal static class WindowsSetup
{
    const string AgentTask = "Desktop MCP Local Agent";
    const string TrayTask = "Desktop MCP Tray";
    const string GatewayTask = "Desktop MCP Gateway Link";
    const int CreateTask = 2;
    const int InteractiveToken = 3;
    const int LimitedRunLevel = 0;
    const int AtLogon = 9;
    const int Execute = 0;

    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--install-command-helper")
        {
            try { InstallCommandHelperElevated(); Environment.ExitCode = 0; }
            catch (Exception error) { MessageBox.Show(error.Message, "Desktop MCP administrator helper", MessageBoxButtons.OK, MessageBoxIcon.Error); Environment.ExitCode = 1; }
            return;
        }
        if (args.Length == 2 && args[0] == "--install-unattended")
        {
            try {
                InstallUnattendedElevated(args[1]);
                Environment.ExitCode = 0;
            } catch (Exception error) {
                MessageBox.Show(error.Message, "Desktop MCP unattended service",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                Environment.ExitCode = 1;
            }
            return;
        }
        if (args.Length != 0) { Environment.ExitCode = 2; return; }
        Application.EnableVisualStyles();
        try
        {
            if (MessageBox.Show(
                "Install Desktop MCP for this PC?\n\nThe app runs in the background at sign-in. " +
                "No project folder or Git installation is required. Repository access can be selected later, " +
                "with your approval. Remote requests still require local authorization.",
                "Set up Desktop MCP", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            string programs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs");
            Directory.CreateDirectory(programs);
            string install = Path.Combine(programs, "DesktopMCP");
            string state = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "com.jacqueb.desktopmcp");
            string code = Install(install, state, AgentTask, TrayTask, GatewayTask);
            // Finish service setup before exposing the code for enrollment.
            // Command authority is granted separately by the owner after pairing.
            if (typeof(WindowsSetup).Assembly.GetManifestResourceStream("unattended-service") != null &&
                MessageBox.Show("Install the protected Windows service?\\n\\n" +
                    "After pairing, the controller can request unattended administrator access. " +
                    "You can approve the requested duration and revoke access locally.",
                    "Desktop MCP unattended access", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes)
            {
                var start = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,
                    "--install-unattended " + Quote(state)) { UseShellExecute=true, Verb="runas" };
                using (var process=Process.Start(start))
                {
                    if (process==null)throw new InvalidOperationException("Windows elevation was not started.");
                    process.WaitForExit();
                    if(process.ExitCode!=0)throw new InvalidOperationException(
                        "Protected service setup did not finish. Ordinary Desktop MCP remains installed.");
                }
            }
            ShowCode(code);
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "Desktop MCP setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    static string Install(string install, string state, string agentTask, string trayTask, string gatewayTask)
    {
        if (Exists(install) || Exists(state))
            throw new InvalidOperationException("Desktop MCP already has files on this PC. This installer only supports a fresh installation.");

        SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true));
        service.Connect();
        dynamic tasks = service.GetFolder("\\");
        bool installCreated = false, stateCreated = false;
        dynamic agentJob = null;
        dynamic trayJob = null;
        dynamic gatewayJob = null;
        try
        {
            CreatePrivateDirectory(install, user);
            installCreated = true;
            CreatePrivateDirectory(state, user);
            stateCreated = true;

            string agent = Path.Combine(install, "desktop-mcp-agent.exe");
            string tray = Path.Combine(install, "desktop-mcp.exe");
            Extract("agent", agent);
            Extract("tray", tray);
            File.WriteAllText(Path.Combine(state, "remote-readonly.enabled"), "enabled\n");
            agentJob = Register(tasks, service, agentTask, user.Value, agent, install,
                "--serve-local --state-dir " + Quote(state) +
                " --allow-remote-readonly --require-pairing-consent --enable-admin-diagnostics" +
                (typeof(WindowsSetup).Assembly.GetManifestResourceStream("command-helper") != null ? " --enable-admin-commands" : ""), true);
            trayJob = Register(tasks, service, trayTask, user.Value, tray, install, "", false);
            agentJob.Run(null);
            string code = WaitForCode(agent, install, state);
            using (var config = typeof(WindowsSetup).Assembly.GetManifestResourceStream("gateway"))
            {
                if (config != null)
                {
                    string address, tlsName;
                    using (var reader = new StreamReader(config))
                    {
                        address = reader.ReadLine();
                        tlsName = reader.ReadLine();
                    }
                    string ca = Path.Combine(install, "nas-ca.pem");
                    Extract("gateway-ca", ca);
                    gatewayJob = Register(tasks, service, gatewayTask, user.Value, agent, install,
                        "--gateway-connect --state-dir " + Quote(state) + " --gateway-address " + Quote(address) +
                        " --gateway-tls-name " + Quote(tlsName) + " --gateway-ca " + Quote(ca), true);
                    gatewayJob.Run(null);
                }
            }
            trayJob.Run(null);
            if (typeof(WindowsSetup).Assembly.GetManifestResourceStream("command-helper") != null)
                InstallCommandHelperWithConsent();
            return code;
        }
        catch
        {
            try
            {
                RemoveTask(tasks, gatewayTask, gatewayJob);
                RemoveTask(tasks, trayTask, trayJob);
                RemoveTask(tasks, agentTask, agentJob);
                if (stateCreated) Directory.Delete(state, true);
                if (installCreated) Directory.Delete(install, true);
            }
            catch (Exception cleanupError)
            {
                throw new InvalidOperationException("Setup could not finish cleaning up: " + cleanupError.Message);
            }
            throw;
        }
    }

    // Only the interactive administrator-approved installer may deploy the
    // embedded SYSTEM service. Never elevate a user-supplied executable.
    static void InstallUnattendedElevated(string sourceState)
    {
        using (var identity = WindowsIdentity.GetCurrent())
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("Administrator approval required.");
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DesktopMCP");
        if (!Directory.Exists(root))
        {
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
            var security=new DirectorySecurity();
            security.SetOwner(admins);
            security.SetAccessRuleProtection(true,false);
            foreach (var sid in new[]{admins,system})
                security.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,AccessControlType.Allow));
            Directory.CreateDirectory(root,security);
        }
        if ((File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)
            throw new InvalidOperationException("Protected Desktop MCP directory is a reparse point.");
        var rootAcl=Directory.GetAccessControl(root);
        var rootOwner=rootAcl.GetOwner(typeof(SecurityIdentifier)).Value;
        if(rootOwner!="S-1-5-32-544" && rootOwner!="S-1-5-18")
            throw new InvalidOperationException("Protected Desktop MCP directory has an unsafe owner.");
        var dangerous=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|
            FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in rootAcl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow &&
                rule.IdentityReference.Value!="S-1-5-32-544" && rule.IdentityReference.Value!="S-1-5-18" &&
                (rule.FileSystemRights&dangerous)!=0)
                throw new InvalidOperationException("Protected Desktop MCP directory is writable by a non-administrator.");
        string bootstrap=Path.Combine(root,"DesktopMCPServiceBootstrap-"+Guid.NewGuid().ToString("N")+".exe");
        using (var resource=typeof(WindowsSetup).Assembly.GetManifestResourceStream("unattended-service"))
        {
            if(resource==null)throw new InvalidOperationException("Unattended service payload missing.");
            using (var output=new FileStream(bootstrap,FileMode.CreateNew,FileAccess.Write,FileShare.None))
            {
                resource.CopyTo(output);
                output.Flush(true);
            }
        }
        var start=new ProcessStartInfo(bootstrap,"--install " + Quote(sourceState)){
            UseShellExecute=false,CreateNoWindow=false
        };
        try {
            using (var process=Process.Start(start))
            {
                if(process==null)throw new InvalidOperationException("Service installer could not launch.");
                process.WaitForExit();
                if(process.ExitCode!=0)throw new InvalidOperationException("Service installation did not finish.");
            }
        } finally { File.Delete(bootstrap); }
    }

    // UAC belongs to the PC owner. No remote caller can invoke this installation path.
    static void InstallCommandHelperWithConsent()
    {
        // An existing byte-identical protected helper does not need reinstallation.
        string target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DesktopMCP", "CommandRunner.exe");
        using (var embedded = typeof(WindowsSetup).Assembly.GetManifestResourceStream("command-helper"))
        {
            if (embedded != null && File.Exists(target))
            {
                using (var memory = new MemoryStream())
                using (var digest = SHA256.Create())
                {
                    embedded.CopyTo(memory);
                    if (DigestEquals(digest.ComputeHash(memory.ToArray()), DigestFile(target))) return;
                }
            }
        }
        if (MessageBox.Show(
            "Desktop MCP can install its administrator command helper now.\n\n" +
            "Windows will ask for administrator approval. Remote commands will still require " +
            "the PC owner's pairing, an administrator grant, exact-command review, and UAC.\n\n" +
            "Install the administrator helper?",
            "Desktop MCP administrator helper", MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            throw new InvalidOperationException("Administrator helper installation was declined. Setup was cancelled.");
        var start = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName, "--install-command-helper");
        start.UseShellExecute = true;
        start.Verb = "runas";
        using (var process = Process.Start(start))
        {
            if (process == null) throw new InvalidOperationException("Could not launch the administrator helper installer.");
            process.WaitForExit();
            if (process.ExitCode != 0)
                throw new InvalidOperationException("Administrator helper installation did not complete. Setup was cancelled.");
        }
    }

    static void InstallCommandHelperElevated()
    {
        using (var identity = WindowsIdentity.GetCurrent())
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("Administrator approval is required.");

        byte[] payload;
        using (var resource = typeof(WindowsSetup).Assembly.GetManifestResourceStream("command-helper"))
        {
            if (resource == null) throw new InvalidOperationException("Administrator helper is not bundled.");
            using (var buffer = new MemoryStream())
            {
                resource.CopyTo(buffer);
                payload = buffer.ToArray();
            }
        }
        if (payload.Length == 0 || payload.Length > 1048576)
            throw new InvalidOperationException("Unexpected administrator helper size.");
        string root = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string directory = Path.Combine(root, "DesktopMCP");
        string target = Path.Combine(directory, "CommandRunner.exe");
        if (Directory.Exists(directory))
        {
            // Reinstall: reuse only the exact expected helper. Never overwrite protected files.
            if (File.Exists(target) && DigestEquals(SHA256.Create().ComputeHash(payload), DigestFile(target)))
                return;
            throw new InvalidOperationException("Protected Desktop MCP helper differs or is missing. No files were overwritten.");
        }

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var security = new DirectorySecurity();
        security.SetOwner(admins);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
            AccessControlType.Allow));
        Directory.CreateDirectory(directory, security);
        try
        {
            using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                output.Write(payload, 0, payload.Length);
            using (var digest = SHA256.Create())
                if (!DigestEquals(digest.ComputeHash(payload), DigestFile(target)))
                    throw new InvalidOperationException("Installed administrator helper checksum mismatch.");
        }
        catch
        {
            if (File.Exists(target)) File.Delete(target);
            Directory.Delete(directory);
            throw;
        }
    }

    static byte[] DigestFile(string file)
    {
        using (var source = File.OpenRead(file))
        using (var digest = SHA256.Create())
            return digest.ComputeHash(source);
    }

    static bool DigestEquals(byte[] left, byte[] right)
    {
        if (left.Length != right.Length) return false;
        int difference = 0;
        for (int i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
        return difference == 0;
    }

    static bool Exists(string path)
    {
        try { File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    static void CreatePrivateDirectory(string path, SecurityIdentifier user)
    {
        string profile = Path.GetFullPath(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)).TrimEnd('\\');
        for (var parent = Directory.GetParent(path); parent != null; parent = parent.Parent)
        {
            if ((parent.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Desktop MCP needs a local Windows profile without redirected setup folders.");
            if (String.Equals(parent.FullName, profile, StringComparison.OrdinalIgnoreCase)) break;
        }
        if (!Path.GetFullPath(path).StartsWith(profile + "\\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Desktop MCP setup folders must be in your Windows profile.");

        // Create the directory exclusively with its private ACL in the same operation.
        string sddl = "O:" + user.Value + "D:P(A;OICI;FA;;;" + user.Value + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        IntPtr descriptor;
        uint length;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out length))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var security = new SecurityAttributes { Length = Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor = descriptor };
            if (!CreateDirectory(path, ref security))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        finally { LocalFree(descriptor); }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SecurityAttributes
    {
        public int Length;
        public IntPtr Descriptor;
        public int InheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string text, uint revision, out IntPtr descriptor, out uint length);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateDirectory(string path, ref SecurityAttributes security);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);

    static void Extract(string resource, string path)
    {
        using (var input = typeof(WindowsSetup).Assembly.GetManifestResourceStream(resource))
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
            input.CopyTo(output);
    }

    static dynamic Register(dynamic tasks, dynamic service, string name, string user, string exe, string dir, string arguments, bool restart)
    {
        dynamic task = service.NewTask(0);
        task.RegistrationInfo.Description = "Desktop MCP per-user startup";
        task.Principal.UserId = user;
        task.Principal.LogonType = InteractiveToken;
        task.Principal.RunLevel = LimitedRunLevel;
        task.Settings.ExecutionTimeLimit = "PT0S";
        task.Settings.DisallowStartIfOnBatteries = false;
        task.Settings.StopIfGoingOnBatteries = false;
        if (restart)
        {
            task.Settings.RestartInterval = "PT1M";
            task.Settings.RestartCount = 10;
        }
        task.Triggers.Create(AtLogon).UserId = user;
        dynamic action = task.Actions.Create(Execute);
        action.Path = exe;
        action.Arguments = arguments;
        action.WorkingDirectory = dir;
        return tasks.RegisterTaskDefinition(name, task, CreateTask, user, null, InteractiveToken, null);
    }

    static void RemoveTask(dynamic tasks, string name, dynamic job)
    {
        if (job == null) return;
        job.Stop(0);
        tasks.DeleteTask(name, 0);
    }

    static string Quote(string path)
    {
        // Windows paths cannot contain quotes. Double trailing backslashes before the closing quote.
        return "\"" + Regex.Replace(path, @"\\+$", match => match.Value + match.Value) + "\"";
    }

    static string WaitForCode(string agent, string dir, string state)
    {
        var time = Stopwatch.StartNew();
        while (time.Elapsed.TotalSeconds < 25)
        {
            var info = new ProcessStartInfo(agent, "--local-status --state-dir " + Quote(state)) {
                WorkingDirectory = dir, UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            using (var probe = Process.Start(info))
            {
                var output = probe.StandardOutput.ReadToEndAsync();
                probe.StandardError.ReadToEndAsync();
                if (!probe.WaitForExit(3000))
                {
                    probe.Kill();
                    continue;
                }
                if (probe.ExitCode == 0)
                {
                    var status = new JavaScriptSerializer().DeserializeObject(output.GetAwaiter().GetResult())
                        as System.Collections.Generic.Dictionary<string, object>;
                    var identity = status["identity"] as System.Collections.Generic.Dictionary<string, object>;
                    string key = identity["public_key"] as string;
                    if (key != null && Regex.IsMatch(key, @"\A[a-f0-9]{64}\z"))
                        return "DM1-" + key;
                }
            }
            Thread.Sleep(250);
        }
        throw new InvalidOperationException("Desktop MCP could not start. Check the Desktop MCP agent and local service.");
    }

    static void ShowCode(string code)
    {
        using (var window = new Form { Text = "Desktop MCP setup code", Width = 610, Height = 185,
            StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog,
            MinimizeBox = false, MaximizeBox = false })
        {
            var explanation = new Label { Left = 16, Top = 16, Width = 560,
                Text = "Send this code to the person connecting this PC." };
            var field = new TextBox { Left = 16, Top = 46, Width = 560, ReadOnly = true, Text = code };
            var copy = new Button { Left = 16, Top = 84, Width = 136, Text = "Copy setup code" };
            copy.Click += (sender, args) =>
            {
                try { Clipboard.SetText(code); copy.Text = "Copied"; }
                catch (ExternalException) { field.Focus(); field.SelectAll(); }
            };
            window.Controls.AddRange(new Control[] { explanation, field, copy });
            window.ShowDialog();
        }
    }
}
