// Desktop MCP unattended Windows service.
// Installation and access grants require interactive owner UAC elevation.
// The service runs under LocalSystem and owns the gateway identity and grant store.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("Desktop MCP unattended service")]
[assembly: AssemblyProduct("Desktop MCP")]

internal sealed class DesktopService : ServiceBase
{
    internal const string Name = "DesktopMCPUnattended";
    internal static readonly string InstallRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "DesktopMCP");
    internal static readonly string DataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DesktopMCP");
    internal static readonly string State = Path.Combine(DataRoot, "State");
    internal static readonly string Agent = Path.Combine(InstallRoot, "DesktopMCPAgentService.exe");
    internal static readonly string ServiceExe = Path.Combine(InstallRoot, "DesktopMCPService.exe");
    internal static readonly string Ca = Path.Combine(InstallRoot, "gateway-ca.pem");
    internal static readonly string Grant = Path.Combine(DataRoot, "grant.json");
    private readonly List<Process> processes = new List<Process>();
    private Thread watchdog;
    private Thread ownerPrompt;

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId,out IntPtr token);
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("wtsapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSSendMessage(IntPtr server,uint sessionId,string title,int titleBytes,
        string message,int messageBytes,uint style,uint timeout,out uint response,bool wait);
    private volatile bool shuttingDown;

    public DesktopService() { ServiceName=Name; CanStop=true; CanShutdown=true; AutoLog=false; }
    protected override void OnStart(string[] args)
    {
        shuttingDown=false;
        watchdog=new Thread(Supervise){IsBackground=true,Name="Desktop MCP SYSTEM service supervisor"};
        watchdog.Start();
        ownerPrompt=new Thread(ReviewRequests){IsBackground=true,Name="Desktop MCP owner approval"};
        ownerPrompt.Start();
    }
    protected override void OnStop(){StopChildren();}
    protected override void OnShutdown(){StopChildren();base.OnShutdown();}
    private void StopChildren()
    {
        shuttingDown=true;
        lock(processes) foreach(var p in processes) { try { if(!p.HasExited)p.Kill(); } catch {} }
        if(watchdog!=null && Thread.CurrentThread!=watchdog)watchdog.Join(5000);
    }
    private static string Quote(string s){return "\""+s.Replace("\"","")+"\"";}
    private Process Launch(string parameters)
    {
        var start=new ProcessStartInfo(Agent,parameters) {
            WorkingDirectory=State,UseShellExecute=false,CreateNoWindow=true,
            RedirectStandardInput=false,RedirectStandardOutput=false,RedirectStandardError=false
        };
        var process=Process.Start(start);
        if(process==null)throw new InvalidOperationException("Cannot launch agent process.");
        lock(processes)processes.Add(process);
        return process;
    }
    private void Supervise()
    {
        // Parent LocalSystem service is the only launcher for the machine-mode agent.
        while(!shuttingDown) {
            Process local=null, gateway=null;
            try {
                var cfg=new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(File.ReadAllText(Path.Combine(DataRoot,"gateway.json")));
                if(!File.Exists(Agent)||!File.Exists(Ca)||cfg==null)throw new InvalidOperationException("Machine installation incomplete");
                local=Launch("--serve-local --system-mode --state-dir "+Quote(State)+" --allow-remote-readonly --require-pairing-consent --enable-admin-commands");
                var live=Path.Combine(State,"local-agent.json");
                int count=0;
                while(count++<40 && !shuttingDown && !File.Exists(live))Thread.Sleep(250);
                if(!File.Exists(live))throw new InvalidOperationException("Machine local agent failed to start");
                gateway=Launch("--gateway-connect --state-dir "+Quote(State)
                    +" --gateway-address "+Quote(cfg["address"])
                    +" --gateway-tls-name "+Quote(cfg["tlsName"])
                    +" --gateway-ca "+Quote(Ca));
                while(!shuttingDown && !local.HasExited && !gateway.HasExited)Thread.Sleep(1000);
            } catch(Exception error) {
                try { File.AppendAllText(Path.Combine(DataRoot,"service-errors.log"),
                        DateTime.UtcNow.ToString("o")+" "+error.GetType().Name+"\r\n"); } catch{}
            } finally {
                foreach(var child in new[]{gateway,local})if(child!=null){
                    try{if(!child.HasExited)child.Kill();}catch{}
                    try{child.Dispose();}catch{}
                }
                lock(processes)processes.Clear();
            }
            if(!shuttingDown)Thread.Sleep(3000);
        }
    }

    private static bool SessionBelongsTo(uint session,string ownerSid)
    {
        IntPtr token;
        if(session==UInt32.MaxValue || !WTSQueryUserToken(session,out token))return false;
        try {
            using(var identity=new WindowsIdentity(token))
                return identity.User != null && identity.User.Value==ownerSid;
        } finally {CloseHandle(token);}
    }

    private void ReviewRequests()
    {
        var json=new JavaScriptSerializer();
        string requestPath=Path.Combine(State,"owner-request.json");
        string decisionPath=Path.Combine(State,"owner-decision.json");
        string lastRequest=null;
        while(!shuttingDown) {
            try {
                if(!File.Exists(requestPath)) {Thread.Sleep(250);continue;}
                string raw=File.ReadAllText(requestPath);
                var request=json.Deserialize<Dictionary<string,object>>(raw);
                var id=(string)request["request_id"];
                var host=(string)request["host_id"];
                var duration=(string)request["duration"];
                long remaining=Convert.ToInt64(request["expires_at"])-Now();
                Guid requestId;
                if(id==lastRequest || remaining<=0 || remaining>120 ||
                    !Guid.TryParseExact(id,"D",out requestId) ||
                    host!=File.ReadAllText(Path.Combine(DataRoot,"host-id.txt")).Trim()) {
                    Thread.Sleep(250);continue;
                }
                string time;
                if(duration=="permanent")time="until you revoke it";
                else if(duration=="1h")time="for 60 minutes";
                else if(duration=="4h")time="for 240 minutes";
                else {
                    int minutes;
                    if(!duration.EndsWith("m",StringComparison.Ordinal) ||
                        !Int32.TryParse(duration.Substring(0,duration.Length-1),out minutes) ||
                        minutes<1 || minutes>1440 || duration!=minutes.ToString()+"m") {
                        Thread.Sleep(250);continue;
                    }
                    time="for "+minutes+" minutes";
                }
                var config=json.Deserialize<Dictionary<string,string>>(File.ReadAllText(Path.Combine(DataRoot,"gateway.json")));
                uint session=WTSGetActiveConsoleSessionId();
                if(!SessionBelongsTo(session,config["ownerSid"])) {Thread.Sleep(250);continue;}
                string title="Desktop MCP: unattended administrator access";
                string message="Your paired ChatGPT controller requests Windows SYSTEM command access "+time+".\n\n"
                    +"If you approve, it can run elevated commands without further prompts, including after sign-out "
                    +"and reboot. Use the Desktop MCP revoke shortcut to end access.\n\nAllow this request?";
                uint response;
                bool displayed=WTSSendMessage(IntPtr.Zero,session,title,Encoding.Unicode.GetByteCount(title),
                    message,Encoding.Unicode.GetByteCount(message),0x134,(uint)remaining,out response,true);
                if(!displayed) {Thread.Sleep(1000);continue;}
                lastRequest=id;
                if(shuttingDown || Now()>=Convert.ToInt64(request["expires_at"]) ||
                    !File.Exists(requestPath) || File.ReadAllText(requestPath)!=raw ||
                    !SessionBelongsTo(session,config["ownerSid"]))continue;
                string temporary=decisionPath+"."+Guid.NewGuid().ToString("N")+".tmp";
                try {
                    File.WriteAllText(temporary,json.Serialize(new {request_id=id,approved=response==6}));
                    if(File.Exists(decisionPath))File.Replace(temporary,decisionPath,null);
                    else File.Move(temporary,decisionPath);
                } finally {if(File.Exists(temporary))File.Delete(temporary);}
            } catch(Exception error) {
                try {File.AppendAllText(Path.Combine(DataRoot,"service-errors.log"),
                    DateTime.UtcNow.ToString("o")+" Owner approval: "+error.GetType().Name+"\r\n");} catch{}
                Thread.Sleep(1000);
            }
        }
    }

    private static bool IsAdministrator()
    {
        using(var identity=WindowsIdentity.GetCurrent())
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    private static void RequireAdministrator()
    {
        if(!IsAdministrator())
            throw new InvalidOperationException("Windows administrator approval is required.");
    }
    private static DirectorySecurity ProtectedAcl()
    {
        var acl=new DirectorySecurity();
        acl.SetAccessRuleProtection(true,false);
        var admins=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
        var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
        acl.SetOwner(admins);
        foreach(var sid in new[]{admins,system})
            acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,
                PropagationFlags.None,AccessControlType.Allow));
        return acl;
    }
    private static void PrivateDirectory(string path)
    {
        if(Directory.Exists(path)) {
            if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
                throw new InvalidOperationException("Protected state directory is a reparse point.");
            var acl=Directory.GetAccessControl(path);
            var owner=acl.GetOwner(typeof(SecurityIdentifier)).ToString();
            if(owner!="S-1-5-32-544" && owner!="S-1-5-18")
                throw new InvalidOperationException("Existing machine state directory has an unsafe owner.");
            var allowed = new HashSet<string>(new[]{"S-1-5-32-544","S-1-5-18"});
            var rules=acl.GetAccessRules(true,true,typeof(SecurityIdentifier));
            foreach(FileSystemAccessRule rule in rules) {
                if(rule.AccessControlType!=AccessControlType.Allow)continue;
                var sid=rule.IdentityReference.Value;
                if(allowed.Contains(sid))continue;
                var dangerous=FileSystemRights.Write|FileSystemRights.Delete|
                    FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
                if((rule.FileSystemRights&dangerous)!=0)
                    throw new InvalidOperationException("Unprotected directory permissions are unsafe.");
            }
            return;
        }
        Directory.CreateDirectory(path,ProtectedAcl());
    }
    private static void ResourceToFile(string resource,string output)
    {
        using(var input=Assembly.GetExecutingAssembly().GetManifestResourceStream(resource)){
            if(input==null)throw new InvalidOperationException("Installer resource is missing: "+resource);
            using(var destination=new FileStream(output,FileMode.Create,FileAccess.Write,FileShare.None)){
                input.CopyTo(destination);
                destination.Flush(true);
            }
        }
    }
    private static void RunSc(string arguments)
    {
        var psi=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"sc.exe"),arguments){
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var proc=Process.Start(psi)){
            if(proc==null)throw new InvalidOperationException("Service Control Manager unavailable");
            var output=proc.StandardOutput.ReadToEnd();
            var error=proc.StandardError.ReadToEnd();
            proc.WaitForExit();
            if(proc.ExitCode!=0)throw new InvalidOperationException("Service operation failed: "+output+" "+error);
        }
    }
    private static bool ServiceExists(){
        foreach(var service in ServiceController.GetServices()){
            if(service.ServiceName==Name)return true;
        }
        return false;
    }
    private static long Now(){return DateTimeOffset.UtcNow.ToUnixTimeSeconds();}
    private static string GetHostIdentity()
    {
        var psi=new ProcessStartInfo(Agent,"--machine-host-id --state-dir "+Quote(State)){
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        using(var process=Process.Start(psi)){
            var output=process.StandardOutput.ReadToEnd().Trim();
            var error=process.StandardError.ReadToEnd();
            process.WaitForExit();
            if(process.ExitCode!=0||output.Length!=32)throw new InvalidOperationException("Cannot confirm copied machine identity: "+error);
            return output;
        }
    }
    private static void InstallMachine(string userState)
    {
        RequireAdministrator();
        if(!Directory.Exists(userState) || Path.GetFileName(userState.TrimEnd('\\'))!="com.jacqueb.desktopmcp")
            throw new InvalidOperationException("Invalid source pairing state.");
        var owner=Directory.GetAccessControl(userState).GetOwner(typeof(SecurityIdentifier));
        if(owner==null || !(owner.Value.StartsWith("S-1-5-21-",StringComparison.Ordinal) ||
            owner.Value.StartsWith("S-1-12-1-",StringComparison.Ordinal)))
            throw new InvalidOperationException("Cannot identify the Windows account that owns this Desktop MCP installation.");
        string identity=Path.Combine(userState,"pairing-identity.json");
        if(!File.Exists(identity)||new FileInfo(identity).Length>131072)
            throw new InvalidOperationException("Device pairing identity missing.");
        // Only reuse a previously paired identity; never silently enroll a new one.
        var pair=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(identity));
        if(pair==null || !pair.ContainsKey("private_key") || !pair.ContainsKey("version") ||
            Convert.ToInt32(pair["version"])!=1)
            throw new InvalidOperationException("Device pairing state invalid.");
        PrivateDirectory(DataRoot);
        PrivateDirectory(State);
        PrivateDirectory(InstallRoot);
        if(ServiceExists()){
            try{RunSc("stop "+Name);}catch{}
            Thread.Sleep(900);
        }
        // Install only the *embedded* tested agent, never execute a user-writable supplied binary.
        ResourceToFile("agent",Agent);
        ResourceToFile("gateway-ca",Ca);
        File.Copy(Assembly.GetExecutingAssembly().Location,ServiceExe,true);
        var folderAcl=Directory.GetAccessControl(InstallRoot);
        folderAcl.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.ReadAndExecute,AccessControlType.Allow));
        Directory.SetAccessControl(InstallRoot,folderAcl);
        var serviceAcl=File.GetAccessControl(ServiceExe);
        serviceAcl.AddAccessRule(new FileSystemAccessRule(owner,FileSystemRights.ReadAndExecute,AccessControlType.Allow));
        File.SetAccessControl(ServiceExe,serviceAcl);
        File.Copy(identity,Path.Combine(State,"pairing-identity.json"),true);
        File.WriteAllText(Path.Combine(State,"remote-readonly.enabled"),"enabled\n");
        using(var gateway=Assembly.GetExecutingAssembly().GetManifestResourceStream("gateway")) {
            if(gateway==null)throw new InvalidOperationException("Gateway configuration missing.");
            using(var reader=new StreamReader(gateway)){
                string address=reader.ReadLine(), tlsName=reader.ReadLine();
                if(String.IsNullOrWhiteSpace(address)||String.IsNullOrWhiteSpace(tlsName))
                    throw new InvalidOperationException("Invalid gateway address or TLS name.");
                File.WriteAllText(Path.Combine(DataRoot,"gateway.json"),new JavaScriptSerializer().Serialize(
                    new {address=address,tlsName=tlsName,ownerSid=owner.Value}));
            }
        }
        // Prints only the public, derived host id. The secret never enters command-line arguments.
        var host=GetHostIdentity();
        File.WriteAllText(Path.Combine(DataRoot,"host-id.txt"),host);
        if(!ServiceExists()){
            RunSc("create "+Name+" binPath= \"\\\""+ServiceExe+"\\\"\""+" start= auto obj= LocalSystem DisplayName= "+Quote("Desktop MCP Unattended"));
        }
        RunSc("start "+Name);
        // Recover the long-lived service after crashes without relying on user logon.
        try {RunSc("failure "+Name+" reset= 86400 actions= restart/60000/restart/60000/restart/60000");}
        catch {}
        // Disable the obsolete per-user gateway connector; retain the tray and pairing UI.
        try{
            var stop=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"schtasks.exe"),
                "/End /TN "+Quote("Desktop MCP Gateway Link")){UseShellExecute=false,CreateNoWindow=true};
            using(var stopping=Process.Start(stop)){if(stopping!=null)stopping.WaitForExit(10000);}
            var task=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"schtasks.exe"),
                "/Change /TN "+Quote("Desktop MCP Gateway Link")+" /Disable"){
                UseShellExecute=false,CreateNoWindow=true};
            using(var process=Process.Start(task)){if(process!=null)process.WaitForExit(10000);}
        }catch{}
        CreateOwnerShortcuts();
        MessageBox.Show("The protected Desktop MCP Windows service is installed.\n\n"
            +"After pairing, ChatGPT can request unattended administrator access for you to approve.",
            "Desktop MCP Service",MessageBoxButtons.OK,MessageBoxIcon.Information);
    }
    private static void CreateOwnerShortcuts()
    {
        string desktop=Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
        dynamic shell=Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell",true));
        foreach(var item in new[]{
            new {title="Desktop MCP - Grant Administrator Access.lnk",argument="--grant"},
            new {title="Desktop MCP - Revoke Administrator Access.lnk",argument="--revoke"}}) {
            dynamic link=shell.CreateShortcut(Path.Combine(desktop,item.title));
            link.TargetPath=ServiceExe;
            link.Arguments=item.argument;
            link.WorkingDirectory=InstallRoot;
            link.Description="Owner-controlled Desktop MCP elevated delegation";
            link.Save();
        }
    }
    private static void GrantAccess()
    {
        RequireAdministrator();
        if(!ServiceExists()||!File.Exists(Path.Combine(DataRoot,"host-id.txt")))
            throw new InvalidOperationException("Desktop MCP elevated service is not installed.");
        string host=File.ReadAllText(Path.Combine(DataRoot,"host-id.txt")).Trim();
        if(host!=GetHostIdentity())throw new InvalidOperationException("Machine identity mismatch.");
        using(var form=new Form{Text="Desktop MCP: unattended ADMINISTRATOR delegation",
            Width=700,Height=395,StartPosition=FormStartPosition.CenterScreen,
            FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,TopMost=true}){
            var label=new Label{Left=16,Top=16,Width=650,Height=120,Text=
                "This grants the paired ChatGPT Desktop MCP controller unattended Windows SYSTEM administrator command execution. "
                +"It remains active even if you close the tray, sign out, or reboot. "
                +"No approval popup or UAC confirmation will appear for each command.\n\n"
                +"Only authorize a computer and controller you trust. All requests are logged and this grant can be revoked."};
            var duration=new ComboBox{Left=16,Top=150,Width=330,DropDownStyle=ComboBoxStyle.DropDownList};
            duration.Items.AddRange(new object[]{"1 hour","4 hours","24 hours","Permanent until revoked"});
            duration.SelectedIndex=0;
            var approve=new Button{Left=360,Top=260,Width=150,Text="Grant access",DialogResult=DialogResult.Yes};
            var cancel=new Button{Left=520,Top=260,Width=130,Text="Cancel",DialogResult=DialogResult.Cancel};
            form.Controls.AddRange(new Control[]{label,duration,approve,cancel});
            form.AcceptButton=cancel;form.CancelButton=cancel;
            if(form.ShowDialog()!=DialogResult.Yes)return;
            long issued=Now(), expires=duration.SelectedIndex==0?issued+3600:
                duration.SelectedIndex==1?issued+14400:duration.SelectedIndex==2?issued+86400:0;
            if(duration.SelectedIndex==3 &&
                MessageBox.Show("Grant PERMANENT unattended administrator access until manually revoked?",
                "Confirm permanent elevation",MessageBoxButtons.YesNo,MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2)!=DialogResult.Yes)return;
            var record=new {
                version=1,scope="unattended_admin",host_id=host,
                grant_id=Guid.NewGuid().ToString(),issued_at=issued,
                expires_at=(object)(expires==0?null:(object)expires),revoked=false
            };
            string tmp=Grant+"."+Guid.NewGuid().ToString("N")+".tmp";
            File.WriteAllText(tmp,new JavaScriptSerializer().Serialize(record));
            if(File.Exists(Grant))File.Delete(Grant);
            File.Move(tmp,Grant);
            File.AppendAllText(Path.Combine(DataRoot,"owner-grants.jsonl"),
                new JavaScriptSerializer().Serialize(new {at=Now(),event_type="grant",
                    host_id=host,grant_id=record.grant_id,expires_at=record.expires_at})+"\n");
            MessageBox.Show("Unattended elevated access granted. You can revoke it from the administrator utility.",
                "Desktop MCP",MessageBoxButtons.OK,MessageBoxIcon.Information);
        }
    }
    private static void RevokeAccess()
    {
        RequireAdministrator();
        if(MessageBox.Show("Immediately revoke unattended administrator access?",
            "Desktop MCP",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
        File.Delete(Path.Combine(State,"owner-request.json"));
        if(File.Exists(Grant))File.Delete(Grant);
        File.AppendAllText(Path.Combine(DataRoot,"owner-grants.jsonl"),
            new JavaScriptSerializer().Serialize(new {at=Now(),event_type="revoke"})+"\n");
        // The runtime checks the owner grant for every command and interrupts active commands on revocation.
        MessageBox.Show("Unattended grant revoked.","Desktop MCP",MessageBoxButtons.OK,MessageBoxIcon.Information);
    }
    private static void ShowError(Exception error){
        MessageBox.Show(error.Message,"Desktop MCP elevated service",MessageBoxButtons.OK,MessageBoxIcon.Error);
    }
    [STAThread]
    private static void Main(string[] args)
    {
        // The owner's desktop shortcuts can self-elevate. A normal process can
        // never write the protected grant store or install the service.
        if(args.Length>0 && (args[0]=="--grant" || args[0]=="--revoke") &&
            !IsAdministrator()) {
            try {
                var info=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,args[0]){
                    UseShellExecute=true,Verb="runas"
                };
                using(var process=Process.Start(info)){
                    if(process!=null){process.WaitForExit();Environment.ExitCode=process.ExitCode;}
                }
            }catch{Environment.ExitCode=1;}
            return;
        }
        if(args.Length==0) {
            if(!Environment.UserInteractive){
                ServiceBase.Run(new DesktopService());
                return;
            }
            // Double-clicking this installer requests UAC to install the service.
            var userState=Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "com.jacqueb.desktopmcp");
            if(!IsAdministrator()){
                try {
                    var start=new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
                        "--install \"" + userState.Replace("\"","") + "\""){
                        UseShellExecute=true,Verb="runas"
                    };
                    using(var process=Process.Start(start)){
                        if(process!=null){process.WaitForExit();Environment.ExitCode=process.ExitCode;}
                    }
                }catch{Environment.ExitCode=1;}
                return;
            }
            Application.EnableVisualStyles();
            try{InstallMachine(userState);}
            catch(Exception error){ShowError(error);Environment.ExitCode=1;}
            return;
        }
        if(args.Length==1 && args[0]=="--self-test"){
            foreach(var required in new[]{"agent","gateway-ca","gateway"}){
                using(var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream(required)){
                    if(stream==null || stream.Length==0){Environment.ExitCode=5;return;}
                }
            }
            Environment.ExitCode=0;
            return;
        }
        Application.EnableVisualStyles();
        try{
            if(args.Length==2 && args[0]=="--install"){InstallMachine(args[1]);return;}
            if(args.Length==1 && args[0]=="--grant"){GrantAccess();return;}
            if(args.Length==1 && args[0]=="--revoke"){RevokeAccess();return;}
            throw new ArgumentException("Usage: --install <pairing state>, --grant, or --revoke.");
        }catch(Exception error){ShowError(error);Environment.ExitCode=1;}
    }
}
