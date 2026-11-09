using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

// Replaces only application binaries. Pairing data, grants, gateway settings,
// WireGuard identities, and scheduler task definitions are not rewritten.
internal static class WindowsInPlaceUpgrade
{
    private sealed class TaskRecord
    {
        internal dynamic Job;
        internal bool WasRunning;
    }

    private static byte[] Bundled(string resource)
    {
        using (var stream=Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
        {
            if (stream==null || stream.Length==0 || stream.Length>67108864)
                throw new InvalidDataException("Complete installer is missing: "+resource);
            using (var memory=new MemoryStream())
            {
                stream.CopyTo(memory);
                return memory.ToArray();
            }
        }
    }

    private static bool EqualBytes(byte[] a,byte[] b)
    {
        if (a.Length!=b.Length)return false;
        int difference=0;
        for(int i=0;i<a.Length;i++)difference|=a[i]^b[i];
        return difference==0;
    }

    private static byte[] Sha(byte[] content)
    {
        using(var digest=SHA256.Create())return digest.ComputeHash(content);
    }

    internal static string PairingFingerprint(string state)
    {
        string path=Path.Combine(state,"pairing-identity.json");
        BinaryUpgradeTransaction.CheckOrdinaryFile(path);
        if(new FileInfo(path).Length>131072)
            throw new InvalidDataException("Pairing state is invalid.");
        var stored=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(path));
        if(stored==null || !stored.ContainsKey("version") || Convert.ToInt32(stored["version"])!=1 ||
           !stored.ContainsKey("private_key"))throw new InvalidDataException("Pairing identity is missing.");
        string key=stored["private_key"] as string;
        if(key==null || !Regex.IsMatch(key,@"\A[a-f0-9]{64}\z"))
            throw new InvalidDataException("Invalid pairing identity.");
        return Convert.ToBase64String(Sha(Encoding.ASCII.GetBytes(key)));
    }

    private static void ValidateLocation(string install,string state)
    {
        foreach(string path in new[]{install,state})
        {
            if(!Directory.Exists(path) || (File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
                throw new InvalidDataException("Desktop MCP installation or state folder is missing or redirected.");
            var owner=Directory.GetAccessControl(path).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            var user=WindowsIdentity.GetCurrent().User;
            if(owner==null || user==null || owner.Value!=user.Value)
                throw new UnauthorizedAccessException("Only the owning Windows account may upgrade this Desktop MCP installation.");
        }
        if(!String.Equals(Path.GetFileName(state.TrimEnd('\\')),"com.jacqueb.desktopmcp",StringComparison.Ordinal))
            throw new InvalidDataException("Unexpected Desktop MCP state location.");
        BinaryUpgradeTransaction.CheckOrdinaryFile(Path.Combine(install,"desktop-mcp-agent.exe"));
        BinaryUpgradeTransaction.CheckOrdinaryFile(Path.Combine(install,"desktop-mcp.exe"));
    }

    private static TaskRecord FindTask(dynamic tasks,string name,string executable,bool required)
    {
        dynamic job=null;
        try {job=tasks.GetTask(name);}
        catch(FileNotFoundException)
        {
            if(required)throw new InvalidOperationException("Existing Desktop MCP scheduled task is missing: "+name);
            return null;
        }
        catch(COMException)
        {
            if(required)throw new InvalidOperationException("Existing Desktop MCP scheduled task is missing: "+name);
            return null;
        }
        dynamic definition=job.Definition;
        if(Convert.ToInt32(definition.Actions.Count)!=1 ||
           !String.Equals(Path.GetFullPath(Convert.ToString(definition.Actions.Item(1).Path).Trim('"')),
              Path.GetFullPath(executable),StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Scheduled task executable differs from the installed Desktop MCP binary: "+name);
        string principal=Convert.ToString(definition.Principal.UserId);
        string owningSid=WindowsIdentity.GetCurrent().User.Value;
        string principalSid=principal;
        if(!principal.StartsWith("S-1-",StringComparison.OrdinalIgnoreCase))
        {
            try {
                principalSid=((SecurityIdentifier)new NTAccount(principal)
                    .Translate(typeof(SecurityIdentifier))).Value;
            }
            catch(IdentityNotMappedException) {
                throw new InvalidOperationException("Cannot validate Desktop MCP scheduled-task owner: "+name);
            }
        }
        if(!String.Equals(principalSid,owningSid,StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Scheduled task belongs to another Windows owner: "+name);
        return new TaskRecord{Job=job,WasRunning=Convert.ToInt32(job.State)==4};
    }

    private static void Stop(TaskRecord task)
    {
        if(task==null||!task.WasRunning)return;
        try{task.Job.Stop(0);}
        catch(COMException error)
        {
            if((uint)error.ErrorCode!=0x8004130B)throw;
        }
    }

    private static void Resume(TaskRecord task)
    {
        if(task!=null&&task.WasRunning)task.Job.Run(null);
    }

    internal static void Run(
        string install,string state,string agentTask,string trayTask,
        string gatewayTask,GatewayEndpoint chosenEndpoint,Action upgradeMachine)
    {
        ValidateLocation(install,state);
        string fingerprint=PairingFingerprint(state);
        string agent=Path.Combine(install,"desktop-mcp-agent.exe");
        string tray=Path.Combine(install,"desktop-mcp.exe");

        GatewayEndpoint saved=GatewayEndpoint.Load(state);
        if(saved!=null && chosenEndpoint!=null && saved.Display!=chosenEndpoint.Display)
            throw new InvalidOperationException("Saved gateway endpoint must never be silently changed.");
        if(saved==null && chosenEndpoint==null)
            throw new InvalidOperationException("Gateway address is required to migrate this installation.");

        // A different CA cannot be silently introduced on upgrade.
        byte[] ca=Bundled("gateway-ca");
        string caPath=Path.Combine(install,"nas-ca.pem");
        if(File.Exists(caPath))
        {
            BinaryUpgradeTransaction.CheckOrdinaryFile(caPath);
            if(!EqualBytes(Sha(File.ReadAllBytes(caPath)),Sha(ca)))
                throw new InvalidDataException("Pinned gateway TLS identity differs. Refusing an automatic trust rotation.");
        }

        dynamic scheduler=Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service",true));
        scheduler.Connect();
        dynamic tasks=scheduler.GetFolder("\\");
        TaskRecord agentJob=FindTask(tasks,agentTask,agent,true);
        TaskRecord trayJob=FindTask(tasks,trayTask,tray,true);
        TaskRecord gatewayJob=FindTask(tasks,gatewayTask,agent,false);
        string originalCode=agentJob.WasRunning ?
            WindowsSetup.WaitForCode(agent,install,state) : null;
        var tx=new BinaryUpgradeTransaction(install);
        bool endpointCreated=false;
        try
        {
            tx.Stage("desktop-mcp-agent.exe",Bundled("agent"),false);
            tx.Stage("desktop-mcp.exe",Bundled("tray"),false);
            if(!File.Exists(caPath))tx.Stage("nas-ca.pem",ca,true);
            // Stage and verify every payload before any process is stopped.
            if(saved==null)
            {
                chosenEndpoint.SaveNew(state);
                endpointCreated=true;
            }
            Stop(gatewayJob);
            Stop(trayJob);
            Stop(agentJob);
            Thread.Sleep(350);
            tx.Apply();
            Resume(agentJob);
            Resume(trayJob);
            Resume(gatewayJob);
            if(fingerprint!=PairingFingerprint(state))
                throw new InvalidDataException("Upgraded agent changed the device's signing identity.");
            if(agentJob.WasRunning &&
               !String.Equals(originalCode,WindowsSetup.WaitForCode(agent,install,state),
                   StringComparison.Ordinal))
                throw new IOException("Upgraded local agent failed to restart with the same public identity.");
            // Protected service runs its own independent rollback transaction.
            if(upgradeMachine!=null)upgradeMachine();
            if(fingerprint!=PairingFingerprint(state))
                throw new InvalidDataException("Machine upgrade modified the user's pairing identity.");
            tx.Commit();
        }
        catch(Exception failure)
        {
            Exception rollbackError=null;
            try
            {
                Stop(gatewayJob);
                Stop(trayJob);
                Stop(agentJob);
                Thread.Sleep(350);
                tx.Rollback();
                Resume(agentJob);
                Resume(trayJob);
                Resume(gatewayJob);
            }
            catch(Exception error){rollbackError=error;}
            if(endpointCreated)
            {
                try{File.Delete(Path.Combine(state,GatewayEndpoint.FileName));}
                catch(Exception error){if(rollbackError==null)rollbackError=error;}
            }
            if(rollbackError!=null)
                throw new InvalidOperationException("Upgrade failed, and rollback requires manual recovery from "+
                    tx.BackupDirectory+". Cause: "+failure.GetType().Name+"; rollback: "+rollbackError.Message);
            throw new InvalidOperationException("Update failed; previous binaries and pairing were restored. "+
                failure.Message,failure);
        }
    }
}
