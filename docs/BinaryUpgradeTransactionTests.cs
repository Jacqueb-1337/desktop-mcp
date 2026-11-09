using System;
using System.IO;
using System.Text;

internal static class BinaryUpgradeTransactionTests
{
    private static void Assert(bool result, string label)
    {
        if (!result) throw new Exception("FAIL: " + label);
    }
    private static byte[] B(string text) { return Encoding.UTF8.GetBytes(text); }
    private static bool EqualsFile(string path, string value) { return File.ReadAllText(path) == value; }
    private static bool Try(Action action)
    {
        try { action(); return false; } catch (IOException) { return true; }
    }

    public static void Main()
    {
        string root = Path.Combine(Path.GetTempPath(), "desktop-mcp-upgrade-" + Guid.NewGuid().ToString("N"));
        string install = Path.Combine(root, "installed");
        string userState = Path.Combine(root, "paired-state");
        Directory.CreateDirectory(install);
        Directory.CreateDirectory(userState);
        string agent = Path.Combine(install,"desktop-mcp-agent.exe");
        string tray = Path.Combine(install,"desktop-mcp.exe");
        string ca = Path.Combine(install,"nas-ca.pem");
        string pairing = Path.Combine(userState,"pairing-identity.json");
        string gateway = Path.Combine(userState,"gateway-endpoint.json");
        File.WriteAllText(agent,"agent_v1");
        File.WriteAllText(tray,"tray_v1");
        File.WriteAllText(pairing,"UNTOUCHABLE_PAIRING");
        File.WriteAllText(gateway,"UNTOUCHABLE_GATEWAY");
        try
        {
            // Successful upgrade retains all state and protects prior versions until commit.
            var success = new BinaryUpgradeTransaction(install);
            success.Stage("desktop-mcp-agent.exe",B("agent_v2"),false);
            success.Stage("desktop-mcp.exe",B("tray_v2"),false);
            success.Stage("nas-ca.pem",B("public_ca"),true);
            success.Apply();
            Assert(EqualsFile(agent,"agent_v2"),"agent updated");
            Assert(EqualsFile(tray,"tray_v2"),"tray updated");
            Assert(EqualsFile(ca,"public_ca"),"new CA added");
            success.Commit();
            Assert(!Directory.Exists(success.BackupDirectory),"transaction cleanup");
            Assert(EqualsFile(pairing,"UNTOUCHABLE_PAIRING"),"pairing never changed");
            Assert(EqualsFile(gateway,"UNTOUCHABLE_GATEWAY"),"gateway never changed");
            Console.WriteLine("PASS: update binaries, preserve user state and commit.");

            // Explicit rollback restores bytes, including a component introduced by an upgrade.
            var rollback = new BinaryUpgradeTransaction(install);
            rollback.Stage("desktop-mcp-agent.exe",B("agent_v3"),false);
            rollback.Stage("desktop-mcp.exe",B("tray_v3"),false);
            rollback.Apply();
            rollback.Rollback();
            Assert(EqualsFile(agent,"agent_v2") && EqualsFile(tray,"tray_v2"),"rollback restores original binaries");
            Console.WriteLine("PASS: verified rollback.");

            File.Delete(ca);
            var createThenUndo = new BinaryUpgradeTransaction(install);
            createThenUndo.Stage("nas-ca.pem",B("temporary"),true);
            createThenUndo.Apply();
            createThenUndo.Rollback();
            Assert(!File.Exists(ca),"newly created file removed on rollback");
            Console.WriteLine("PASS: new component is removed on rollback.");

            // Mid-transaction failure must leave a reversible first file.
            var failed = new BinaryUpgradeTransaction(install);
            failed.Stage("desktop-mcp-agent.exe",B("agent_failure"),false);
            failed.Stage("desktop-mcp.exe",B("tray_failure"),false);
            bool blocked;
            using (var locked = new FileStream(tray,FileMode.Open,FileAccess.ReadWrite,FileShare.None))
                blocked = Try(() => failed.Apply());
            Assert(blocked,"injected file lock causes transaction error");
            failed.Rollback();
            Assert(EqualsFile(agent,"agent_v2") && EqualsFile(tray,"tray_v2"),"mid-transaction rollback");
            Console.WriteLine("PASS: mid-update failure restores previous binaries.");

            var concurrent = new BinaryUpgradeTransaction(install);
            concurrent.Stage("desktop-mcp-agent.exe",B("different"),false);
            File.WriteAllText(agent,"modified_while_staged");
            Assert(Try(()=>concurrent.Apply()),"reject concurrent modification");
            concurrent.Rollback();
            Assert(EqualsFile(agent,"modified_while_staged"),"never clobber unexpected changes");
            File.WriteAllText(agent,"agent_v2");
            Console.WriteLine("PASS: concurrent edits are refused without overwriting.");

            var invalid = new BinaryUpgradeTransaction(install);
            bool outside=false;
            try {invalid.Stage("..\\pairing-identity.json",B("bad"),true);}catch(ArgumentException){outside=true;}
            Assert(outside,"cannot target state/outside directory");
            invalid.Rollback();
            Assert(EqualsFile(pairing,"UNTOUCHABLE_PAIRING"),"state protected after rejection");
            Console.WriteLine("PASS: path escape rejected.");
        }
        finally { Directory.Delete(root,true); }
    }
}
