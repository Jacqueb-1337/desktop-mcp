using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

internal static class GatewayPeerIdentityTests
{
    private static void Assert(bool condition, string failure) {if(!condition)throw new Exception(failure);}
    private static string Key(int seed)
    {
        var bytes=new byte[32];
        for(int i=0;i<32;i++)bytes[i]=(byte)(seed+i);
        return Convert.ToBase64String(bytes);
    }
    public static void Main()
    {
        var dm1="DM1-"+new string('a',64);
        var wg=Key(9);
        string reg=GatewayPeerIdentity.RegistrationCode(dm1,wg);
        string parsedDm1,parsedWire;
        GatewayPeerIdentity.ParseRegistrationCode(reg,out parsedDm1,out parsedWire);
        Assert(parsedDm1==dm1 && parsedWire==wg,"Registration code roundtrip");
        Assert(reg.StartsWith("DMW1:DM1-"),"One-copy onboarding token");
        string addr=GatewayPeerIdentity.ClientAddress(dm1);
        byte[] hash;
        using(var sha=SHA256.Create())hash=sha.ComputeHash(Enumerable.Repeat((byte)0xaa,32).ToArray());
        string expected="10.93."+hash[16]+"."+hash[17];
        Assert(addr==expected,"NAS and Windows deterministic client IP derivation");
        Assert(!addr.Equals("10.93.42.1"),"Never uses gateway tunnel IP");
        bool invalid=false;
        try { GatewayPeerIdentity.ParseRegistrationCode(reg+"A",out parsedDm1,out parsedWire); }
        catch(ArgumentException){invalid=true;}
        Assert(invalid,"Reject malformed registration code");
        Console.WriteLine("PASS: client tunnel address and DMW1 registration code.");
    }
}
