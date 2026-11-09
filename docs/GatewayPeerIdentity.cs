using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

// A public enrollment code ties one device's existing DM1 signing identity
// to the WireGuard public key generated on that very same machine.
// Only the NAS owner can authorize either key.
internal static class GatewayPeerIdentity
{
    internal static string ValidateDm1(string code)
    {
        string text = (code ?? "").Trim();
        if (!Regex.IsMatch(text, @"\ADM1-[a-f0-9]{64}\z"))
            throw new ArgumentException("Expected DM1 signing identity.");
        return text;
    }

    internal static string ClientAddress(string dm1)
    {
        dm1 = ValidateDm1(dm1);
        var pub = new byte[32];
        for (int i=0; i<pub.Length; ++i)
            pub[i] = Convert.ToByte(dm1.Substring(4+i*2, 2), 16);
        using (var sha = SHA256.Create())
        {
            byte[] digest = sha.ComputeHash(pub);
            string ip = "10.93." + digest[16] + "." + digest[17];
            if (ip == "10.93.42.1" || ip == "10.93.42.2")
                throw new InvalidDataException("Peer identity maps to a reserved tunnel address.");
            return ip;
        }
    }

    internal static string RegistrationCode(string dm1, string wireguardPublicKey)
    {
        dm1=ValidateDm1(dm1);
        string key=WireGuardProvisioning.ValidateKey(wireguardPublicKey);
        return "DMW1:" + dm1 + ":" + key;
    }

    internal static void ParseRegistrationCode(string code, out string dm1, out string wireguardPublicKey)
    {
        var parts = (code ?? "").Split(':');
        if (parts.Length != 3 || parts[0] != "DMW1")
            throw new ArgumentException("Expected complete DMW1 registration code.");
        dm1 = ValidateDm1(parts[1]);
        wireguardPublicKey = WireGuardProvisioning.ValidateKey(parts[2]);
        ClientAddress(dm1);
    }
}
