using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

// File-only transaction. It never accepts a state directory as a write target.
// Callers stop the relevant processes first and restart them after Apply.
// Backup files remain available until Commit, and can be recovered after failure.
internal sealed class BinaryUpgradeTransaction
{
    private sealed class Entry
    {
        internal string Target;
        internal string Incoming;
        internal string Backup;
        internal byte[] PreviousDigest;
        internal bool Existed;
        internal bool Applied;
    }

    private readonly string root;
    private readonly string working;
    private readonly List<Entry> entries = new List<Entry>();
    private bool completed;

    internal BinaryUpgradeTransaction(string installationRoot)
    {
        root = Path.GetFullPath(installationRoot).TrimEnd(Path.DirectorySeparatorChar);
        if (!Directory.Exists(root) ||
            (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Installation directory is missing or redirected.");
        working = Path.Combine(root, ".upgrade-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(working);
    }

    private static byte[] DigestFile(string file)
    {
        using (var sha = SHA256.Create())
        using (var read = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            return sha.ComputeHash(read);
    }

    private static bool SameBytes(byte[] left, byte[] right)
    {
        if (left == null || right == null || left.Length != right.Length) return false;
        int diff = 0;
        for (int i = 0; i < left.Length; ++i) diff |= left[i] ^ right[i];
        return diff == 0;
    }

    internal static void CheckOrdinaryFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException("Expected installed file is missing.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException("Refusing a redirected installed file.");
    }

    internal void Stage(string fileName, byte[] payload, bool allowNew)
    {
        if (completed) throw new InvalidOperationException("Upgrade already completed.");
        if (String.IsNullOrWhiteSpace(fileName) ||
            Path.GetFileName(fileName) != fileName ||
            fileName.IndexOfAny(new[]{'/', '\\', ':'}) >= 0 ||
            fileName.StartsWith(".", StringComparison.Ordinal))
            throw new ArgumentException("Upgrade target must be a direct installation filename.");
        if (payload == null || payload.Length == 0 || payload.Length > 67108864)
            throw new ArgumentException("Invalid embedded component size.");
        string target = Path.Combine(root, fileName);
        foreach (var item in entries)
            if (String.Equals(item.Target, target, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Duplicate upgrade target.");
        bool existed = File.Exists(target);
        if (!existed && !allowNew)
            throw new FileNotFoundException("Existing installed component is required.", target);
        if (existed) CheckOrdinaryFile(target);
        string index = entries.Count.ToString("D2");
        string incoming = Path.Combine(working, index + ".incoming");
        string backup = Path.Combine(working, index + ".previous");
        byte[] previous = null;
        if (existed)
        {
            previous = DigestFile(target);
            File.Copy(target, backup, false);
            if (!SameBytes(previous, DigestFile(backup)))
                throw new IOException("Could not verify component backup.");
        }
        using (var output = new FileStream(incoming, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            output.Write(payload, 0, payload.Length);
            output.Flush(true);
        }
        using (var sha = SHA256.Create())
            if (!SameBytes(sha.ComputeHash(payload), DigestFile(incoming)))
                throw new IOException("Staged component checksum mismatch.");
        entries.Add(new Entry{
            Target = target, Incoming = incoming, Backup = backup,
            PreviousDigest = previous, Existed = existed
        });
    }

    internal void Apply()
    {
        if (completed) throw new InvalidOperationException("Upgrade already completed.");
        foreach (var entry in entries)
        {
            if (entry.Existed)
            {
                CheckOrdinaryFile(entry.Target);
                if (!SameBytes(entry.PreviousDigest, DigestFile(entry.Target)))
                    throw new IOException("An installed component changed during the update.");
                File.Replace(entry.Incoming, entry.Target, null, false);
            }
            else
            {
                if (File.Exists(entry.Target) || Directory.Exists(entry.Target))
                    throw new IOException("An upgrade target unexpectedly appeared.");
                File.Move(entry.Incoming, entry.Target);
            }
            entry.Applied = true;
        }
    }

    internal void Rollback()
    {
        if (completed) throw new InvalidOperationException("Upgrade already completed.");
        for (int i = entries.Count - 1; i >= 0; --i)
        {
            var entry = entries[i];
            if (!entry.Applied) continue;
            if (entry.Existed)
            {
                CheckOrdinaryFile(entry.Target);
                if (!SameBytes(entry.PreviousDigest, DigestFile(entry.Backup)))
                    throw new IOException("Backup integrity mismatch. Backup retained at " + working);
                string restoring = Path.Combine(working, i.ToString("D2") + ".restore");
                File.Copy(entry.Backup, restoring, false);
                File.Replace(restoring, entry.Target, null, false);
                if (!SameBytes(entry.PreviousDigest, DigestFile(entry.Target)))
                    throw new IOException("Restore verification failed. Backup retained at " + working);
            }
            else if (File.Exists(entry.Target)) File.Delete(entry.Target);
            entry.Applied = false;
        }
        Commit();
    }

    internal void Commit()
    {
        if (completed) throw new InvalidOperationException("Upgrade already completed.");
        Directory.Delete(working, true);
        completed = true;
    }

    internal string BackupDirectory { get { return working; } }
}
