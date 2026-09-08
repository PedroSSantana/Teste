using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Teste.Core;
using Teste.Native;

namespace Teste.Collect;

public static class TargetCollector
{
    public static void Collect(Report r)
    {
        ScanFiles(r);
        ScanMasterKeys(r);
        ScanEfs(r);
        ScanBitLocker(r);
    }

    private static void ScanFiles(Report r)
    {
        var roots = Flags.Roots.Count > 0
            ? Flags.Roots
            : DriveInfo.GetDrives()
                .Where(d => d.DriveType is DriveType.Fixed or DriveType.Removable && d.IsReady)
                .Select(d => d.RootDirectory.FullName);

        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) { r.Errors.Add(new ErrorRec("targets", $"raiz nao existe: {root}")); continue; }
            foreach (var path in Enumerate.Safe(root))
            {
                if (r.Targets.Count >= Limits.Targets) return;
                try
                {
                    var t = Triage(path);
                    if (t != null) r.Targets.Add(t);
                }
                catch { }
            }
        }
    }

    private static TargetRec? Triage(string path)
    {
        var fi = new FileInfo(path);
        if (fi.Length < Limits.MinBytes) return null;

        var head = Files.Head(path, 4096);
        if (head.Length < 8) return null;

        var sig = Magic.Classify(path, head);
        if (sig is null) return null;

        // descartas que salvam GPU:
        if (sig.Kind == "zip" && !Magic.ZipEncrypted(head)) return null;
        if (sig.Kind == "pdf" && !Magic.PdfEncrypted(head) && !Magic.PdfEncrypted(Files.Tail(path, 65536))) return null;
        if (sig.Kind == "ole-office" && fi.Length <= 1_000_000 && !Magic.OLEEncrypted(Files.Head(path, 1_000_000))) return null;

        var entropy = Crypto.Entropy(head);
        if (sig.Mode is null && entropy < Limits.MinEntropy) return null;   // so a extensao, sem cara de cifra

        return new TargetRec
        {
            Path = path,
            Kind = sig.Kind,
            ModeHint = sig.Mode,
            Extractor = sig.Extractor,
            Size = fi.Length,
            Mtime = fi.LastWriteTimeUtc.ToString("O"),
            Entropy = Math.Round(entropy, 2),
            WholeFileNeeded = sig.WholeFile,
            HeaderBytes = (int)Math.Min(sig.HeaderBytes > 0 ? sig.HeaderBytes : 4096, Limits.HeaderBytes),
            Fingerprint = Finger(path, fi),
            Confidence = entropy >= 7.6 ? "alta" : "media"
        };
    }

    // %APPDATA%\Microsoft\Protect\<SID>\<GUID> -> DPAPI masterkey: alvo 15300/15900 de usuario morto
    private static void ScanMasterKeys(Report r)
    {
        var protect = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Protect");
        if (!Directory.Exists(protect)) return;

        foreach (var sidDir in Directory.EnumerateDirectories(protect))
        foreach (var f in Directory.EnumerateFiles(sidDir))
        {
            try
            {
                var bytes = Files.Head(f, 8192);
                if (bytes.Length < 48) continue;
                var ver = BitConverter.ToInt32(bytes, 4);
                var mode = ver >= 2 ? 15900 : 15300;

                r.Targets.Add(new TargetRec
                {
                    Path = f,
                    Kind = "dpapi-masterkey",
                    ModeHint = mode,
                    Extractor = $"hashcat -m {mode} (SID = {Path.GetFileName(sidDir)})",
                    Size = new FileInfo(f).Length,
                    Mtime = File.GetLastWriteTimeUtc(f).ToString("O"),
                    Entropy = Math.Round(Crypto.Entropy(bytes), 2),
                    HeaderBytes = (int)Math.Min(new FileInfo(f).Length, Limits.HeaderBytes),
                    Fingerprint = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
                    Confidence = "alta"
                });
            }
            catch { }
        }
    }

    private static void ScanEfs(Report r)
    {
        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (var dir in new[]
        {
            Path.Combine(user, "Documents"), Path.Combine(user, "Desktop"), Path.Combine(user, "Downloads")
        })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var f in Enumerate.Safe(dir))
            {
                try
                {
                    if ((File.GetAttributes(f) & FileAttributes.Encrypted) == 0) continue;
                    var fi = new FileInfo(f);
                    r.Targets.Add(new TargetRec
                    {
                        Path = f, Kind = "efs", Extractor = "precisa do certificado/DFPU do usuario",
                        Size = fi.Length, Mtime = fi.LastWriteTimeUtc.ToString("O"),
                        WholeFileNeeded = true, Confidence = "alta"
                    });
                }
                catch { }
            }
        }
    }

    // manage-bde sem admin devolve lista sem protecao: por isso o erro explicito.
    private static void ScanBitLocker(Report r)
    {
        var outp = Shell.Run("manage-bde", "-status");
        if (string.IsNullOrWhiteSpace(outp))
        {
            r.Errors.Add(new ErrorRec("bitlocker", "manage-bde vazio ou sem privilegio"));
            return;
        }

        foreach (var block in Regex.Split(outp, @"Volume\s+\(.*?\):", RegexOptions.IgnoreCase))
        {
            var letter = Regex.Match(block, @"([A-Z]:)").Groups[1].Value;
            var conv = Regex.Match(block, @"Conversion Status\s*:\s*(.+)").Groups[1].Value.Trim();
            if (letter == "" || !(conv.Contains("Used", StringComparison.OrdinalIgnoreCase)
                               || conv.Contains("Fully", StringComparison.OrdinalIgnoreCase))) continue;

            var pin = Regex.Match(block, @"PIN\s*:\s*(\w+)").Groups[1].Value;
            var pwd = Regex.Match(block, @"Password\s*:\s*(\w+)").Groups[1].Value;
            long size = 0;
            try { size = new DriveInfo(letter).TotalSize; } catch { }

            r.Targets.Add(new TargetRec
            {
                Path = letter + "\\", Kind = "bitlocker",
                ModeHint = pin.Equals("Yes", StringComparison.OrdinalIgnoreCase) ? 24210 : 24200,
                Extractor = "bitlocker2john / dislocker (extracao do VMK pede admin)",
                Size = size, Mtime = "", Entropy = 8.0,
                WholeFileNeeded = true,
                Confidence = pwd.Equals("Yes", StringComparison.OrdinalIgnoreCase) ||
                             pin.Equals("Yes", StringComparison.OrdinalIgnoreCase) ? "alta" : "media"
            });
        }
    }

    private static string Finger(string path, FileInfo fi)
    {
        using var s = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var head = new byte[(int)Math.Min(1 << 20, s.Length)];
        s.Read(head);
        if (fi.Length <= Limits.MaxFullHash)
            return Convert.ToHexString(SHA256.HashData(s)).ToLowerInvariant();

        using var sha = SHA256.Create();
        var key = $"{Convert.ToHexString(sha.ComputeHash(head))}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}";
        return "partial-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant();
    }
}