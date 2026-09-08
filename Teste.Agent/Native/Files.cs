using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Teste.Native;

public static class Files
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CopyFileW(string from, string to, bool failIfExists);

    public static void Copy(string src, string dst)
    {
        try
        {
            using var fs = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var to = File.Create(dst);
            fs.CopyTo(to);
        }
        catch (IOException)
        {
            if (!CopyFileW(src, dst, false)) Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
        }
    }

    public static string ReadAllText(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var sr = new StreamReader(fs, Encoding.UTF8);
        return sr.ReadToEnd();
    }

    public static byte[] Head(string path, int count)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var buf = new byte[(int)Math.Min(count, fs.Length)];
        var n = fs.Read(buf, 0, buf.Length);
        return n == buf.Length ? buf : buf[..n];
    }

    public static byte[] Tail(string path, int count)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var len = (int)Math.Min(count, fs.Length);
        fs.Seek(-len, SeekOrigin.End);
        var buf = new byte[len];
        fs.ReadExactly(buf);
        return buf;
    }
}

internal sealed class DbSnapshot : IDisposable
{
    private readonly string _dir;
    public SqliteConnection Conn { get; }

    public DbSnapshot(string dbPath)
    {
        _dir = Path.Combine(Path.GetTempPath(), "tsc" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(_dir);
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            var src = dbPath + suffix;
            if (!File.Exists(src)) continue;
            try { Files.Copy(src, Path.Combine(_dir, Path.GetFileName(src))); } catch when (suffix.Length > 0) { }
        }
        Conn = new SqliteConnection($"Data Source={Path.Combine(_dir, Path.GetFileName(dbPath))}");
        Conn.Open();          // read-write no snapshot: o SQLite reaplica o WAL antes da leitura
    }

    public void Dispose()
    {
        Conn.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { }
    }
}

internal static class Enumerate
{
    private static readonly string[] Skip =
    {
        @"\\Windows", @"\Program Files", @"\Program Files (x86)", @"\ProgramData",
        @"\AppData\Local\Temp", @"node_modules", @"\.nuget", @"\.gradle", @"$Recycle.Bin", @"AppData\Local\Packages"
    };

    public static IEnumerable<string> Safe(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> subs, files;
            try { subs = Directory.EnumerateDirectories(dir); } catch { subs = Array.Empty<string>(); }
            try { files = Directory.EnumerateFiles(dir); } catch { files = Array.Empty<string>(); }

            foreach (var f in files) yield return f;
            foreach (var s in subs)
            {
                if (Skip.Any(k => s.EndsWith(k, StringComparison.OrdinalIgnoreCase) || s.Contains(k, StringComparison.OrdinalIgnoreCase))) continue;
                try
                {
                    var a = File.GetAttributes(s);
                    if ((a & (FileAttributes.ReparsePoint | FileAttributes.Hidden | FileAttributes.System)) != 0) continue;
                }
                catch { continue; }
                stack.Push(s);
            }
        }
    }
}

internal static class Shell
{
    public static string Run(string file, string args, int ms = 15000)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args)
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            })!;
            var o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(ms);
            return o;
        }
        catch { return ""; }
    }
}