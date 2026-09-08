using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Teste.Native;

public static class Dpapi
{
    [StructLayout(LayoutKind.Sequential)] private struct BLOB { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref BLOB pDataIn, string? pDescr, IntPtr pEntropy,
        IntPtr pReserved, IntPtr pPrompt, int dwFlags, out BLOB pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr LocalFree(IntPtr h);

    public const int UI_FORGOTTEN = 0x4;

    public static byte[] Unprotect(byte[] blob, int flags = UI_FORGOTTEN)
    {
        var input = new BLOB { cbData = blob.Length, pbData = Marshal.AllocHGlobal(blob.Length) };
        Marshal.Copy(blob, 0, input.pbData, blob.Length);
        try
        {
            if (!CryptUnprotectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, flags, out var output))
                throw new CryptographicException(Marshal.GetLastWin32Error());   // 13001/13009 = outro usuário
            try
            {
                var data = new byte[output.cbData];
                Marshal.Copy(output.pbData, data, 0, output.cbData);
                return data;
            }
            finally { LocalFree(output.pbData); }
        }
        finally { Marshal.FreeHGlobal(input.pbData); }
    }
}

public static class Crypto
{
    public static byte[] OpenKeyed(byte[] key, byte[] blob)
    {
        if (blob.Length < 31) throw new CryptographicException("blob curto");
        var ver = Encoding.ASCII.GetString(blob, 0, 3);
        if (ver is not ("v10" or "v11")) throw new CryptographicException($"versao '{ver}'");
        return OpenGcm(key, blob.AsSpan(3));
    }

    public static byte[] OpenGcm(byte[] key, ReadOnlySpan<byte> v)
    {
        var pt = new byte[v.Length - 28];                       // nonce(12) + ct + tag(16)
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(v[..12], v.Slice(12, v.Length - 28), v[^16..], pt);
        return pt;
    }

    public static byte[] StripHostPrefix(byte[] plain, string hostKey)
    {
        if (plain.Length <= 32) return plain;
        if (plain.AsSpan(0, 32).SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(hostKey)))) return plain[32..];
        return plain;
    }

    public static string? ChromeTime(long microseconds)
    {
        if (microseconds <= 0 || microseconds > 99486215040000000L) return null;
        try { return DateTimeOffset.FromFileTimeUtc(microseconds * 10).ToString("O"); } catch { return null; }
    }

    public static double Entropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        var counts = new int[256];
        foreach (var b in data) counts[b]++;
        double h = 0;
        foreach (var c in counts)
            if (c > 0) { var p = (double)c / data.Length; h -= p * Math.Log2(p); }
        return h;
    }
}