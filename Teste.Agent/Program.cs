using System.Diagnostics;
using System.Security.Principal;
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

        Flags.Parse(args);
        var log = new Logger(f.Contains("debug"));
        var r = Report.New();
        var all = Stopwatch.StartNew();
        var executed = new List<string>();
        AvGuard? guard = null;

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
                guard = new AvGuard(log).Disable(r);
                log.Line($"[av]    {r.AvAction}");
            }
        }

        r.Finish();
        r.ScanSeconds = Math.Round(all.Elapsed.TotalSeconds, 2);

        var dir = ReportWriter.Write(r, executed);

        // so existe reversao se houve acao
        if (guard is not null)
        {
            guard.Restore(r);
            dir = ReportWriter.Write(r, executed);   // mesma pasta: o nome sai de r.StartedAt
        }

        if (f.Contains("send")) Uploader.Send(r, log);
        if (f.Contains("json")) Console.WriteLine(r.ToJson(true));

        // unica linha que o terminal recebe numa execucao normal
        Console.WriteLine(dir);
        return 0;
    }
}
