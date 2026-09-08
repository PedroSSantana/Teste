using System.Diagnostics;
using Teste.Core;
using Teste.Exfil;

namespace Teste;

internal static class Program
{
    private static int Main(string[] args)
    {
        var f = args.Select(a => a.TrimStart('-').ToLowerInvariant()).ToHashSet();
        if (f.Contains("uninstall")) return Installer.Uninstall();
        if (f.Contains("install")) return Installer.Install();

        Flags.Parse(args);
        var log = new Logger(f.Contains("debug"));
        var r = Report.New();
        var all = Stopwatch.StartNew();
        var executed = new List<string>();

        foreach (var step in Steps.All(log))
        {
            if (!Steps.Wanted(step.Key)) { log.Line($"[pula] {step.Key}"); continue; }
            var sw = Stopwatch.StartNew();
            try
            {
                step.Collect(r);
                executed.Add(step.Key);
                log.Line($"[ok]   {step.Key,-8} {sw.ElapsedMilliseconds,6} ms");
            }
            catch (Exception ex)
            {
                r.Errors.Add(new ErrorRec(step.Key, $"{ex.GetType().Name}: {ex.Message}"));
                log.Line($"[falha]{step.Key,-8} {ex.GetType().Name}: {ex.Message}");
            }
        }

        r.Finish();
        r.ScanSeconds = Math.Round(all.Elapsed.TotalSeconds, 2);

        var dir = ReportWriter.Write(r, executed);

        if (f.Contains("send")) Uploader.Send(r, log);
        if (f.Contains("json")) Console.WriteLine(r.ToJson(true));

        // unica linha que o terminal recebe numa execucao normal
        Console.WriteLine(dir);
        return 0;
    }
}