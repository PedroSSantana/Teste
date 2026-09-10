using System.Diagnostics;
using Microsoft.Win32;
using Teste.Core;
using Teste.Native;

namespace Teste.Collect;

public static class AvInventario
{
    // Tokens conhecidos: produto instalado, servico com nome/path que casa com antivirus.
    private static readonly string[] Tokens =
    {
        "defender","msmpeng","windefend","wdenable","sentinel","cylance","crowdstrike","falcon",
        "carbonblack","cb.exe","symantec","sep","ccSvcHst","mcafee","mcshield","trendmicro","tmccsfw",
        "kaspersky","avp.exe","avastui","aswids","avg","eset","ekrn","egui","bitdefender","vscore",
        "vsserv","panda","avira","sophos","sav","webroot","wrsh","forticlient","fireeye","maldoc",
        "malwarebytes","mbam","superantispyware","norton","ntrtscan","nhancer"
    };

    // Nome de servico que cada token costuma carregar. O sc query substitui o Win32_Service.
    private static readonly string[] ServiceGuesses =
    {
        "WinDefend","SecurityHealthService","Sense","SentinelAgent","CSFalconService",
        "CbDefense","Symantec Enterprise Protection","Sep Master Service","ccSetMgr","mcshield",
        "TmCCSF","TmPfw","kavfsg","klnagent","AVP19.0.1","AvastSvc","aswSP","aswMonFlt","avgsvc",
        "ekrn","efwflt","vsserv","vscore","PandaAgent","Avira.ServiceHost","Sophos SAV Service",
        "SavService","WebrootSvc","FortiClient","MBAMService","NortonEnterprise","NHancer"
    };

    public static void Collect(Report r, Logger log)
    {
        FromRegistry(r, log);
        FromServices(r, log);
        FromProcesses(r);
        r.FilterOutput = Shell("fltmc filters");   // o scanner de verdade mora aqui
        log.Line($"antivirus: {r.Avs.Count} produtos, {r.Filters.Count} processos ativos");
    }

    // SOFTWARE\...\Uninstall e onde todo AV se registra. E o mesmo DisplayName que o
    // SecurityCenter2 devolve em displayName, sem precisar de WMI.
    private static void FromRegistry(Report r, Logger log)
    {
        const string Uninstall =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var root = machine.OpenSubKey(Uninstall);
                if (root is null) continue;

                foreach (var sub in root.GetSubKeyNames())
                {
                    try
                    {
                        using var app = root.OpenSubKey(sub);
                        if (app is null) continue;

                        var name = app.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(name)) continue;

                        var publisher = app.GetValue("Publisher") as string ?? "";
                        var path = app.GetValue("InstallLocation") as string
                                   ?? app.GetValue("UninstallString") as string ?? "";

                        var hay = $"{name} {publisher} {path}".ToLowerInvariant();
                        if (!Tokens.Any(t => hay.Contains(t))) continue;

                        var hit = r.Avs.FirstOrDefault(a =>
                            a.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                        if (hit is null)
                        {
                            r.Avs.Add(hit = new AvRec
                            {
                                Name = name.Trim(),
                                Kind = "registrado",
                                Path = Clean(path)
                            });
                        }
                        else if (string.IsNullOrEmpty(hit.Path))
                        {
                            hit.Path = Clean(path);
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                r.Errors.Add(new ErrorRec("antivirus", $"Uninstall/{view}: {ex.Message}"));
            }
        }
    }

    // sc query exaustivo devolve NOME + ESTADO + TIPO + ROTA de cada servico. Sem WMI,
    // sem assembly extra, e o estado vem verificavel (RUNNING/STOPPED) em vez do
    // productState de layout nao documentado.
    private static void FromServices(Report r, Logger log)
    {
        var dump = Shell("sc query exaustivo");
        if (dump.StartsWith("indisponivel"))
        {
            r.Errors.Add(new ErrorRec("antivirus", $"sc query: {dump}"));
            return;
        }

        foreach (var block in dump.Split(new[] { "\r\n\r\n", "\n\n" },
                                        StringSplitOptions.RemoveEmptyEntries))
        {
            var svc = Field(block, "NOME");
            if (string.IsNullOrEmpty(svc)) continue;

            var display = Field(block, "DESCRICAO");
            var path = Field(block, "BINARIO DA ROTA") ?? Field(block, "PATH DO BINARIO");
            var state = Field(block, "ESTADO");

            var hay = $"{svc} {display} {path}".ToLowerInvariant();
            if (!Tokens.Any(t => hay.Contains(t))) continue;

            var hit = r.Avs.FirstOrDefault(a =>
                a.Service.Equals(svc, StringComparison.OrdinalIgnoreCase) ||
                hay.Contains(Sig(a.Name)));

            if (hit is null)
            {
                r.Avs.Add(hit = new AvRec
                {
                    Name = string.IsNullOrWhiteSpace(display) ? svc : display.Trim(),
                    Kind = "servico"
                });
            }

            hit.Service = svc;
            hit.ServiceState = state ?? "";
            if (string.IsNullOrEmpty(hit.Path) && !string.IsNullOrWhiteSpace(path))
                hit.Path = Clean(path!);
        }

        // StartMode nao vem no sc query; pega do registro, servico por servico.
        foreach (var av in r.Avs)
        {
            if (string.IsNullOrEmpty(av.Service) || !string.IsNullOrEmpty(av.StartMode)) continue;
            av.StartMode = RegistryStart(av.Service);
        }
    }

    // Todo processo cuja imagem casa com um token. Este e o alvo do suspend.
    private static void FromProcesses(Report r)
    {
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                var img = Procs.ImagePath(p.Id);
                var hay = $"{p.ProcessName} {img}".ToLowerInvariant();
                if (!Tokens.Any(t => hay.Contains(t))) continue;

                var dono = img is null ? null : r.Avs.FirstOrDefault(a =>
                    a.Path.Length > 0 &&
                    img.StartsWith(Dir(a.Path), StringComparison.OrdinalIgnoreCase));

                r.Filters.Add(new ProcRec
                {
                    Pid = p.Id,
                    Name = p.ProcessName,
                    Image = img ?? "",
                    Parent = ProcessTree.ParentOf(p.Id),
                    Owner = dono?.Name ?? "(sem produto associado)"
                });
            }
            catch { }
            finally { p.Dispose(); }
        }
    }

    // StartType: 2=automatico 3=manual 4=desabilitado.
    private static string RegistryStart(string service)
    {
        try
        {
            using var machine = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = machine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{service}");
            var start = key?.GetValue("Start");
            return start switch
            {
                2 => "Auto",
                3 => "Manual",
                4 => "Disabled",
                _ => ""
            };
        }
        catch { return ""; }
    }

    // sc.exe imprime no idioma do Windows, entao casa pela prefixacao, nao pelo nome
    // traduzido: "NOME", "NAME", "Nom" caem no mesmo StartsWith.
    private static string? Field(string block, params string[] prefixes)
    {
        foreach (var raw in block.Split('\n'))
        {
            var line = raw.Trim();
            var i = line.IndexOf(':');
            if (i <= 0) continue;
            var label = line[..i].Trim();
            if (!prefixes.Any(p => label.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                continue;
            var value = line[(i + 1)..].Trim();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        return null;
    }

    private static string Clean(string path)
    {
        var p = (path ?? "").Trim().Trim('"');
        var cut = p.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return cut > 0 ? p[..(cut + 4)] : p;
    }

    private static string Dir(string path)
    {
        var clean = path.Trim().Trim('"');
        var dir = Path.GetDirectoryName(clean);
        return string.IsNullOrEmpty(dir) ? clean : dir;
    }

    private static string Sig(string n) => n.Split(' ')[0].ToLowerInvariant();

    private static string Shell(string cmd)
    {
        try
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8
            };
            using var ps = Process.Start(psi);
            if (ps is null) return "indisponivel: Process.Start null";
            var s = ps.StandardOutput.ReadToEnd();
            ps.WaitForExit(6000);
            return s;
        }
        catch (Exception ex) { return $"indisponivel: {ex.GetType().Name}"; }
    }
}