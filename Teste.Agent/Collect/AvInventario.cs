using System.Diagnostics;
using System.Management;
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

    public static void Collect(Report r, Logger log)
    {
        FromSecurityCenter(r, log);
        FromServices(r, log);
        FromProcesses(r);
        r.FilterOutput = Shell("fltmc filters");   // o scanner de verdade mora aqui
        log.Line($"antivirus: {r.Avs.Count} produtos, {r.Filters.Count} processos ativos");
    }

    // root\SecurityCenter2 e o registro oficial do Windows: o que se declarou como antivirus.
    private static void FromSecurityCenter(Report r, Logger log)
    {
        try
        {
            using var scope = new ManagementScope(@"root\SecurityCenter2") { Options = { EnablePrivileges = true } };
            scope.Connect();
            using var searcher = new ManagementObjectSearcher("SELECT * FROM AntiVirusProduct");
            searcher.Scope = scope;
            foreach (ManagementObject o in searcher.Get())
            {
                var name = o["displayName"]?.ToString() ?? "(sem nome)";
                var st = o["productState"]?.ToString();
                r.Avs.Add(new AvRec
                {
                    Name = name,
                    Kind = "registrado",
                    ProductState = st is null ? "" : $"0x{Convert.ToInt64(st):X6}",
                    Path = o["pathToSignedProductExe"]?.ToString() ?? ""
                });
            }
        }
        catch (Exception ex) { r.Errors.Add(new ErrorRec("antivirus", $"SecurityCenter2: {ex.Message}")); }
    }

    // productState e um DWORD de layout nao documentado. Registro o hex e decido pelo
    // estado do servico, que e verificavel: servico parado nao assina nada.
    private static void FromServices(Report r, Logger log)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service");
            foreach (ManagementObject o in searcher.Get())
            {
                var hay = $"{o["Name"]} {o["DisplayName"]} {o["PathName"]}".ToLowerInvariant();
                if (!Tokens.Any(t => hay.Contains(t))) continue;
                var svc = o["Name"]!.ToString();
                var hit = r.Avs.FirstOrDefault(a => hay.Contains(Sig(a.Name)));
                if (hit is null) r.Avs.Add(hit = new AvRec { Name = svc, Kind = "servico" });
                hit.Service = svc;
                hit.ServiceState = o["State"]?.ToString() ?? "";
                hit.StartMode = o["StartMode"]?.ToString() ?? "";
                if (string.IsNullOrEmpty(hit.Path)) hit.Path = o["PathName"]?.ToString() ?? "";
            }
        }
        catch (Exception ex) { r.Errors.Add(new ErrorRec("antivirus", $"Win32_Service: {ex.Message}")); }
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
                    Parent = Safe(p),
                    Owner = dono?.Name ?? "(sem produto associado)"
                });
            }
            catch { }
            finally { p.Dispose(); }
        }
    }

    private static string Dir(string path)
    {
        var clean = path.Trim().Trim('"');
        var dir = Path.GetDirectoryName(clean);
        return string.IsNullOrEmpty(dir) ? clean : dir;
    }

    private static int Safe(Process p) { try { return p.ParentId; } catch { return -1; } }
    private static string Sig(string n) => n.Split(' ')[0].ToLowerInvariant();
    private static string Shell(string cmd)
    {
        try
        {
            using var ps = Process.Start(new ProcessStartInfo("cmd", "/c " + cmd)
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true })!;
            var s = ps.StandardOutput.ReadToEnd(); ps.WaitForExit(4000);
            return s;
        }
        catch (Exception ex) { return $"indisponivel: {ex.GetType().Name}"; }
    }
}
