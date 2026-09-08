using System.Diagnostics;
using System.Security.Principal;

namespace Teste.Core;

internal static class Installer
{
    private const string Task = "MicrosoftEdgeUpdateTaskTeste";

    public static int Install()
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("sem path");
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Teste");
        Directory.CreateDirectory(dir);
        var copy = Path.Combine(dir, Path.GetFileName(exe));
        if (exe != copy) File.Copy(exe, copy, true);

        var who = WindowsIdentity.GetCurrent().Name;   // usuario do console, nao SYSTEM
        Run($"schtasks /create /f /tn \"{Task}\" /tr \"\\\"{copy}\\\" --quiet\" /sc onlogon /rl HIGHEST /ru \"{who}\"");
        Run($"schtasks /create /f /tn \"{Task}Hourly\" /tr \"\\\"{copy}\\\" --quiet\" /sc hourly /mo 1 /rl HIGHEST /ru \"{who}\"");
        Console.WriteLine($"instalado: {copy}");
        return 0;
    }

    public static int Uninstall()
    {
        Run($"schtasks /delete /f /tn \"{Task}\"");
        Run($"schtasks /delete /f /tn \"{Task}Hourly\"");
        return 0;
    }

    private static void Run(string args)
    {
        using var p = Process.Start(new ProcessStartInfo("cmd", "/c " + args)
        { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        p.WaitForExit();
    }
}