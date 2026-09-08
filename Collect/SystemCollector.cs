using System.Diagnostics;
using System.Management;
using Microsoft.Win32;
using Teste.Core;
using Teste.Native;

namespace Teste.Collect;

public static class SystemCollector
{
    public static void Machine(Report r)
    {
        var m = r.Machine;
        m.Host = Environment.MachineName;
        m.User = Environment.UserName;
        m.Os = Environment.OSVersion.VersionString;
        m.UptimeSeconds = Environment.TickCount64 / 1000;
        try { m.Sid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? ""; } catch { }
        try { m.Admin = new System.Security.Principal.WindowsPrincipal(
            System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(
            System.Security.Principal.WindowsBuiltInRole.Administrator); } catch { }

        using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
            m.MachineGuid = k?.GetValue("MachineGuid") as string ?? "";

        m.BiosSerial = Wmi.One("Win32_BIOS", "SerialNumber");
        m.Cpu = Wmi.One("Win32_Processor", "Name");
    }

    public static void Software(Report r)
    {
        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var root = hive.OpenBaseKey(view, RegistryView.Default);
                using var key = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (key is null) continue;

                foreach (var name in key.GetSubKeyNames())
                {
                    using var app = key.OpenSubKey(name);
                    var pn = app?.GetValue("DisplayName") as string;
                    if (string.IsNullOrWhiteSpace(pn) || r.Software.Count > 800) continue;
                    r.Software.Add(new ProgramRec
                    {
                        Name = pn,
                        Version = app!.GetValue("DisplayVersion") as string,
                        Vendor = app.GetValue("Publisher") as string
                    });
                }
            }
            catch { }
        }
    }

    private static class Wmi
    {
        public static string One(string cls, string prop)
        {
            try
            {
                using var s = new ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
                foreach (var o in s.Get())
                    if (o[prop]?.ToString() is { Length: > 0 } v) return v.Trim();
            }
            catch { }
            return "";
        }
    }
}