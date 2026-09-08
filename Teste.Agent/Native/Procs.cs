using System.Runtime.InteropServices;
using System.Management;
using System.Text;

namespace Teste.Native;

public static class Procs
{
    public static int ParentOf(int pid)
    {
        try
        {
            using var col = new ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}").Get();
            foreach (ManagementObject o in col)
                return Convert.ToInt32(o["ParentProcessId"]);
        }
        catch { }
        return -1;
    }
    
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("ntdll.dll")] private static extern int NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")] private static extern int NtResumeProcess(IntPtr h);

    private const int QueryLimited = 0x1000, SuspendResume = 0x0800;

    public static string? ImagePath(int pid)
    {
        var h = OpenProcess(QueryLimited, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            var size = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally { CloseHandle(h); }
    }

    // A contagem de suspensao vive no objeto do processo, nao no handle:
    // fechar o handle mantem o processo congelado.
    public static bool Suspend(int pid) => Call(pid, NtSuspendProcess);
    public static bool Resume(int pid) => Call(pid, NtResumeProcess);

    private static bool Call(int pid, Func<IntPtr, int> nt)
    {
        var h = OpenProcess(SuspendResume, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return nt(h) == 0; }
        finally { CloseHandle(h); }
    }
}
