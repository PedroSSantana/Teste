namespace Teste.Api.Models;

public class Inventario
{
    public string Computador { get; set; } = "";

    public string Usuario { get; set; } = "";

    public DateTime DataColeta { get; set; }

    public string SistemaOperacional { get; set; } = "";

    public string Processador { get; set; } = "";

    public int Nucleos { get; set; }

    public int Threads { get; set; }

    public long MemoriaRamBytes { get; set; }

    public string PlacaVideo { get; set; } = "";
}