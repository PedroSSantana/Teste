using Teste.Api.Models;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.MapGet("/", () =>
{
    return "API de inventário funcionando!";
});

app.MapPost("/inventario", (Inventario dados) =>
{
    Console.WriteLine();
    Console.WriteLine("=================================");
    Console.WriteLine("NOVO INVENTÁRIO RECEBIDO");
    Console.WriteLine("=================================");

    Console.WriteLine($"Computador: {dados.Computador}");
    Console.WriteLine($"Usuário: {dados.Usuario}");
    Console.WriteLine($"Data: {dados.DataColeta}");
    Console.WriteLine($"Sistema: {dados.SistemaOperacional}");
    Console.WriteLine($"Processador: {dados.Processador}");
    Console.WriteLine($"Núcleos: {dados.Nucleos}");
    Console.WriteLine($"Threads: {dados.Threads}");
    Console.WriteLine($"RAM: {dados.MemoriaRamBytes} bytes");
    Console.WriteLine($"GPU: {dados.PlacaVideo}");

    return Results.Ok(new
    {
        sucesso = true,
        mensagem = "Inventário recebido com sucesso."
    });
});

app.Run();

