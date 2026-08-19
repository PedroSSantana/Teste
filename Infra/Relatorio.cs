using System;
using System.IO;
using System.Text;

namespace Teste.Infra
{
    public class Relatorio
    {
        private readonly string pastaDoDia;

        public Relatorio()
        {
            // Data da execução
            DateTime hoje = DateTime.Now;

            // Pasta principal dos relatórios
            string pastaRelatorios = Path.Combine(
                AppContext.BaseDirectory,
                "Relatorios"
            );

            // Pasta específica do dia
            string nomePasta =
                "Dia " + hoje.ToString("dd-MM-yyyy");

            pastaDoDia = Path.Combine(
                pastaRelatorios,
                nomePasta
            );

            // Cria as pastas caso não existam
            Directory.CreateDirectory(pastaDoDia);
        }


        // ==================================================
        // CRIAR ARQUIVO DE RELATÓRIO
        // ==================================================

        public void CriarArquivo(
            string nomeArquivo,
            string titulo,
            StringBuilder conteudo)
        {
            string caminho = Path.Combine(
                pastaDoDia,
                nomeArquivo
            );

            StringBuilder relatorio =
                new StringBuilder();

            relatorio.AppendLine(
                "============================================================"
            );

            relatorio.AppendLine(
                titulo
            );

            relatorio.AppendLine(
                "============================================================"
            );

            relatorio.AppendLine();

            relatorio.AppendLine(
                "Data da coleta: " +
                DateTime.Now.ToString(
                    "dd/MM/yyyy HH:mm:ss"
                )
            );

            relatorio.AppendLine();

            relatorio.Append(
                conteudo.ToString()
            );

            relatorio.AppendLine();

            relatorio.AppendLine(
                "============================================================"
            );

            relatorio.AppendLine(
                "                    FIM DO RELATÓRIO"
            );

            relatorio.AppendLine(
                "============================================================"
            );

            File.WriteAllText(
                caminho,
                relatorio.ToString(),
                Encoding.UTF8
            );
        }


        // ==================================================
        // LOCAL DA PASTA
        // ==================================================

        public string ObterPasta()
        {
            return pastaDoDia;
        }
    }
}