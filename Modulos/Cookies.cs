using System;
using System.IO;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Teste.Modulos
{
    public class Cookies
    {
        public StringBuilder Coletar()
        {
            StringBuilder resultado = new StringBuilder();

            resultado.AppendLine(
                "---------------- COOKIES DO CHROME ----------------"
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

                string caminhoCookies =
                    Path.Combine(
                        perfil,
                        "Network",
                        "Cookies"
                    );

                if (!File.Exists(caminhoCookies))
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
                        "ChromeCookies_" +
                        Guid.NewGuid().ToString("N") +
                        ".db"
                    );

                try
                {
                    File.Copy(
                        caminhoCookies,
                        copiaTemporaria,
                        true
                    );

                    ConsultarCookies(
                        copiaTemporaria,
                        resultado
                    );
                }
                catch (Exception erro)
                {
                    resultado.AppendLine(
                        "Erro ao consultar cookies: " +
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
                        // Não interrompe a coleta.
                    }
                }
            }

            return resultado;
        }


        private void ConsultarCookies(
            string banco,
            StringBuilder resultado)
        {
            using SqliteConnection conexao =
                new SqliteConnection(
                    $"Data Source={banco}"
                );

            conexao.Open();

            using SqliteCommand comando =
                conexao.CreateCommand();

            comando.CommandText = @"
                SELECT
                    host_key,
                    name,
                    path,
                    creation_utc,
                    expires_utc,
                    last_access_utc,
                    is_secure,
                    is_httponly,
                    length(encrypted_value)
                FROM cookies
                ORDER BY host_key, name;
            ";

            using SqliteDataReader leitor =
                comando.ExecuteReader();

            int quantidade = 0;

            while (leitor.Read())
            {
                string host =
                    leitor.IsDBNull(0)
                        ? ""
                        : leitor.GetString(0);

                string nome =
                    leitor.IsDBNull(1)
                        ? ""
                        : leitor.GetString(1);

                string caminho =
                    leitor.IsDBNull(2)
                        ? ""
                        : leitor.GetString(2);

                long criacao =
                    leitor.IsDBNull(3)
                        ? 0
                        : leitor.GetInt64(3);

                long expiracao =
                    leitor.IsDBNull(4)
                        ? 0
                        : leitor.GetInt64(4);

                long ultimoAcesso =
                    leitor.IsDBNull(5)
                        ? 0
                        : leitor.GetInt64(5);

                bool seguro =
                    !leitor.IsDBNull(6) &&
                    leitor.GetInt64(6) != 0;

                bool httpOnly =
                    !leitor.IsDBNull(7) &&
                    leitor.GetInt64(7) != 0;

                long tamanhoProtegido =
                    leitor.IsDBNull(8)
                        ? 0
                        : leitor.GetInt64(8);

                quantidade++;

                resultado.AppendLine();

                resultado.AppendLine(
                    $"[{quantidade}]"
                );

                resultado.AppendLine(
                    "Domínio: " + host
                );

                resultado.AppendLine(
                    "Nome: " + nome
                );

                resultado.AppendLine(
                    "Caminho: " + caminho
                );

                resultado.AppendLine(
                    "Criação: " +
                    ConverterDataChrome(criacao)
                );

                resultado.AppendLine(
                    "Expiração: " +
                    ConverterDataChrome(expiracao)
                );

                resultado.AppendLine(
                    "Último acesso: " +
                    ConverterDataChrome(ultimoAcesso)
                );

                resultado.AppendLine(
                    "Secure: " +
                    (seguro ? "SIM" : "NÃO")
                );

                resultado.AppendLine(
                    "HttpOnly: " +
                    (httpOnly ? "SIM" : "NÃO")
                );

                resultado.AppendLine(
                    "Valor protegido presente: " +
                    (tamanhoProtegido > 0 ? "SIM" : "NÃO")
                );

                resultado.AppendLine(
                    "Tamanho do valor protegido: " +
                    tamanhoProtegido +
                    " bytes"
                );

                resultado.AppendLine(
                    "Valor: [PROTEGIDO]"
                );
            }

            resultado.AppendLine();

            resultado.AppendLine(
                "Total de cookies encontrados: " +
                quantidade
            );
        }


        private DateTime ConverterDataChrome(
            long valor)
        {
            if (valor <= 0)
                return DateTime.MinValue;

            try
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
            catch
            {
                return DateTime.MinValue;
            }
        }
    }
}