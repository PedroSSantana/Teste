using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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
                    has_expires,
                    samesite,
                    source_scheme,
                    source_port,
                    priority,
                    length(encrypted_value),
                    encrypted_value
                FROM cookies
                ORDER BY host_key, name;
            ";

            using SqliteDataReader leitor =
                comando.ExecuteReader();

            int quantidade = 0;

            Dictionary<string, int> cookiesPorDominio =
                new Dictionary<string, int>(
                    StringComparer.OrdinalIgnoreCase
                );

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

                bool possuiExpiracao =
                    !leitor.IsDBNull(8) &&
                    leitor.GetInt64(8) != 0;

                long sameSite =
                    leitor.IsDBNull(9)
                        ? -1
                        : leitor.GetInt64(9);

                long sourceScheme =
                    leitor.IsDBNull(10)
                        ? -1
                        : leitor.GetInt64(10);

                long sourcePort =
                    leitor.IsDBNull(11)
                        ? -1
                        : leitor.GetInt64(11);

                long prioridade =
                    leitor.IsDBNull(12)
                        ? -1
                        : leitor.GetInt64(12);

                long tamanhoProtegido =
                    leitor.IsDBNull(13)
                        ? 0
                        : leitor.GetInt64(13);

                string formatoProtecao =
                    ObterFormatoProtecao(
                        leitor,
                        14
                    );

                // Fingerprint baseado somente nos metadados.
                string fingerprint =
                    GerarFingerprint(
                        host,
                        nome,
                        caminho,
                        criacao,
                        expiracao,
                        ultimoAcesso,
                        seguro,
                        httpOnly,
                        possuiExpiracao,
                        sameSite,
                        sourceScheme,
                        sourcePort,
                        prioridade
                    );

                quantidade++;

                if (!cookiesPorDominio.ContainsKey(host))
                {
                    cookiesPorDominio[host] = 0;
                }

                cookiesPorDominio[host]++;

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
                    "Possui expiração: " +
                    (possuiExpiracao ? "SIM" : "NÃO")
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
                    "SameSite: " +
                    ConverterSameSite(sameSite)
                );

                resultado.AppendLine(
                    "Source Scheme: " +
                    ConverterSourceScheme(sourceScheme)
                );

                resultado.AppendLine(
                    "Source Port: " +
                    sourcePort
                );

                resultado.AppendLine(
                    "Prioridade: " +
                    ConverterPrioridade(prioridade)
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
                    "Formato da proteção: " +
                    formatoProtecao
                );

                resultado.AppendLine(
                    "Fingerprint SHA-256: " +
                    fingerprint
                );

                resultado.AppendLine(
                    "Valor: [NÃO EXPORTADO]"
                );
            }

            resultado.AppendLine();
            resultado.AppendLine(
                "============================================================"
            );

            resultado.AppendLine(
                "RESUMO"
            );

            resultado.AppendLine(
                "============================================================"
            );

            resultado.AppendLine(
                "Total de cookies encontrados: " +
                quantidade
            );

            resultado.AppendLine();
            resultado.AppendLine(
                "Cookies por domínio:"
            );

            foreach (
                KeyValuePair<string, int> item
                in cookiesPorDominio)
            {
                resultado.AppendLine(
                    $"{item.Key}: {item.Value}"
                );
            }
        }

        private string GerarFingerprint(
            string host,
            string nome,
            string caminho,
            long criacao,
            long expiracao,
            long ultimoAcesso,
            bool seguro,
            bool httpOnly,
            bool possuiExpiracao,
            long sameSite,
            long sourceScheme,
            long sourcePort,
            long prioridade)
        {
            string dados =
                host + "|" +
                nome + "|" +
                caminho + "|" +
                criacao + "|" +
                expiracao + "|" +
                ultimoAcesso + "|" +
                seguro + "|" +
                httpOnly + "|" +
                possuiExpiracao + "|" +
                sameSite + "|" +
                sourceScheme + "|" +
                sourcePort + "|" +
                prioridade;

            byte[] bytes =
                Encoding.UTF8.GetBytes(dados);

            byte[] hash =
                SHA256.HashData(bytes);

            return Convert.ToHexString(hash);
        }

        private string ObterFormatoProtecao(
            SqliteDataReader leitor,
            int coluna)
        {
            if (leitor.IsDBNull(coluna))
                return "Não disponível";

            try
            {
                byte[] dados =
                    (byte[])leitor.GetValue(coluna);

                if (dados.Length < 3)
                    return "Formato não identificado";

                string prefixo =
                    Encoding.ASCII.GetString(
                        dados,
                        0,
                        Math.Min(3, dados.Length)
                    );

                if (
                    prefixo == "v10" ||
                    prefixo == "v11" ||
                    prefixo == "v20"
                )
                {
                    return prefixo;
                }

                return "Formato protegido";
            }
            catch
            {
                return "Não identificado";
            }
        }

        private string ConverterSameSite(long valor)
        {
            return valor switch
            {
                0 => "No Restriction",
                1 => "Lax",
                2 => "Strict",
                _ => "Não informado"
            };
        }

        private string ConverterSourceScheme(long valor)
        {
            return valor switch
            {
                0 => "HTTP",
                1 => "HTTPS",
                2 => "Outro",
                _ => "Não informado"
            };
        }

        private string ConverterPrioridade(long valor)
        {
            return valor switch
            {
                0 => "Low",
                1 => "Medium",
                2 => "High",
                _ => "Não informado"
            };
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