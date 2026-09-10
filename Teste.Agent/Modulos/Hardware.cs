using System;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;

namespace Teste.Modulos
{
    public class Hardware
    {
        public StringBuilder Coletar()
        {
            StringBuilder resultado =
                new StringBuilder();

            resultado.AppendLine(
                "INFORMAÇÕES DO COMPUTADOR"
            );

            resultado.AppendLine();

            resultado.AppendLine(
                "Nome do computador: " +
                Environment.MachineName
            );

            resultado.AppendLine(
                "Sistema operacional: " +
                RuntimeInformation.OSDescription
            );

            resultado.AppendLine(
                "Arquitetura: " +
                RuntimeInformation.OSArchitecture
            );

            resultado.AppendLine(
                "Processadores lógicos: " +
                Environment.ProcessorCount
            );

            resultado.AppendLine();


            // ==============================================
            // CPU
            // ==============================================

            resultado.AppendLine(
                "---------------- CPU ----------------"
            );

            try
            {
                using ManagementObjectSearcher
                    pesquisa =
                    new ManagementObjectSearcher(
                        "SELECT Name, NumberOfCores, " +
                        "NumberOfLogicalProcessors, " +
                        "MaxClockSpeed " +
                        "FROM Win32_Processor"
                    );

                foreach (
                    ManagementObject cpu
                    in pesquisa.Get())
                {
                    resultado.AppendLine(
                        "Modelo: " +
                        cpu["Name"]
                    );

                    resultado.AppendLine(
                        "Núcleos: " +
                        cpu["NumberOfCores"]
                    );

                    resultado.AppendLine(
                        "Threads: " +
                        cpu["NumberOfLogicalProcessors"]
                    );

                    resultado.AppendLine(
                        "Frequência máxima: " +
                        cpu["MaxClockSpeed"] +
                        " MHz"
                    );
                }
            }
            catch (Exception erro)
            {
                resultado.AppendLine(
                    "Erro ao obter CPU: " +
                    erro.Message
                );
            }

            resultado.AppendLine();


            // ==============================================
            // RAM
            // ==============================================

            resultado.AppendLine(
                "---------------- RAM ----------------"
            );

            try
            {
                using ManagementObjectSearcher
                    pesquisa =
                    new ManagementObjectSearcher(
                        "SELECT Capacity, Speed, " +
                        "Manufacturer, PartNumber " +
                        "FROM Win32_PhysicalMemory"
                    );

                long memoriaTotal = 0;

                foreach (
                    ManagementObject memoria
                    in pesquisa.Get())
                {
                    if (memoria["Capacity"] != null)
                    {
                        long capacidade =
                            Convert.ToInt64(
                                memoria["Capacity"]
                            );

                        memoriaTotal += capacidade;
                    }

                    resultado.AppendLine(
                        "Fabricante: " +
                        memoria["Manufacturer"]
                    );

                    resultado.AppendLine(
                        "Modelo/Part Number: " +
                        memoria["PartNumber"]
                    );

                    resultado.AppendLine(
                        "Velocidade: " +
                        memoria["Speed"] +
                        " MHz"
                    );

                    resultado.AppendLine();
                }

                resultado.AppendLine(
                    "Memória física total: " +
                    FormatarBytes(memoriaTotal)
                );
            }
            catch (Exception erro)
            {
                resultado.AppendLine(
                    "Erro ao obter RAM: " +
                    erro.Message
                );
            }

            resultado.AppendLine();


            // ==============================================
            // GPU
            // ==============================================

            resultado.AppendLine(
                "---------------- GPU ----------------"
            );

            try
            {
                using ManagementObjectSearcher
                    pesquisa =
                    new ManagementObjectSearcher(
                        "SELECT Name, AdapterRAM, " +
                        "DriverVersion " +
                        "FROM Win32_VideoController"
                    );

                foreach (
                    ManagementObject gpu
                    in pesquisa.Get())
                {
                    resultado.AppendLine(
                        "Modelo: " +
                        gpu["Name"]
                    );

                    if (gpu["AdapterRAM"] != null)
                    {
                        long memoria =
                            Convert.ToInt64(
                                gpu["AdapterRAM"]
                            );

                        resultado.AppendLine(
                            "Memória: " +
                            FormatarBytes(memoria)
                        );
                    }

                    resultado.AppendLine(
                        "Driver: " +
                        gpu["DriverVersion"]
                    );

                    resultado.AppendLine();
                }
            }
            catch (Exception erro)
            {
                resultado.AppendLine(
                    "Erro ao obter GPU: " +
                    erro.Message
                );
            }


            // ==============================================
            // PLACA-MÃE
            // ==============================================

            resultado.AppendLine(
                "---------------- PLACA-MÃE ----------------"
            );

            try
            {
                using ManagementObjectSearcher
                    pesquisa =
                    new ManagementObjectSearcher(
                        "SELECT Manufacturer, Product " +
                        "FROM Win32_BaseBoard"
                    );

                foreach (
                    ManagementObject placa
                    in pesquisa.Get())
                {
                    resultado.AppendLine(
                        "Fabricante: " +
                        placa["Manufacturer"]
                    );

                    resultado.AppendLine(
                        "Modelo: " +
                        placa["Product"]
                    );
                }
            }
            catch (Exception erro)
            {
                resultado.AppendLine(
                    "Erro ao obter placa-mãe: " +
                    erro.Message
                );
            }

            resultado.AppendLine();


            // ==============================================
            // DISCOS
            // ==============================================

            resultado.AppendLine(
                "---------------- DISCOS ----------------"
            );

            try
            {
                DriveInfo[] discos =
                    DriveInfo.GetDrives();

                foreach (
                    DriveInfo disco
                    in discos)
                {
                    if (!disco.IsReady)
                        continue;

                    resultado.AppendLine(
                        "Unidade: " +
                        disco.Name
                    );

                    resultado.AppendLine(
                        "Tipo: " +
                        disco.DriveType
                    );

                    resultado.AppendLine(
                        "Capacidade: " +
                        FormatarBytes(
                            disco.TotalSize
                        )
                    );

                    resultado.AppendLine(
                        "Espaço livre: " +
                        FormatarBytes(
                            disco.AvailableFreeSpace
                        )
                    );

                    resultado.AppendLine(
                        "Espaço utilizado: " +
                        FormatarBytes(
                            disco.TotalSize -
                            disco.AvailableFreeSpace
                        )
                    );

                    resultado.AppendLine();
                }
            }
            catch (Exception erro)
            {
                resultado.AppendLine(
                    "Erro ao obter discos: " +
                    erro.Message
                );
            }


            return resultado;
        }


        // ==============================================
        // CONVERSÃO DE BYTES
        // ==============================================

        private string FormatarBytes(
            long bytes)
        {
            string[] unidades =
            {
                "B",
                "KB",
                "MB",
                "GB",
                "TB"
            };

            double valor = bytes;
            int indice = 0;

            while (
                valor >= 1024 &&
                indice < unidades.Length - 1)
            {
                valor /= 1024;
                indice++;
            }

            return $"{valor:F2} {unidades[indice]}";
        }
    }
}