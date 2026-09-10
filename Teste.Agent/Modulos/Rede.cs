using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace Teste.Modulos;

public static class Rede
{
    public static StringBuilder Coletar()
    {
        StringBuilder resultado = new();

        resultado.AppendLine("========================================");
        resultado.AppendLine("05 - REDE");
        resultado.AppendLine("========================================");
        resultado.AppendLine();

        resultado.AppendLine($"Computador: {Environment.MachineName}");
        resultado.AppendLine(
            $"Data da coleta: {DateTime.Now:dd/MM/yyyy HH:mm:ss}"
        );
        resultado.AppendLine();

        NetworkInterface[] interfaces =
            NetworkInterface.GetAllNetworkInterfaces();

        foreach (NetworkInterface rede in interfaces)
        {
            resultado.AppendLine("----------------------------------------");
            resultado.AppendLine($"Nome: {rede.Name}");
            resultado.AppendLine($"Descrição: {rede.Description}");
            resultado.AppendLine($"Tipo: {rede.NetworkInterfaceType}");
            resultado.AppendLine($"Status: {rede.OperationalStatus}");

            string mac = rede.GetPhysicalAddress().ToString();

            resultado.AppendLine(
                $"MAC: {(string.IsNullOrWhiteSpace(mac) ? "Não disponível" : mac)}"
            );

            if (rede.Speed > 0)
            {
                resultado.AppendLine(
                    $"Velocidade: {rede.Speed / 1_000_000} Mbps"
                );
            }
            else
            {
                resultado.AppendLine("Velocidade: Não disponível");
            }

            IPInterfaceProperties propriedades =
                rede.GetIPProperties();

            resultado.AppendLine();
            resultado.AppendLine("ENDEREÇOS IP:");

            bool encontrouIp = false;

            foreach (UnicastIPAddressInformation ip
                     in propriedades.UnicastAddresses)
            {
                if (ip.Address.AddressFamily ==
                    AddressFamily.InterNetwork)
                {
                    resultado.AppendLine($"IPv4: {ip.Address}");
                    encontrouIp = true;
                }
                else if (ip.Address.AddressFamily ==
                         AddressFamily.InterNetworkV6)
                {
                    resultado.AppendLine($"IPv6: {ip.Address}");
                    encontrouIp = true;
                }
            }

            if (!encontrouIp)
            {
                resultado.AppendLine(
                    "Nenhum endereço IP encontrado."
                );
            }

            resultado.AppendLine();
            resultado.AppendLine("GATEWAY:");

            bool encontrouGateway = false;

            foreach (GatewayIPAddressInformation gateway
                     in propriedades.GatewayAddresses)
            {
                resultado.AppendLine(
                    $"Gateway: {gateway.Address}"
                );

                encontrouGateway = true;
            }

            if (!encontrouGateway)
            {
                resultado.AppendLine(
                    "Nenhum gateway encontrado."
                );
            }

            resultado.AppendLine();
            resultado.AppendLine("DNS:");

            bool encontrouDns = false;

            foreach (IPAddress dns
                     in propriedades.DnsAddresses)
            {
                resultado.AppendLine($"DNS: {dns}");
                encontrouDns = true;
            }

            if (!encontrouDns)
            {
                resultado.AppendLine(
                    "Nenhum DNS encontrado."
                );
            }

            resultado.AppendLine();
        }

        return resultado;
    }
}