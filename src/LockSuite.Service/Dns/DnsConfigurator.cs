using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service.Dns;

/// <summary>
/// Configura Windows para dirigir las resoluciones DNS hacia el resolutor local (127.0.0.1)
/// y permite restaurar la configuración anterior. Usa reglas NRPT (Name Resolution Policy Table)
/// para el namespace "." (todos los dominios).
/// </summary>
public sealed class DnsConfigurator
{
    private readonly ILogger<DnsConfigurator> _logger;
    private bool _nrptApplied;
    public bool IsNrptApplied => _nrptApplied;

    public DnsConfigurator(ILogger<DnsConfigurator> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Aplica (de forma idempotente) la regla NRPT que redirige todas las consultas DNS del
    /// sistema al resolutor local 127.0.0.1. Primero remueve cualquier regla previa de LockSuite
    /// y luego crea la nueva, todo en UNA sola invocación de PowerShell para acelerar el arranque.
    /// </summary>
    public bool ApplyNrptRedirect()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;

        try
        {
            string psCommand =
                "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'LockSuiteDNS' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; " +
                "Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -Comment 'LockSuiteDNS'";

            int exit = RunPowerShell(psCommand, out string err);
            if (exit == 0)
            {
                _nrptApplied = true;
                _logger.LogInformation("Regla NRPT aplicada: todo el tráfico DNS del sistema redirigido a 127.0.0.1");
                return true;
            }

            _logger.LogWarning("Fallo al aplicar regla NRPT (ExitCode: {Code}): {Error}", exit, err);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al configurar redirección NRPT de DNS");
        }

        return false;
    }

    /// <summary>
    /// Vacía la caché DNS del sistema (ipconfig /flushdns). Se llama cuando el tutor permite un
    /// dominio nuevo: Windows cachea las respuestas NXDOMAIN (negativas) de los dominios bloqueados,
    /// así que sin esto el dominio recién permitido podía seguir sin abrir unos minutos (caso 3.7).
    /// </summary>
    public void FlushDnsCache()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ipconfig.exe",
                Arguments = "/flushdns",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var p = Process.Start(psi);
            if (p == null) return;
            var outTask = p.StandardOutput.ReadToEndAsync();
            var errTask = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(5000)) { try { p.Kill(true); } catch { } return; }
            Task.WhenAll(outTask, errTask).Wait(1000);
            _logger.LogInformation("Caché DNS del sistema vaciada (flushdns).");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo vaciar la caché DNS.");
        }
    }

    /// <summary>
    /// Captura los servidores DNS actualmente configurados en las interfaces de red activas
    /// (antes de aplicar la regla NRPT), excluyendo loopback, comodines y site-local IPv6 (fec0::/10).
    /// </summary>
    public IReadOnlyList<IPAddress> CaptureCurrentDnsServers()
    {
        var result = new List<IPAddress>();
        var seen = new HashSet<IPAddress>();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up ||
                    nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                IPInterfaceProperties props;
                try
                {
                    props = nic.GetIPProperties();
                }
                catch
                {
                    continue;
                }

                foreach (var dns in props.DnsAddresses)
                {
                    if (IsExcludedDnsAddress(dns)) continue;
                    if (seen.Add(dns))
                    {
                        result.Add(dns);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudieron capturar los servidores DNS del adaptador.");
        }

        return result;
    }

    private static bool IsExcludedDnsAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) ||
            ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None))
        {
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6SiteLocal) return true;
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 16 && bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0)
            {
                return true; // fec0::/10
            }
        }

        return false;
    }

    /// <summary>Remueve la regla NRPT de LockSuite si fue aplicada.</summary>
    public void RemoveNrptRedirect()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;

        try
        {
            string psCommand = "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'LockSuiteDNS' } | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue";
            RunPowerShell(psCommand, out _);
            _nrptApplied = false;
            _logger.LogInformation("Regla NRPT de LockSuite removida");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error al remover regla NRPT");
        }
    }

    private static int RunPowerShell(string command, out string stderr)
    {
        stderr = string.Empty;
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{command}\"",
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        };

        using var process = Process.Start(psi);
        if (process == null) return -1;

        var outTask = process.StandardOutput.ReadToEndAsync();
        var errTask = process.StandardError.ReadToEndAsync();

        if (!process.WaitForExit(8000))
        {
            try { process.Kill(true); } catch { /* best-effort */ }
            stderr = "timeout";
            return -1;
        }

        Task.WhenAll(outTask, errTask).Wait(1000);
        stderr = errTask.IsCompletedSuccessfully ? errTask.Result : string.Empty;
        return process.ExitCode;
    }
}
