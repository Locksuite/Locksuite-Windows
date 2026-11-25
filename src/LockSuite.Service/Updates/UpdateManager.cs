using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LockSuite.Service.Dns;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service.Updates;

public sealed class UpdateManager : IDisposable
{
    private readonly ILogger<UpdateManager> _logger;
    private readonly HttpClient _httpClient;
    private readonly DnsResolver? _dnsResolver;
    private readonly string _repoOwner = "Locksuite";
    private readonly string _repoName = "Locksuite-Windows";
    private readonly SemaphoreSlim _updateLock = new(1, 1);
    private readonly CancellationTokenSource _disposeCts = new();
    private Timer? _periodicTimer;
    private bool _disposed;

    internal string? UpdatesDirectoryOverride { get; set; }

    // Intervalo de chequeo: cada 4 horas
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(4);
    // Demora inicial al arrancar el servicio: 60 segundos para permitir estabilizar red/WFP
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(60);

    // Nombre del asset con los hashes (obligatorio en el release). Se verifica el .exe antes de ejecutarlo.
    private const string SumsAssetName = "SHA256SUMS.txt";

    public UpdateManager(ILogger<UpdateManager> logger, HttpClient? httpClient = null, DnsResolver? dnsResolver = null)
    {
        _logger = logger;
        _dnsResolver = dnsResolver;

        if (httpClient != null)
        {
            _httpClient = httpClient;
        }
        else
        {
            var handler = new SocketsHttpHandler
            {
                ConnectCallback = ConnectWithFilterAsync
            };
            _httpClient = new HttpClient(handler);
        }

        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("LockSuite-Updater", Program.Version));
        _httpClient.Timeout = TimeSpan.FromMinutes(5);
    }

    internal static bool IsAllowedUpdateHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        string clean = host.Trim().TrimEnd('.').ToLowerInvariant();
        if (clean.Length == 0) return false;

        if (string.Equals(clean, "api.github.com", StringComparison.Ordinal) ||
            string.Equals(clean, "github.com", StringComparison.Ordinal) ||
            string.Equals(clean, "githubusercontent.com", StringComparison.Ordinal))
        {
            return true;
        }

        return clean.EndsWith(".githubusercontent.com", StringComparison.Ordinal);
    }

    private async ValueTask<Stream> ConnectWithFilterAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        string host = context.DnsEndPoint.Host;
        if (!IsAllowedUpdateHost(host))
        {
            throw new HttpRequestException($"Host de actualización no permitido: {host}");
        }

        IReadOnlyList<IPAddress> ips = Array.Empty<IPAddress>();
        if (_dnsResolver != null)
        {
            ips = await _dnsResolver.ResolveUpstreamIpsAsync(host, ct);
        }

        if (ips.Count == 0)
        {
            try
            {
                ips = await System.Net.Dns.GetHostAddressesAsync(host, ct);
            }
            catch (Exception ex)
            {
                throw new HttpRequestException($"No se pudo resolver el host de actualización '{host}'.", ex);
            }
        }

        Exception? lastEx = null;
        foreach (var rawIp in ips)
        {
            if (DnsResolver.IsPrivateOrSpecialIp(rawIp))
            {
                continue;
            }

            Socket? socket = null;
            try
            {
                socket = new Socket(rawIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                await socket.ConnectAsync(new IPEndPoint(rawIp, context.DnsEndPoint.Port), ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex)
            {
                lastEx = ex;
                try { socket?.Dispose(); } catch { }
            }
        }

        throw new HttpRequestException($"No se pudo conectar a ningún endpoint público válido para '{host}'.", lastEx);
    }

    public void StartPeriodicChecks()
    {
        if (_disposed) return;

        _periodicTimer = new Timer(async _ =>
        {
            try
            {
                await CheckAndApplyUpdateAsync(_disposeCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Servicio deteniéndose
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error en ciclo periódico de auto-actualización.");
            }
        }, null, InitialDelay, CheckInterval);

        _logger.LogInformation("Actualizador automático iniciado. Próximo chequeo en {Delay}s.", (int)InitialDelay.TotalSeconds);
    }

    public async Task<bool> CheckAndApplyUpdateAsync(CancellationToken cancellationToken)
    {
        if (_disposed) return false;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeCts.Token);
        CancellationToken ct = linkedCts.Token;

        if (!await _updateLock.WaitAsync(0, ct))
        {
            _logger.LogInformation("Ya hay una verificación o descarga de actualización en curso.");
            return false;
        }

        string? targetPath = null;
        bool installerLaunched = false;

        try
        {
            _logger.LogInformation("Verificando si hay nuevas actualizaciones en GitHub ({Owner}/{Repo})...", _repoOwner, _repoName);

            string apiUrl = $"https://api.github.com/repos/{_repoOwner}/{_repoName}/releases/latest";
            using var request = new HttpRequestMessage(HttpMethod.Get, apiUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github.v3+json"));

            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("GitHub API devolvió código {StatusCode} al buscar actualizaciones.", response.StatusCode);
                return false;
            }

            await using var contentStream = await response.Content.ReadAsStreamAsync(ct);
            using var jsonDoc = await JsonDocument.ParseAsync(contentStream, cancellationToken: ct);
            var root = jsonDoc.RootElement;

            if (!root.TryGetProperty("tag_name", out var tagElem))
            {
                _logger.LogWarning("Respuesta de GitHub Release no contiene 'tag_name'.");
                return false;
            }

            string tagName = tagElem.GetString() ?? "";
            string cleanRemoteVersion = tagName.TrimStart('v', 'V');

            if (!Version.TryParse(cleanRemoteVersion, out var remoteVer) ||
                !Version.TryParse(Program.Version, out var currentVer))
            {
                _logger.LogWarning("No se pudo comparar versiones: Remota='{Remote}', Local='{Local}'", cleanRemoteVersion, Program.Version);
                return false;
            }

            if (remoteVer <= currentVer)
            {
                _logger.LogInformation("LockSuite está actualizado a la última versión (v{Current}).", Program.Version);
                return false;
            }

            _logger.LogInformation("Nueva versión detectada: v{Remote} (actual: v{Current}). Buscando instalador...", remoteVer, currentVer);

            string? downloadUrl = null;
            string? assetName = null;
            string? sumsUrl = null;

            if (root.TryGetProperty("assets", out var assetsElem) && assetsElem.ValueKind == JsonValueKind.Array)
            {
                foreach (var asset in assetsElem.EnumerateArray())
                {
                    if (!asset.TryGetProperty("name", out var nameProp) ||
                        !asset.TryGetProperty("browser_download_url", out var urlProp))
                        continue;

                    string name = nameProp.GetString() ?? "";
                    string url = urlProp.GetString() ?? "";

                    if (name.Equals(SumsAssetName, StringComparison.OrdinalIgnoreCase))
                    {
                        sumsUrl = url;
                    }
                    else if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                             name.Contains("LockSuiteSetup", StringComparison.OrdinalIgnoreCase))
                    {
                        assetName = Path.GetFileName(name);
                        downloadUrl = url;
                    }
                }
            }

            if (string.IsNullOrEmpty(downloadUrl) || string.IsNullOrEmpty(assetName))
            {
                _logger.LogWarning("El release v{Version} no contiene un ejecutable de instalador válido.", remoteVer);
                return false;
            }

            string updatesDir = !string.IsNullOrWhiteSpace(UpdatesDirectoryOverride)
                ? UpdatesDirectoryOverride
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "LockSuite",
                    "updates");

            Directory.CreateDirectory(updatesDir);
            CleanupOldInstallers(updatesDir);
            targetPath = Path.Combine(updatesDir, assetName);

            _logger.LogInformation("Descargando actualización desde {Url} hacia {Path}...", downloadUrl, targetPath);

            using (var downloadResp = await _httpClient.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                downloadResp.EnsureSuccessStatusCode();
                await using var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write, FileShare.None);
                await downloadResp.Content.CopyToAsync(fileStream, ct);
            }

            var fileInfo = new FileInfo(targetPath);
            if (!fileInfo.Exists || fileInfo.Length < 1_000_000)
            {
                _logger.LogError("El archivo descargado en {Path} es inválido o corrupto ({Size} bytes).", targetPath, fileInfo.Exists ? fileInfo.Length : 0);
                TryDeleteFile(targetPath);
                return false;
            }

            // --- Verificación de integridad (SHA-256) ANTES de ejecutar como SYSTEM ---
            if (string.IsNullOrEmpty(sumsUrl))
            {
                _logger.LogError("El release v{Version} no incluye {Sums}: se aborta la actualización por política de seguridad.", remoteVer, SumsAssetName);
                TryDeleteFile(targetPath);
                return false;
            }

            string? sumsText = await TryDownloadTextAsync(sumsUrl!, ct);
            if (sumsText == null)
            {
                _logger.LogError("No se pudo descargar {Sums}; se aborta la actualización por seguridad.", SumsAssetName);
                TryDeleteFile(targetPath);
                return false;
            }
            if (!TryGetExpectedSha256(sumsText, assetName, out string expected))
            {
                _logger.LogError("{Sums} no contiene un hash para {Asset}; se aborta la actualización.", SumsAssetName, assetName);
                TryDeleteFile(targetPath);
                return false;
            }
            string actual = ComputeSha256(targetPath);
            if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("Hash SHA-256 NO coincide para {Asset}. Esperado={Expected} Actual={Actual}. Se aborta la actualización (posible descarga corrupta o manipulada).",
                    assetName, expected, actual);
                TryDeleteFile(targetPath);
                return false;
            }
            _logger.LogInformation("Integridad verificada (SHA-256 OK) para {Asset}.", assetName);

            _logger.LogInformation("Instalador listo ({Size:N0} bytes). Ejecutando actualización silenciosa...", fileInfo.Length);

            // Inno Setup /VERYSILENT /SUPPRESSMSGBOXES /NORESTART detiene el servicio viejo (PrepareToInstall),
            // sobreescribe los ejecutables en C:\Program Files\LockSuite y levanta el nuevo servicio.
            var psi = new ProcessStartInfo
            {
                FileName = targetPath,
                Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Process.Start(psi);
            installerLaunched = true;
            _logger.LogInformation("Instalador de LockSuite lanzado con éxito para actualización a v{Version}.", remoteVer);
            return true;
        }
        catch (OperationCanceledException)
        {
            if (targetPath != null && !installerLaunched) TryDeleteFile(targetPath);
            return false;
        }
        catch (Exception ex)
        {
            if (targetPath != null && !installerLaunched) TryDeleteFile(targetPath);
            _logger.LogError(ex, "Fallo durante la auto-actualización de LockSuite.");
            return false;
        }
        finally
        {
            _updateLock.Release();
        }
    }

    private async Task<string?> TryDownloadTextAsync(string url, CancellationToken ct)
    {
        try
        {
            using var resp = await _httpClient.GetAsync(url, ct);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsStringAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo descargar el texto de {Url}.", url);
            return null;
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch { /* best-effort */ }
    }

    private void CleanupOldInstallers(string updatesDir)
    {
        try
        {
            foreach (var old in Directory.GetFiles(updatesDir, "*.exe"))
            {
                try { File.Delete(old); } catch { /* en uso o sin permiso: ignorar */ }
            }
        }
        catch { /* best-effort */ }
    }

    /// <summary>Calcula el SHA-256 de un archivo como cadena hex en minúsculas.</summary>
    internal static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(filePath);
        byte[] hash = sha.ComputeHash(fs);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>
    /// Extrae el hash esperado para un asset desde el texto de un SHA256SUMS.txt.
    /// Acepta el formato clásico "&lt;hash&gt;  &lt;nombre&gt;" (dos espacios) y "&lt;hash&gt; *&lt;nombre&gt;".
    /// </summary>
    internal static bool TryGetExpectedSha256(string sumsText, string assetName, out string hash)
    {
        hash = "";
        if (string.IsNullOrEmpty(sumsText)) return false;

        foreach (var rawLine in sumsText.Replace("\r", "").Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

            var parts = line.Split(new[] { ' ', '\t' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var name = parts[1].Trim().TrimStart('*').Trim();
            if (string.Equals(name, assetName, StringComparison.OrdinalIgnoreCase))
            {
                hash = parts[0].Trim().ToLowerInvariant();
                return hash.Length == 64;
            }
        }
        return false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _disposeCts.Cancel(); } catch { }
        _periodicTimer?.Dispose();
        _httpClient.Dispose();
        _updateLock.Dispose();
        _disposeCts.Dispose();
    }
}
