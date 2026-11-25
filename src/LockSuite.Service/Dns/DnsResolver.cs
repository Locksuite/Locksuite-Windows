using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using LockSuite.Core;
using LockSuite.Service.Config;
using LockSuite.Service.Learning;
using LockSuite.Service.Wfp;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service.Dns;

public sealed class DnsResolver : IDisposable
{
    private readonly ILogger<DnsResolver> _logger;
    private readonly ConfigManager _configManager;
    private readonly IWfpManager _wfpManager;
    private readonly LearningManager _learningManager;

    private readonly IPEndPoint _listenEndpoint;
    private readonly List<IPEndPoint> _upstreamEndpoints = new();
    private readonly List<IPEndPoint> _fallbackUpstreams = new();
    private readonly object _upstreamLock = new();

    private Socket? _listenerSocket;
    private Socket? _tcpListenerSocket;
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;
    private Task? _tcpListenerTask;

    private Func<bool>? _sniProxyActive;

    // Limita las consultas concurrentes en vuelo para no crear tareas/sockets sin tope
    // ante una rafaga (back-pressure). 256 es amplio para una sola maquina.
    private readonly SemaphoreSlim _concurrency = new(256, 256);

    // Caché interna de IPs upstream para SniProxy y UpdateManager (máx 2048 entradas, TTL [30s, 300s])
    private readonly Dictionary<string, CachedIpEntry> _upstreamIpCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheLock = new();
    private int _nextTxId = 1000;

    private const int MinTtlSeconds = 180;  // Mínimo 3 minutos de validez de regla WFP
    private const int MaxTtlSeconds = 1800; // Máximo 30 minutos de validez de regla WFP
    private const uint MinCacheTtlSeconds = 30;
    private const uint MaxCacheTtlSeconds = 300;
    private const int MaxCacheEntries = 2048;
    private const int UpstreamTimeoutMs = 3000;
    private const int TcpClientTimeoutMs = 5000;
    private const int MaxBindAttempts = 3;

    private static readonly string[] DirectDomainsOrSubdomains =
    {
        "msftconnecttest.com",
        "msftncsi.com",
        "time.windows.com",
        "ntp.org"
    };

    private static readonly HashSet<string> DirectFirstLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "imap", "smtp", "pop", "pop3", "ntp", "time", "stun", "turn"
    };

    private sealed record CachedIpEntry(IReadOnlyList<IPAddress> Ips, DateTimeOffset ExpiresAt);

    // Estadisticas: se actualizan desde multiples hebras -> Interlocked.
    private long _totalQueries;
    private long _allowedQueries;
    private long _blockedQueries;

    public long TotalQueries => Interlocked.Read(ref _totalQueries);
    public long AllowedQueries => Interlocked.Read(ref _allowedQueries);
    public long BlockedQueries => Interlocked.Read(ref _blockedQueries);

    /// <summary>True si el socket UDP esta efectivamente escuchando en 127.0.0.1:53.</summary>
    public bool IsListening { get; private set; }

    public DnsResolver(
        ILogger<DnsResolver> logger,
        ConfigManager configManager,
        IWfpManager wfpManager,
        LearningManager learningManager,
        int listenPort = 53)
    {
        _logger = logger;
        _configManager = configManager;
        _wfpManager = wfpManager;
        _learningManager = learningManager;

        _listenEndpoint = new IPEndPoint(IPAddress.Loopback, listenPort);

        // Servidores DNS upstream por defecto: Cloudflare y Google (IPv4 + IPv6)
        _upstreamEndpoints.Add(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53));
        _upstreamEndpoints.Add(new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53));
        _upstreamEndpoints.Add(new IPEndPoint(IPAddress.Parse("2606:4700:4700::1111"), 53));
        _upstreamEndpoints.Add(new IPEndPoint(IPAddress.Parse("2001:4860:4860::8888"), 53));
    }

    public void SetSniProxyActiveProvider(Func<bool> provider)
    {
        _sniProxyActive = provider;
    }

    public void SetFallbackUpstreams(IEnumerable<IPAddress> dnsServers)
    {
        if (dnsServers == null) return;

        lock (_upstreamLock)
        {
            _fallbackUpstreams.Clear();
            var seen = new HashSet<IPAddress>();
            foreach (var ip in dnsServers)
            {
                if (ip == null) continue;
                var normalizedIp = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
                if (IPAddress.IsLoopback(normalizedIp) ||
                    normalizedIp.Equals(IPAddress.Any) ||
                    normalizedIp.Equals(IPAddress.IPv6Any) ||
                    normalizedIp.Equals(IPAddress.None) ||
                    normalizedIp.Equals(IPAddress.IPv6None))
                {
                    continue;
                }

                if (seen.Add(normalizedIp))
                {
                    _fallbackUpstreams.Add(new IPEndPoint(normalizedIp, 53));
                }
            }
        }
    }

    public void ClearUpstreamCache()
    {
        lock (_cacheLock)
        {
            _upstreamIpCache.Clear();
        }
    }

    /// <summary>
    /// Inicia el resolutor. No lanza excepcion si el bind falla: reintenta y, de no poder,
    /// deja el servicio en pie con IsListening=false (el estado WFP sigue siendo fail-closed).
    /// Asi el servicio "arranca" siempre y la GUI puede reportar el problema al tutor.
    /// </summary>
    public void Start()
    {
        if (_listenerSocket != null) return;

        for (int attempt = 1; attempt <= MaxBindAttempts; attempt++)
        {
            Socket? socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
                DisableUdpConnReset(socket);
                socket.Bind(_listenEndpoint);

                _listenerSocket = socket;
                _cts?.Dispose();
                _cts = new CancellationTokenSource();
                _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
                IsListening = true;
                _logger.LogInformation("Resolutor DNS local (UDP) iniciado y escuchando en {Endpoint}", socket.LocalEndPoint);

                TryStartTcpListener((IPEndPoint)socket.LocalEndPoint!, _cts.Token);
                return;
            }
            catch (Exception ex)
            {
                try { socket?.Dispose(); } catch { /* best-effort */ }
                _logger.LogError(ex, "Fallo al enlazar el resolutor DNS en {Endpoint} (intento {Attempt}/{Max})",
                    _listenEndpoint, attempt, MaxBindAttempts);
                if (attempt < MaxBindAttempts)
                {
                    Thread.Sleep(1000);
                }
            }
        }

        IsListening = false;
        _logger.LogCritical(
            "No se pudo iniciar el resolutor DNS local en {Endpoint}. " +
            "El filtrado por dominio no funcionara hasta resolver esto (¿puerto 53 ocupado por otro servicio DNS?). " +
            "La red permanece bloqueada por WFP (fail-closed).", _listenEndpoint);
    }

    private void TryStartTcpListener(IPEndPoint boundUdpEndpoint, CancellationToken token)
    {
        Socket? tcpSocket = null;
        try
        {
            tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
            tcpSocket.Bind(boundUdpEndpoint);
            tcpSocket.Listen(64);
            _tcpListenerSocket = tcpSocket;
            _tcpListenerTask = Task.Run(() => ListenTcpLoopAsync(token));
            _logger.LogInformation("Resolutor DNS local (TCP) escuchando en {Endpoint}", boundUdpEndpoint);
        }
        catch (Exception ex)
        {
            try { tcpSocket?.Dispose(); } catch { /* best-effort */ }
            _logger.LogWarning(ex, "No se pudo iniciar listener DNS TCP en {Endpoint}; continúa solo UDP.", boundUdpEndpoint);
        }
    }

    /// <summary>
    /// En Windows, si se le responde a un cliente UDP que ya cerro su puerto, llega un ICMP
    /// "puerto inalcanzable" y el SIGUIENTE ReceiveFrom del socket de escucha falla con 10054
    /// (WSAECONNRESET). Es inofensivo, pero ensuciaba el registro de eventos cada pocos segundos.
    /// SIO_UDP_CONNRESET = false lo desactiva.
    /// </summary>
    private static void DisableUdpConnReset(Socket socket)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            const int SIO_UDP_CONNRESET = -1744830452;
            socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        }
        catch
        {
            // best-effort: si falla, el bucle de escucha ya tolera el error.
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listenerSocket?.Close(); } catch { }
        try { _tcpListenerSocket?.Close(); } catch { }
        _listenerSocket = null;
        _tcpListenerSocket = null;
        IsListening = false;
        _logger.LogInformation("Resolutor DNS local detenido");
    }

    private async Task ListenLoopAsync(CancellationToken token)
    {
        byte[] buffer = new byte[4096];
        EndPoint remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);

        while (!token.IsCancellationRequested && _listenerSocket != null)
        {
            try
            {
                var result = await _listenerSocket.ReceiveFromAsync(
                    buffer,
                    SocketFlags.None,
                    remoteEndpoint,
                    token);

                int bytesRead = result.ReceivedBytes;
                var clientEp = result.RemoteEndPoint;

                byte[] queryData = new byte[bytesRead];
                Buffer.BlockCopy(buffer, 0, queryData, 0, bytesRead);

                // Back-pressure: espera un cupo antes de procesar; limita tareas/sockets en vuelo.
                await _concurrency.WaitAsync(token);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        string clientIp = clientEp is IPEndPoint ipEp ? ipEp.Address.ToString() : "127.0.0.1";
                        byte[] response = await ProcessQueryPayloadAsync(queryData, clientIp, token);
                        if (response.Length > 0)
                        {
                            await SendResponseAsync(response, clientEp);
                        }
                    }
                    finally
                    {
                        _concurrency.Release();
                    }
                }, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (!token.IsCancellationRequested)
                {
                    _logger.LogWarning(ex, "Error al recibir consulta DNS UDP");
                    // Evita un bucle caliente (CPU/bateria) si el error se repite sin parar.
                    try { await Task.Delay(50, token); } catch (OperationCanceledException) { break; }
                }
            }
        }
    }

    private async Task ListenTcpLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested && _tcpListenerSocket != null)
        {
            try
            {
                Socket client = await _tcpListenerSocket.AcceptAsync(token);
                await _concurrency.WaitAsync(token);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleTcpClientAsync(client, token);
                    }
                    finally
                    {
                        try { client.Dispose(); } catch { }
                        _concurrency.Release();
                    }
                }, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (!token.IsCancellationRequested)
                {
                    _logger.LogWarning(ex, "Error al aceptar consulta DNS TCP");
                    try { await Task.Delay(50, token); } catch (OperationCanceledException) { break; }
                }
            }
        }
    }

    private async Task HandleTcpClientAsync(Socket client, CancellationToken token)
    {
        try
        {
            using var stream = new NetworkStream(client, ownsSocket: false);
            string clientIp = client.RemoteEndPoint is IPEndPoint ipEp ? ipEp.Address.ToString() : "127.0.0.1";

            while (!token.IsCancellationRequested)
            {
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                readCts.CancelAfter(TcpClientTimeoutMs);

                byte[] lenBuf = new byte[2];
                if (!await ReadExactAsync(stream, lenBuf, 2, readCts.Token))
                {
                    break;
                }

                int msgLen = (lenBuf[0] << 8) | lenBuf[1];
                if (msgLen < 12 || msgLen > 65535)
                {
                    break;
                }

                byte[] queryData = new byte[msgLen];
                if (!await ReadExactAsync(stream, queryData, msgLen, readCts.Token))
                {
                    break;
                }

                byte[] response = await ProcessQueryPayloadAsync(queryData, clientIp, token);
                if (response.Length == 0)
                {
                    break;
                }

                byte[] framed = new byte[2 + response.Length];
                framed[0] = (byte)(response.Length >> 8);
                framed[1] = (byte)response.Length;
                Buffer.BlockCopy(response, 0, framed, 2, response.Length);

                using var writeCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                writeCts.CancelAfter(TcpClientTimeoutMs);
                await stream.WriteAsync(framed, writeCts.Token);
                await stream.FlushAsync(writeCts.Token);
            }
        }
        catch (OperationCanceledException)
        {
            // Timeout o apagado
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error en sesión DNS TCP");
        }
    }

    private async Task<byte[]> ProcessQueryPayloadAsync(byte[] queryData, string clientIp, CancellationToken token)
    {
        Interlocked.Increment(ref _totalQueries);
        var packet = DnsPacket.Parse(queryData, queryData.Length);
        if (packet == null || !packet.IsQuery || packet.QdCount != 1 || string.IsNullOrWhiteSpace(packet.QuestionName))
        {
            return DnsPacket.CreateFormErrResponse(queryData, queryData.Length);
        }

        string domain = packet.QuestionName;
        bool isAllowed = _configManager.IsAllowed(domain);

        if (!isAllowed)
        {
            Interlocked.Increment(ref _blockedQueries);
            _logger.LogInformation("BLOQUEADO: {Domain} desde {Client}", domain, clientIp);

            if (_configManager.LearningMode)
            {
                _learningManager.RecordBlocked(domain, clientIp);
            }

            return DnsPacket.CreateNxDomainResponse(queryData, queryData.Length);
        }

        // Bloquear consultas SVCB / HTTPS para impedir hints ECH / DoH alternativos
        if (packet.QuestionType == DnsPacket.TypeHTTPS || packet.QuestionType == DnsPacket.TypeSVCB)
        {
            Interlocked.Increment(ref _allowedQueries);
            return DnsPacket.CreateNoDataResponse(queryData, queryData.Length);
        }

        bool useSniProxy = (_sniProxyActive?.Invoke() == true) &&
                           _configManager.CurrentConfig.SniInspectionEnabled &&
                           !ShouldUseDirectIp(domain);

        if (useSniProxy)
        {
            if (packet.QuestionType == DnsPacket.TypeAAAA)
            {
                Interlocked.Increment(ref _allowedQueries);
                return DnsPacket.CreateNoDataResponse(queryData, queryData.Length);
            }

            if (packet.QuestionType == DnsPacket.TypeA)
            {
                byte[]? sniUpstreamResp = await QueryUpstreamAsync(queryData, token);
                if (sniUpstreamResp == null || sniUpstreamResp.Length < 12)
                {
                    return DnsPacket.CreateServFailResponse(queryData, queryData.Length);
                }

                var sniRespPacket = DnsPacket.Parse(sniUpstreamResp, sniUpstreamResp.Length);
                if (sniRespPacket == null)
                {
                    return DnsPacket.CreateServFailResponse(queryData, queryData.Length);
                }

                var analysis = AnalyzeResponseAnswers(sniRespPacket, domain, MinCacheTtlSeconds, MaxCacheTtlSeconds);
                if (analysis.BlockedCname != null)
                {
                    Interlocked.Increment(ref _blockedQueries);
                    _logger.LogWarning("BLOQUEADO por CNAME fijo: {Domain} -> {CName}", domain, analysis.BlockedCname);
                    if (_configManager.LearningMode)
                    {
                        _learningManager.RecordBlocked(analysis.BlockedCname, clientIp);
                    }
                    return DnsPacket.CreateNxDomainResponse(queryData, queryData.Length);
                }

                Interlocked.Increment(ref _allowedQueries);

                if (analysis.ValidIps.Count > 0)
                {
                    var ipsOnly = new List<IPAddress>(analysis.ValidIps.Count);
                    uint minTtl = MaxCacheTtlSeconds;
                    foreach (var (ip, ttl) in analysis.ValidIps)
                    {
                        ipsOnly.Add(ip);
                        if (ttl < minTtl) minTtl = ttl;
                    }

                    CacheIps(domain, ipsOnly, minTtl);
                    return DnsPacket.CreateSyntheticAResponse(queryData, queryData.Length, IPAddress.Loopback, 60);
                }

                // Sin IPs públicas válidas (ej. NXDOMAIN, NODATA o solo IPs privadas filtradas)
                if (analysis.SawRejectedPrivateIp)
                {
                    return DnsPacket.CreateNoDataResponse(queryData, queryData.Length);
                }

                return sniUpstreamResp;
            }
        }

        _logger.LogDebug("Consulta permitida: {Domain}", domain);

        byte[]? upstreamResponse = await QueryUpstreamAsync(queryData, token);
        if (upstreamResponse == null || upstreamResponse.Length == 0)
        {
            return DnsPacket.CreateServFailResponse(queryData, queryData.Length);
        }

        var responsePacket = DnsPacket.Parse(upstreamResponse, upstreamResponse.Length);
        if (responsePacket != null)
        {
            var analysis = AnalyzeResponseAnswers(responsePacket, domain, MinTtlSeconds, MaxTtlSeconds);
            if (analysis.BlockedCname != null)
            {
                Interlocked.Increment(ref _blockedQueries);
                _logger.LogWarning("BLOQUEADO por CNAME fijo: {Domain} -> {CName}", domain, analysis.BlockedCname);
                if (_configManager.LearningMode)
                {
                    _learningManager.RecordBlocked(analysis.BlockedCname, clientIp);
                }
                return DnsPacket.CreateNxDomainResponse(queryData, queryData.Length);
            }

            if (!useSniProxy)
            {
                foreach (var (ip, ttl) in analysis.ValidIps)
                {
                    TimeSpan duration = TimeSpan.FromSeconds(ttl);
                    _wfpManager.AllowIpTemporary(ip, duration);
                    _logger.LogInformation("Regla dinámica autorizada para IP {IP} ({Domain}), TTL: {Sec}s",
                        ip, domain, (int)duration.TotalSeconds);
                }
            }
        }

        Interlocked.Increment(ref _allowedQueries);
        return upstreamResponse;
    }

    private sealed record ResponseAnalysis(
        string? BlockedCname,
        List<(IPAddress Ip, uint ClampedTtl)> ValidIps,
        bool SawRejectedPrivateIp);

    private ResponseAnalysis AnalyzeResponseAnswers(DnsPacket responsePacket, string domain, uint minTtl, uint maxTtl)
    {
        string normalizedDomain = DomainMatcher.Normalize(domain);
        var allowedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { normalizedDomain };

        // Resolución CNAME multi-pasada (punto fijo, máx 16 pasadas)
        for (int pass = 0; pass < 16; pass++)
        {
            bool added = false;
            foreach (var ans in responsePacket.Answers)
            {
                if (ans.Type == DnsPacket.TypeCNAME && !string.IsNullOrWhiteSpace(ans.CName))
                {
                    string ansName = DomainMatcher.Normalize(ans.Name);
                    string cname = DomainMatcher.Normalize(ans.CName);
                    if (ansName.Length > 0 && cname.Length > 0 && allowedNames.Contains(ansName))
                    {
                        if (_configManager.IsHardBlocked(cname))
                        {
                            return new ResponseAnalysis(cname, new List<(IPAddress, uint)>(), false);
                        }

                        if (allowedNames.Add(cname))
                        {
                            added = true;
                        }
                    }
                }
            }

            if (!added) break;
        }

        var validIps = new List<(IPAddress Ip, uint ClampedTtl)>();
        bool sawRejectedPrivateIp = false;

        foreach (var ans in responsePacket.Answers)
        {
            if (ans.IpAddress == null) continue;

            string ansName = DomainMatcher.Normalize(ans.Name);
            if (!allowedNames.Contains(ansName))
            {
                _logger.LogWarning("Respuesta DNS descartada por dominio no solicitado: {Name} (esperado: {Domain})",
                    ans.Name, domain);
                continue;
            }

            if (IsPrivateOrSpecialIp(ans.IpAddress))
            {
                sawRejectedPrivateIp = true;
                _logger.LogWarning("Respuesta DNS descartada por IP privada/especial: {IP} ({Name})",
                    ans.IpAddress, ans.Name);
                continue;
            }

            uint clampedTtl = Math.Clamp(ans.Ttl, minTtl, maxTtl);
            validIps.Add((ans.IpAddress, clampedTtl));
        }

        return new ResponseAnalysis(null, validIps, sawRejectedPrivateIp);
    }

    internal static bool ShouldUseDirectIp(string domain)
    {
        string h = DomainMatcher.Normalize(domain);
        if (h.Length == 0) return false;

        foreach (string target in DirectDomainsOrSubdomains)
        {
            if (string.Equals(h, target, StringComparison.Ordinal) ||
                (h.Length > target.Length && h[h.Length - target.Length - 1] == '.' && h.EndsWith(target, StringComparison.Ordinal)))
            {
                return true;
            }
        }

        if (string.Equals(h, "fcmconnection.googleapis.com", StringComparison.Ordinal))
        {
            return true;
        }

        int dot = h.IndexOf('.');
        string firstLabel = dot > 0 ? h[..dot] : h;
        return DirectFirstLabels.Contains(firstLabel);
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveUpstreamIpsAsync(string hostname, CancellationToken token)
    {
        string normalized = DomainMatcher.Normalize(hostname);
        if (normalized.Length == 0) return Array.Empty<IPAddress>();

        if (IPAddress.TryParse(normalized, out var literalIp))
        {
            return IsPrivateOrSpecialIp(literalIp)
                ? Array.Empty<IPAddress>()
                : new[] { literalIp.IsIPv4MappedToIPv6 ? literalIp.MapToIPv4() : literalIp };
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        lock (_cacheLock)
        {
            if (_upstreamIpCache.TryGetValue(normalized, out var cached))
            {
                if (cached.ExpiresAt > now)
                {
                    return cached.Ips;
                }
                _upstreamIpCache.Remove(normalized);
            }
        }

        var resolved = new List<IPAddress>();
        uint minTtl = MaxCacheTtlSeconds;

        bool blockedByCname = await ResolveTypeAsync(normalized, DnsPacket.TypeA, resolved, ttl =>
        {
            if (ttl < minTtl) minTtl = ttl;
        }, token);

        if (blockedByCname)
        {
            return Array.Empty<IPAddress>();
        }

        if (resolved.Count == 0)
        {
            blockedByCname = await ResolveTypeAsync(normalized, DnsPacket.TypeAAAA, resolved, ttl =>
            {
                if (ttl < minTtl) minTtl = ttl;
            }, token);

            if (blockedByCname)
            {
                return Array.Empty<IPAddress>();
            }
        }

        if (resolved.Count > 0)
        {
            CacheIps(normalized, resolved, minTtl);
        }

        return resolved;
    }

    private async Task<bool> ResolveTypeAsync(
        string normalizedDomain,
        ushort qtype,
        List<IPAddress> output,
        Action<uint> onTtl,
        CancellationToken token)
    {
        ushort txId = (ushort)Interlocked.Increment(ref _nextTxId);
        byte[] query = DnsPacket.BuildStandardQuery(normalizedDomain, qtype, txId);
        byte[]? rawResp = await QueryUpstreamAsync(query, token);
        if (rawResp == null || rawResp.Length < 12) return false;

        var parsed = DnsPacket.Parse(rawResp, rawResp.Length);
        if (parsed == null) return false;

        var analysis = AnalyzeResponseAnswers(parsed, normalizedDomain, MinCacheTtlSeconds, MaxCacheTtlSeconds);
        if (analysis.BlockedCname != null)
        {
            return true;
        }

        foreach (var (ip, ttl) in analysis.ValidIps)
        {
            if (!output.Contains(ip))
            {
                output.Add(ip);
            }
            onTtl(ttl);
        }

        return false;
    }

    private void CacheIps(string domain, IReadOnlyList<IPAddress> ips, uint ttlSeconds)
    {
        string normalized = DomainMatcher.Normalize(domain);
        if (normalized.Length == 0 || ips.Count == 0) return;

        uint clamped = Math.Clamp(ttlSeconds, MinCacheTtlSeconds, MaxCacheTtlSeconds);
        DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddSeconds(clamped);

        lock (_cacheLock)
        {
            if (_upstreamIpCache.Count >= MaxCacheEntries && !_upstreamIpCache.ContainsKey(normalized))
            {
                // Purgar expiradas primero; si sigue lleno, eliminar la más próxima a expirar
                var now = DateTimeOffset.UtcNow;
                var toRemove = new List<string>();
                string? oldestKey = null;
                DateTimeOffset oldestExp = DateTimeOffset.MaxValue;

                foreach (var kvp in _upstreamIpCache)
                {
                    if (kvp.Value.ExpiresAt <= now)
                    {
                        toRemove.Add(kvp.Key);
                    }
                    else if (kvp.Value.ExpiresAt < oldestExp)
                    {
                        oldestExp = kvp.Value.ExpiresAt;
                        oldestKey = kvp.Key;
                    }
                }

                foreach (var k in toRemove) _upstreamIpCache.Remove(k);
                if (_upstreamIpCache.Count >= MaxCacheEntries && oldestKey != null)
                {
                    _upstreamIpCache.Remove(oldestKey);
                }
            }

            _upstreamIpCache[normalized] = new CachedIpEntry(ips, expiresAt);
        }
    }

    private List<IPEndPoint> GetOrderedUpstreams()
    {
        var list = new List<IPEndPoint>(_upstreamEndpoints);
        lock (_upstreamLock)
        {
            foreach (var fb in _fallbackUpstreams)
            {
                if (!list.Contains(fb))
                {
                    list.Add(fb);
                }
            }
        }
        return list;
    }

    private async Task<byte[]?> QueryUpstreamAsync(byte[] queryData, CancellationToken token)
    {
        if (queryData.Length < 2) return null;
        ushort queryTxId = (ushort)((queryData[0] << 8) | queryData[1]);

        foreach (var upstream in GetOrderedUpstreams())
        {
            try
            {
                using var upstreamSocket = new Socket(upstream.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                await upstreamSocket.ConnectAsync(upstream, token);
                await upstreamSocket.SendAsync(queryData, SocketFlags.None, token);

                byte[] respBuffer = new byte[4096];
                using var ctsTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                ctsTimeout.CancelAfter(UpstreamTimeoutMs);

                int received = await upstreamSocket.ReceiveAsync(respBuffer, SocketFlags.None, ctsTimeout.Token);
                if (received >= 12)
                {
                    ushort respTxId = (ushort)((respBuffer[0] << 8) | respBuffer[1]);
                    if (respTxId == queryTxId)
                    {
                        bool isTruncated = (respBuffer[2] & 0x02) != 0;
                        if (isTruncated)
                        {
                            byte[]? tcpResp = await QueryUpstreamTcpAsync(upstream, queryData, queryTxId, token);
                            if (tcpResp != null)
                            {
                                return tcpResp;
                            }
                            continue;
                        }

                        byte[] response = new byte[received];
                        Buffer.BlockCopy(respBuffer, 0, response, 0, received);
                        return response;
                    }
                }
            }
            catch
            {
                // Intenta con el siguiente upstream
            }
        }
        return null;
    }

    private static async Task<byte[]?> QueryUpstreamTcpAsync(
        IPEndPoint upstream,
        byte[] queryData,
        ushort expectedTxId,
        CancellationToken token)
    {
        try
        {
            using var tcpSocket = new Socket(upstream.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            using var ctsTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            ctsTimeout.CancelAfter(UpstreamTimeoutMs);

            await tcpSocket.ConnectAsync(upstream, ctsTimeout.Token);
            using var stream = new NetworkStream(tcpSocket, ownsSocket: false);

            byte[] framed = new byte[2 + queryData.Length];
            framed[0] = (byte)(queryData.Length >> 8);
            framed[1] = (byte)queryData.Length;
            Buffer.BlockCopy(queryData, 0, framed, 2, queryData.Length);

            await stream.WriteAsync(framed, ctsTimeout.Token);
            await stream.FlushAsync(ctsTimeout.Token);

            byte[] lenBuf = new byte[2];
            if (!await ReadExactAsync(stream, lenBuf, 2, ctsTimeout.Token))
            {
                return null;
            }

            int respLen = (lenBuf[0] << 8) | lenBuf[1];
            if (respLen < 12 || respLen > 65535)
            {
                return null;
            }

            byte[] resp = new byte[respLen];
            if (!await ReadExactAsync(stream, resp, respLen, ctsTimeout.Token))
            {
                return null;
            }

            ushort respTxId = (ushort)((resp[0] << 8) | resp[1]);
            return respTxId == expectedTxId ? resp : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int count, CancellationToken token)
    {
        int offset = 0;
        while (offset < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), token);
            if (n <= 0) return false;
            offset += n;
        }
        return true;
    }

    private async Task SendResponseAsync(byte[] responseData, EndPoint clientEndpoint)
    {
        try
        {
            var sock = _listenerSocket;
            if (sock != null && responseData.Length > 0)
            {
                await sock.SendToAsync(responseData, SocketFlags.None, clientEndpoint);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error al enviar respuesta DNS al cliente {Endpoint}", clientEndpoint);
        }
    }

    public static bool IsPrivateOrSpecialIp(IPAddress ip)
    {
        if (ip == null) return true;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IsSpecialOrBogusIp(ip)) return true;

        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            // 10.0.0.0/8 (RFC 1918)
            if (bytes[0] == 10) return true;
            // 172.16.0.0/12 (RFC 1918)
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
            // 192.168.0.0/16 (RFC 1918)
            if (bytes[0] == 192 && bytes[1] == 168) return true;
            // 169.254.0.0/16 (Link-local)
            if (bytes[0] == 169 && bytes[1] == 254) return true;
            // 100.64.0.0/10 (CGNAT RFC 6598)
            if (bytes[0] == 100 && (bytes[1] & 0xC0) == 64) return true;
        }
        else if (bytes.Length == 16)
        {
            // fe80::/10 (Link-local)
            if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) return true;
            // fc00::/7 (ULA)
            if ((bytes[0] & 0xFE) == 0xFC) return true;
            // fec0::/10 (Site-local)
            if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0) return true;
        }

        return false;
    }

    private static bool IsSpecialOrBogusIp(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.None) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None)) return true;

        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            // 0.0.0.0/8
            if (bytes[0] == 0) return true;
            // 255.255.255.255
            if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255) return true;
            // 224.0.0.0/4 (multicast)
            if ((bytes[0] & 0xF0) == 0xE0) return true;
        }
        else if (bytes.Length == 16)
        {
            // Multicast IPv6 (ff00::/8)
            if (bytes[0] == 0xFF) return true;
        }
        return false;
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
        _concurrency.Dispose();
    }
}
