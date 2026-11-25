using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LockSuite.Core;
using LockSuite.Service.Config;
using LockSuite.Service.Dns;
using LockSuite.Service.Learning;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service.Proxy;

/// <summary>
/// Proxy TCP transparente (passthrough sin descifrar TLS) en 127.0.0.1:443 y 127.0.0.1:80.
/// Inspecciona el SNI del ClientHello TLS (o la cabecera Host HTTP) antes de conectar al servidor
/// real, bloqueando dominios no autorizados, conexiones con ECH o intentos SSRF a IPs privadas.
/// </summary>
public sealed class SniProxy : IDisposable
{
    private readonly ILogger<SniProxy> _logger;
    private readonly ConfigManager _configManager;
    private readonly LearningManager _learningManager;
    private readonly DnsResolver? _dnsResolver;
    private readonly int _httpsPort;
    private readonly int _httpPort;
    private readonly Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? _customResolver;
    private readonly int? _upstreamHttpsPortOverride;
    private readonly int? _upstreamHttpPortOverride;
    private readonly bool _allowPrivateUpstreamForTests;

    private readonly SemaphoreSlim _concurrency = new(512, 512);
    private Socket? _httpsListener;
    private Socket? _httpListener;
    private CancellationTokenSource? _cts;
    private Task? _httpsAcceptTask;
    private Task? _httpAcceptTask;
    private bool _disposed;

    private long _allowedConnections;
    private long _blockedConnections;

    private const int HandshakeTimeoutMs = 10000;
    private const int ConnectTimeoutMs = 8000;
    private const int MaxHttpsClientHelloBytes = 32 * 1024;
    private const int MaxHttpHeaderBytes = 16 * 1024;
    private const int MaxTlsRecordPayloadBytes = 16 * 1024;

    private static readonly HashSet<string> AllowedHttpMethods = new(StringComparer.Ordinal)
    {
        "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
    };

    public bool IsHttpsListening { get; private set; }
    public bool IsHttpListening { get; private set; }
    public bool IsListening => IsHttpsListening && IsHttpListening;
    public int BoundHttpsPort { get; private set; }
    public int BoundHttpPort { get; private set; }
    public long AllowedConnections => Interlocked.Read(ref _allowedConnections);
    public long BlockedConnections => Interlocked.Read(ref _blockedConnections);

    public SniProxy(
        ILogger<SniProxy> logger,
        ConfigManager configManager,
        LearningManager learningManager,
        DnsResolver? dnsResolver = null,
        int httpsPort = 443,
        int httpPort = 80,
        Func<string, CancellationToken, Task<IReadOnlyList<IPAddress>>>? customResolver = null,
        int? upstreamHttpsPortOverride = null,
        int? upstreamHttpPortOverride = null,
        bool allowPrivateUpstreamForTests = false)
    {
        _logger = logger;
        _configManager = configManager;
        _learningManager = learningManager;
        _dnsResolver = dnsResolver;
        _httpsPort = httpsPort;
        _httpPort = httpPort;
        _customResolver = customResolver;
        _upstreamHttpsPortOverride = upstreamHttpsPortOverride;
        _upstreamHttpPortOverride = upstreamHttpPortOverride;
        _allowPrivateUpstreamForTests = allowPrivateUpstreamForTests;
    }

    public void Start()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(SniProxy));
        if (_cts != null) return;

        _cts = new CancellationTokenSource();

        // Listener HTTPS (443)
        try
        {
            var httpsSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            httpsSock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
            httpsSock.Bind(new IPEndPoint(IPAddress.Loopback, _httpsPort));
            httpsSock.Listen(128);

            _httpsListener = httpsSock;
            BoundHttpsPort = ((IPEndPoint)httpsSock.LocalEndPoint!).Port;
            IsHttpsListening = true;
            _httpsAcceptTask = Task.Run(() => AcceptLoopAsync(httpsSock, isHttps: true, _cts.Token));
            _logger.LogInformation("SNI Proxy (HTTPS) escuchando en 127.0.0.1:{Port}", BoundHttpsPort);
        }
        catch (Exception ex)
        {
            IsHttpsListening = false;
            _logger.LogError(ex, "No se pudo enlazar SNI Proxy HTTPS en 127.0.0.1:{Port}", _httpsPort);
        }

        // Listener HTTP (80)
        try
        {
            var httpSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            httpSock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, true);
            httpSock.Bind(new IPEndPoint(IPAddress.Loopback, _httpPort));
            httpSock.Listen(128);

            _httpListener = httpSock;
            BoundHttpPort = ((IPEndPoint)httpSock.LocalEndPoint!).Port;
            IsHttpListening = true;
            _httpAcceptTask = Task.Run(() => AcceptLoopAsync(httpSock, isHttps: false, _cts.Token));
            _logger.LogInformation("SNI Proxy (HTTP) escuchando en 127.0.0.1:{Port}", BoundHttpPort);
        }
        catch (Exception ex)
        {
            IsHttpListening = false;
            _logger.LogError(ex, "No se pudo enlazar SNI Proxy HTTP en 127.0.0.1:{Port}", _httpPort);
        }
    }

    public void Stop()
    {
        try { _cts?.Cancel(); } catch { }
        try { _httpsListener?.Close(); } catch { }
        try { _httpListener?.Close(); } catch { }
        try { _httpsListener?.Dispose(); } catch { }
        try { _httpListener?.Dispose(); } catch { }
        _httpsListener = null;
        _httpListener = null;
        IsHttpsListening = false;
        IsHttpListening = false;

        try { _cts?.Dispose(); } catch { }
        _cts = null;
        _logger.LogInformation("SNI Proxy detenido");
    }

    private async Task AcceptLoopAsync(Socket listener, bool isHttps, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                Socket client = await listener.AcceptAsync(token);
                await _concurrency.WaitAsync(token);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        if (isHttps)
                        {
                            await HandleHttpsClientAsync(client, token);
                        }
                        else
                        {
                            await HandleHttpClientAsync(client, token);
                        }
                    }
                    finally
                    {
                        try { client.Shutdown(SocketShutdown.Both); } catch { }
                        try { client.Dispose(); } catch { }
                        _concurrency.Release();
                    }
                }, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (!token.IsCancellationRequested)
                {
                    _logger.LogWarning(ex, "Error aceptando conexión en SNI Proxy ({Proto})", isHttps ? "HTTPS" : "HTTP");
                    try { await Task.Delay(50, token); } catch (OperationCanceledException) { break; }
                }
            }
        }
    }

    private async Task HandleHttpsClientAsync(Socket clientSocket, CancellationToken token)
    {
        try
        {
            clientSocket.NoDelay = true;
            using var clientStream = new NetworkStream(clientSocket, ownsSocket: false);
            using var hsCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            hsCts.CancelAfter(HandshakeTimeoutMs);

            using var rawStream = new MemoryStream();
            using var handshakeStream = new MemoryStream();

            byte[] recordHeader = new byte[5];
            int expectedHandshakeTotal = -1;

            while (rawStream.Length < MaxHttpsClientHelloBytes)
            {
                if (!await ReadExactAsync(clientStream, recordHeader, 0, 5, hsCts.Token))
                {
                    return;
                }

                // Solo aceptamos registros TLS Handshake (0x16)
                if (recordHeader[0] != 0x16)
                {
                    Interlocked.Increment(ref _blockedConnections);
                    return;
                }

                int recLen = (recordHeader[3] << 8) | recordHeader[4];
                if (recLen <= 0 || recLen > MaxTlsRecordPayloadBytes ||
                    rawStream.Length + 5 + recLen > MaxHttpsClientHelloBytes)
                {
                    Interlocked.Increment(ref _blockedConnections);
                    return;
                }

                byte[] payload = new byte[recLen];
                if (!await ReadExactAsync(clientStream, payload, 0, recLen, hsCts.Token))
                {
                    return;
                }

                rawStream.Write(recordHeader, 0, 5);
                rawStream.Write(payload, 0, recLen);
                handshakeStream.Write(payload, 0, recLen);

                byte[] hsBuf = handshakeStream.GetBuffer();
                int hsTotalRead = (int)handshakeStream.Length;
                if (hsTotalRead >= 1 && hsBuf[0] != 0x01)
                {
                    Interlocked.Increment(ref _blockedConnections);
                    return;
                }

                if (expectedHandshakeTotal < 0 && hsTotalRead >= 4)
                {
                    int hsLen = (hsBuf[1] << 16) | (hsBuf[2] << 8) | hsBuf[3];
                    expectedHandshakeTotal = 4 + hsLen;
                    if (expectedHandshakeTotal > MaxHttpsClientHelloBytes)
                    {
                        Interlocked.Increment(ref _blockedConnections);
                        return;
                    }
                }

                if (expectedHandshakeTotal > 0 && hsTotalRead >= expectedHandshakeTotal)
                {
                    break;
                }
            }

            if (expectedHandshakeTotal <= 0 || handshakeStream.Length < expectedHandshakeTotal)
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            var parseResult = SniParser.TryParseFromHandshake(
                handshakeStream.GetBuffer().AsSpan(0, (int)handshakeStream.Length));

            if (!parseResult.IsClientHello ||
                parseResult.HasEch ||
                string.IsNullOrWhiteSpace(parseResult.HostName))
            {
                Interlocked.Increment(ref _blockedConnections);
                _logger.LogInformation("SNI Proxy bloqueó conexión HTTPS sin SNI válido o con ECH (IsHello={Hello}, ECH={Ech})",
                    parseResult.IsClientHello, parseResult.HasEch);
                return;
            }

            string host = parseResult.HostName;
            if (!_configManager.IsAllowed(host))
            {
                Interlocked.Increment(ref _blockedConnections);
                _logger.LogInformation("SNI Proxy HTTPS BLOQUEADO: {Host}", host);
                if (_configManager.LearningMode)
                {
                    _learningManager.RecordBlocked(host, "127.0.0.1");
                }
                return;
            }

            int targetPort = _upstreamHttpsPortOverride ?? 443;
            using var upstreamSocket = await ConnectUpstreamAsync(host, targetPort, token);
            if (upstreamSocket == null)
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            upstreamSocket.NoDelay = true;
            using var upstreamStream = new NetworkStream(upstreamSocket, ownsSocket: false);

            // Reenviar exactamente los bytes crudos del ClientHello al servidor real
            await upstreamStream.WriteAsync(rawStream.GetBuffer().AsMemory(0, (int)rawStream.Length), token);
            await upstreamStream.FlushAsync(token);

            Interlocked.Increment(ref _allowedConnections);
            await RelayBidirectionalAsync(clientSocket, clientStream, upstreamSocket, upstreamStream, token);
        }
        catch (OperationCanceledException)
        {
            // Timeout o apagado
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error en conexión HTTPS de SNI Proxy");
        }
    }

    private async Task HandleHttpClientAsync(Socket clientSocket, CancellationToken token)
    {
        try
        {
            clientSocket.NoDelay = true;
            using var clientStream = new NetworkStream(clientSocket, ownsSocket: false);
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            readCts.CancelAfter(HandshakeTimeoutMs);

            byte[] buffer = new byte[MaxHttpHeaderBytes];
            int totalRead = 0;
            int headerEndIndex = -1;

            while (totalRead < MaxHttpHeaderBytes)
            {
                int read = await clientStream.ReadAsync(buffer.AsMemory(totalRead, MaxHttpHeaderBytes - totalRead), readCts.Token);
                if (read <= 0)
                {
                    return;
                }

                totalRead += read;
                headerEndIndex = FindHeaderTerminator(buffer, totalRead);
                if (headerEndIndex >= 0)
                {
                    break;
                }
            }

            if (headerEndIndex < 0)
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            string headerText = Encoding.Latin1.GetString(buffer, 0, headerEndIndex - 4);
            string[] lines = headerText.Split("\r\n", StringSplitOptions.None);
            if (lines.Length == 0)
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            // Validar request line: METHOD SP TARGET SP HTTP/1.x
            string[] reqParts = lines[0].Split(' ');
            if (reqParts.Length != 3 ||
                !AllowedHttpMethods.Contains(reqParts[0]) ||
                string.IsNullOrEmpty(reqParts[1]) ||
                !reqParts[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            string? rawHost = null;
            int hostHeaderCount = 0;
            var rewrittenLines = new List<string>(lines.Length + 1) { lines[0] };

            for (int i = 1; i < lines.Length; i++)
            {
                string line = lines[i];
                int colon = line.IndexOf(':');
                if (colon <= 0)
                {
                    Interlocked.Increment(ref _blockedConnections);
                    return;
                }

                string name = line[..colon].Trim();
                string value = line[(colon + 1)..].Trim();

                if (string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
                {
                    hostHeaderCount++;
                    rawHost = value;
                }

                if (string.Equals(name, "Connection", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(name, "Proxy-Connection", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                rewrittenLines.Add(line);
            }

            if (hostHeaderCount != 1 || string.IsNullOrWhiteSpace(rawHost))
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            string hostCandidate = rawHost;
            if (hostCandidate.EndsWith(":80", StringComparison.Ordinal))
            {
                hostCandidate = hostCandidate[..^3];
            }

            if (hostCandidate.IndexOfAny(new[] { ':', '/', '@', ' ', '\t' }) >= 0)
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            string host = DomainMatcher.Normalize(hostCandidate);
            if (string.IsNullOrWhiteSpace(host))
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            if (!_configManager.IsAllowed(host))
            {
                Interlocked.Increment(ref _blockedConnections);
                _logger.LogInformation("SNI Proxy HTTP BLOQUEADO: {Host}", host);
                if (_configManager.LearningMode)
                {
                    _learningManager.RecordBlocked(host, "127.0.0.1");
                }
                return;
            }

            rewrittenLines.Add("Connection: close");
            string rewrittenHeaderBlock = string.Join("\r\n", rewrittenLines) + "\r\n\r\n";
            byte[] rewrittenBytes = Encoding.Latin1.GetBytes(rewrittenHeaderBlock);

            int targetPort = _upstreamHttpPortOverride ?? 80;
            using var upstreamSocket = await ConnectUpstreamAsync(host, targetPort, token);
            if (upstreamSocket == null)
            {
                Interlocked.Increment(ref _blockedConnections);
                return;
            }

            upstreamSocket.NoDelay = true;
            using var upstreamStream = new NetworkStream(upstreamSocket, ownsSocket: false);

            await upstreamStream.WriteAsync(rewrittenBytes, token);
            int remainingBodyBytes = totalRead - headerEndIndex;
            if (remainingBodyBytes > 0)
            {
                await upstreamStream.WriteAsync(buffer.AsMemory(headerEndIndex, remainingBodyBytes), token);
            }
            await upstreamStream.FlushAsync(token);

            Interlocked.Increment(ref _allowedConnections);
            await RelayBidirectionalAsync(clientSocket, clientStream, upstreamSocket, upstreamStream, token);
        }
        catch (OperationCanceledException)
        {
            // Timeout o apagado
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Error en conexión HTTP de SNI Proxy");
        }
    }

    private async Task<Socket?> ConnectUpstreamAsync(string host, int port, CancellationToken token)
    {
        IReadOnlyList<IPAddress> ips;
        if (_customResolver != null)
        {
            ips = await _customResolver(host, token);
        }
        else if (_dnsResolver != null)
        {
            ips = await _dnsResolver.ResolveUpstreamIpsAsync(host, token);
        }
        else
        {
            return null;
        }

        if (ips == null || ips.Count == 0)
        {
            return null;
        }

        foreach (var rawIp in ips)
        {
            if (rawIp == null) continue;
            if (!_allowPrivateUpstreamForTests && DnsResolver.IsPrivateOrSpecialIp(rawIp))
            {
                _logger.LogWarning("SNI Proxy rechazó IP privada/especial {IP} para {Host} (anti-SSRF)", rawIp, host);
                continue;
            }

            Socket? sock = null;
            try
            {
                sock = new Socket(rawIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                connectCts.CancelAfter(ConnectTimeoutMs);
                await sock.ConnectAsync(new IPEndPoint(rawIp, port), connectCts.Token);
                return sock;
            }
            catch
            {
                try { sock?.Dispose(); } catch { }
            }
        }

        return null;
    }

    private async Task RelayBidirectionalAsync(
        Socket clientSocket,
        NetworkStream clientStream,
        Socket upstreamSocket,
        NetworkStream upstreamStream,
        CancellationToken token)
    {
        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(token);

        async Task PumpAsync(string dir, NetworkStream src, NetworkStream dst, Socket dstSocket)
        {
            try
            {
                byte[] buf = new byte[16384];
                long total = 0;
                while (true)
                {
                    int n = await src.ReadAsync(buf, relayCts.Token);
                    if (n <= 0) break;
                    total += n;
                    await dst.WriteAsync(buf.AsMemory(0, n), relayCts.Token);
                    await dst.FlushAsync(relayCts.Token);
                }
                _logger.LogDebug("SNI Proxy Pump {Dir} EOF tras {Bytes} bytes", dir, total);
            }
            catch (OperationCanceledException)
            {
                // Timeout de drenado o apagado del servicio
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error en PumpAsync {Dir} de SNI Proxy", dir);
            }
            finally
            {
                try { dstSocket.Shutdown(SocketShutdown.Send); } catch { }
            }
        }

        var t1 = PumpAsync("C->U", clientStream, upstreamStream, upstreamSocket);
        var t2 = PumpAsync("U->C", upstreamStream, clientStream, clientSocket);
        await Task.WhenAny(t1, t2);
        // Dar margen para drenar el sentido restante y luego evitar sockets colgados indefinidamente
        relayCts.CancelAfter(TimeSpan.FromSeconds(5));
        await Task.WhenAll(t1, t2);
    }

    private static int FindHeaderTerminator(byte[] buffer, int length)
    {
        for (int i = 3; i < length; i++)
        {
            if (buffer[i - 3] == '\r' &&
                buffer[i - 2] == '\n' &&
                buffer[i - 1] == '\r' &&
                buffer[i] == '\n')
            {
                return i + 1;
            }
        }
        return -1;
    }

    private static async Task<bool> ReadExactAsync(NetworkStream stream, byte[] buffer, int offset, int count, CancellationToken token)
    {
        int total = 0;
        while (total < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(offset + total, count - total), token);
            if (n <= 0) return false;
            total += n;
        }
        return true;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _concurrency.Dispose();
    }
}
