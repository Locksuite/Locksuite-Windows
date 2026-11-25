using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LockSuite.Service.Config;
using LockSuite.Service.Learning;
using LockSuite.Service.Proxy;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LockSuite.Service.Tests;

public class SniProxyTests : IDisposable
{
    private readonly string _tempConfigFile;
    private readonly string _tempLearningFile;
    private readonly ConfigManager _configManager;
    private readonly LearningManager _learningManager;

    public SniProxyTests()
    {
        _tempConfigFile = Path.Combine(Path.GetTempPath(), "ls_sniproxy_cfg_" + Guid.NewGuid().ToString("N") + ".json");
        _tempLearningFile = Path.Combine(Path.GetTempPath(), "ls_sniproxy_learn_" + Guid.NewGuid().ToString("N") + ".json");
        _configManager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        _learningManager = new LearningManager(NullLogger<LearningManager>.Instance, _tempLearningFile);
    }

    public void Dispose()
    {
        _learningManager.Dispose();
        try { if (File.Exists(_tempConfigFile)) File.Delete(_tempConfigFile); } catch { }
        try { if (File.Exists(_tempLearningFile)) File.Delete(_tempLearningFile); } catch { }
    }

    private static byte[] BuildTlsClientHello(string? sniHost, bool includeEch = false, int paddingBytes = 0)
    {
        using var extStream = new MemoryStream();

        if (!string.IsNullOrEmpty(sniHost))
        {
            byte[] hostBytes = Encoding.ASCII.GetBytes(sniHost);
            int entryLen = 1 + 2 + hostBytes.Length;
            int listLen = entryLen;
            int extLen = 2 + listLen;

            extStream.WriteByte(0x00); extStream.WriteByte(0x00); // extension type: server_name
            extStream.WriteByte((byte)(extLen >> 8)); extStream.WriteByte((byte)extLen);
            extStream.WriteByte((byte)(listLen >> 8)); extStream.WriteByte((byte)listLen);
            extStream.WriteByte(0x00); // name_type: host_name
            extStream.WriteByte((byte)(hostBytes.Length >> 8)); extStream.WriteByte((byte)hostBytes.Length);
            extStream.Write(hostBytes, 0, hostBytes.Length);
        }

        if (includeEch)
        {
            extStream.WriteByte(0xFE); extStream.WriteByte(0x0D); // extension type: encrypted_client_hello
            extStream.WriteByte(0x00); extStream.WriteByte(0x04);
            extStream.Write(new byte[] { 0x00, 0x01, 0x02, 0x03 }, 0, 4);
        }

        if (paddingBytes > 0)
        {
            extStream.WriteByte(0x00); extStream.WriteByte(0x15); // extension type: padding
            extStream.WriteByte((byte)(paddingBytes >> 8)); extStream.WriteByte((byte)paddingBytes);
            extStream.Write(new byte[paddingBytes], 0, paddingBytes);
        }

        byte[] extensions = extStream.ToArray();

        using var hsBody = new MemoryStream();
        hsBody.WriteByte(0x03); hsBody.WriteByte(0x03); // client_version TLS 1.2
        hsBody.Write(new byte[32], 0, 32);              // random
        hsBody.WriteByte(0x00);                         // session_id len = 0
        hsBody.WriteByte(0x00); hsBody.WriteByte(0x02); // cipher_suites len = 2
        hsBody.WriteByte(0x13); hsBody.WriteByte(0x01); // TLS_AES_128_GCM_SHA256
        hsBody.WriteByte(0x01); hsBody.WriteByte(0x00); // compression_methods = null
        hsBody.WriteByte((byte)(extensions.Length >> 8));
        hsBody.WriteByte((byte)extensions.Length);
        hsBody.Write(extensions, 0, extensions.Length);

        byte[] bodyBytes = hsBody.ToArray();
        using var tlsRecord = new MemoryStream();
        int hsTotalLen = 4 + bodyBytes.Length;
        tlsRecord.WriteByte(0x16); // ContentType: Handshake
        tlsRecord.WriteByte(0x03); tlsRecord.WriteByte(0x01); // TLS 1.0 record version
        tlsRecord.WriteByte((byte)(hsTotalLen >> 8));
        tlsRecord.WriteByte((byte)hsTotalLen);
        tlsRecord.WriteByte(0x01); // HandshakeType: ClientHello
        tlsRecord.WriteByte((byte)(bodyBytes.Length >> 16));
        tlsRecord.WriteByte((byte)(bodyBytes.Length >> 8));
        tlsRecord.WriteByte((byte)bodyBytes.Length);
        tlsRecord.Write(bodyBytes, 0, bodyBytes.Length);

        return tlsRecord.ToArray();
    }

    private static async Task<byte[]> ReadAllUntilEofAsync(Stream stream, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        while (true)
        {
            int n = await stream.ReadAsync(buf, ct);
            if (n <= 0) break;
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    [Fact]
    public async Task Https_AllowedDomain_PassesThroughClientHelloAndResponse()
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        byte[] clientHello = BuildTlsClientHello("mail.google.com");
        byte[] receivedAtUpstream = Array.Empty<byte>();
        byte[] expectedReply = Encoding.ASCII.GetBytes("SERVER_HELLO_OK");

        var upstreamTask = Task.Run(async () =>
        {
            using var client = await upstreamListener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (ms.Length < clientHello.Length)
            {
                int n = await stream.ReadAsync(buf);
                if (n <= 0) break;
                ms.Write(buf, 0, n);
            }
            receivedAtUpstream = ms.ToArray();
            await stream.WriteAsync(expectedReply);
            await stream.FlushAsync();
            client.Client.Shutdown(SocketShutdown.Send);
        });

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }),
            upstreamHttpsPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: true);

        proxy.Start();
        Assert.True(proxy.IsListening);

        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpsPort);
        using var netStream = tcp.GetStream();
        await netStream.WriteAsync(clientHello);
        await netStream.FlushAsync();

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);
        await upstreamTask;

        Assert.Equal(clientHello, receivedAtUpstream);
        Assert.Equal(expectedReply, reply);
        Assert.Equal(1, proxy.AllowedConnections);
        Assert.Equal(0, proxy.BlockedConnections);
    }

    [Fact]
    public async Task Https_BlockedDomain_ClosesConnectionAndRecordsInLearningManager()
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }),
            upstreamHttpsPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: true);

        proxy.Start();

        byte[] clientHello = BuildTlsClientHello("www.google.com");

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpsPort);
        using var netStream = tcp.GetStream();
        await netStream.WriteAsync(clientHello);

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);

        Assert.Empty(reply);
        Assert.False(upstreamListener.Pending());
        Assert.Equal(0, proxy.AllowedConnections);
        Assert.Equal(1, proxy.BlockedConnections);
        Assert.Contains(_learningManager.GetRecent(), e => e.Domain == "www.google.com");
    }

    [Fact]
    public async Task Https_WithEchExtensionOnAllowedDomain_IsRejected()
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }),
            upstreamHttpsPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: true);

        proxy.Start();

        byte[] clientHelloWithEch = BuildTlsClientHello("mail.google.com", includeEch: true);

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpsPort);
        using var netStream = tcp.GetStream();
        await netStream.WriteAsync(clientHelloWithEch);

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);

        Assert.Empty(reply);
        Assert.False(upstreamListener.Pending());
        Assert.Equal(1, proxy.BlockedConnections);
    }

    [Fact]
    public async Task Https_FragmentedLargeClientHelloOver2000Bytes_ReassemblesAndPassesThrough()
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        byte[] clientHello = BuildTlsClientHello("mail.google.com", includeEch: false, paddingBytes: 2200);
        Assert.True(clientHello.Length > 2000);

        byte[] receivedAtUpstream = Array.Empty<byte>();
        var upstreamTask = Task.Run(async () =>
        {
            using var client = await upstreamListener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var ms = new MemoryStream();
            byte[] buf = new byte[1024];
            while (ms.Length < clientHello.Length)
            {
                int n = await stream.ReadAsync(buf);
                if (n <= 0) break;
                ms.Write(buf, 0, n);
            }
            receivedAtUpstream = ms.ToArray();
            await stream.WriteAsync(Encoding.ASCII.GetBytes("LARGE_OK"));
            client.Client.Shutdown(SocketShutdown.Send);
        });

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }),
            upstreamHttpsPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: true);

        proxy.Start();

        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpsPort);
        using var netStream = tcp.GetStream();

        // Fragmentar en escrituras pequeñas
        int chunkSize = 150;
        for (int offset = 0; offset < clientHello.Length; offset += chunkSize)
        {
            int count = Math.Min(chunkSize, clientHello.Length - offset);
            await netStream.WriteAsync(clientHello.AsMemory(offset, count));
            await netStream.FlushAsync();
            await Task.Delay(5);
        }

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);
        await upstreamTask;

        Assert.Equal(clientHello, receivedAtUpstream);
        Assert.Equal("LARGE_OK", Encoding.ASCII.GetString(reply));
        Assert.Equal(1, proxy.AllowedConnections);
    }

    [Fact]
    public async Task Http_AllowedDomain_PassesThroughAndForcesConnectionClose()
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        string receivedRequest = "";
        var upstreamTask = Task.Run(async () =>
        {
            using var client = await upstreamListener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var ms = new MemoryStream();
            byte[] buf = new byte[4096];
            while (true)
            {
                int n = await stream.ReadAsync(buf);
                if (n <= 0) break;
                ms.Write(buf, 0, n);
                if (Encoding.ASCII.GetString(ms.GetBuffer(), 0, (int)ms.Length).Contains("\r\n\r\n", StringComparison.Ordinal))
                    break;
            }
            receivedRequest = Encoding.ASCII.GetString(ms.ToArray());
            byte[] resp = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            await stream.WriteAsync(resp);
            await stream.FlushAsync();
            client.Client.Shutdown(SocketShutdown.Send);
        });

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }),
            upstreamHttpPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: true);

        proxy.Start();

        string rawReq =
            "GET /inbox HTTP/1.1\r\n" +
            "Host: mail.google.com\r\n" +
            "Connection: keep-alive\r\n" +
            "Proxy-Connection: keep-alive\r\n" +
            "User-Agent: Test\r\n\r\n";

        using var tcp = new TcpClient(AddressFamily.InterNetwork);
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpPort);
        using var netStream = tcp.GetStream();
        await netStream.WriteAsync(Encoding.ASCII.GetBytes(rawReq));
        await netStream.FlushAsync();

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);
        await upstreamTask;

        Assert.Contains("Connection: close\r\n", receivedRequest);
        Assert.DoesNotContain("keep-alive", receivedRequest, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("OK", Encoding.ASCII.GetString(reply));
        Assert.Equal(1, proxy.AllowedConnections);
    }

    [Theory]
    [InlineData("CONNECT mail.google.com:443 HTTP/1.1\r\nHost: mail.google.com\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: mail.google.com\r\nHost: evil.com\r\n\r\n")]
    [InlineData("GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n")]
    public async Task Http_ConnectDoubleHostOrBlockedDomain_IsRejected(string rawRequest)
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }),
            upstreamHttpPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: true);

        proxy.Start();

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpPort);
        using var netStream = tcp.GetStream();
        await netStream.WriteAsync(Encoding.ASCII.GetBytes(rawRequest));

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);

        Assert.Empty(reply);
        Assert.False(upstreamListener.Pending());
        Assert.Equal(0, proxy.AllowedConnections);
        Assert.Equal(1, proxy.BlockedConnections);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("192.168.1.10")]
    public async Task Https_PrivateUpstreamIpWithoutTestOverride_IsRejectedAntiSsrf(string privateIp)
    {
        using var upstreamListener = new TcpListener(IPAddress.Loopback, 0);
        upstreamListener.Start();
        int upstreamPort = ((IPEndPoint)upstreamListener.LocalEndpoint).Port;

        using var proxy = new SniProxy(
            NullLogger<SniProxy>.Instance,
            _configManager,
            _learningManager,
            httpsPort: 0,
            httpPort: 0,
            customResolver: (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Parse(privateIp) }),
            upstreamHttpsPortOverride: upstreamPort,
            allowPrivateUpstreamForTests: false);

        proxy.Start();

        byte[] clientHello = BuildTlsClientHello("mail.google.com");

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, proxy.BoundHttpsPort);
        using var netStream = tcp.GetStream();
        await netStream.WriteAsync(clientHello);

        using var cts = new CancellationTokenSource(5000);
        byte[] reply = await ReadAllUntilEofAsync(netStream, cts.Token);

        Assert.Empty(reply);
        Assert.False(upstreamListener.Pending());
        Assert.Equal(0, proxy.AllowedConnections);
        Assert.Equal(1, proxy.BlockedConnections);
    }
}
