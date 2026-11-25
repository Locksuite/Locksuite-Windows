using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading.Tasks;
using LockSuite.Core;
using LockSuite.Service.Config;
using LockSuite.Service.Dns;
using LockSuite.Service.Ipc;
using LockSuite.Service.Learning;
using LockSuite.Service.Security;
using LockSuite.Service.Trial;
using LockSuite.Service.Wfp;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LockSuite.Service.Tests;

/// <summary>
/// Pruebas del canal IPC REAL (Named Pipe) de punta a punta: cliente (LockSuiteClient) contra el
/// servidor (NamedPipeServer). Antes solo se probaba ProcessRequest() directo, y por eso nadie
/// vio el deadlock del BOM: la ventana se congelaba y el servicio nunca respondia.
/// </summary>
public class IpcRoundTripTests : IDisposable
{
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(15);

    private readonly string _tempDir;
    private readonly string _pipeName = "LockSuiteTestPipe_" + Guid.NewGuid().ToString("N");
    private readonly ConfigManager _configManager;
    private readonly WfpManager _wfpManager;
    private readonly LearningManager _learningManager;
    private readonly DnsResolver _dnsResolver;
    private readonly NamedPipeServer _server;

    public IpcRoundTripTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "locksuite_ipcrt_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempDir);
        _configManager = new ConfigManager(NullLogger<ConfigManager>.Instance, Path.Combine(_tempDir, "whitelist.json"));
        var security = new SecurityManager(NullLogger<SecurityManager>.Instance, Path.Combine(_tempDir, "auth.dat"));
        _wfpManager = new WfpManager(NullLogger<WfpManager>.Instance);
        _wfpManager.Initialize(failClosed: false);
        _learningManager = new LearningManager(NullLogger<LearningManager>.Instance, Path.Combine(_tempDir, "blocked.json"));
        _dnsResolver = new DnsResolver(NullLogger<DnsResolver>.Instance, _configManager, _wfpManager, _learningManager, listenPort: 5356);
        var trial = new TrialManager(NullLogger<TrialManager>.Instance, Path.Combine(_tempDir, "trial.json"));
        _server = new NamedPipeServer(
            NullLogger<NamedPipeServer>.Instance,
            _configManager, security, _wfpManager, _dnsResolver, _learningManager, trial, _pipeName);
        _server.Start();
    }

    public void Dispose()
    {
        _server.Dispose();
        _dnsResolver.Dispose();
        _wfpManager.Dispose();
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public async Task Ping_RoundTrip_Responds()
    {
        var client = new LockSuiteClient(_pipeName);
        var resp = await client.SendCommandAsync("Ping", timeoutMs: 5000).WaitAsync(Guard);
        Assert.True(resp.Success, resp.ErrorMessage);
        Assert.Equal("Pong", resp.Payload);
    }

    [Fact]
    public async Task GetStatus_RoundTrip_ReturnsStatus()
    {
        var client = new LockSuiteClient(_pipeName);
        var status = await client.GetStatusAsync().WaitAsync(Guard);
        Assert.NotNull(status);
        Assert.True(status!.IsRunning);
    }

    [Fact]
    public async Task ManyConsecutiveRequests_AllAnswered()
    {
        var client = new LockSuiteClient(_pipeName);
        for (int i = 0; i < 25; i++)
        {
            var resp = await client.SendCommandAsync("Ping", timeoutMs: 5000).WaitAsync(Guard);
            Assert.True(resp.Success, $"fallo en la peticion {i}: {resp.ErrorMessage}");
        }
    }

    [Fact]
    public async Task ConcurrentRequests_AllAnswered()
    {
        var client = new LockSuiteClient(_pipeName);
        var tasks = new Task<IpcResponse>[10];
        for (int i = 0; i < tasks.Length; i++)
        {
            tasks[i] = client.SendCommandAsync("Ping", timeoutMs: 8000);
        }
        var all = await Task.WhenAll(tasks).WaitAsync(Guard);
        Assert.All(all, r => Assert.True(r.Success, r.ErrorMessage));
    }

    [Fact]
    public async Task ClientWithBom_IsStillUnderstoodByServer()
    {
        // Compatibilidad: un cliente viejo/externo que antepone BOM (Encoding.UTF8) no debe romper al servidor.
        // Se escribe el BOM a mano en un solo Write; el servidor ya esta leyendo, asi que no hay deadlock.
        using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        byte[] payload = Encoding.UTF8.GetPreamble();
        byte[] body = Encoding.UTF8.GetBytes("{\"command\":\"Ping\"}\n");
        byte[] all = new byte[payload.Length + body.Length];
        Buffer.BlockCopy(payload, 0, all, 0, payload.Length);
        Buffer.BlockCopy(body, 0, all, payload.Length, body.Length);
        await pipe.WriteAsync(all).AsTask().WaitAsync(Guard);
        await pipe.FlushAsync();

        using var reader = new StreamReader(pipe, LockSuiteClient.IpcEncoding, true, 4096, leaveOpen: true);
        string? line = await reader.ReadLineAsync().WaitAsync(Guard);
        Assert.NotNull(line);
        var resp = IpcResponse.Deserialize(line!);
        Assert.True(resp!.Success);
    }

    [Fact]
    public async Task GarbageLine_GetsInvalidRequestResponse_NotAHang()
    {
        using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(5000);
        byte[] body = Encoding.UTF8.GetBytes("esto no es json\n");
        await pipe.WriteAsync(body).AsTask().WaitAsync(Guard);
        await pipe.FlushAsync();

        using var reader = new StreamReader(pipe, LockSuiteClient.IpcEncoding, true, 4096, leaveOpen: true);
        string? line = await reader.ReadLineAsync().WaitAsync(Guard);
        Assert.NotNull(line);
        var resp = IpcResponse.Deserialize(line!);
        Assert.False(resp!.Success);
    }

    [Fact]
    public async Task NoServer_ClientFailsFastInsteadOfHanging()
    {
        var client = new LockSuiteClient("LockSuiteNoExiste_" + Guid.NewGuid().ToString("N"));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var resp = await client.SendCommandAsync("Ping", timeoutMs: 1500).WaitAsync(Guard);
        sw.Stop();
        Assert.False(resp.Success);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(6), $"tardo demasiado: {sw.Elapsed}");
    }

    [Fact]
    public async Task OversizedRequestLine_RejectedWithoutCrashingServer()
    {
        using (var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
        {
            await pipe.ConnectAsync(5000).WaitAsync(Guard);
            using var reader = new StreamReader(pipe, LockSuiteClient.IpcEncoding, true, 4096, leaveOpen: true);

            // Escribimos y leemos en paralelo porque un pipe bidireccional sin buffer puede
            // bloquear WriteAsync cuando el servidor corta la lectura al alcanzar el límite.
            var readTask = reader.ReadLineAsync();
            var writeTask = Task.Run(async () =>
            {
                byte[] chunk = new byte[16_384];
                Array.Fill(chunk, (byte)'A');
                for (int i = 0; i < 20; i++) // 320 KB > 256 KB
                {
                    await pipe.WriteAsync(chunk);
                }
                await pipe.WriteAsync(new byte[] { (byte)'\n' });
                await pipe.FlushAsync();
            });

            string? line = await readTask.WaitAsync(Guard);
            try { await writeTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { /* pipe cerrado tras rechazo: esperado */ }

            if (line != null)
            {
                var resp = IpcResponse.Deserialize(line);
                Assert.False(resp!.Success);
                Assert.Contains("límite", resp.ErrorMessage ?? "", StringComparison.OrdinalIgnoreCase);
            }
        }

        // El servidor sigue vivo y responde normalmente después del intento de DoS
        var client = new LockSuiteClient(_pipeName);
        var ping = await client.SendCommandAsync("Ping", timeoutMs: 5000).WaitAsync(Guard);
        Assert.True(ping.Success);
    }

    [Fact]
    public async Task RequireTrustedServer_RejectsStandardUserPipe()
    {
        if (!OperatingSystem.IsWindows()) return;

        // En el entorno de test (usuario estándar sin elevación), el pipe pertenece al usuario actual (no SYSTEM ni Admin).
        // Si requireTrustedServer=true está activo, el cliente debe rechazarlo antes de enviar nada.
        var strictClient = new LockSuiteClient(_pipeName, requireTrustedServer: true);
        var resp = await strictClient.SendCommandAsync("Ping", timeoutMs: 5000).WaitAsync(Guard);

        // Solo falla si el proceso actual no es Admin/SYSTEM (en CI/dev estándar es usuario normal o admin elevado).
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        bool isElevatedAdminOrSystem = identity.IsSystem || principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        if (!isElevatedAdminOrSystem)
        {
            Assert.False(resp.Success);
            Assert.Contains("propietario", resp.ErrorMessage ?? "", StringComparison.OrdinalIgnoreCase);
        }
    }
}
