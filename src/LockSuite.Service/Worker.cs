using System;
using System.Threading;
using System.Threading.Tasks;
using LockSuite.Service.CaptivePortal;
using LockSuite.Service.Config;
using LockSuite.Service.Dns;
using LockSuite.Service.Ipc;
using LockSuite.Service.Proxy;
using LockSuite.Service.Security;
using LockSuite.Service.Trial;
using LockSuite.Service.Updates;
using LockSuite.Service.Wfp;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service;

public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ConfigManager _configManager;
    private readonly IWfpManager _wfpManager;
    private readonly DnsResolver _dnsResolver;
    private readonly DnsConfigurator _dnsConfigurator;
    private readonly NamedPipeServer _pipeServer;
    private readonly UpdateManager _updateManager;
    private readonly TrialManager _trialManager;
    private readonly SniProxy? _sniProxy;
    private readonly CaptivePortalManager? _captivePortal;
    private readonly bool _testWfpMode;

    public Worker(
        ILogger<Worker> logger,
        ConfigManager configManager,
        IWfpManager wfpManager,
        DnsResolver dnsResolver,
        DnsConfigurator dnsConfigurator,
        NamedPipeServer pipeServer,
        UpdateManager updateManager,
        TrialManager trialManager,
        SniProxy? sniProxy = null,
        CaptivePortalManager? captivePortal = null,
        bool testWfpMode = false)
    {
        _logger = logger;
        _configManager = configManager;
        _wfpManager = wfpManager;
        _dnsResolver = dnsResolver;
        _dnsConfigurator = dnsConfigurator;
        _pipeServer = pipeServer;
        _updateManager = updateManager;
        _trialManager = trialManager;
        _sniProxy = sniProxy;
        _captivePortal = captivePortal;
        _testWfpMode = testWfpMode;
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("=================================================");
        _logger.LogInformation("  Iniciando LockSuite Windows Service            ");
        _logger.LogInformation("=================================================");

        // 0. Endurecer permisos NTFS de %ProgramData%\LockSuite (remover herencia de Users)
        AclHelper.SecureProgramDataDirectory();

        // 1. Inicializar WFP (default-deny). No lanza: ante error pasa a simulación.
        var cfg = _configManager.CurrentConfig;
        _wfpManager.Initialize(cfg.FailClosed, cfg.AllowLocalNetwork);

        // Al cambiar la config: aplicar en vivo el permiso de red local, revocar IPs/caché si hubo bajas y vaciar la caché DNS.
        _configManager.ConfigChangedDetailed += OnConfigChangedDetailed;

        // 2. Capturar DNS originales del adaptador ANTES de aplicar NRPT (fallback en redes que bloquean 1.1.1.1/8.8.8.8)
        var systemDns = _dnsConfigurator.CaptureCurrentDnsServers();
        _dnsResolver.SetFallbackUpstreams(systemDns);

        // 3. Iniciar proxy SNI transparente (Fase 2) y enlazarlo al resolutor DNS
        if (_sniProxy != null)
        {
            _sniProxy.Start();
            _dnsResolver.SetSniProxyActiveProvider(() => _sniProxy.IsListening);
        }

        // 4. Iniciar resolutor DNS local (127.0.0.1:53). No lanza: si no puede enlazar,
        //    queda IsListening=false y el servicio sigue en pie (la red sigue bloqueada).
        _dnsResolver.Start();

        // 5. Iniciar servidor IPC (Named Pipe para la GUI) ANTES de tocar NRPT: aplicar la regla
        //    llama a PowerShell y puede demorar varios segundos; asi la ventana puede conectarse
        //    de inmediato en vez de esperar a que termine.
        _pipeServer.Start();

        // 6. Aplicar redirección DNS del sistema hacia 127.0.0.1 SOLO si el resolutor local
        //    realmente esta escuchando.
        if (_dnsResolver.IsListening)
        {
            _dnsConfigurator.ApplyNrptRedirect();
        }
        else
        {
            _logger.LogError("El resolutor DNS local no esta escuchando: NO se redirige el DNS del sistema (se evita cortar el internet).");
            _dnsConfigurator.RemoveNrptRedirect();
        }

        // 7. Iniciar verificador de actualizaciones automáticas
        _updateManager.StartPeriodicChecks();

        // 8. Si está en modo test WFP, activar auto-rollback
        if (_testWfpMode)
        {
            _logger.LogWarning("MODO TEST WFP ACTIVO: Se iniciará auto-rollback en 30 segundos.");
            _wfpManager.StartAutoRollback(TimeSpan.FromSeconds(30), () =>
            {
                _dnsConfigurator.RemoveNrptRedirect();
            });
        }

        return base.StartAsync(cancellationToken);
    }

    private void OnConfigChangedDetailed(LockSuite.Core.WhitelistConfig cfg, bool revokeDynamicIps)
    {
        try { _wfpManager.SetAllowLocalNetwork(cfg.AllowLocalNetwork); } catch (Exception ex) { _logger.LogWarning(ex, "No se pudo aplicar el permiso de red local."); }
        if (revokeDynamicIps)
        {
            try { _wfpManager.RemoveAllDynamicRules(); } catch (Exception ex) { _logger.LogWarning(ex, "No se pudieron revocar reglas dinámicas tras cambio de lista."); }
            _dnsResolver.ClearUpstreamCache();
        }
        // Vaciar la caché DNS del sistema para que los permisos o bloqueos nuevos surtan efecto inmediato.
        _dnsConfigurator.FlushDnsCache();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("LockSuite Windows Service está en ejecución y filtrando.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(10_000, stoppingToken);

                // Modo de prueba descartable: si venció y está en AutoRemove, desinstala solo.
                // (El flujo Prompt NO borra nada acá: espera la decisión del usuario desde la GUI.)
                _trialManager.CheckAutoRemove();

                _logger.LogDebug("Estado LockSuite: Reglas dinámicas={Rules}, Consultas={Queries} (Permitidas={Allowed}, Bloqueadas={Blocked}), DNS escuchando={Dns}, SNI={Sni}",
                    _wfpManager.ActiveDynamicRulesCount,
                    _dnsResolver.TotalQueries,
                    _dnsResolver.AllowedQueries,
                    _dnsResolver.BlockedQueries,
                    _dnsResolver.IsListening,
                    _sniProxy?.IsListening ?? false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Deteniendo LockSuite Windows Service (parada ordenada)...");

        _configManager.ConfigChangedDetailed -= OnConfigChangedDetailed;

        // 0. Detener timer de portal cautivo antes de revertir NRPT (evita carrera en apagado)
        try { _captivePortal?.Dispose(); } catch { }

        // 1. Detener IPC
        _pipeServer.Stop();

        // 2. Detener actualizador
        _updateManager.Dispose();

        // 3. Detener proxy SNI
        try { _sniProxy?.Stop(); } catch { }

        // 4. Restaurar DNS del sistema
        _dnsConfigurator.RemoveNrptRedirect();

        // 5. Detener resolutor DNS
        _dnsResolver.Stop();

        // 6. Revertir filtros WFP.
        _wfpManager.Rollback();

        _logger.LogInformation("LockSuite Windows Service detenido correctamente. Conectividad restaurada.");
        return base.StopAsync(cancellationToken);
    }
}
