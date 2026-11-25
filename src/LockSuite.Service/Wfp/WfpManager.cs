using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service.Wfp;

public sealed class WfpManager : IWfpManager
{
    private readonly ILogger<WfpManager> _logger;
    private readonly object _engineLock = new();
    private readonly object _rulesLock = new();
    private IntPtr _engineHandle = IntPtr.Zero;
    private IntPtr _dynamicEngineHandle = IntPtr.Zero;
    private bool _isActive;
    private bool _isSimulationMode;
    private long _simNextId = 100_000;

    public const int MaxDynamicRules = 4096;

    // SDDL para restringir reglas criticas a SYSTEM o servicios de red/locales
    internal const string SddlSystemOnly = "O:SYG:SYD:(A;;0x00000001;;;SY)";
    internal const string SddlSystemServices = "O:SYG:SYD:(A;;0x00000001;;;SY)(A;;0x00000001;;;LS)(A;;0x00000001;;;NS)";

    // Codigos WFP relevantes
    private const uint FWP_E_ALREADY_EXISTS = 0x80320002;
    private const uint ERROR_ACCESS_DENIED_WIN32 = 0x00000005;
    private const uint E_ACCESSDENIED_COM = 0x80070005;
    private const uint FWP_E_ACCESS_DENIED_WFP = 0x80320009;

    // Claves FIJAS de los filtros base. Al ser estables (no aleatorias), la instalacion
    // es idempotente: en cada arranque se borran por clave y se vuelven a crear dentro de
    // una transaccion, por lo que nunca se acumulan duplicados entre reinicios del servicio.
    private static readonly Guid KeyLoopbackV4 = new("9b1d2e01-0001-4a01-8b01-10c6b7e5a001");
    private static readonly Guid KeyLoopbackV6 = new("9b1d2e01-0002-4a01-8b01-10c6b7e5a002");
    private static readonly Guid KeyDhcpV4     = new("9b1d2e01-0003-4a01-8b01-10c6b7e5a003");
    private static readonly Guid KeyLocalDns   = new("9b1d2e01-0004-4a01-8b01-10c6b7e5a004");

    // Claves heredadas (legacy) de versiones previas para limpieza idempotente
    private static readonly Guid KeyLegacyServiceAppIdDns   = new("9b1d2e01-0005-4a01-8b01-10c6b7e5a005");
    private static readonly Guid KeyLegacyServiceAppIdHttps = new("9b1d2e01-000e-4a01-8b01-10c6b7e5a00e");
    private static readonly Guid KeyLegacyServiceAppIdHttp  = new("9b1d2e01-000f-4a01-8b01-10c6b7e5a00f");

    // Claves actuales del propio servicio (AppId + SYSTEM + Protocolo, IPv4 e IPv6)
    private static readonly Guid KeyServiceAppIdDnsUdpV4 = new("9b1d2e01-0010-4a01-8b01-10c6b7e5a010");
    private static readonly Guid KeyServiceAppIdDnsTcpV4 = new("9b1d2e01-0011-4a01-8b01-10c6b7e5a011");
    private static readonly Guid KeyServiceAppIdDnsUdpV6 = new("9b1d2e01-0012-4a01-8b01-10c6b7e5a012");
    private static readonly Guid KeyServiceAppIdDnsTcpV6 = new("9b1d2e01-0013-4a01-8b01-10c6b7e5a013");
    private static readonly Guid KeyServiceAppIdHttpsV4  = new("9b1d2e01-0014-4a01-8b01-10c6b7e5a014");
    private static readonly Guid KeyServiceAppIdHttpsV6  = new("9b1d2e01-0015-4a01-8b01-10c6b7e5a015");
    private static readonly Guid KeyServiceAppIdHttpV4   = new("9b1d2e01-0016-4a01-8b01-10c6b7e5a016");
    private static readonly Guid KeyServiceAppIdHttpV6   = new("9b1d2e01-0017-4a01-8b01-10c6b7e5a017");

    private static readonly Guid KeyBlockV4 = new("9b1d2e01-0006-4a01-8b01-10c6b7e5a006");
    private static readonly Guid KeyBlockV6 = new("9b1d2e01-0007-4a01-8b01-10c6b7e5a007");

    // Permisos ADITIVOS (best-effort, fuera de la transaccion base): NTP, DHCPv6 y red local.
    private static readonly Guid KeyNtpV4       = new("9b1d2e01-0008-4a01-8b01-10c6b7e5a008");
    private static readonly Guid KeyNtpV6       = new("9b1d2e01-0018-4a01-8b01-10c6b7e5a018");
    private static readonly Guid KeyDhcpV6      = new("9b1d2e01-0009-4a01-8b01-10c6b7e5a009");
    private static readonly Guid KeyLocalNet10  = new("9b1d2e01-000a-4a01-8b01-10c6b7e5a00a");
    private static readonly Guid KeyLocalNet172 = new("9b1d2e01-000b-4a01-8b01-10c6b7e5a00b");
    private static readonly Guid KeyLocalNet192 = new("9b1d2e01-000c-4a01-8b01-10c6b7e5a00c");
    private static readonly Guid KeyLocalNet169 = new("9b1d2e01-000d-4a01-8b01-10c6b7e5a00d");

    // Reglas entrantes (ALE_AUTH_RECV_ACCEPT_V4/V6) para cerrar tuneles entrantes (Evasion #6)
    private static readonly Guid KeyRecvLoopbackV4  = new("9b1d2e01-0019-4a01-8b01-10c6b7e5a019");
    private static readonly Guid KeyRecvLoopbackV6  = new("9b1d2e01-001a-4a01-8b01-10c6b7e5a01a");
    private static readonly Guid KeyRecvDhcpV4      = new("9b1d2e01-001b-4a01-8b01-10c6b7e5a01b");
    private static readonly Guid KeyRecvDhcpV6      = new("9b1d2e01-001c-4a01-8b01-10c6b7e5a01c");
    private static readonly Guid KeyRecvBlockV4     = new("9b1d2e01-001d-4a01-8b01-10c6b7e5a01d");
    private static readonly Guid KeyRecvBlockV6     = new("9b1d2e01-001e-4a01-8b01-10c6b7e5a01e");
    private static readonly Guid KeyRecvLocalNet10  = new("9b1d2e01-001f-4a01-8b01-10c6b7e5a01f");
    private static readonly Guid KeyRecvLocalNet172 = new("9b1d2e01-0020-4a01-8b01-10c6b7e5a020");
    private static readonly Guid KeyRecvLocalNet192 = new("9b1d2e01-0021-4a01-8b01-10c6b7e5a021");
    private static readonly Guid KeyRecvLocalNet169 = new("9b1d2e01-0022-4a01-8b01-10c6b7e5a022");

    private static readonly Guid[] BaseFilterKeys =
    {
        KeyLoopbackV4, KeyLoopbackV6, KeyDhcpV4, KeyLocalDns,
        KeyLegacyServiceAppIdDns, KeyLegacyServiceAppIdHttps, KeyLegacyServiceAppIdHttp,
        KeyServiceAppIdDnsUdpV4, KeyServiceAppIdDnsTcpV4,
        KeyServiceAppIdDnsUdpV6, KeyServiceAppIdDnsTcpV6,
        KeyServiceAppIdHttpsV4, KeyServiceAppIdHttpsV6,
        KeyServiceAppIdHttpV4, KeyServiceAppIdHttpV6,
        KeyBlockV4, KeyBlockV6,
        KeyNtpV4, KeyNtpV6, KeyDhcpV6,
        KeyLocalNet10, KeyLocalNet172, KeyLocalNet192, KeyLocalNet169,
        KeyRecvLoopbackV4, KeyRecvLoopbackV6, KeyRecvDhcpV4, KeyRecvDhcpV6,
        KeyRecvBlockV4, KeyRecvBlockV6,
        KeyRecvLocalNet10, KeyRecvLocalNet172, KeyRecvLocalNet192, KeyRecvLocalNet169
    };

    // (red local: direcciones privadas addr/mask en host byte order)
    private static readonly (uint Addr, uint Mask, Guid ConnectKey, Guid RecvKey, string Name)[] PrivateRangesV4 =
    {
        (0x0A000000u, 0xFF000000u, KeyLocalNet10,  KeyRecvLocalNet10,  "10.0.0.0/8"),      // 10.0.0.0/8
        (0xAC100000u, 0xFFF00000u, KeyLocalNet172, KeyRecvLocalNet172, "172.16.0.0/12"),   // 172.16.0.0/12
        (0xC0A80000u, 0xFFFF0000u, KeyLocalNet192, KeyRecvLocalNet192, "192.168.0.0/16"),  // 192.168.0.0/16
        (0xA9FE0000u, 0xFFFF0000u, KeyLocalNet169, KeyRecvLocalNet169, "169.254.0.0/16"),  // link-local
    };

    // Control de reglas dinamicas (por IP) con claves aleatorias, rastreadas por id en memoria.
    private readonly ConcurrentDictionary<ulong, DynamicRuleInfo> _dynamicRules = new();
    private readonly ConcurrentDictionary<string, ulong> _ipToFilterId = new();
    private Timer? _expirationTimer;
    private Timer? _autoRollbackTimer;

    private sealed class DynamicRuleInfo
    {
        public ulong FilterId { get; init; }
        public IPAddress IpAddress { get; init; } = IPAddress.None;
        public DateTimeOffset ExpiresAt { get; set; }
    }

    public bool IsActive => _isActive;
    public bool IsSimulationMode => _isSimulationMode;
    public bool IsDynamicSessionActive => _dynamicEngineHandle != IntPtr.Zero;
    public int ActiveDynamicRulesCount
    {
        get
        {
            lock (_rulesLock)
            {
                return _dynamicRules.Count;
            }
        }
    }

    private bool _allowLocalNetwork;
    public bool AllowLocalNetwork => _allowLocalNetwork;

    public WfpManager(ILogger<WfpManager> logger)
    {
        _logger = logger;
    }

    public void Initialize(bool failClosed) => Initialize(failClosed, allowLocalNetwork: false);

    public void Initialize(bool failClosed, bool allowLocalNetwork)
    {
        lock (_engineLock)
        {
            _allowLocalNetwork = allowLocalNetwork;
            if (_isActive) return;

            _logger.LogInformation("Inicializando Windows Filtering Platform (WFP)... FailClosed={FailClosed}, RedLocal={Local}", failClosed, allowLocalNetwork);

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger.LogWarning("Plataforma no es Windows. Activando WFP en modo simulación.");
                _isSimulationMode = true;
                _isActive = true;
                StartExpirationTimer();
                return;
            }

            var session = new FWPM_SESSION0
            {
                sessionKey = Guid.NewGuid(),
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = "LockSuite Filtering Session",
                    description = "Filtro por lista blanca para LockSuite Windows"
                },
                // failClosed=true  -> sesion NO dinamica (flags=0): si el proceso muere, los
                //                     filtros base persisten (la red queda bloqueada = fail-closed)
                //                     hasta el reinicio; en el arranque se re-aplican idempotentes.
                // failClosed=false -> sesion dinamica (flags=1): si el proceso muere, Windows
                //                     remueve los filtros (fail-open explicito).
                flags = failClosed ? 0u : 1u,
                txnWaitTimeoutInMSec = 5000
            };

            // Reintento progresivo ante arranque temprano de BFE (si no es acceso denegado)
            int[] retryDelaysMs = { 500, 1000, 2000, 4000 };
            uint status = NativeMethods.FwpmEngineOpen0(null, 0, IntPtr.Zero, in session, out _engineHandle);
            for (int attempt = 0; status != 0 && !IsAccessDeniedStatus(status) && attempt < retryDelaysMs.Length; attempt++)
            {
                int delayMs = retryDelaysMs[attempt];
                _logger.LogWarning(
                    "FwpmEngineOpen0 retornó 0x{Status:X8} (BFE posiblemente iniciando). Reintento {Attempt}/{Max} en {Delay}ms...",
                    status, attempt + 1, retryDelaysMs.Length, delayMs);
                Thread.Sleep(delayMs);
                status = NativeMethods.FwpmEngineOpen0(null, 0, IntPtr.Zero, in session, out _engineHandle);
            }

            if (status != 0 || _engineHandle == IntPtr.Zero)
            {
                _logger.LogWarning("FwpmEngineOpen0 retornó código 0x{Status:X8}. Se requiere elevación de Administrador. Activando modo simulación.", status);
                _engineHandle = IntPtr.Zero;
                _dynamicEngineHandle = IntPtr.Zero;
                _isSimulationMode = true;
                _isActive = true;
                StartExpirationTimer();
                return;
            }

            // Abrir segunda sesión SIEMPRE dinámica para reglas temporales por IP
            var dynamicSession = new FWPM_SESSION0
            {
                sessionKey = Guid.NewGuid(),
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = "LockSuite Dynamic Rules Session",
                    description = "Sesión dinámica para reglas temporales por IP de LockSuite"
                },
                flags = 1u,
                txnWaitTimeoutInMSec = 5000
            };

            uint dynStatus = NativeMethods.FwpmEngineOpen0(null, 0, IntPtr.Zero, in dynamicSession, out _dynamicEngineHandle);
            if (dynStatus != 0 || _dynamicEngineHandle == IntPtr.Zero)
            {
                _logger.LogWarning(
                    "No se pudo abrir la sesión dinámica WFP secundaria (0x{Status:X8}). Usando sesión base como fallback.",
                    dynStatus);
                _dynamicEngineHandle = IntPtr.Zero;
            }

            try
            {
                InstallBaseFiltersTransacted();
                // Permisos ADITIVOS, best-effort: su fallo NO tira abajo el filtro base (no fail-open).
                InstallOptionalPermits();
                _isActive = true;
                _isSimulationMode = false;
                StartExpirationTimer();
                _logger.LogInformation(
                    "WFP inicializado exitosamente en modo kernel. Subcapa y filtros base aplicados (DynamicSession={DynActive}).",
                    IsDynamicSessionActive);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al instalar subcapa y filtros base en WFP. Efectuando rollback y pasando a simulación.");
                Rollback();
                _isSimulationMode = true;
                _isActive = true;
                StartExpirationTimer();
            }
        }
    }

    private static bool IsAccessDeniedStatus(uint status) =>
        status == ERROR_ACCESS_DENIED_WIN32 ||
        status == E_ACCESSDENIED_COM ||
        status == FWP_E_ACCESS_DENIED_WFP;

    internal static byte[] BuildSecurityDescriptorBytes(string sddl)
    {
        var rsd = new RawSecurityDescriptor(sddl);
        byte[] bytes = new byte[rsd.BinaryLength];
        rsd.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static IntPtr AllocSecurityDescriptorBlob(string sddl, out IntPtr sdDataPtr)
    {
        byte[] sdBytes = BuildSecurityDescriptorBytes(sddl);
        sdDataPtr = Marshal.AllocHGlobal(sdBytes.Length);
        IntPtr sdBlobPtr = IntPtr.Zero;
        try
        {
            Marshal.Copy(sdBytes, 0, sdDataPtr, sdBytes.Length);
            sdBlobPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWP_BYTE_BLOB>());
            Marshal.StructureToPtr(new FWP_BYTE_BLOB
            {
                size = (uint)sdBytes.Length,
                data = sdDataPtr
            }, sdBlobPtr, false);
            return sdBlobPtr;
        }
        catch
        {
            if (sdBlobPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdBlobPtr);
            Marshal.FreeHGlobal(sdDataPtr);
            sdDataPtr = IntPtr.Zero;
            throw;
        }
    }

    public ulong AllowIpTemporary(IPAddress ip, TimeSpan duration)
    {
        if (ip == null || ip.Equals(IPAddress.None) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6None))
            return 0;

        string ipKey = ip.ToString();
        var expiresAt = DateTimeOffset.UtcNow.Add(duration);

        // 1. Fast-path atómico bajo _rulesLock: si la IP ya existe, extender TTL sin tocar WFP.
        lock (_rulesLock)
        {
            if (_ipToFilterId.TryGetValue(ipKey, out ulong existingFilterId) &&
                _dynamicRules.TryGetValue(existingFilterId, out var existingInfo))
            {
                if (expiresAt > existingInfo.ExpiresAt)
                {
                    existingInfo.ExpiresAt = expiresAt;
                }
                return existingFilterId;
            }
        }

        // 2. Crear filtro en WFP fuera de _rulesLock (usando la sesión dinámica si está abierta).
        ulong filterId = 0;
        bool useKernel = false;
        lock (_engineLock)
        {
            IntPtr targetHandle = _dynamicEngineHandle != IntPtr.Zero ? _dynamicEngineHandle : _engineHandle;
            if (!_isSimulationMode && targetHandle != IntPtr.Zero)
            {
                useKernel = true;
                filterId = AddIpFilter(ip, targetHandle);
            }
        }

        if (!useKernel)
        {
            filterId = (ulong)Interlocked.Increment(ref _simNextId);
        }

        if (filterId == 0)
            return 0;

        ulong duplicateToDelete = 0;
        List<ulong>? evictedToDelete = null;
        ulong resultFilterId = filterId;

        // 3. Registrar atómicamente bajo _rulesLock, resolviendo carreras y límite MaxDynamicRules.
        lock (_rulesLock)
        {
            if (_ipToFilterId.TryGetValue(ipKey, out ulong winnerFilterId) &&
                _dynamicRules.TryGetValue(winnerFilterId, out var winnerInfo))
            {
                if (expiresAt > winnerInfo.ExpiresAt)
                {
                    winnerInfo.ExpiresAt = expiresAt;
                }
                duplicateToDelete = useKernel ? filterId : 0;
                resultFilterId = winnerFilterId;
            }
            else
            {
                while (_dynamicRules.Count >= MaxDynamicRules)
                {
                    DynamicRuleInfo? oldest = null;
                    foreach (var rule in _dynamicRules.Values)
                    {
                        if (oldest == null || rule.ExpiresAt < oldest.ExpiresAt)
                        {
                            oldest = rule;
                        }
                    }

                    if (oldest == null) break;

                    if (_dynamicRules.TryRemove(oldest.FilterId, out _))
                    {
                        string oldIpKey = oldest.IpAddress.ToString();
                        if (_ipToFilterId.TryGetValue(oldIpKey, out ulong cur) && cur == oldest.FilterId)
                        {
                            _ipToFilterId.TryRemove(oldIpKey, out _);
                        }
                        if (useKernel)
                        {
                            evictedToDelete ??= new List<ulong>();
                            evictedToDelete.Add(oldest.FilterId);
                        }
                    }
                }

                var info = new DynamicRuleInfo
                {
                    FilterId = filterId,
                    IpAddress = ip,
                    ExpiresAt = expiresAt
                };
                _dynamicRules[filterId] = info;
                _ipToFilterId[ipKey] = filterId;

                _logger.LogDebug("Regla WFP dinámica agregada: IP={IP}, Duración={Seconds}s, FilterId={Id}",
                    ipKey, duration.TotalSeconds, filterId);
            }
        }

        // 4. Eliminar en WFP fuera de _rulesLock cualquier duplicado de carrera o regla evictada.
        if (duplicateToDelete != 0 || evictedToDelete != null)
        {
            lock (_engineLock)
            {
                IntPtr targetHandle = _dynamicEngineHandle != IntPtr.Zero ? _dynamicEngineHandle : _engineHandle;
                if (!_isSimulationMode && targetHandle != IntPtr.Zero)
                {
                    if (duplicateToDelete != 0)
                    {
                        NativeMethods.FwpmFilterDeleteById0(targetHandle, duplicateToDelete);
                    }
                    if (evictedToDelete != null)
                    {
                        foreach (ulong evId in evictedToDelete)
                        {
                            NativeMethods.FwpmFilterDeleteById0(targetHandle, evId);
                        }
                    }
                }
            }
        }

        return resultFilterId;
    }

    public void RemoveDynamicRule(ulong filterId)
    {
        DynamicRuleInfo? removed = null;
        lock (_rulesLock)
        {
            removed = RemoveFromMapsLocked(filterId);
        }

        if (removed != null)
        {
            DeleteDynamicFiltersFromWfp(new[] { (removed.FilterId, removed.IpAddress) });
        }
    }

    public void RemoveDynamicRules(IEnumerable<ulong> filterIds)
    {
        if (filterIds == null) return;

        List<(ulong FilterId, IPAddress Ip)>? removed = null;
        lock (_rulesLock)
        {
            foreach (ulong filterId in filterIds)
            {
                var info = RemoveFromMapsLocked(filterId);
                if (info != null)
                {
                    removed ??= new List<(ulong, IPAddress)>();
                    removed.Add((info.FilterId, info.IpAddress));
                }
            }
        }

        if (removed != null)
        {
            DeleteDynamicFiltersFromWfp(removed);
        }
    }

    public void RemoveAllDynamicRules()
    {
        List<(ulong FilterId, IPAddress Ip)>? removed = null;
        lock (_rulesLock)
        {
            if (_dynamicRules.IsEmpty)
            {
                _ipToFilterId.Clear();
                return;
            }

            removed = new List<(ulong, IPAddress)>(_dynamicRules.Count);
            foreach (var info in _dynamicRules.Values)
            {
                removed.Add((info.FilterId, info.IpAddress));
            }
            _dynamicRules.Clear();
            _ipToFilterId.Clear();
        }

        DeleteDynamicFiltersFromWfp(removed);
    }

    private DynamicRuleInfo? RemoveFromMapsLocked(ulong filterId)
    {
        if (_dynamicRules.TryRemove(filterId, out var info))
        {
            string ipKey = info.IpAddress.ToString();
            if (_ipToFilterId.TryGetValue(ipKey, out ulong currentId) && currentId == filterId)
            {
                _ipToFilterId.TryRemove(ipKey, out _);
            }
            return info;
        }
        return null;
    }

    private void DeleteDynamicFiltersFromWfp(IEnumerable<(ulong FilterId, IPAddress Ip)> removed)
    {
        lock (_engineLock)
        {
            IntPtr targetHandle = _dynamicEngineHandle != IntPtr.Zero ? _dynamicEngineHandle : _engineHandle;
            bool canDeleteKernel = !_isSimulationMode && targetHandle != IntPtr.Zero;

            foreach (var (filterId, ip) in removed)
            {
                if (canDeleteKernel)
                {
                    NativeMethods.FwpmFilterDeleteById0(targetHandle, filterId);
                }
                _logger.LogDebug("Regla WFP dinámica removida: IP={IP}, FilterId={Id}", ip, filterId);
            }
        }
    }

    public void Rollback()
    {
        lock (_engineLock)
        {
            CancelAutoRollback();
            RemoveAllDynamicRules();

            if (_dynamicEngineHandle != IntPtr.Zero)
            {
                NativeMethods.FwpmEngineClose0(_dynamicEngineHandle);
                _dynamicEngineHandle = IntPtr.Zero;
            }

            if (_engineHandle != IntPtr.Zero)
            {
                // Borrado por CLAVE (no por id): limpia de forma confiable incluso filtros
                // base que hayan quedado de una instancia previa.
                foreach (var key in BaseFilterKeys)
                {
                    var k = key;
                    NativeMethods.FwpmFilterDeleteByKey0(_engineHandle, in k);
                }

                NativeMethods.FwpmSubLayerDeleteByKey0(_engineHandle, in WfpConstants.LockSuiteSubLayerGuid);
                NativeMethods.FwpmEngineClose0(_engineHandle);
                _engineHandle = IntPtr.Zero;
            }

            _isActive = false;
            _logger.LogInformation("WFP Rollback completado. Todas las reglas y subcapa han sido removidas.");
        }
    }

    /// <summary>
    /// Limpieza total fuera del ciclo de vida normal del servicio (para --reset-wfp y el
    /// desinstalador). Abre su propio motor, borra por clave los filtros base y la subcapa,
    /// y cierra. Seguro de llamar aunque no exista nada (ignora "no encontrado").
    /// </summary>
    public void HardReset()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _logger.LogInformation("HardReset omitido (plataforma no Windows).");
            return;
        }

        lock (_engineLock)
        {
            var session = new FWPM_SESSION0
            {
                sessionKey = Guid.NewGuid(),
                displayData = new FWPM_DISPLAY_DATA0 { name = "LockSuite Reset Session", description = "Limpieza de filtros LockSuite" },
                flags = 0,
                txnWaitTimeoutInMSec = 5000
            };

            uint status = NativeMethods.FwpmEngineOpen0(null, 0, IntPtr.Zero, in session, out IntPtr handle);
            if (status != 0 || handle == IntPtr.Zero)
            {
                _logger.LogWarning("HardReset: no se pudo abrir el motor WFP (0x{Status:X8}). ¿Falta elevación?", status);
                return;
            }

            try
            {
                foreach (var key in BaseFilterKeys)
                {
                    var k = key;
                    NativeMethods.FwpmFilterDeleteByKey0(handle, in k);
                }
                NativeMethods.FwpmSubLayerDeleteByKey0(handle, in WfpConstants.LockSuiteSubLayerGuid);
                _logger.LogInformation("HardReset: filtros base y subcapa de LockSuite removidos de WFP.");
            }
            finally
            {
                NativeMethods.FwpmEngineClose0(handle);
            }
        }
    }

    public void StartAutoRollback(TimeSpan timeout, Action? onRollback = null)
    {
        CancelAutoRollback();
        _logger.LogWarning("Iniciando auto-rollback de seguridad en {Seconds} segundos...", timeout.TotalSeconds);
        _autoRollbackTimer = new Timer(_ =>
        {
            _logger.LogWarning("Tiempo de auto-rollback cumplido. Revirtiendo filtros WFP por seguridad.");
            Rollback();
            onRollback?.Invoke();
        }, null, timeout, Timeout.InfiniteTimeSpan);
    }

    public void CancelAutoRollback()
    {
        _autoRollbackTimer?.Dispose();
        _autoRollbackTimer = null;
    }

    public string RunHealthCheck()
    {
        bool isActive;
        bool isSim;
        bool baseOpen;
        bool dynOpen;
        bool allowLocal;
        lock (_engineLock)
        {
            isActive = _isActive;
            isSim = _isSimulationMode;
            baseOpen = _engineHandle != IntPtr.Zero;
            dynOpen = _dynamicEngineHandle != IntPtr.Zero;
            allowLocal = _allowLocalNetwork;
        }

        int dynRules = ActiveDynamicRulesCount;
        string mode = isSim ? "Simulación" : "Kernel";
        return $"WFP HealthCheck: Modo={mode}, IsActive={isActive}, BaseSessionOpen={baseOpen}, IsDynamicSessionActive={dynOpen}, ActiveDynamicRulesCount={dynRules}, AllowLocalNetwork={allowLocal}";
    }

    /// <summary>
    /// Instala la subcapa y los filtros base de forma ATOMICA (transaccion WFP): o se aplican
    /// todos o ninguno, y nunca hay un estado intermedio visible (p.ej. permits sin el block).
    /// Es idempotente: borra por clave los filtros base previos antes de re-crearlos.
    /// </summary>
    private void InstallBaseFiltersTransacted()
    {
        uint tx = NativeMethods.FwpmTransactionBegin0(_engineHandle, 0);
        if (tx != 0)
        {
            throw new InvalidOperationException($"FwpmTransactionBegin0 falló. Código: 0x{tx:X8}");
        }

        try
        {
            EnsureSubLayer();

            // Borra los filtros base previos por clave (idempotencia). "No encontrado" se ignora.
            foreach (var key in BaseFilterKeys)
            {
                var k = key;
                NativeMethods.FwpmFilterDeleteByKey0(_engineHandle, in k);
            }

            // 1. Permit Loopback saliente y entrante (IPv4 e IPv6)
            AddLoopbackPermitFilter(KeyLoopbackV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4);
            AddLoopbackPermitFilter(KeyLoopbackV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6);
            AddLoopbackPermitFilter(KeyRecvLoopbackV4, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
            AddLoopbackPermitFilter(KeyRecvLoopbackV6, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);

            // 2. Permit DHCP saliente y entrante restringido a SYSTEM/LS/NS (Evasiones #2 y #6)
            AddDhcpStylePermitFilter(
                KeyDhcpV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WfpConstants.PORT_DHCP_CLIENT, WfpConstants.PORT_DHCP_SERVER,
                "LockSuite Permit DHCP Outbound", "Permite DHCP saliente para obtencion de IP (SYSTEM/LS/NS)");
            AddDhcpStylePermitFilter(
                KeyRecvDhcpV4, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                WfpConstants.PORT_DHCP_CLIENT, WfpConstants.PORT_DHCP_SERVER,
                "LockSuite Permit DHCP Inbound", "Permite respuestas DHCPv4 entrantes (SYSTEM/LS/NS)");
            AddDhcpStylePermitFilter(
                KeyRecvDhcpV6, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                WfpConstants.PORT_DHCPV6_CLIENT, WfpConstants.PORT_DHCPV6_SERVER,
                "LockSuite Permit DHCPv6 Inbound", "Permite respuestas DHCPv6 entrantes (SYSTEM/LS/NS)");

            // 3. Permit DNS al resolutor local (127.0.0.1:53)
            AddLocalDnsPermitFilter(KeyLocalDns);

            // 4. Permit salida para el ejecutable del servicio (SYSTEM + AppId + Protocolo, IPv4 e IPv6) - Evasion #1
            AddServiceAppIdPermitFilter(KeyServiceAppIdDnsUdpV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4, WfpConstants.IPPROTO_UDP, WfpConstants.PORT_DNS, "DNS Upstream UDP v4");
            AddServiceAppIdPermitFilter(KeyServiceAppIdDnsTcpV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4, WfpConstants.IPPROTO_TCP, WfpConstants.PORT_DNS, "DNS Upstream TCP v4");
            AddServiceAppIdPermitFilter(KeyServiceAppIdDnsUdpV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6, WfpConstants.IPPROTO_UDP, WfpConstants.PORT_DNS, "DNS Upstream UDP v6");
            AddServiceAppIdPermitFilter(KeyServiceAppIdDnsTcpV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6, WfpConstants.IPPROTO_TCP, WfpConstants.PORT_DNS, "DNS Upstream TCP v6");
            AddServiceAppIdPermitFilter(KeyServiceAppIdHttpsV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4, WfpConstants.IPPROTO_TCP, WfpConstants.PORT_HTTPS, "Updates HTTPS v4");
            AddServiceAppIdPermitFilter(KeyServiceAppIdHttpsV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6, WfpConstants.IPPROTO_TCP, WfpConstants.PORT_HTTPS, "Updates HTTPS v6");
            AddServiceAppIdPermitFilter(KeyServiceAppIdHttpV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4, WfpConstants.IPPROTO_TCP, WfpConstants.PORT_HTTP, "Portal Cautivo HTTP v4");
            AddServiceAppIdPermitFilter(KeyServiceAppIdHttpV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6, WfpConstants.IPPROTO_TCP, WfpConstants.PORT_HTTP, "Portal Cautivo HTTP v6");

            // 5. Default-Deny Outbound e Inbound (IPv4 e IPv6) - Reglas terminantes de menor peso en la subcapa
            AddDefaultBlockFilter(KeyBlockV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4, "Default Block Outbound IPv4");
            AddDefaultBlockFilter(KeyBlockV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6, "Default Block Outbound IPv6");
            AddDefaultBlockFilter(KeyRecvBlockV4, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Default Block Inbound IPv4");
            AddDefaultBlockFilter(KeyRecvBlockV6, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Default Block Inbound IPv6");

            uint commit = NativeMethods.FwpmTransactionCommit0(_engineHandle);
            if (commit != 0)
            {
                throw new InvalidOperationException($"FwpmTransactionCommit0 falló. Código: 0x{commit:X8}");
            }
        }
        catch
        {
            NativeMethods.FwpmTransactionAbort0(_engineHandle);
            throw;
        }
    }

    /// <summary>
    /// Permisos ADITIVOS fuera de la transaccion base. Se agregan uno por uno y cada fallo se
    /// registra pero NO interrumpe al resto ni toca los filtros base: asi un bug en uno de estos
    /// permisos nunca puede dejar el filtro en modo simulacion (fail-open). Se borran por clave
    /// antes de recrearse (idempotente). Requiere el engine abierto y el lock tomado.
    /// </summary>
    private void InstallOptionalPermits()
    {
        if (_engineHandle == IntPtr.Zero) return;

        // NTP (UDP 123->123): restringido a SYSTEM/LS/NS (Evasion #2).
        TryAddPortPermit(KeyNtpV4, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            WfpConstants.PORT_NTP, "Permit NTP IPv4 (hora)", WfpConstants.PORT_NTP, SddlSystemServices);
        TryAddPortPermit(KeyNtpV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            WfpConstants.PORT_NTP, "Permit NTP IPv6 (hora)", WfpConstants.PORT_NTP, SddlSystemServices);

        // DHCPv6 (UDP 546->547): restringido a SYSTEM/LS/NS (Evasion #2).
        TryAddPortPermit(KeyDhcpV6, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            WfpConstants.PORT_DHCPV6_SERVER, "Permit DHCPv6", WfpConstants.PORT_DHCPV6_CLIENT, SddlSystemServices);

        ApplyLocalNetworkPermits(_allowLocalNetwork);
    }

    /// <summary>
    /// Activa o desactiva en vivo el permiso de red local (direcciones privadas), sin reiniciar
    /// el servicio. Lo llama el servicio cuando el tutor cambia la opcion en la configuracion.
    /// </summary>
    public void SetAllowLocalNetwork(bool enabled)
    {
        lock (_engineLock)
        {
            _allowLocalNetwork = enabled;
            if (_isSimulationMode || _engineHandle == IntPtr.Zero) return;
            ApplyLocalNetworkPermits(enabled);
        }
    }

    // Agrega o quita los 4 permisos de rangos privados (IPv4) en CONNECT_V4 y RECV_ACCEPT_V4. Idempotente.
    private void ApplyLocalNetworkPermits(bool enabled)
    {
        foreach (var r in PrivateRangesV4)
        {
            var ck = r.ConnectKey;
            var rk = r.RecvKey;
            NativeMethods.FwpmFilterDeleteByKey0(_engineHandle, in ck);
            NativeMethods.FwpmFilterDeleteByKey0(_engineHandle, in rk);
        }
        if (!enabled) return;

        foreach (var r in PrivateRangesV4)
        {
            try
            {
                AddSubnetPermitFilter(r.ConnectKey, WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4, r.Addr, r.Mask, $"Permit red local {r.Name}");
                AddSubnetPermitFilter(r.RecvKey, WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, r.Addr, r.Mask, $"Permit red local entrante {r.Name}");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "No se pudo agregar el permiso de red local {Range}", r.Name);
            }
        }
        _logger.LogInformation("Permiso de red local (direcciones privadas) ACTIVADO.");
    }

    private static FWP_VALUE0 CreateWeight(ulong weight, out IntPtr allocPtr)
    {
        allocPtr = Marshal.AllocHGlobal(sizeof(ulong));
        Marshal.WriteInt64(allocPtr, unchecked((long)weight));
        return new FWP_VALUE0
        {
            type = WfpConstants.FWP_UINT64,
            uint64 = allocPtr
        };
    }

    private static uint AddFilterCore(
        IntPtr engineHandle,
        Guid filterKey,
        string name,
        string description,
        Guid layerKey,
        ulong weight,
        uint actionType,
        FWPM_FILTER_CONDITION0[] conditions,
        out ulong filterId)
    {
        IntPtr condArrayPtr = IntPtr.Zero;
        IntPtr weightPtr = IntPtr.Zero;
        try
        {
            if (conditions.Length > 0)
            {
                int itemSize = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
                condArrayPtr = Marshal.AllocHGlobal(itemSize * conditions.Length);
                for (int i = 0; i < conditions.Length; i++)
                {
                    Marshal.StructureToPtr(conditions[i], IntPtr.Add(condArrayPtr, i * itemSize), false);
                }
            }

            var weightVal = CreateWeight(weight, out weightPtr);
            var filter = new FWPM_FILTER0
            {
                filterKey = filterKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = name,
                    description = description
                },
                layerKey = layerKey,
                subLayerKey = WfpConstants.LockSuiteSubLayerGuid,
                weight = weightVal,
                numFilterConditions = (uint)conditions.Length,
                filterCondition = condArrayPtr,
                action = new FWPM_ACTION0 { type = actionType }
            };

            return NativeMethods.FwpmFilterAdd0(engineHandle, in filter, IntPtr.Zero, out filterId);
        }
        finally
        {
            if (weightPtr != IntPtr.Zero) Marshal.FreeHGlobal(weightPtr);
            if (condArrayPtr != IntPtr.Zero) Marshal.FreeHGlobal(condArrayPtr);
        }
    }

    // Permiso UDP a un puerto remoto/local dado, opcionalmente restringido por SDDL. Best-effort.
    private void TryAddPortPermit(Guid filterKey, Guid layerGuid, ushort remotePort, string label, ushort? localPort = null, string? sddl = null)
    {
        IntPtr sdDataPtr = IntPtr.Zero;
        IntPtr sdBlobPtr = IntPtr.Zero;
        try
        {
            var k = filterKey;
            NativeMethods.FwpmFilterDeleteByKey0(_engineHandle, in k);

            var condList = new List<FWPM_FILTER_CONDITION0>(4)
            {
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_PROTOCOL,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_UINT8, uint8 = WfpConstants.IPPROTO_UDP }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_UINT16, uint16 = remotePort }
                }
            };

            if (localPort.HasValue)
            {
                condList.Add(new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_LOCAL_PORT,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_UINT16, uint16 = localPort.Value }
                });
            }

            if (!string.IsNullOrEmpty(sddl))
            {
                sdBlobPtr = AllocSecurityDescriptorBlob(sddl, out sdDataPtr);
                condList.Add(new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_ALE_USER_ID,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = WfpConstants.FWP_SECURITY_DESCRIPTOR_TYPE,
                        sd = sdBlobPtr
                    }
                });
            }

            uint status = AddFilterCore(
                _engineHandle, filterKey, "LockSuite " + label, label,
                layerGuid, 50, WfpConstants.FWP_ACTION_PERMIT, condList.ToArray(), out _);

            if (status != 0 && status != FWP_E_ALREADY_EXISTS)
                _logger.LogWarning("No se pudo agregar '{Label}' (0x{Status:X8}).", label, status);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error al agregar el permiso '{Label}'.", label);
        }
        finally
        {
            if (sdBlobPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdBlobPtr);
            if (sdDataPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdDataPtr);
        }
    }

    // Permiso a un rango IPv4 (direccion + mascara, en host byte order).
    private void AddSubnetPermitFilter(Guid filterKey, Guid layerGuid, uint addr, uint mask, string label)
    {
        IntPtr addrMaskPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWP_V4_ADDR_AND_MASK>());
        try
        {
            Marshal.StructureToPtr(new FWP_V4_ADDR_AND_MASK { addr = addr, mask = mask }, addrMaskPtr, false);

            var conditions = new[]
            {
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_V4_ADDR_MASK, v4AddrMask = addrMaskPtr }
                }
            };

            uint status = AddFilterCore(
                _engineHandle, filterKey, "LockSuite " + label, "Permite la red local (direcciones privadas)",
                layerGuid, 60, WfpConstants.FWP_ACTION_PERMIT, conditions, out _);

            if (status != 0 && status != FWP_E_ALREADY_EXISTS)
                throw new InvalidOperationException($"FwpmFilterAdd0 ('{label}') falló. Código: 0x{status:X8}");
        }
        finally
        {
            Marshal.FreeHGlobal(addrMaskPtr);
        }
    }

    private void EnsureSubLayer()
    {
        var subLayer = new FWPM_SUBLAYER0
        {
            subLayerKey = WfpConstants.LockSuiteSubLayerGuid,
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = "LockSuite SubLayer",
                description = "Subcapa de alta prioridad para filtrado de salida y entrada LockSuite"
            },
            flags = 0,
            providerKey = IntPtr.Zero,
            providerData = default,
            weight = WfpConstants.LockSuiteSubLayerWeight
        };

        uint status = NativeMethods.FwpmSubLayerAdd0(_engineHandle, in subLayer, IntPtr.Zero);
        if (status != 0 && status != FWP_E_ALREADY_EXISTS)
        {
            throw new InvalidOperationException($"Error al crear subcapa en WFP. Código: 0x{status:X8}");
        }
    }

    private void AddLoopbackPermitFilter(Guid filterKey, Guid layerGuid)
    {
        var conditions = new[]
        {
            new FWPM_FILTER_CONDITION0
            {
                fieldKey = WfpConstants.FWPM_CONDITION_FLAGS,
                matchType = WfpConstants.FWP_MATCH_FLAGS_ALL_SET,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = WfpConstants.FWP_UINT32,
                    uint32 = WfpConstants.FWP_CONDITION_FLAG_IS_LOOPBACK
                }
            }
        };

        uint status = AddFilterCore(
            _engineHandle, filterKey, "LockSuite Permit Loopback", "Permite todo el trafico local de loopback",
            layerGuid, 50, WfpConstants.FWP_ACTION_PERMIT, conditions, out _);
        ThrowIfFilterAddFailed(status, "Permit Loopback");
    }

    private void AddDhcpStylePermitFilter(Guid filterKey, Guid layerGuid, ushort localPort, ushort remotePort, string name, string description)
    {
        IntPtr sdDataPtr = IntPtr.Zero;
        IntPtr sdBlobPtr = IntPtr.Zero;
        try
        {
            sdBlobPtr = AllocSecurityDescriptorBlob(SddlSystemServices, out sdDataPtr);

            var conditions = new[]
            {
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_PROTOCOL,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_UINT8, uint8 = WfpConstants.IPPROTO_UDP }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_UINT16, uint16 = remotePort }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_LOCAL_PORT,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_UINT16, uint16 = localPort }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_ALE_USER_ID,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0 { type = WfpConstants.FWP_SECURITY_DESCRIPTOR_TYPE, sd = sdBlobPtr }
                }
            };

            uint status = AddFilterCore(
                _engineHandle, filterKey, name, description,
                layerGuid, 50, WfpConstants.FWP_ACTION_PERMIT, conditions, out _);
            ThrowIfFilterAddFailed(status, name);
        }
        finally
        {
            if (sdBlobPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdBlobPtr);
            if (sdDataPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdDataPtr);
        }
    }

    private void AddLocalDnsPermitFilter(Guid filterKey)
    {
        var conditions = new[]
        {
            new FWPM_FILTER_CONDITION0
            {
                fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_PORT,
                matchType = WfpConstants.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = WfpConstants.FWP_UINT16,
                    uint16 = WfpConstants.PORT_DNS
                }
            },
            // 127.0.0.1 en host byte order: 0x7F000001
            new FWPM_FILTER_CONDITION0
            {
                fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType = WfpConstants.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = WfpConstants.FWP_UINT32,
                    uint32 = 0x7F000001
                }
            }
        };

        uint status = AddFilterCore(
            _engineHandle, filterKey,
            "LockSuite Permit Local DNS",
            "Permite consultas DNS hacia el resolutor local en 127.0.0.1:53",
            WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            50, WfpConstants.FWP_ACTION_PERMIT, conditions, out _);
        ThrowIfFilterAddFailed(status, "Permit Local DNS");
    }

    private void AddServiceAppIdPermitFilter(Guid filterKey, Guid layerGuid, byte protocol, ushort remotePort, string label)
    {
        string? exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            _logger.LogWarning("No se pudo determinar la ruta del ejecutable para el permit AppId del servicio.");
            return;
        }

        uint appStatus = NativeMethods.FwpmGetAppIdFromFileName0(exePath, out IntPtr blobPtr);
        if (appStatus != 0 || blobPtr == IntPtr.Zero)
        {
            _logger.LogWarning("FwpmGetAppIdFromFileName0 falló (0x{Status:X8}). El servicio podría no alcanzar {Label}.", appStatus, label);
            return;
        }

        IntPtr sdDataPtr = IntPtr.Zero;
        IntPtr sdBlobPtr = IntPtr.Zero;
        try
        {
            sdBlobPtr = AllocSecurityDescriptorBlob(SddlSystemOnly, out sdDataPtr);

            var conditions = new[]
            {
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_ALE_APP_ID,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = WfpConstants.FWP_BYTE_BLOB_TYPE,
                        byteBlob = blobPtr
                    }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_ALE_USER_ID,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = WfpConstants.FWP_SECURITY_DESCRIPTOR_TYPE,
                        sd = sdBlobPtr
                    }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_PROTOCOL,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = WfpConstants.FWP_UINT8,
                        uint8 = protocol
                    }
                },
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = WfpConstants.FWP_UINT16,
                        uint16 = remotePort
                    }
                }
            };

            uint status = AddFilterCore(
                _engineHandle, filterKey,
                $"LockSuite Permit Service {label}",
                $"Permite al propio servicio (SYSTEM) conectar a {label} (puerto {remotePort})",
                layerGuid, 50, WfpConstants.FWP_ACTION_PERMIT, conditions, out _);
            ThrowIfFilterAddFailed(status, $"Permit Service {label}");
        }
        finally
        {
            if (sdBlobPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdBlobPtr);
            if (sdDataPtr != IntPtr.Zero) Marshal.FreeHGlobal(sdDataPtr);
            NativeMethods.FwpmFreeMemory0(ref blobPtr);
        }
    }

    private void AddDefaultBlockFilter(Guid filterKey, Guid layerGuid, string name)
    {
        uint status = AddFilterCore(
            _engineHandle, filterKey, name,
            "Bloqueo por defecto (LockSuite default-deny)",
            layerGuid, 1, WfpConstants.FWP_ACTION_BLOCK,
            Array.Empty<FWPM_FILTER_CONDITION0>(), out _);
        ThrowIfFilterAddFailed(status, name);
    }

    private static void ThrowIfFilterAddFailed(uint status, string label)
    {
        if (status != 0 && status != FWP_E_ALREADY_EXISTS)
        {
            throw new InvalidOperationException($"FwpmFilterAdd0 ('{label}') falló. Código: 0x{status:X8}");
        }
    }

    private static ulong AddIpFilter(IPAddress ip, IntPtr engineHandle)
    {
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = ip.GetAddressBytes();
            uint ipv4HostOrder = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];

            var conditions = new[]
            {
                new FWPM_FILTER_CONDITION0
                {
                    fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType = WfpConstants.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_CONDITION_VALUE0
                    {
                        type = WfpConstants.FWP_UINT32,
                        uint32 = ipv4HostOrder
                    }
                }
            };

            uint status = AddFilterCore(
                engineHandle, Guid.NewGuid(),
                $"LockSuite Allow IP {ip}",
                "Regla dinámica temporal abierta por resolución DNS permitida",
                WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                100, WfpConstants.FWP_ACTION_PERMIT, conditions, out ulong id);
            return status == 0 ? id : 0;
        }
        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] bytes = ip.GetAddressBytes();
            IntPtr byte16Ptr = Marshal.AllocHGlobal(16);
            try
            {
                Marshal.Copy(bytes, 0, byte16Ptr, 16);

                var conditions = new[]
                {
                    new FWPM_FILTER_CONDITION0
                    {
                        fieldKey = WfpConstants.FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType = WfpConstants.FWP_MATCH_EQUAL,
                        conditionValue = new FWP_CONDITION_VALUE0
                        {
                            type = WfpConstants.FWP_BYTE_ARRAY16_TYPE,
                            byteArray16 = byte16Ptr
                        }
                    }
                };

                uint status = AddFilterCore(
                    engineHandle, Guid.NewGuid(),
                    $"LockSuite Allow IPv6 {ip}",
                    "Regla dinámica temporal abierta por resolución DNS permitida",
                    WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    100, WfpConstants.FWP_ACTION_PERMIT, conditions, out ulong id);
                return status == 0 ? id : 0;
            }
            finally
            {
                Marshal.FreeHGlobal(byte16Ptr);
            }
        }

        return 0;
    }

    private void StartExpirationTimer()
    {
        _expirationTimer?.Dispose();
        _expirationTimer = new Timer(CheckExpiredRules, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    private void CheckExpiredRules(object? state)
    {
        var now = DateTimeOffset.UtcNow;
        List<(ulong FilterId, IPAddress Ip)>? removed = null;

        lock (_rulesLock)
        {
            foreach (var rule in _dynamicRules.Values)
            {
                if (now >= rule.ExpiresAt && _dynamicRules.TryRemove(rule.FilterId, out var info))
                {
                    string ipKey = info.IpAddress.ToString();
                    if (_ipToFilterId.TryGetValue(ipKey, out ulong cur) && cur == rule.FilterId)
                    {
                        _ipToFilterId.TryRemove(ipKey, out _);
                    }
                    removed ??= new List<(ulong, IPAddress)>();
                    removed.Add((rule.FilterId, info.IpAddress));
                }
            }
        }

        if (removed != null)
        {
            DeleteDynamicFiltersFromWfp(removed);
        }
    }

    public void Dispose()
    {
        _expirationTimer?.Dispose();
        _autoRollbackTimer?.Dispose();
        Rollback();
    }
}
