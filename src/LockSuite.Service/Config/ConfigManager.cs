using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using LockSuite.Core;
using Microsoft.Extensions.Logging;

namespace LockSuite.Service.Config;

/// <summary>
/// Administra la carga y guardado de WhitelistConfig en disco.
/// Ruta: %ProgramData%\LockSuite\config\whitelist.json
///
/// Rendimiento y concurrencia:
///   - El resolutor DNS consulta IsAllowed() en el camino caliente, por consulta.
///     Para no recalcular LINQ (flatten+distinct) ni tomar el lock en cada consulta,
///     se mantiene un snapshot inmutable (_snapshot) con los patrones permitidos y los de
///     bloqueo, que se reemplaza atomicamente cuando cambia la config. Los lectores (DNS)
///     lo leen sin lock.
///   - Todas las mutaciones y la serializacion toman _lock, por lo que nunca se serializa
///     una lista que otra hebra esta mutando.
///
/// Paquetes de fabrica (sesion 9):
///   - Al cargar (y al guardar por IPC) se ejecuta PresetSync: migra los paquetes viejos
///     ("Google (Gmail, Chat, Drive, Fotos)" -> un paquete por servicio, etc.), agrega el
///     "Bloqueo fijo" y actualiza los dominios de cada preset.
///   - Los paquetes con Blocks=true bloquean con prioridad sobre la lista blanca.
///   - Quitar un dominio de un paquete de fabrica lo anota en "excluded" para que la
///     sincronizacion no lo vuelva a agregar; agregarlo de nuevo lo restituye.
/// </summary>
public sealed class ConfigManager
{
    private readonly string _configPath;
    private readonly ILogger<ConfigManager> _logger;
    private readonly object _lock = new();
    private WhitelistConfig _currentConfig;

    /// <summary>Patrones activos (permitidos y de bloqueo). Inmutable: se reemplaza entero en cada cambio.</summary>
    private sealed class PatternSnapshot
    {
        public static readonly PatternSnapshot Empty = new(Array.Empty<string>(), Array.Empty<string>());

        public PatternSnapshot(string[] allow, string[] block)
        {
            Allow = allow;
            Block = block;
        }

        public string[] Allow { get; }
        public string[] Block { get; }
    }

    private volatile PatternSnapshot _snapshot = PatternSnapshot.Empty;

    public event Action<WhitelistConfig>? ConfigChanged;
    public event Action<WhitelistConfig, bool>? ConfigChangedDetailed;

    private void NotifyConfigChanged(WhitelistConfig cfg, bool revokeDynamicIps)
    {
        ConfigChangedDetailed?.Invoke(cfg, revokeDynamicIps);
        ConfigChanged?.Invoke(cfg);
    }

    public ConfigManager(ILogger<ConfigManager> logger, string? customPath = null)
    {
        _logger = logger;

        if (!string.IsNullOrEmpty(customPath))
        {
            _configPath = customPath;
        }
        else
        {
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string baseDir = Path.Combine(programData, "LockSuite", "config");
            _configPath = Path.Combine(baseDir, "whitelist.json");
        }

        _currentConfig = LoadOrCreateDefault();
        RebuildPatternSnapshot();
    }

    public WhitelistConfig CurrentConfig
    {
        get
        {
            lock (_lock)
            {
                return _currentConfig;
            }
        }
    }

    /// <summary>
    /// Lectura del hot path: sin lock, sobre el snapshot inmutable.
    /// Permitido = coincide con la lista blanca y NO con un paquete de bloqueo activo.
    /// </summary>
    public bool IsAllowed(string? host)
    {
        var s = _snapshot;
        return DomainMatcher.IsAllowed(s.Allow, host, s.Block);
    }

    /// <summary>True si el host cae en un paquete de bloqueo activo (p. ej. el buscador de Google).</summary>
    public bool IsHardBlocked(string? host)
    {
        return DomainMatcher.MatchesAny(_snapshot.Block, host);
    }

    /// <summary>Cantidad de patrones permitidos activos (desde el snapshot, sin recalcular).</summary>
    public int ActivePatternCount => _snapshot.Allow.Length;

    /// <summary>Cantidad de patrones de bloqueo activos.</summary>
    public int ActiveBlockPatternCount => _snapshot.Block.Length;

    /// <summary>Estado actual del modo aprendizaje.</summary>
    public bool LearningMode
    {
        get { lock (_lock) { return _currentConfig.LearningMode; } }
    }

    /// <summary>Serializa la config de forma consistente (bajo lock).</summary>
    public string GetConfigJson()
    {
        lock (_lock)
        {
            return _currentConfig.ToJson();
        }
    }

    public void UpdateConfig(WhitelistConfig newConfig)
    {
        lock (_lock)
        {
            var cfg = newConfig ?? new WhitelistConfig();
            cfg.Packs ??= new();
            cfg.Packs.RemoveAll(p => p is null);

            // Sanitiza patrones en cualquier paquete que no sea un preset reconocido del catalogo
            // (evita que un cliente IPC inyecte BuiltIn = true con Id = null o Id desconocido).
            foreach (var pack in cfg.Packs)
            {
                pack.Domains ??= new();
                pack.Excluded ??= new();
                if (pack.Id is null || Presets.Find(pack.Id) is null)
                {
                    pack.Domains.RemoveAll(d => !DomainMatcher.IsValidPattern(d));
                }
            }
            // Los paquetes de fabrica siempre quedan integros (incluido el bloqueo fijo).
            PresetSync.Apply(cfg);
            // Segunda pasada tras PresetSync por si se migraron extras de paquetes built-in a Personalizados.
            foreach (var pack in cfg.Packs)
            {
                if (pack.Id is null || Presets.Find(pack.Id) is null)
                {
                    pack.Domains.RemoveAll(d => !DomainMatcher.IsValidPattern(d));
                }
            }
            _currentConfig = cfg;
            SaveToDisk(_currentConfig);
            RebuildPatternSnapshot();
        }

        _logger.LogInformation("Configuracion de lista blanca actualizada. Patrones activos: {Count}, bloqueos: {Blocks}",
            ActivePatternCount, ActiveBlockPatternCount);

        NotifyConfigChanged(CurrentConfig, revokeDynamicIps: true);
    }

    public void TogglePack(string packName, bool enabled)
    {
        bool changed = false;
        lock (_lock)
        {
            var pack = _currentConfig.Packs.Find(p => string.Equals(p.Name, packName, StringComparison.OrdinalIgnoreCase));
            if (pack is not null)
            {
                pack.Enabled = enabled;
                SaveToDisk(_currentConfig);
                RebuildPatternSnapshot();
                changed = true;
                _logger.LogInformation("Paquete '{Pack}' {Status}", packName, enabled ? "activado" : "desactivado");
            }
        }
        if (changed) NotifyConfigChanged(CurrentConfig, revokeDynamicIps: !enabled);
    }

    /// <summary>Activa o desactiva el registro de dominios bloqueados (modo aprendizaje).</summary>
    public void SetLearningMode(bool enabled)
    {
        lock (_lock)
        {
            _currentConfig.LearningMode = enabled;
            SaveToDisk(_currentConfig);
        }
        _logger.LogInformation("Modo aprendizaje {Status}", enabled ? "activado" : "desactivado");
        NotifyConfigChanged(CurrentConfig, revokeDynamicIps: false);
    }

    /// <summary>Estado actual del permiso de red local (direcciones privadas).</summary>
    public bool AllowLocalNetwork
    {
        get { lock (_lock) { return _currentConfig.AllowLocalNetwork; } }
    }

    /// <summary>Permite o bloquea la red local (impresoras, router, NAS). Internet sigue filtrado igual.</summary>
    public void SetAllowLocalNetwork(bool enabled)
    {
        lock (_lock)
        {
            _currentConfig.AllowLocalNetwork = enabled;
            SaveToDisk(_currentConfig);
        }
        _logger.LogInformation("Permiso de red local {Status}", enabled ? "activado" : "desactivado");
        NotifyConfigChanged(CurrentConfig, revokeDynamicIps: false);
    }

    /// <summary>Estado actual de la inspección SNI TLS.</summary>
    public bool SniInspectionEnabled
    {
        get { lock (_lock) { return _currentConfig.SniInspectionEnabled; } }
    }

    /// <summary>Activa o desactiva la inspección SNI TLS.</summary>
    public void SetSniInspectionEnabled(bool enabled)
    {
        lock (_lock)
        {
            _currentConfig.SniInspectionEnabled = enabled;
            SaveToDisk(_currentConfig);
        }
        _logger.LogInformation("Inspección SNI {Status}", enabled ? "activada" : "desactivada");
        NotifyConfigChanged(CurrentConfig, revokeDynamicIps: false);
    }

    /// <summary>
    /// Agrega un dominio a un paquete (por defecto "Personalizados").
    ///   - Si el dominio es de un paquete de fabrica permitidor y el tutor lo habia quitado, se restituye ahi.
    ///   - Los paquetes de fabrica no reciben dominios nuevos: van a "Personalizados"
    ///     (si no, la sincronizacion de presets los moveria igual).
    ///   - Nunca se agrega ni restituye en un paquete de bloqueo (eso convertiria un bloqueo en permiso o viceversa).
    /// </summary>
    public bool AddDomain(string domain, string? targetPackName = null)
        => AddDomain(domain, targetPackName, out _);

    public bool AddDomain(string domain, string? targetPackName, out string? errorMessage)
    {
        errorMessage = null;
        domain = DomainMatcher.Normalize(domain);
        if (!DomainMatcher.IsValidPattern(domain))
        {
            errorMessage = $"El patrón '{domain}' es inválido o demasiado amplio (no se permiten TLDs sueltos, sufijos públicos ni IPs).";
            _logger.LogWarning("Dominio rechazado por patron invalido o peligroso: '{Domain}'", domain);
            return false;
        }

        string? addedTo = null;
        lock (_lock)
        {
            // 1) ¿Es un dominio de fabrica de paquetes permitidores que el tutor habia quitado?
            // Se restituye en TODOS los presets permitidores donde estuviera excluido (nunca en paquetes de bloqueo).
            var restorePacks = _currentConfig.Packs.FindAll(p => p.BuiltIn && !p.Blocks &&
                p.Excluded.Exists(d => string.Equals(DomainMatcher.Normalize(d), domain, StringComparison.Ordinal)));
            if (restorePacks.Count > 0)
            {
                foreach (var restorePack in restorePacks)
                {
                    restorePack.Excluded.RemoveAll(d => string.Equals(DomainMatcher.Normalize(d), domain, StringComparison.Ordinal));
                }
                PresetSync.Apply(_currentConfig);   // lo vuelve a poner en su lugar dentro de cada paquete
                SaveToDisk(_currentConfig);
                RebuildPatternSnapshot();
                addedTo = string.Join(", ", restorePacks.Select(p => p.Name));
            }
            else
            {
                string packName = string.IsNullOrWhiteSpace(targetPackName) ? Presets.CustomPackName : targetPackName.Trim();
                var pack = _currentConfig.Packs.Find(p => string.Equals(p.Name, packName, StringComparison.OrdinalIgnoreCase));

                if (pack is not null && pack.Blocks)
                {
                    errorMessage = "No se puede agregar a un paquete de bloqueo.";
                    _logger.LogWarning("No se agrega '{Domain}' al paquete de bloqueo '{Pack}'", domain, pack.Name);
                    return false;
                }

                if (pack is not null && pack.BuiltIn)
                {
                    packName = Presets.CustomPackName;
                    pack = _currentConfig.Packs.Find(p => !p.BuiltIn && !p.Blocks &&
                        string.Equals(p.Name, packName, StringComparison.OrdinalIgnoreCase));
                }

                if (pack is null)
                {
                    pack = new DomainPack
                    {
                        Name = packName,
                        BuiltIn = false,
                        Enabled = true,
                        Domains = new()
                    };
                    _currentConfig.Packs.Add(pack);
                }

                if (!pack.Domains.Exists(d => string.Equals(DomainMatcher.Normalize(d), domain, StringComparison.OrdinalIgnoreCase)))
                {
                    pack.Domains.Add(domain);
                    SaveToDisk(_currentConfig);
                    RebuildPatternSnapshot();
                }
                addedTo = pack.Name;
            }
        }

        _logger.LogInformation("Dominio '{Domain}' agregado al paquete '{Pack}'", domain, addedTo);
        NotifyConfigChanged(CurrentConfig, revokeDynamicIps: false);
        return true;
    }

    /// <summary>
    /// Quita un dominio de todos los paquetes donde aparezca. En los paquetes de fabrica
    /// queda anotado en "excluded" para que la sincronizacion de presets no lo vuelva a agregar.
    /// </summary>
    public bool RemoveDomain(string domain)
    {
        domain = DomainMatcher.Normalize(domain);
        if (string.IsNullOrWhiteSpace(domain)) return false;

        bool removedAny = false;
        lock (_lock)
        {
            foreach (var pack in _currentConfig.Packs)
            {
                int removed = pack.Domains.RemoveAll(d => string.Equals(DomainMatcher.Normalize(d), domain, StringComparison.OrdinalIgnoreCase));
                if (removed == 0) continue;
                removedAny = true;

                if (pack.BuiltIn && !pack.Excluded.Exists(d => string.Equals(DomainMatcher.Normalize(d), domain, StringComparison.OrdinalIgnoreCase)))
                {
                    pack.Excluded.Add(domain);
                }
            }

            if (removedAny)
            {
                SaveToDisk(_currentConfig);
                RebuildPatternSnapshot();
                _logger.LogInformation("Dominio '{Domain}' eliminado de la lista blanca", domain);
            }
        }

        if (removedAny)
        {
            NotifyConfigChanged(CurrentConfig, revokeDynamicIps: true);
        }
        return removedAny;
    }

    /// <summary>Recalcula el snapshot inmutable de patrones. Debe llamarse con _lock tomado.</summary>
    private void RebuildPatternSnapshot()
    {
        _snapshot = new PatternSnapshot(
            _currentConfig.ActivePatterns().ToArray(),
            _currentConfig.ActiveBlockPatterns().ToArray());
    }

    private WhitelistConfig LoadOrCreateDefault()
    {
        try
        {
            if (File.Exists(_configPath))
            {
                string json = File.ReadAllText(_configPath);
                var loaded = WhitelistConfig.FromJson(json);

                // Migracion / actualizacion de paquetes de fabrica (idempotente).
                if (PresetSync.Apply(loaded))
                {
                    _logger.LogInformation("Paquetes de fabrica actualizados (migracion de presets). Se guarda la configuracion.");
                    try
                    {
                        SaveToDisk(loaded);
                    }
                    catch (Exception ex)
                    {
                        // Se sigue con la config migrada en memoria; se reintentara al proximo cambio.
                        _logger.LogWarning(ex, "No se pudo guardar la configuracion migrada en {Path}", _configPath);
                    }
                }

                _logger.LogInformation("Configuracion cargada desde {Path}. Patrones activos: {Count}, bloqueos: {Blocks}",
                    _configPath, loaded.ActivePatterns().Count, loaded.ActiveBlockPatterns().Count);
                return loaded;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al leer configuracion en {Path}. Usando valores predeterminados.", _configPath);
        }

        var defaultConfig = Presets.DefaultConfig();
        try
        {
            SaveToDisk(defaultConfig);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "No se pudo guardar la configuracion inicial en {Path}", _configPath);
        }

        return defaultConfig;
    }

    private void SaveToDisk(WhitelistConfig config)
    {
        string? dir = Path.GetDirectoryName(_configPath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        string tempFile = _configPath + ".tmp";
        string json = config.ToJson();
        File.WriteAllText(tempFile, json);
        File.Move(tempFile, _configPath, overwrite: true);
    }
}
