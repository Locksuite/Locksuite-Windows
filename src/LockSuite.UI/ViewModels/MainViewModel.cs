using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using LockSuite.Core;

namespace LockSuite.UI.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly LockSuiteClient _client = new();
    private readonly DispatcherTimer _refreshTimer;

    private bool _isConnected;
    private bool _isWfpActive;
    private bool _isSimulationMode;
    private bool _isDnsListening;
    private bool _isSniProxyActive;
    private bool _sniInspectionEnabled = true;
    private long _sniAllowedConnections;
    private long _sniBlockedConnections;
    private bool _isNrptApplied;
    private bool _failClosed = true;
    private bool _learningMode = true;
    private bool _allowLocalNetwork;
    private bool _captivePortalActive;
    private string _captivePortalBannerText = "";
    private bool _isPasswordConfigured;
    private int _activeDynamicRulesCount;
    private long _totalQueries;
    private long _allowedQueries;
    private long _blockedQueries;
    private int _whitelistPatternsCount;
    private string _searchQuery = "";

    // Modo de prueba
    private bool _isTrialActive;
    private bool _isTrialAwaiting;
    private bool _trialRequireTutorToRemove;
    private string _trialBannerText = "";
    private bool _trialPromptShown;

    private bool _isAuthenticated;
    private string? _sessionToken;
    private string _statusMessage = "Conectando al servicio LockSuite...";
    private string _activeTab = "Estado";

    /// <summary>Se dispara (una vez) cuando la prueba venció y espera la decisión del usuario.</summary>
    public event Action? TrialAwaitingDecision;

    public bool IsConnected
    {
        get => _isConnected;
        set
        {
            if (SetProperty(ref _isConnected, value))
            {
                OnPropertyChanged(nameof(IsDnsDown));
                OnPropertyChanged(nameof(DnsSummaryText));
                OnPropertyChanged(nameof(SniSummaryText));
                RaiseHeroPropertiesChanged();
            }
        }
    }

    public bool IsWfpActive
    {
        get => _isWfpActive;
        set
        {
            if (SetProperty(ref _isWfpActive, value))
                RaiseHeroPropertiesChanged();
        }
    }

    public bool IsSimulationMode
    {
        get => _isSimulationMode;
        set
        {
            if (SetProperty(ref _isSimulationMode, value))
                RaiseHeroPropertiesChanged();
        }
    }

    public bool IsDnsListening
    {
        get => _isDnsListening;
        set
        {
            if (SetProperty(ref _isDnsListening, value))
            {
                OnPropertyChanged(nameof(IsDnsDown));
                OnPropertyChanged(nameof(DnsSummaryText));
                RaiseHeroPropertiesChanged();
            }
        }
    }

    /// <summary>
    /// True cuando el servicio está conectado pero el resolutor DNS local NO está escuchando
    /// (p. ej. el puerto 53 lo ocupa Docker/WSL/VPN). En ese estado el filtrado por dominio no
    /// funciona y conviene avisarlo con un cartel, no solo con un renglón de detalle (caso 3.3).
    /// </summary>
    public bool IsDnsDown => _isConnected && !_isDnsListening;

    public bool IsSniProxyActive
    {
        get => _isSniProxyActive;
        set
        {
            if (SetProperty(ref _isSniProxyActive, value))
                OnPropertyChanged(nameof(SniSummaryText));
        }
    }

    public bool SniInspectionEnabled
    {
        get => _sniInspectionEnabled;
        set
        {
            if (SetProperty(ref _sniInspectionEnabled, value))
                OnPropertyChanged(nameof(SniSummaryText));
        }
    }

    public long SniAllowedConnections
    {
        get => _sniAllowedConnections;
        set
        {
            if (SetProperty(ref _sniAllowedConnections, value))
                OnPropertyChanged(nameof(SniSummaryText));
        }
    }

    public long SniBlockedConnections
    {
        get => _sniBlockedConnections;
        set
        {
            if (SetProperty(ref _sniBlockedConnections, value))
                OnPropertyChanged(nameof(SniSummaryText));
        }
    }

    public bool IsNrptApplied
    {
        get => _isNrptApplied;
        set
        {
            if (SetProperty(ref _isNrptApplied, value))
                OnPropertyChanged(nameof(DnsSummaryText));
        }
    }

    public bool AllowLocalNetwork
    {
        get => _allowLocalNetwork;
        set => SetProperty(ref _allowLocalNetwork, value);
    }

    public bool CaptivePortalActive
    {
        get => _captivePortalActive;
        set
        {
            if (SetProperty(ref _captivePortalActive, value))
                OnPropertyChanged(nameof(DnsSummaryText));
        }
    }

    public string CaptivePortalBannerText
    {
        get => _captivePortalBannerText;
        set => SetProperty(ref _captivePortalBannerText, value);
    }

    public bool FailClosed
    {
        get => _failClosed;
        set
        {
            if (SetProperty(ref _failClosed, value))
                OnPropertyChanged(nameof(FailClosedSummaryText));
        }
    }

    public string DnsSummaryText
    {
        get
        {
            if (!IsConnected) return "Sin conexión con el servicio";
            if (!IsDnsListening) return "Puerto 53 ocupado — Resolutor detenido";
            if (CaptivePortalActive) return "127.0.0.1:53 (UDP/TCP) — NRPT suspendido por portal cautivo";
            if (IsNrptApplied) return "127.0.0.1:53 (UDP/TCP) — Redirección NRPT Activa";
            return "127.0.0.1:53 (UDP/TCP) — NRPT pendiente";
        }
    }

    public string SniSummaryText
    {
        get
        {
            if (!IsConnected) return "Sin conexión con el servicio";
            if (!SniInspectionEnabled) return "Desactivada por el tutor";
            if (IsSniProxyActive) return $"Activa (127.0.0.1:443/80) — Permitidas: {SniAllowedConnections}, Bloqueadas: {SniBlockedConnections}";
            return "Inactiva (puerto 443/80 no disponible)";
        }
    }

    public string FailClosedSummaryText => FailClosed
        ? "Fail-Closed (Cerrado por defecto)"
        : "Fail-Open";

    public string HeroBannerBackground
    {
        get
        {
            if (!IsConnected) return "#991B1B";
            if (IsSimulationMode) return "#B45309";
            if (!IsWfpActive) return "#991B1B";
            if (IsDnsDown) return "#B45309";
            return "#1E40AF";
        }
    }

    public string HeroBannerTitle
    {
        get
        {
            if (!IsConnected) return "Sin conexión con el servicio LockSuite";
            if (IsSimulationMode) return "Modo Simulación — Sin Filtrado Real";
            if (!IsWfpActive) return "Filtro WFP Inactivo — Protección Detenida";
            if (IsDnsDown) return "Resolutor DNS Detenido — Red Bloqueada";
            return "Protección por Lista Blanca Activa";
        }
    }

    public string HeroBannerSubtitle
    {
        get
        {
            if (!IsConnected)
                return "No se pudo contactar al servicio LockSuite. Verificá que LockSuiteService esté en ejecución.";
            if (IsSimulationMode)
                return "El servicio no pudo aplicar los filtros WFP por falta de privilegios de administrador. La navegación no está protegida.";
            if (!IsWfpActive)
                return "El servicio está conectado, pero los filtros WFP de salida no están aplicados en este momento.";
            if (IsDnsDown)
                return "El puerto 53 está ocupado por otro programa. El bloqueo Fail-Closed sigue activo, pero los sitios permitidos pueden no abrir.";
            return "Todo internet está bloqueado por defecto. Solo las conexiones a sitios permitidos en la lista son resueltas y autorizadas temporalmente en WFP.";
        }
    }

    private void RaiseHeroPropertiesChanged()
    {
        OnPropertyChanged(nameof(HeroBannerBackground));
        OnPropertyChanged(nameof(HeroBannerTitle));
        OnPropertyChanged(nameof(HeroBannerSubtitle));
    }

    public bool LearningMode
    {
        get => _learningMode;
        set => SetProperty(ref _learningMode, value);
    }

    public bool IsPasswordConfigured
    {
        get => _isPasswordConfigured;
        set => SetProperty(ref _isPasswordConfigured, value);
    }

    public int ActiveDynamicRulesCount
    {
        get => _activeDynamicRulesCount;
        set => SetProperty(ref _activeDynamicRulesCount, value);
    }

    public long TotalQueries
    {
        get => _totalQueries;
        set => SetProperty(ref _totalQueries, value);
    }

    public long AllowedQueries
    {
        get => _allowedQueries;
        set => SetProperty(ref _allowedQueries, value);
    }

    public long BlockedQueries
    {
        get => _blockedQueries;
        set => SetProperty(ref _blockedQueries, value);
    }

    public int WhitelistPatternsCount
    {
        get => _whitelistPatternsCount;
        set => SetProperty(ref _whitelistPatternsCount, value);
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value ?? ""))
            {
                ApplyPackFilter();
            }
        }
    }

    public bool IsTrialActive
    {
        get => _isTrialActive;
        set => SetProperty(ref _isTrialActive, value);
    }

    public bool IsTrialAwaiting
    {
        get => _isTrialAwaiting;
        set => SetProperty(ref _isTrialAwaiting, value);
    }

    public bool TrialRequireTutorToRemove
    {
        get => _trialRequireTutorToRemove;
        set => SetProperty(ref _trialRequireTutorToRemove, value);
    }

    public string TrialBannerText
    {
        get => _trialBannerText;
        set => SetProperty(ref _trialBannerText, value);
    }

    public bool IsAuthenticated
    {
        get => _isAuthenticated;
        set => SetProperty(ref _isAuthenticated, value);
    }

    public string? SessionToken => _sessionToken;

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string ActiveTab
    {
        get => _activeTab;
        set => SetProperty(ref _activeTab, value);
    }

    public ObservableCollection<PackViewModel> Packs { get; } = new();

    public ObservableCollection<PackViewModel> FilteredPacks { get; } = new();

    /// <summary>
    /// Paquetes que se muestran como tarjeta "Permitir X" (Gmail, Chat, Drive, Fotos, prog.co.il,
    /// mitmachim.top), en el orden del catalogo. Son las mismas instancias que en <see cref="Packs"/>.
    /// </summary>
    public ObservableCollection<PackViewModel> ServicePacks { get; } = new();

    public ObservableCollection<BlockedDomainEvent> RecentBlocked { get; } = new();

    public MainViewModel()
    {
        _refreshTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(3)
        };
        _refreshTimer.Tick += async (_, _) => await RefreshDataAsync();
        _refreshTimer.Start();

        _ = RefreshDataAsync();
    }

    // Evita refrescos superpuestos: el temporizador dispara cada 3 s y, si el servicio tarda en
    // responder, antes se acumulaban consultas (y ventanas "colgadas") una encima de otra.
    private int _refreshing;
    private int _pauseRefreshCount;

    /// <summary>
    /// Pausa temporalmente el refresco periódico mientras hay diálogos modales abiertos,
    /// evitando que el timer pise cambios pendientes en la UI.
    /// </summary>
    public IDisposable PauseRefresh() => new RefreshPauseScope(this);

    private sealed class RefreshPauseScope : IDisposable
    {
        private readonly MainViewModel _owner;
        private int _disposed;

        public RefreshPauseScope(MainViewModel owner)
        {
            _owner = owner;
            Interlocked.Increment(ref _owner._pauseRefreshCount);
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                Interlocked.Decrement(ref _owner._pauseRefreshCount);
            }
        }
    }

    public async Task RefreshDataAsync()
    {
        if (Volatile.Read(ref _pauseRefreshCount) > 0) return;
        if (Interlocked.Exchange(ref _refreshing, 1) == 1) return;
        try
        {
            var status = await _client.GetStatusAsync();
            if (status != null)
            {
                IsConnected = true;
                IsWfpActive = status.IsWfpActive;
                IsSimulationMode = status.IsSimulationMode;
                IsDnsListening = status.IsDnsListening;
                IsSniProxyActive = status.IsSniProxyActive;
                SniInspectionEnabled = status.SniInspectionEnabled;
                SniAllowedConnections = status.SniAllowedConnections;
                SniBlockedConnections = status.SniBlockedConnections;
                IsNrptApplied = status.IsNrptApplied;
                FailClosed = status.FailClosed;
                LearningMode = status.LearningMode;
                IsPasswordConfigured = status.IsPasswordConfigured;
                ActiveDynamicRulesCount = status.ActiveDynamicRulesCount;
                TotalQueries = status.TotalQueries;
                AllowedQueries = status.AllowedQueries;
                BlockedQueries = status.BlockedQueries;
                WhitelistPatternsCount = status.WhitelistPatternsCount;
                AllowLocalNetwork = status.AllowLocalNetwork;
                CaptivePortalActive = status.CaptivePortalActive;
                if (status.CaptivePortalActive)
                {
                    int s = status.CaptivePortalRemainingSeconds;
                    CaptivePortalBannerText = $"Modo portal cautivo activo: quedan {s / 60} min {s % 60} s. " +
                        "Podés abrir la página de la red Wi-Fi. Al terminar, el filtro vuelve solo.";
                }

                StatusMessage = IsWfpActive
                    ? (IsSimulationMode ? "Modo Simulación Activo (Sin Elevación)" : "Filtro WFP Activo — Navegación Protegida")
                    : "Servicio conectado (Filtro en espera)";
            }
            else
            {
                // Sin servicio: la ventana se muestra igual al instante. No se encadenan mas consultas
                // (cada una esperaria otro timeout); se reintenta en el proximo ciclo del temporizador.
                IsConnected = false;
                StatusMessage = "Servicio LockSuite detenido o inaccesible";
                return;
            }

            // Actualizar recientes incrementalmente sin perder posición/scroll si no hace falta
            var blockedList = await _client.GetRecentBlockedAsync();
            SyncRecentBlocked(blockedList);

            // Estado del modo de prueba
            await RefreshTrialAsync();

            // Cargar configuración si la lista está vacía
            if (Packs.Count == 0 && IsConnected)
            {
                await ReloadConfigAsync();
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error al sincronizar: {ex.Message}";
        }
        finally
        {
            Interlocked.Exchange(ref _refreshing, 0);
        }
    }

    private void SyncRecentBlocked(IReadOnlyList<BlockedDomainEvent> latest)
    {
        if (latest.Count == 0)
        {
            if (RecentBlocked.Count > 0) RecentBlocked.Clear();
            return;
        }

        if (RecentBlocked.Count == latest.Count)
        {
            bool identical = true;
            for (int i = 0; i < latest.Count; i++)
            {
                if (!SameBlockedEvent(RecentBlocked[i], latest[i]))
                {
                    identical = false;
                    break;
                }
            }
            if (identical) return;
        }

        for (int i = 0; i < latest.Count; i++)
        {
            var item = latest[i];
            if (i < RecentBlocked.Count)
            {
                if (SameBlockedEvent(RecentBlocked[i], item)) continue;

                if (i + 1 < RecentBlocked.Count && SameBlockedEvent(RecentBlocked[i + 1], item))
                {
                    RecentBlocked.RemoveAt(i);
                }
                else if (RecentBlocked.Count < latest.Count && SameBlockedEvent(RecentBlocked[i], latest[i + 1]))
                {
                    RecentBlocked.Insert(i, item);
                }
                else
                {
                    RecentBlocked[i] = item;
                }
            }
            else
            {
                RecentBlocked.Add(item);
            }
        }

        while (RecentBlocked.Count > latest.Count)
        {
            RecentBlocked.RemoveAt(RecentBlocked.Count - 1);
        }
    }

    private static bool SameBlockedEvent(BlockedDomainEvent a, BlockedDomainEvent b)
        => a.Count == b.Count
        && a.Timestamp == b.Timestamp
        && string.Equals(a.Domain, b.Domain, StringComparison.OrdinalIgnoreCase)
        && string.Equals(a.ClientIp, b.ClientIp, StringComparison.Ordinal);

    private async Task RefreshTrialAsync()
    {
        var trial = await _client.GetTrialStatusAsync();
        if (trial == null || !trial.Enabled)
        {
            IsTrialActive = false;
            IsTrialAwaiting = false;
            _trialPromptShown = false;
            return;
        }

        TrialRequireTutorToRemove = trial.RequireTutorToRemove;

        if (trial.State == "Active")
        {
            IsTrialActive = true;
            IsTrialAwaiting = false;
            _trialPromptShown = false;
            int total = trial.RemainingSeconds;
            int h = total / 3600;
            int m = (total % 3600) / 60;
            TrialBannerText = $"Modo de prueba: quedan {h} h {m} min. Al terminar se te preguntará si conservar LockSuite o quitarlo.";
        }
        else if (trial.State == "AwaitingDecision")
        {
            IsTrialActive = false;
            IsTrialAwaiting = true;
            TrialBannerText = "El período de prueba terminó. Elegí si conservar LockSuite de forma permanente o quitarlo.";
            if (!_trialPromptShown)
            {
                _trialPromptShown = true;
                TrialAwaitingDecision?.Invoke();
            }
        }
        else
        {
            // None / Kept / Removing
            IsTrialActive = false;
            IsTrialAwaiting = false;
        }
    }

    public async Task ReloadConfigAsync()
    {
        var config = await _client.GetConfigAsync();
        if (config != null)
        {
            Packs.Clear();
            ServicePacks.Clear();
            foreach (var p in config.Packs ?? new List<DomainPack>())
            {
                if (p is null) continue;
                Packs.Add(PackViewModel.FromModel(p));
            }

            // Tarjetas de servicios: en el orden del catalogo de presets.
            foreach (var def in Presets.Catalog.Where(d => d.IsService))
            {
                var vm = Packs.FirstOrDefault(p => string.Equals(p.Id, def.Id, StringComparison.OrdinalIgnoreCase));
                if (vm != null) ServicePacks.Add(vm);
            }

            ApplyPackFilter();
        }
    }

    public void ApplyPackFilter()
    {
        string q = _searchQuery.Trim();
        IEnumerable<PackViewModel> matches = string.IsNullOrEmpty(q)
            ? Packs
            : Packs.Where(p =>
                p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                p.Title.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                p.Domains.Any(d => d.Contains(q, StringComparison.OrdinalIgnoreCase)));

        FilteredPacks.Clear();
        foreach (var pack in matches)
        {
            FilteredPacks.Add(pack);
        }
    }

    /// <summary>
    /// True si el host esta en un paquete de bloqueo activo (p. ej. el buscador de Google o Gemini):
    /// agregarlo a la lista blanca no lo habilitaria.
    /// </summary>
    public bool IsHardBlocked(string host)
    {
        var blockPatterns = Packs.Where(p => p.Blocks && p.Enabled).SelectMany(p => p.Domains);
        return DomainMatcher.MatchesAny(blockPatterns, host);
    }

    /// <summary>Paquetes del tutor (no de fabrica ni de bloqueo) para el dialogo "Agregar dominio".</summary>
    public List<string> CustomPackNames()
    {
        var names = Packs.Where(p => !p.BuiltIn && !p.Blocks).Select(p => p.Name).ToList();
        if (!names.Any(n => string.Equals(n, Presets.CustomPackName, StringComparison.OrdinalIgnoreCase)))
        {
            names.Insert(0, Presets.CustomPackName);
        }
        return names;
    }

    public async Task<(bool Success, string? Error)> AuthenticateTutorAsync(string password)
    {
        var (success, token, error) = await _client.AuthenticateAsync(password);
        if (success && !string.IsNullOrEmpty(token))
        {
            _sessionToken = token;
            IsAuthenticated = true;
            return (true, null);
        }
        return (false, error);
    }

    public void ClearLocalSession()
    {
        _sessionToken = null;
        IsAuthenticated = false;
    }

    public void LockTutor()
    {
        ClearLocalSession();
    }

    public async Task LockTutorAsync()
    {
        string? token = _sessionToken;
        ClearLocalSession();
        if (!string.IsNullOrEmpty(token))
        {
            try
            {
                await _client.LogoutAsync(token);
            }
            catch
            {
                // Best-effort: el token local ya fue limpiado.
            }
        }
    }

    private async Task<(bool Success, bool SessionExpired, string? Error)> ExecuteTutorMutationAsync(
        Func<string, Task<(bool Success, bool Unauthorized, string? Error)>> action,
        Func<Task>? onSuccess = null)
    {
        if (string.IsNullOrEmpty(_sessionToken))
        {
            ClearLocalSession();
            return (false, true, "Sesión no autenticada.");
        }

        var (success, unauthorized, error) = await action(_sessionToken);
        if (unauthorized)
        {
            ClearLocalSession();
            return (false, true, error ?? "La sesión del tutor expiró. Volvé a autenticarte.");
        }

        if (success)
        {
            if (onSuccess != null) await onSuccess();
            return (true, false, null);
        }

        return (false, false, error);
    }

    public Task<(bool Success, bool SessionExpired, string? Error)> TogglePackDetailedAsync(PackViewModel pack)
        => ExecuteTutorMutationAsync(
            token => _client.TogglePackDetailedAsync(pack.Name, pack.Enabled, token),
            RefreshDataAsync);

    public Task<(bool Success, bool SessionExpired, string? Error)> AddDomainDetailedAsync(string domain, string? packName)
        => ExecuteTutorMutationAsync(
            token => _client.AddDomainDetailedAsync(domain, packName, token),
            async () =>
            {
                await ReloadConfigAsync();
                await RefreshDataAsync();
            });

    public Task<(bool Success, bool SessionExpired, string? Error)> RemoveDomainDetailedAsync(string domain)
        => ExecuteTutorMutationAsync(
            token => _client.RemoveDomainDetailedAsync(domain, token),
            async () =>
            {
                await ReloadConfigAsync();
                await RefreshDataAsync();
            });

    public Task<(bool Success, bool SessionExpired, string? Error)> ClearRecentBlockedDetailedAsync()
        => ExecuteTutorMutationAsync(
            token => _client.ClearRecentBlockedDetailedAsync(token),
            () =>
            {
                RecentBlocked.Clear();
                return Task.CompletedTask;
            });

    public Task<(bool Success, bool SessionExpired, string? Error)> SetLearningModeDetailedAsync(bool enabled)
        => ExecuteTutorMutationAsync(
            token => _client.SetLearningModeDetailedAsync(enabled, token),
            RefreshDataAsync);

    public Task<(bool Success, bool SessionExpired, string? Error)> SetAllowLocalNetworkDetailedAsync(bool enabled)
        => ExecuteTutorMutationAsync(
            token => _client.SetAllowLocalNetworkDetailedAsync(enabled, token),
            RefreshDataAsync);

    public Task<(bool Success, bool SessionExpired, string? Error)> SetSniInspectionDetailedAsync(bool enabled)
        => ExecuteTutorMutationAsync(
            token => _client.SetSniInspectionDetailedAsync(enabled, token),
            RefreshDataAsync);

    public Task<(bool Success, bool SessionExpired, string? Error)> StartCaptivePortalDetailedAsync(int minutes)
        => ExecuteTutorMutationAsync(
            token => _client.StartCaptivePortalDetailedAsync(minutes, token),
            RefreshDataAsync);

    public Task<(bool Success, bool SessionExpired, string? Error)> EndCaptivePortalDetailedAsync()
        => ExecuteTutorMutationAsync(
            token => _client.EndCaptivePortalDetailedAsync(token),
            RefreshDataAsync);

    public async Task<bool> TogglePackAsync(PackViewModel pack)
        => (await TogglePackDetailedAsync(pack)).Success;

    public async Task<bool> AddDomainAsync(string domain, string? packName)
        => (await AddDomainDetailedAsync(domain, packName)).Success;

    public async Task<bool> RemoveDomainAsync(string domain)
        => (await RemoveDomainDetailedAsync(domain)).Success;

    public async Task<bool> ClearRecentBlockedAsync()
        => (await ClearRecentBlockedDetailedAsync()).Success;

    public async Task<bool> SetLearningModeAsync(bool enabled)
        => (await SetLearningModeDetailedAsync(enabled)).Success;

    public async Task<bool> SetAllowLocalNetworkAsync(bool enabled)
        => (await SetAllowLocalNetworkDetailedAsync(enabled)).Success;

    public async Task<(bool Success, string? Error)> StartCaptivePortalAsync(int minutes)
    {
        var r = await StartCaptivePortalDetailedAsync(minutes);
        return (r.Success, r.Error);
    }

    public async Task<bool> EndCaptivePortalAsync()
        => (await EndCaptivePortalDetailedAsync()).Success;

    public async Task<(bool Success, string? Error)> SetInitialPasswordAsync(string password)
    {
        return await _client.SetInitialPasswordAsync(password);
    }

    public async Task<(bool Success, string? Error)> ChangePasswordAsync(string oldPassword, string newPassword)
    {
        if (string.IsNullOrEmpty(_sessionToken)) return (false, "Sesión no autenticada");
        var result = await _client.ChangePasswordAsync(oldPassword, newPassword, _sessionToken);
        if (result.Success)
        {
            var reauth = await AuthenticateTutorAsync(newPassword);
            if (!reauth.Success)
            {
                ClearLocalSession();
            }
        }
        return result;
    }

    public async Task<string> RunWfpTestAsync()
    {
        if (string.IsNullOrEmpty(_sessionToken)) return "Requiere autenticación de tutor";
        return await _client.TestWfpAsync(_sessionToken);
    }

    /// <summary>Decisión del usuario al terminar la prueba. Para "quitar" con tutorlock, pasar el token.</summary>
    public async Task<(bool Success, string? Error)> DecideTrialAsync(bool keep, string? token)
    {
        var result = await _client.DecideTrialAsync(keep, token);
        if (result.Success)
        {
            await RefreshTrialAsync();
        }
        return result;
    }
}
