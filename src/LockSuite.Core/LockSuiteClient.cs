using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace LockSuite.Core;

public sealed class LockSuiteClient
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };
    private readonly string _pipeName;
    private readonly bool _requireTrustedServer;

    public LockSuiteClient(string? pipeName = null, bool? requireTrustedServer = null)
    {
        _pipeName = pipeName ?? IpcConstants.PipeName;
        _requireTrustedServer = requireTrustedServer ?? string.Equals(_pipeName, IpcConstants.PipeName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// UTF-8 SIN marca BOM para el canal IPC. Con <c>Encoding.UTF8</c> y <c>AutoFlush = true</c>,
    /// el StreamWriter escribe el BOM (3 bytes) de forma SINCRONA apenas se crea; como el pipe no
    /// tiene buffer, cliente y servidor quedaban bloqueados escribiendose el BOM el uno al otro
    /// (deadlock: la ventana se congelaba y el servicio nunca respondia).
    /// </summary>
    public static readonly Encoding IpcEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public async Task<IpcResponse> SendCommandAsync(string command, string? payload = null, string? sessionToken = null, int timeoutMs = 3000)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var cts = new CancellationTokenSource(timeoutMs);

            await pipe.ConnectAsync(cts.Token).ConfigureAwait(false);

            if (OperatingSystem.IsWindows() && _requireTrustedServer && !VerifyTrustedServerOwner(pipe))
            {
                return IpcResponse.Fail("Servidor IPC rechazado: el proceso propietario no es SYSTEM ni Administrador");
            }

            using var reader = new StreamReader(pipe, IpcEncoding, detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: true);
            // Sin AutoFlush: el vaciado es explicito y asincrono (FlushAsync) con timeout.
            using var writer = new StreamWriter(pipe, IpcEncoding, bufferSize: 4096, leaveOpen: true);

            var req = new IpcRequest
            {
                Command = command,
                Payload = payload,
                SessionToken = sessionToken
            };

            string reqJson = IpcRequest.Serialize(req);
            await writer.WriteLineAsync(reqJson.AsMemory(), cts.Token).ConfigureAwait(false);
            await writer.FlushAsync(cts.Token).ConfigureAwait(false);

            string? resJson = await reader.ReadLineAsync(cts.Token).ConfigureAwait(false);
            if (string.IsNullOrEmpty(resJson))
            {
                return IpcResponse.Fail("Respuesta vacía del servicio");
            }

            var resp = IpcResponse.Deserialize(resJson);
            return resp ?? IpcResponse.Fail("No se pudo deserializar la respuesta");
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            return IpcResponse.Fail("Tiempo de espera agotado al conectar con el servicio");
        }
        catch (Exception ex)
        {
            return IpcResponse.Fail($"No se pudo conectar al servicio LockSuite: {ex.Message}");
        }
    }

    public async Task<ServiceStatusDto?> GetStatusAsync()
    {
        var resp = await SendCommandAsync("GetStatus");
        if (resp.Success && !string.IsNullOrEmpty(resp.Payload))
        {
            return JsonSerializer.Deserialize<ServiceStatusDto>(resp.Payload, JsonOpts);
        }
        return null;
    }

    public async Task<WhitelistConfig?> GetConfigAsync()
    {
        var resp = await SendCommandAsync("GetConfig");
        if (resp.Success && !string.IsNullOrEmpty(resp.Payload))
        {
            return WhitelistConfig.FromJson(resp.Payload);
        }
        return null;
    }

    public async Task<List<BlockedDomainEvent>> GetRecentBlockedAsync()
    {
        var resp = await SendCommandAsync("GetRecentBlocked");
        if (resp.Success && !string.IsNullOrEmpty(resp.Payload))
        {
            return JsonSerializer.Deserialize<List<BlockedDomainEvent>>(resp.Payload, JsonOpts) ?? new();
        }
        return new();
    }

    public async Task<bool> ClearRecentBlockedAsync(string sessionToken)
        => (await ClearRecentBlockedDetailedAsync(sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> ClearRecentBlockedDetailedAsync(string sessionToken)
        => ToDetailedResult(await SendCommandAsync("ClearRecentBlocked", sessionToken: sessionToken));

    public async Task<(bool Success, string? Token, string? Error)> AuthenticateAsync(string password)
    {
        string payload = JsonSerializer.Serialize(new AuthRequestDto { Password = password });
        var resp = await SendCommandAsync("Authenticate", payload: payload);
        if (resp.Success)
        {
            return (true, resp.Payload, null);
        }
        return (false, null, resp.ErrorMessage ?? "Contraseña incorrecta");
    }

    public async Task<bool> LogoutAsync(string sessionToken)
    {
        var resp = await SendCommandAsync("Logout", sessionToken: sessionToken);
        return resp.Success;
    }

    public async Task<(bool Success, string? Error)> SetInitialPasswordAsync(string password)
    {
        string payload = JsonSerializer.Serialize(new AuthRequestDto { Password = password });
        var resp = await SendCommandAsync("SetInitialPassword", payload: payload);
        return (resp.Success, resp.ErrorMessage);
    }

    public async Task<(bool Success, string? Error)> ChangePasswordAsync(string oldPassword, string newPassword, string sessionToken)
    {
        string payload = JsonSerializer.Serialize(new AuthRequestDto { Password = oldPassword, NewPassword = newPassword });
        var resp = await SendCommandAsync("ChangePassword", payload: payload, sessionToken: sessionToken);
        return (resp.Success, resp.ErrorMessage);
    }

    public async Task<bool> TogglePackAsync(string packName, bool enabled, string sessionToken)
        => (await TogglePackDetailedAsync(packName, enabled, sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> TogglePackDetailedAsync(string packName, bool enabled, string sessionToken)
    {
        string payload = JsonSerializer.Serialize(new TogglePackDto { PackName = packName, Enabled = enabled });
        return ToDetailedResult(await SendCommandAsync("TogglePack", payload: payload, sessionToken: sessionToken));
    }

    public async Task<bool> AddDomainAsync(string domain, string? packName, string sessionToken)
        => (await AddDomainDetailedAsync(domain, packName, sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> AddDomainDetailedAsync(string domain, string? packName, string sessionToken)
    {
        string payload = JsonSerializer.Serialize(new AddDomainDto { Domain = domain, PackName = packName });
        return ToDetailedResult(await SendCommandAsync("AddDomain", payload: payload, sessionToken: sessionToken));
    }

    public async Task<bool> RemoveDomainAsync(string domain, string sessionToken)
        => (await RemoveDomainDetailedAsync(domain, sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> RemoveDomainDetailedAsync(string domain, string sessionToken)
        => ToDetailedResult(await SendCommandAsync("RemoveDomain", payload: domain, sessionToken: sessionToken));

    public async Task<bool> SaveConfigAsync(WhitelistConfig config, string sessionToken)
    {
        string payload = config.ToJson();
        var resp = await SendCommandAsync("SaveConfig", payload: payload, sessionToken: sessionToken);
        return resp.Success;
    }

    public async Task<string> TestWfpAsync(string sessionToken)
    {
        var resp = await SendCommandAsync("TestWfp", sessionToken: sessionToken);
        return resp.Success ? (resp.Payload ?? "Test iniciado") : (resp.ErrorMessage ?? "Error");
    }

    public async Task<bool> SetLearningModeAsync(bool enabled, string sessionToken)
        => (await SetLearningModeDetailedAsync(enabled, sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> SetLearningModeDetailedAsync(bool enabled, string sessionToken)
        => ToDetailedResult(await SendCommandAsync("SetLearningMode", payload: enabled ? "true" : "false", sessionToken: sessionToken));

    public async Task<bool> SetAllowLocalNetworkAsync(bool enabled, string sessionToken)
        => (await SetAllowLocalNetworkDetailedAsync(enabled, sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> SetAllowLocalNetworkDetailedAsync(bool enabled, string sessionToken)
        => ToDetailedResult(await SendCommandAsync("SetAllowLocalNetwork", payload: enabled ? "true" : "false", sessionToken: sessionToken));

    public async Task<bool> SetSniInspectionAsync(bool enabled, string sessionToken)
        => (await SetSniInspectionDetailedAsync(enabled, sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> SetSniInspectionDetailedAsync(bool enabled, string sessionToken)
        => ToDetailedResult(await SendCommandAsync("SetSniInspection", payload: enabled ? "true" : "false", sessionToken: sessionToken));

    /// <summary>Abre el modo portal cautivo por unos minutos (requiere tutor). Devuelve el error si falló.</summary>
    public async Task<(bool Success, string? Error)> StartCaptivePortalAsync(int minutes, string sessionToken)
    {
        var res = await StartCaptivePortalDetailedAsync(minutes, sessionToken);
        return (res.Success, res.Error);
    }

    public async Task<(bool Success, bool Unauthorized, string? Error)> StartCaptivePortalDetailedAsync(int minutes, string sessionToken)
        => ToDetailedResult(await SendCommandAsync("StartCaptivePortal", payload: minutes.ToString(), sessionToken: sessionToken));

    public async Task<bool> EndCaptivePortalAsync(string sessionToken)
        => (await EndCaptivePortalDetailedAsync(sessionToken)).Success;

    public async Task<(bool Success, bool Unauthorized, string? Error)> EndCaptivePortalDetailedAsync(string sessionToken)
        => ToDetailedResult(await SendCommandAsync("EndCaptivePortal", sessionToken: sessionToken));

    private static (bool Success, bool Unauthorized, string? Error) ToDetailedResult(IpcResponse resp)
    {
        if (resp.Success) return (true, false, null);
        bool unauthorized = string.Equals(resp.ErrorMessage, "No autorizado", StringComparison.OrdinalIgnoreCase);
        return (false, unauthorized, resp.ErrorMessage);
    }

    [SupportedOSPlatform("windows")]
    private static bool VerifyTrustedServerOwner(NamedPipeClientStream pipe)
    {
        try
        {
            var security = pipe.GetAccessControl();
            var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null) return false;
            return owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
                || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
        }
        catch
        {
            return false;
        }
    }

    // ----------------- Modo de prueba (trial) -----------------

    public async Task<TrialStatusDto?> GetTrialStatusAsync()
    {
        var resp = await SendCommandAsync("GetTrialStatus");
        if (resp.Success && !string.IsNullOrEmpty(resp.Payload))
        {
            return JsonSerializer.Deserialize<TrialStatusDto>(resp.Payload, JsonOpts);
        }
        return null;
    }

    /// <summary>Decisión del usuario al terminar la prueba. keep=true conserva; keep=false quita todo.
    /// El token solo es necesario si la prueba fue configurada con "pedir contraseña del tutor para quitar".</summary>
    public async Task<(bool Success, string? Error)> DecideTrialAsync(bool keep, string? sessionToken = null)
    {
        string payload = JsonSerializer.Serialize(new TrialDecisionDto { Keep = keep });
        var resp = await SendCommandAsync("DecideTrial", payload: payload, sessionToken: sessionToken);
        return (resp.Success, resp.ErrorMessage);
    }

    /// <summary>Inicia/reinicia un período de prueba desde la GUI (requiere tutor autenticado).</summary>
    public async Task<(bool Success, string? Error)> SetTrialAsync(int durationMinutes, string endAction, bool requireTutorToRemove, string sessionToken)
    {
        string payload = JsonSerializer.Serialize(new SetTrialDto
        {
            DurationMinutes = durationMinutes,
            EndAction = endAction,
            RequireTutorToRemove = requireTutorToRemove
        });
        var resp = await SendCommandAsync("SetTrial", payload: payload, sessionToken: sessionToken);
        return (resp.Success, resp.ErrorMessage);
    }
}
