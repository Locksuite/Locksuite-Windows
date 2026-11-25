using System;
using System.Collections.Generic;
using System.Net;

namespace LockSuite.Service.Wfp;

public interface IWfpManager : IDisposable
{
    bool IsActive { get; }
    bool IsSimulationMode { get; }
    bool IsDynamicSessionActive { get; }
    int ActiveDynamicRulesCount { get; }
    bool AllowLocalNetwork { get; }

    void Initialize(bool failClosed);
    void Initialize(bool failClosed, bool allowLocalNetwork);
    void SetAllowLocalNetwork(bool enabled);
    ulong AllowIpTemporary(IPAddress ip, TimeSpan duration);
    void RemoveDynamicRule(ulong filterId);
    void RemoveDynamicRules(IEnumerable<ulong> filterIds);
    void RemoveAllDynamicRules();
    void Rollback();
    void StartAutoRollback(TimeSpan timeout, Action? onRollback = null);
    void CancelAutoRollback();
    string RunHealthCheck();
}
