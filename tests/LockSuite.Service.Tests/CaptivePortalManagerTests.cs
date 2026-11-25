using System;
using System.Collections.Generic;
using System.Net;
using LockSuite.Service.CaptivePortal;
using LockSuite.Service.Dns;
using LockSuite.Service.Wfp;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LockSuite.Service.Tests;

public class CaptivePortalManagerTests
{
    private sealed class MockWfpManager : IWfpManager
    {
        private ulong _nextId = 100;

        public bool IsActive => true;
        public bool IsSimulationMode => true;
        public bool IsDynamicSessionActive => false;
        public int ActiveDynamicRulesCount { get; private set; }
        public bool AllowLocalNetwork { get; private set; }

        public List<IPAddress> AllowedIps { get; } = new();
        public List<ulong> RemovedFilterIds { get; } = new();

        public void Initialize(bool failClosed) { }
        public void Initialize(bool failClosed, bool allowLocalNetwork) { AllowLocalNetwork = allowLocalNetwork; }
        public void SetAllowLocalNetwork(bool enabled) { AllowLocalNetwork = enabled; }

        public ulong AllowIpTemporary(IPAddress ip, TimeSpan duration)
        {
            AllowedIps.Add(ip);
            ActiveDynamicRulesCount++;
            return _nextId++;
        }

        public void RemoveDynamicRule(ulong filterId)
        {
            RemovedFilterIds.Add(filterId);
        }

        public void RemoveDynamicRules(IEnumerable<ulong> filterIds)
        {
            foreach (var id in filterIds)
            {
                RemovedFilterIds.Add(id);
                if (ActiveDynamicRulesCount > 0) ActiveDynamicRulesCount--;
            }
        }

        public void RemoveAllDynamicRules() { ActiveDynamicRulesCount = 0; }
        public void Rollback() { }
        public string RunHealthCheck() => "MockWfpManager OK";
        public void StartAutoRollback(TimeSpan timeout, Action? onRollback = null) { }
        public void CancelAutoRollback() { }
        public void Dispose() { }
    }

    [Fact]
    public void Start_WhenNoLocalAddresses_ReturnsZeroAndDoesNotActivate()
    {
        var wfp = new MockWfpManager();
        var dns = new DnsConfigurator(NullLogger<DnsConfigurator>.Instance);
        using var manager = new CaptivePortalManager(
            NullLogger<CaptivePortalManager>.Instance,
            wfp,
            dns,
            isDnsListening: () => false,
            localAddressProvider: () => Array.Empty<IPAddress>());

        int opened = manager.Start(5);

        Assert.Equal(0, opened);
        Assert.False(manager.IsActive);
        Assert.Equal(0, manager.RemainingSeconds);
        Assert.Empty(wfp.AllowedIps);
        Assert.Empty(wfp.RemovedFilterIds);
    }

    [Fact]
    public void Start_OpensTwoRules_AndEndInvokesRemoveDynamicRulesWithThoseIds()
    {
        var wfp = new MockWfpManager();
        var dns = new DnsConfigurator(NullLogger<DnsConfigurator>.Instance);
        var locals = new[]
        {
            IPAddress.Parse("192.168.1.1"),
            IPAddress.Parse("192.168.1.2")
        };

        using var manager = new CaptivePortalManager(
            NullLogger<CaptivePortalManager>.Instance,
            wfp,
            dns,
            isDnsListening: () => false,
            localAddressProvider: () => locals);

        int opened = manager.Start(5);

        Assert.Equal(2, opened);
        Assert.True(manager.IsActive);
        Assert.Equal(locals, wfp.AllowedIps);
        Assert.Empty(wfp.RemovedFilterIds);

        manager.End();

        Assert.False(manager.IsActive);
        Assert.Equal(new ulong[] { 100, 101 }, wfp.RemovedFilterIds);
    }

    [Fact]
    public void Dispose_CleansTimerAndRevokesRulesWithoutThrowing()
    {
        var wfp = new MockWfpManager();
        var dns = new DnsConfigurator(NullLogger<DnsConfigurator>.Instance);
        var locals = new[]
        {
            IPAddress.Parse("10.0.0.1"),
            IPAddress.Parse("10.0.0.2")
        };

        var manager = new CaptivePortalManager(
            NullLogger<CaptivePortalManager>.Instance,
            wfp,
            dns,
            isDnsListening: () => false,
            localAddressProvider: () => locals);

        Assert.Equal(2, manager.Start(10));
        Assert.True(manager.IsActive);

        manager.Dispose();
        manager.Dispose(); // idempotente

        Assert.False(manager.IsActive);
        Assert.Equal(new ulong[] { 100, 101 }, wfp.RemovedFilterIds);
    }
}
