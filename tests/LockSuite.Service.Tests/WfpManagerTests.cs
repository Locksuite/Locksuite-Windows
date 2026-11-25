using System;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;
using LockSuite.Service.Wfp;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LockSuite.Service.Tests;

public class WfpManagerTests : IDisposable
{
    private readonly WfpManager _manager;

    public WfpManagerTests()
    {
        _manager = new WfpManager(NullLogger<WfpManager>.Instance);
        _manager.Initialize(failClosed: false);
    }

    public void Dispose()
    {
        _manager.Dispose();
    }

    [Fact]
    public void Initialize_ActivatesEngineOrSimulation()
    {
        Assert.True(_manager.IsActive);
    }

    [Fact]
    public void AllowIpTemporary_RegistersDynamicRule()
    {
        var ip = IPAddress.Parse("93.184.216.34");
        ulong filterId = _manager.AllowIpTemporary(ip, TimeSpan.FromSeconds(60));

        Assert.NotEqual(0ul, filterId);
        Assert.Equal(1, _manager.ActiveDynamicRulesCount);

        // Llamar de nuevo con la misma IP actualiza el TTL sin duplicar la regla
        ulong sameFilterId = _manager.AllowIpTemporary(ip, TimeSpan.FromSeconds(120));
        Assert.Equal(filterId, sameFilterId);
        Assert.Equal(1, _manager.ActiveDynamicRulesCount);
    }

    [Fact]
    public void RemoveDynamicRule_RemovesRuleSuccessfully()
    {
        var ip = IPAddress.Parse("1.1.1.1");
        ulong filterId = _manager.AllowIpTemporary(ip, TimeSpan.FromSeconds(60));
        Assert.Equal(1, _manager.ActiveDynamicRulesCount);

        _manager.RemoveDynamicRule(filterId);
        Assert.Equal(0, _manager.ActiveDynamicRulesCount);
    }

    [Fact]
    public void Rollback_CleansAllRules()
    {
        _manager.AllowIpTemporary(IPAddress.Parse("8.8.8.8"), TimeSpan.FromSeconds(60));
        _manager.AllowIpTemporary(IPAddress.Parse("8.8.4.4"), TimeSpan.FromSeconds(60));
        Assert.Equal(2, _manager.ActiveDynamicRulesCount);

        _manager.Rollback();
        Assert.Equal(0, _manager.ActiveDynamicRulesCount);
        Assert.False(_manager.IsActive);
    }

    [Fact]
    public void NativeStructs_64BitLayoutMatchesWindowsSdk()
    {
        if (!Environment.Is64BitProcess) return;

        Assert.Equal(72, System.Runtime.InteropServices.Marshal.SizeOf<FWPM_SUBLAYER0>());
        Assert.Equal(200, System.Runtime.InteropServices.Marshal.SizeOf<FWPM_FILTER0>());
        Assert.Equal(72, System.Runtime.InteropServices.Marshal.SizeOf<FWPM_SESSION0>());
        Assert.Equal(40, System.Runtime.InteropServices.Marshal.SizeOf<FWPM_FILTER_CONDITION0>());
        Assert.Equal(16, System.Runtime.InteropServices.Marshal.SizeOf<FWP_CONDITION_VALUE0>());
        Assert.Equal(16, System.Runtime.InteropServices.Marshal.SizeOf<FWP_VALUE0>());
        Assert.Equal(16, System.Runtime.InteropServices.Marshal.SizeOf<FWP_BYTE_BLOB>());
        Assert.Equal(8, System.Runtime.InteropServices.Marshal.SizeOf<FWP_V4_ADDR_AND_MASK>());
        Assert.Equal(17, Marshal.SizeOf<FWP_V6_ADDR_AND_MASK>());

        // Offsets críticos de FWPM_FILTER0 para 64 bits
        Assert.Equal((IntPtr)16, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("displayData"));
        Assert.Equal((IntPtr)32, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("flags"));
        Assert.Equal((IntPtr)40, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("providerKey"));
        Assert.Equal((IntPtr)48, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("providerData"));
        Assert.Equal((IntPtr)64, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("layerKey"));
        Assert.Equal((IntPtr)80, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("subLayerKey"));
        Assert.Equal((IntPtr)96, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("weight"));
        Assert.Equal((IntPtr)112, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("numFilterConditions"));
        Assert.Equal((IntPtr)120, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("filterCondition"));
        Assert.Equal((IntPtr)128, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("action"));
        Assert.Equal((IntPtr)152, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("providerContextKey"));
        Assert.Equal((IntPtr)168, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("reserved"));
        Assert.Equal((IntPtr)176, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("filterId"));
        Assert.Equal((IntPtr)184, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_FILTER0>("effectiveWeight"));

        // Offsets de FWPM_SUBLAYER0
        Assert.Equal((IntPtr)40, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_SUBLAYER0>("providerKey"));
        Assert.Equal((IntPtr)48, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_SUBLAYER0>("providerData"));
        Assert.Equal((IntPtr)64, System.Runtime.InteropServices.Marshal.OffsetOf<FWPM_SUBLAYER0>("weight"));
    }

    [Fact]
    public void WfpConstants_MatchWindowsSdkCanonicalValues()
    {
        Assert.Equal(new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V4);
        Assert.Equal(new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4"), WfpConstants.FWPM_LAYER_ALE_AUTH_CONNECT_V6);
        Assert.Equal(new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650"), WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4);
        Assert.Equal(new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f"), WfpConstants.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
        Assert.Equal(new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), WfpConstants.FWPM_CONDITION_IP_REMOTE_ADDRESS);
        Assert.Equal(new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b"), WfpConstants.FWPM_CONDITION_IP_LOCAL_PORT);
        Assert.Equal(new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b"), WfpConstants.FWPM_CONDITION_IP_REMOTE_PORT);
        Assert.Equal(new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), WfpConstants.FWPM_CONDITION_IP_PROTOCOL);
        Assert.Equal(new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), WfpConstants.FWPM_CONDITION_ALE_APP_ID);
        Assert.Equal(new Guid("af043a0a-b34d-4f86-979c-c90371af6e66"), WfpConstants.FWPM_CONDITION_ALE_USER_ID);
        Assert.Equal(new Guid("632ce23b-5167-435c-86d7-e903684aa80c"), WfpConstants.FWPM_CONDITION_FLAGS);

        Assert.Equal(11u, WfpConstants.FWP_BYTE_ARRAY16_TYPE);
        Assert.Equal(12u, WfpConstants.FWP_BYTE_BLOB_TYPE);
        Assert.Equal(14u, WfpConstants.FWP_SECURITY_DESCRIPTOR_TYPE);
        Assert.Equal(0x100u, WfpConstants.FWP_V4_ADDR_MASK);
        Assert.Equal(0x101u, WfpConstants.FWP_V6_ADDR_MASK);
        Assert.Equal(0x00000001u, WfpConstants.FWP_ACTRL_MATCH_FILTER);
        Assert.Equal(6u, WfpConstants.FWP_MATCH_FLAGS_ALL_SET);
    }

    [Fact]
    public void BuildSecurityDescriptorBytes_ProducesValidBinarySecurityDescriptors()
    {
        byte[] sysOnly = WfpManager.BuildSecurityDescriptorBytes(WfpManager.SddlSystemOnly);
        Assert.NotNull(sysOnly);
        Assert.NotEmpty(sysOnly);
        var parsedSysOnly = new RawSecurityDescriptor(sysOnly, 0);
        Assert.NotNull(parsedSysOnly.DiscretionaryAcl);
        Assert.Equal(1, parsedSysOnly.DiscretionaryAcl!.Count);

        byte[] sysServices = WfpManager.BuildSecurityDescriptorBytes(WfpManager.SddlSystemServices);
        Assert.NotNull(sysServices);
        Assert.NotEmpty(sysServices);
        var parsedSysServices = new RawSecurityDescriptor(sysServices, 0);
        Assert.NotNull(parsedSysServices.DiscretionaryAcl);
        Assert.Equal(3, parsedSysServices.DiscretionaryAcl!.Count);
    }

    [Fact]
    public async Task AllowIpTemporary_ConcurrentSameIp_DeduplicatesAtomically()
    {
        var ip = IPAddress.Parse("203.0.113.10");
        using var startGate = new ManualResetEventSlim(false);

        var tasks = Enumerable.Range(0, 50).Select(i => Task.Run(() =>
        {
            startGate.Wait();
            return _manager.AllowIpTemporary(ip, TimeSpan.FromSeconds(60 + i));
        })).ToArray();

        startGate.Set();
        ulong[] ids = await Task.WhenAll(tasks);

        Assert.Equal(1, _manager.ActiveDynamicRulesCount);
        Assert.All(ids, id => Assert.NotEqual(0ul, id));
        Assert.Single(ids.Distinct());
    }

    [Fact]
    public void RemoveDynamicRules_RemovesSpecifiedBatch()
    {
        ulong id1 = _manager.AllowIpTemporary(IPAddress.Parse("198.51.100.1"), TimeSpan.FromSeconds(60));
        ulong id2 = _manager.AllowIpTemporary(IPAddress.Parse("198.51.100.2"), TimeSpan.FromSeconds(60));
        ulong id3 = _manager.AllowIpTemporary(IPAddress.Parse("198.51.100.3"), TimeSpan.FromSeconds(60));

        Assert.Equal(3, _manager.ActiveDynamicRulesCount);

        _manager.RemoveDynamicRules(new[] { id1, id2, 999_999_999ul });
        Assert.Equal(1, _manager.ActiveDynamicRulesCount);

        _manager.RemoveDynamicRules(new[] { id3 });
        Assert.Equal(0, _manager.ActiveDynamicRulesCount);
    }

    [Fact]
    public void AllowIpTemporary_ExceedingMaxDynamicRules_EvictsEarliestExpiring()
    {
        ulong firstId = 0;
        ulong lastId = 0;
        int total = WfpManager.MaxDynamicRules + 20;

        for (int i = 0; i < total; i++)
        {
            var ip = new IPAddress(new byte[] { 198, 18, (byte)(i >> 8), (byte)(i & 0xFF) });
            ulong id = _manager.AllowIpTemporary(ip, TimeSpan.FromSeconds(60 + i));
            if (i == 0) firstId = id;
            if (i == total - 1) lastId = id;
        }

        Assert.Equal(WfpManager.MaxDynamicRules, _manager.ActiveDynamicRulesCount);

        // La regla 0 (menor ExpiresAt) debió ser evictada: volver a agregarla genera nuevo ID
        ulong readdedFirstId = _manager.AllowIpTemporary(
            new IPAddress(new byte[] { 198, 18, 0, 0 }),
            TimeSpan.FromSeconds(5000));
        Assert.NotEqual(firstId, readdedFirstId);

        // La última regla (mayor ExpiresAt) sigue activa con el mismo ID
        int lastIndex = total - 1;
        ulong readdedLastId = _manager.AllowIpTemporary(
            new IPAddress(new byte[] { 198, 18, (byte)(lastIndex >> 8), (byte)(lastIndex & 0xFF) }),
            TimeSpan.FromSeconds(5000));
        Assert.Equal(lastId, readdedLastId);
    }

    [Fact]
    public void RunHealthCheck_ReturnsStatusWithoutCallingRollback()
    {
        _manager.AllowIpTemporary(IPAddress.Parse("93.184.216.34"), TimeSpan.FromSeconds(60));

        string report = _manager.RunHealthCheck();

        Assert.True(_manager.IsActive);
        Assert.Equal(1, _manager.ActiveDynamicRulesCount);
        Assert.Contains("IsActive=True", report);
        Assert.Contains("IsDynamicSessionActive=", report);
        Assert.Contains("ActiveDynamicRulesCount=1", report);
        Assert.Contains("AllowLocalNetwork=", report);
    }
}
