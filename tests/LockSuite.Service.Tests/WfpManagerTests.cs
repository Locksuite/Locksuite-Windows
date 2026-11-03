using System;
using System.Net;
using System.Threading;
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
        Assert.Equal(new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045"), WfpConstants.FWPM_CONDITION_IP_REMOTE_ADDRESS);
        Assert.Equal(new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b"), WfpConstants.FWPM_CONDITION_IP_LOCAL_PORT);
        Assert.Equal(new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b"), WfpConstants.FWPM_CONDITION_IP_REMOTE_PORT);
        Assert.Equal(new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7"), WfpConstants.FWPM_CONDITION_IP_PROTOCOL);
        Assert.Equal(new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971"), WfpConstants.FWPM_CONDITION_ALE_APP_ID);
        Assert.Equal(new Guid("af043a0a-b34d-4f86-979c-c90371af6e66"), WfpConstants.FWPM_CONDITION_ALE_USER_ID);
        Assert.Equal(new Guid("632ce23b-5167-435c-86d7-e903684aa80c"), WfpConstants.FWPM_CONDITION_FLAGS);

        Assert.Equal(11u, WfpConstants.FWP_BYTE_ARRAY16_TYPE);
        Assert.Equal(12u, WfpConstants.FWP_BYTE_BLOB_TYPE);
        Assert.Equal(0x100u, WfpConstants.FWP_V4_ADDR_MASK);
        Assert.Equal(6u, WfpConstants.FWP_MATCH_FLAGS_ALL_SET);
    }
}
