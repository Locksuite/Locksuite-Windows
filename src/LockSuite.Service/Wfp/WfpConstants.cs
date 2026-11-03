using System;

namespace LockSuite.Service.Wfp;

public static class WfpConstants
{
    // Subcapa propia de LockSuite
    public static readonly Guid LockSuiteSubLayerGuid = new("8E8E939C-8A95-46D9-8976-96F6EB6CE522");
    public const ushort LockSuiteSubLayerWeight = 0xEE00; // Peso alto

    // Capas WFP (ALE - Application Layer Enforcement)
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    // Campos de condición
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    public static readonly Guid FWPM_CONDITION_IP_LOCAL_PORT     = new("0c1ba1af-5765-453f-af22-a8f791ac775b");
    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT    = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL       = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
    public static readonly Guid FWPM_CONDITION_ALE_APP_ID        = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    public static readonly Guid FWPM_CONDITION_ALE_USER_ID       = new("af043a0a-b34d-4f86-979c-c90371af6e66");
    public static readonly Guid FWPM_CONDITION_FLAGS             = new("632ce23b-5167-435c-86d7-e903684aa80c");

    // Tipos de datos WFP (fwptypes.h)
    public const uint FWP_EMPTY = 0;
    public const uint FWP_UINT8 = 1;
    public const uint FWP_UINT16 = 2;
    public const uint FWP_UINT32 = 3;
    public const uint FWP_UINT64 = 4;
    public const uint FWP_BYTE_ARRAY16_TYPE = 11;
    public const uint FWP_BYTE_BLOB_TYPE = 12;
    public const uint FWP_V4_ADDR_MASK = 0x100;

    // Tipos de comparación (FWP_MATCH_TYPE en fwptypes.h)
    public const uint FWP_MATCH_EQUAL = 0;
    public const uint FWP_MATCH_GREATER = 1;
    public const uint FWP_MATCH_LESS = 2;
    public const uint FWP_MATCH_GREATER_OR_EQUAL = 3;
    public const uint FWP_MATCH_LESS_OR_EQUAL = 4;
    public const uint FWP_MATCH_RANGE = 5;
    public const uint FWP_MATCH_FLAGS_ALL_SET = 6;
    public const uint FWP_MATCH_FLAGS_ANY_SET = 7;
    public const uint FWP_MATCH_FLAGS_NONE_SET = 8;

    // Flags de condición
    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x00000001;

    // Acciones
    public const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;
    public const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;

    // Protocolos IP
    public const byte IPPROTO_TCP = 6;
    public const byte IPPROTO_UDP = 17;

    // Puertos conocidos
    public const ushort PORT_NTP = 123;          // sincronizacion de hora
    public const ushort PORT_DNS = 53;
    public const ushort PORT_DHCP_SERVER = 67;
    public const ushort PORT_DHCP_CLIENT = 68;
    public const ushort PORT_DHCPV6_CLIENT = 546;
    public const ushort PORT_DHCPV6_SERVER = 547;
    public const ushort PORT_HTTP = 80;
    public const ushort PORT_HTTPS = 443;
}
