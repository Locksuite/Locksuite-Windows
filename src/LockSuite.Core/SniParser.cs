using System;
using System.Text;

namespace LockSuite.Core;

/// <summary>Resultado detallado al inspeccionar un ClientHello de TLS.</summary>
public readonly record struct SniParseResult(bool IsClientHello, string? HostName, bool HasEch);

/// <summary>
/// Extrae el campo SNI (server_name) de un ClientHello de TLS y detecta Encrypted Client Hello (ECH/ESNI).
/// El SNI viaja en texto plano, antes del cifrado, asi que permite filtrar
/// por dominio sin descifrar nada (sin CA propia, sin MITM).
/// Es defensivo: ante cualquier largo invalido o paquete truncado devuelve null/default,
/// nunca lanza excepcion ni lee fuera de rango.
/// </summary>
public static class SniParser
{
    /// <summary>
    /// Devuelve el host del SNI normalizado, o null si no hay, el paquete es invalido
    /// o usa Encrypted Client Hello (ECH/ESNI).
    /// </summary>
    public static string? TryParse(ReadOnlySpan<byte> data)
    {
        var res = TryParseDetailed(data);
        if (!res.IsClientHello || res.HasEch) return null;
        return res.HostName;
    }

    /// <summary>
    /// Inspecciona un registro TLS 0x16 completo (record header + handshake) devolviendo
    /// si es ClientHello, el SNI validado/normalizado y si contiene extension ECH (0xFE0D) o ESNI (0xFF0E).
    /// </summary>
    public static SniParseResult TryParseDetailed(ReadOnlySpan<byte> data)
    {
        try
        {
            // Record TLS: content_type(1) version(2) length(2)
            if (data.Length < 5) return default;
            if (data[0] != 0x16) return default;              // 22 = handshake
            int recLen = (data[3] << 8) | data[4];
            int bodyEnd = Math.Min(5 + recLen, data.Length);
            return TryParseFromHandshake(data[5..bodyEnd]);
        }
        catch
        {
            return default;
        }
    }

    /// <summary>
    /// Inspecciona un mensaje Handshake reensamblado (comenzando en 0x01 ClientHello + length 3B + payload).
    /// Util cuando el proxy reensambla un ClientHello fragmentado en multiples registros TLS 0x16.
    /// </summary>
    public static SniParseResult TryParseFromHandshake(ReadOnlySpan<byte> handshakeBody)
    {
        try
        {
            // Handshake: type(1) length(3)
            if (handshakeBody.Length < 4) return default;
            if (handshakeBody[0] != 0x01) return default;     // 1 = ClientHello
            int hsLen = (handshakeBody[1] << 16) | (handshakeBody[2] << 8) | handshakeBody[3];
            int hsEnd = Math.Min(4 + hsLen, handshakeBody.Length);
            var hs = handshakeBody[4..hsEnd];

            int p = 0;
            p += 2 + 32;                                      // client_version + random
            if (p + 1 > hs.Length) return default;
            int sidLen = hs[p]; p += 1 + sidLen;              // session_id
            if (p + 2 > hs.Length) return default;
            int csLen = (hs[p] << 8) | hs[p + 1]; p += 2 + csLen;   // cipher_suites
            if (p + 1 > hs.Length) return default;
            int cmLen = hs[p]; p += 1 + cmLen;                // compression_methods
            if (p > hs.Length) return default;
            if (p + 2 > hs.Length) return new SniParseResult(true, null, false);

            int extTotal = (hs[p] << 8) | hs[p + 1]; p += 2;  // extensions
            int end = Math.Min(p + extTotal, hs.Length);

            string? hostName = null;
            bool hasEch = false;

            while (p + 4 <= end)
            {
                int etype = (hs[p] << 8) | hs[p + 1];
                int elen = (hs[p + 2] << 8) | hs[p + 3];
                p += 4;
                int extEnd = Math.Min(p + elen, end);

                if (etype == 0xFE0D || etype == 0xFF0E)       // ECH / draft ESNI
                {
                    hasEch = true;
                }
                else if (etype == 0x0000 && hostName is null) // server_name
                {
                    hostName = ParseServerNameExtension(hs[p..extEnd]);
                }

                if (elen > end - p) break;
                p += elen;
            }

            return new SniParseResult(true, hostName, hasEch);
        }
        catch
        {
            return default;
        }
    }

    private static string? ParseServerNameExtension(ReadOnlySpan<byte> extData)
    {
        if (extData.Length < 2) return null;
        int listLen = (extData[0] << 8) | extData[1];
        int sp = 2;
        int listEnd = Math.Min(sp + listLen, extData.Length);

        while (sp + 3 <= listEnd)
        {
            int ntype = extData[sp]; sp += 1;
            int nlen = (extData[sp] << 8) | extData[sp + 1]; sp += 2;
            if (nlen > listEnd - sp) return null;

            if (ntype == 0x00)                                // host_name
            {
                var nameBytes = extData.Slice(sp, nlen);
                if (!IsValidHostNameBytes(nameBytes)) return null;
                var normalized = DomainMatcher.Normalize(Encoding.ASCII.GetString(nameBytes));
                return normalized.Length > 0 ? normalized : null;
            }

            sp += nlen;
        }

        return null;
    }

    private static bool IsValidHostNameBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0 || bytes.Length > 253) return false;
        foreach (byte b in bytes)
        {
            bool ok = (b >= (byte)'a' && b <= (byte)'z')
                   || (b >= (byte)'A' && b <= (byte)'Z')
                   || (b >= (byte)'0' && b <= (byte)'9')
                   || b == (byte)'.'
                   || b == (byte)'-'
                   || b == (byte)'_';
            if (!ok) return false;
        }
        return true;
    }
}
