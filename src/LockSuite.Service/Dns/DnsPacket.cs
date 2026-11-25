using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LockSuite.Service.Dns;

public sealed class DnsRecord
{
    public string Name { get; set; } = "";
    public ushort Type { get; set; }
    public ushort Class { get; set; }
    public uint Ttl { get; set; }
    public IPAddress? IpAddress { get; set; }
    public string CName { get; set; } = "";
}

public sealed class DnsPacket
{
    public ushort TransactionId { get; set; }
    public ushort Flags { get; set; }
    public ushort QdCount { get; set; }
    public string QuestionName { get; set; } = "";
    public ushort QuestionType { get; set; }
    public ushort QuestionClass { get; set; }
    public List<DnsRecord> Answers { get; } = new();

    public bool IsQuery => (Flags & 0x8000) == 0;
    public bool RecursionDesired => (Flags & 0x0100) != 0;
    public bool IsTruncated => (Flags & 0x0200) != 0;

    public const ushort TypeA = 1;
    public const ushort TypeCNAME = 5;
    public const ushort TypeAAAA = 28;
    public const ushort TypeSVCB = 64;
    public const ushort TypeHTTPS = 65;

    public static DnsPacket? Parse(byte[] buffer, int length)
    {
        if (buffer == null || length < 12) return null;

        try
        {
            var packet = new DnsPacket();
            packet.TransactionId = (ushort)((buffer[0] << 8) | buffer[1]);
            packet.Flags = (ushort)((buffer[2] << 8) | buffer[3]);
            ushort qdCount = (ushort)((buffer[4] << 8) | buffer[5]);
            ushort anCount = (ushort)((buffer[6] << 8) | buffer[7]);
            packet.QdCount = qdCount;

            int offset = 12;
            if (qdCount > 0 && offset < length)
            {
                packet.QuestionName = ReadDomainName(buffer, ref offset, length);
                if (offset + 4 <= length)
                {
                    packet.QuestionType = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
                    packet.QuestionClass = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);
                    offset += 4;
                }
            }

            for (int i = 0; i < anCount && offset < length; i++)
            {
                string answerName = ReadDomainName(buffer, ref offset, length);
                if (offset + 10 > length) break;

                ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
                ushort cls = (ushort)((buffer[offset + 2] << 8) | buffer[offset + 3]);
                uint ttl = ((uint)buffer[offset + 4] << 24) |
                           ((uint)buffer[offset + 5] << 16) |
                           ((uint)buffer[offset + 6] << 8) |
                           buffer[offset + 7];
                ushort rdLength = (ushort)((buffer[offset + 8] << 8) | buffer[offset + 9]);
                offset += 10;

                IPAddress? ip = null;
                string cname = "";
                if (type == TypeA && rdLength == 4 && offset + 4 <= length)
                {
                    byte[] ipBytes = new byte[4];
                    Buffer.BlockCopy(buffer, offset, ipBytes, 0, 4);
                    ip = new IPAddress(ipBytes);
                }
                else if (type == TypeAAAA && rdLength == 16 && offset + 16 <= length)
                {
                    byte[] ipBytes = new byte[16];
                    Buffer.BlockCopy(buffer, offset, ipBytes, 0, 16);
                    ip = new IPAddress(ipBytes);
                }
                else if (type == TypeCNAME && rdLength > 0 && offset + rdLength <= length)
                {
                    int cnameOffset = offset;
                    cname = ReadDomainName(buffer, ref cnameOffset, length);
                }

                offset += rdLength;

                packet.Answers.Add(new DnsRecord
                {
                    Name = answerName,
                    Type = type,
                    Class = cls,
                    Ttl = ttl,
                    IpAddress = ip,
                    CName = cname
                });
            }

            return packet;
        }
        catch
        {
            return null;
        }
    }

    public static byte[] CreateNxDomainResponse(byte[] queryBuffer, int queryLength)
        => CreateErrorResponse(queryBuffer, queryLength, 3);

    public static byte[] CreateServFailResponse(byte[] queryBuffer, int queryLength)
        => CreateErrorResponse(queryBuffer, queryLength, 2);

    public static byte[] CreateFormErrResponse(byte[] queryBuffer, int queryLength)
        => CreateErrorResponse(queryBuffer, queryLength, 1);

    public static byte[] CreateNoDataResponse(byte[] queryBuffer, int queryLength)
        => CreateErrorResponse(queryBuffer, queryLength, 0);

    public static byte[] CreateErrorResponse(byte[] queryBuffer, int queryLength, byte rcode)
    {
        if (queryBuffer == null || queryLength < 12)
        {
            return Array.Empty<byte>();
        }

        ushort qdCount = (ushort)((queryBuffer[4] << 8) | queryBuffer[5]);
        int copyLength;
        byte qdHigh;
        byte qdLow;

        if (qdCount == 0 || queryLength <= 12)
        {
            copyLength = 12;
            qdHigh = 0;
            qdLow = 0;
        }
        else
        {
            copyLength = FindQuestionEnd(queryBuffer, queryLength);
            qdHigh = 0;
            qdLow = 1;
        }

        byte[] response = new byte[copyLength];
        Buffer.BlockCopy(queryBuffer, 0, response, 0, copyLength);

        // Transaction ID queda intacto (bytes 0 y 1)
        // Flags: QR=1, RD=preservado, RA=1, RCODE=(rcode & 0x0F)
        byte origRd = (byte)(queryBuffer[2] & 0x01);
        response[2] = (byte)(0x80 | origRd);
        response[3] = (byte)(0x80 | (rcode & 0x0F));

        // Contadores
        response[4] = qdHigh; response[5] = qdLow;
        response[6] = 0; response[7] = 0;   // ANCount = 0
        response[8] = 0; response[9] = 0;   // NSCount = 0
        response[10] = 0; response[11] = 0; // ARCount = 0

        return response;
    }

    public static byte[] CreateSyntheticAResponse(byte[] queryBuffer, int queryLength, IPAddress ipv4, uint ttl = 60)
    {
        if (queryBuffer == null || queryLength <= 12 || ipv4 == null || ipv4.AddressFamily != AddressFamily.InterNetwork)
        {
            return Array.Empty<byte>();
        }

        ushort qdCount = (ushort)((queryBuffer[4] << 8) | queryBuffer[5]);
        if (qdCount == 0)
        {
            return Array.Empty<byte>();
        }

        int questionEnd = FindQuestionEnd(queryBuffer, queryLength);
        if (questionEnd <= 12)
        {
            return Array.Empty<byte>();
        }

        byte[] ipBytes = ipv4.GetAddressBytes();
        byte[] response = new byte[questionEnd + 16];
        Buffer.BlockCopy(queryBuffer, 0, response, 0, questionEnd);

        byte origRd = (byte)(queryBuffer[2] & 0x01);
        response[2] = (byte)(0x80 | origRd); // QR=1, RD=preservado
        response[3] = 0x80;                  // RA=1, RCODE=0 (NOERROR)

        response[4] = 0; response[5] = 1;    // QDCount = 1
        response[6] = 0; response[7] = 1;    // ANCount = 1
        response[8] = 0; response[9] = 0;    // NSCount = 0
        response[10] = 0; response[11] = 0;  // ARCount = 0

        int p = questionEnd;
        response[p++] = 0xC0; response[p++] = 0x0C; // Puntero al QNAME en offset 12
        response[p++] = 0x00; response[p++] = 0x01; // TYPE = A (1)
        response[p++] = 0x00; response[p++] = 0x01; // CLASS = IN (1)
        response[p++] = (byte)(ttl >> 24);
        response[p++] = (byte)(ttl >> 16);
        response[p++] = (byte)(ttl >> 8);
        response[p++] = (byte)ttl;
        response[p++] = 0x00; response[p++] = 0x04; // RDLENGTH = 4
        Buffer.BlockCopy(ipBytes, 0, response, p, 4);

        return response;
    }

    public static byte[] BuildStandardQuery(string hostname, ushort qtype, ushort txId)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            throw new ArgumentException("Hostname inválido.", nameof(hostname));
        }

        string clean = hostname.Trim().TrimEnd('.');
        if (clean.Length == 0)
        {
            throw new ArgumentException("Hostname inválido.", nameof(hostname));
        }

        using var ms = new MemoryStream(64);
        // Header (12 bytes)
        ms.WriteByte((byte)(txId >> 8));
        ms.WriteByte((byte)txId);
        ms.WriteByte(0x01); // RD = 1
        ms.WriteByte(0x00);
        ms.WriteByte(0x00); ms.WriteByte(0x01); // QDCOUNT = 1
        ms.WriteByte(0x00); ms.WriteByte(0x00); // ANCOUNT = 0
        ms.WriteByte(0x00); ms.WriteByte(0x00); // NSCOUNT = 0
        ms.WriteByte(0x00); ms.WriteByte(0x00); // ARCOUNT = 0

        // QNAME
        string[] labels = clean.Split('.');
        foreach (string label in labels)
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            if (labelBytes.Length == 0 || labelBytes.Length > 63)
            {
                throw new ArgumentException($"Label DNS inválido en '{hostname}'.", nameof(hostname));
            }
            ms.WriteByte((byte)labelBytes.Length);
            ms.Write(labelBytes, 0, labelBytes.Length);
        }
        ms.WriteByte(0x00); // Terminador de QNAME

        // QTYPE y QCLASS = IN (1)
        ms.WriteByte((byte)(qtype >> 8));
        ms.WriteByte((byte)qtype);
        ms.WriteByte(0x00);
        ms.WriteByte(0x01);

        return ms.ToArray();
    }

    private static int FindQuestionEnd(byte[] queryBuffer, int queryLength)
    {
        int offset = 12;
        while (offset < queryLength)
        {
            byte len = queryBuffer[offset];
            if (len == 0)
            {
                offset += 5; // byte nulo + QType (2B) + QClass (2B)
                break;
            }
            if ((len & 0xC0) == 0xC0)
            {
                offset += 6; // Puntero de compresión (2B) + QType (2B) + QClass (2B)
                break;
            }
            if ((len & 0xC0) != 0)
            {
                offset = queryLength;
                break;
            }
            offset += 1 + len;
        }

        return Math.Min(offset, queryLength);
    }

    private static string ReadDomainName(byte[] buffer, ref int offset, int length)
    {
        var sb = new StringBuilder();
        int currentOffset = offset;
        bool jumped = false;
        int maxJumps = 16;

        while (currentOffset < length)
        {
            byte len = buffer[currentOffset];
            if (len == 0)
            {
                currentOffset++;
                if (!jumped) offset = currentOffset;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                // Puntero de compresión (14 bits)
                if (currentOffset + 1 >= length) return string.Empty;
                int pointer = ((len & 0x3F) << 8) | buffer[currentOffset + 1];
                if (pointer >= length) return string.Empty;
                if (!jumped) offset = currentOffset + 2;
                jumped = true;
                currentOffset = pointer;
                if (--maxJumps < 0) return string.Empty; // Prevenir loops
                continue;
            }

            if ((len & 0xC0) != 0)
            {
                // Etiqueta inválida (> 63 bytes o bits reservados 01/10)
                return string.Empty;
            }

            currentOffset++;
            if (currentOffset + len > length) return string.Empty;

            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(buffer, currentOffset, len));
            currentOffset += len;

            if (!jumped) offset = currentOffset;
        }

        return sb.ToString();
    }
}
