using System;
using System.Net;
using System.Text;
using LockSuite.Service.Dns;
using Xunit;

namespace LockSuite.Service.Tests;

public class DnsPacketTests
{
    [Fact]
    public void Parse_ValidQueryPacket_ExtractsQuestionNameAndType()
    {
        // Consulta A para "google.com" con Transaction ID = 0x1234
        byte[] query = new byte[]
        {
            0x12, 0x34,             // Transaction ID
            0x01, 0x00,             // Flags: Standard query, RD=1
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question: 6google3com0
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d,
            0x00,
            0x00, 0x01,             // QTYPE = A (1)
            0x00, 0x01              // QCLASS = IN (1)
        };

        var packet = DnsPacket.Parse(query, query.Length);

        Assert.NotNull(packet);
        Assert.Equal(0x1234, packet.TransactionId);
        Assert.True(packet.IsQuery);
        Assert.True(packet.RecursionDesired);
        Assert.Equal("google.com", packet.QuestionName);
        Assert.Equal(DnsPacket.TypeA, packet.QuestionType);
        Assert.Equal(1, packet.QuestionClass);
    }

    [Fact]
    public void CreateNxDomainResponse_FromQuery_GeneratesValidNxDomain()
    {
        byte[] query = new byte[]
        {
            0xAB, 0xCD,             // Transaction ID
            0x01, 0x00,             // Flags: Query, RD=1
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question: 7blocked3com0
            0x07, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64,
            0x03, 0x63, 0x6f, 0x6d,
            0x00,
            0x00, 0x01,             // QTYPE = A (1)
            0x00, 0x01              // QCLASS = IN (1)
        };

        byte[] response = DnsPacket.CreateNxDomainResponse(query, query.Length);

        Assert.NotEmpty(response);
        Assert.Equal(0xAB, response[0]);
        Assert.Equal(0xCD, response[1]);

        // Byte 2: QR=1 (0x80) | RD=1 (0x01) -> 0x81
        Assert.Equal(0x81, response[2]);
        // Byte 3: RA=1 (0x80) | RCODE=3 (0x03) -> 0x83
        Assert.Equal(0x83, response[3]);

        // QDCount = 1
        Assert.Equal(0x00, response[4]);
        Assert.Equal(0x01, response[5]);

        // ANCount = 0
        Assert.Equal(0x00, response[6]);
        Assert.Equal(0x00, response[7]);
    }

    [Fact]
    public void Parse_ResponseWithAnswers_ExtractsIpsAndTtl()
    {
        // Respuesta con 1 respuesta A para 142.250.190.46 con TTL = 300
        byte[] response = new byte[]
        {
            0x12, 0x34,             // Transaction ID
            0x81, 0x80,             // Flags: Response, RD=1, RA=1, RCODE=0
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x01,             // ANCOUNT = 1
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            // Question: 6google3com0
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
            0x03, 0x63, 0x6f, 0x6d,
            0x00,
            0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
            // Answer: Puntero a google.com (0xC00C)
            0xC0, 0x0C,
            0x00, 0x01,             // TYPE = A
            0x00, 0x01,             // CLASS = IN
            0x00, 0x00, 0x01, 0x2C, // TTL = 300
            0x00, 0x04,             // RDLENGTH = 4
            142, 250, 190, 46       // IP Address: 142.250.190.46
        };

        var packet = DnsPacket.Parse(response, response.Length);

        Assert.NotNull(packet);
        Assert.False(packet.IsQuery);
        Assert.Single(packet.Answers);
        Assert.Equal(IPAddress.Parse("142.250.190.46"), packet.Answers[0].IpAddress);
        Assert.Equal(300u, packet.Answers[0].Ttl);
    }

    [Fact]
    public void CreateServFailResponse_SetsRcode2AndPreservesRd()
    {
        byte[] query = DnsPacket.BuildStandardQuery("mail.google.com", DnsPacket.TypeA, 0x2233);
        byte[] resp = DnsPacket.CreateServFailResponse(query, query.Length);

        Assert.NotEmpty(resp);
        Assert.Equal(0x22, resp[0]);
        Assert.Equal(0x33, resp[1]);
        Assert.Equal(0x81, resp[2]); // QR=1, RD=1
        Assert.Equal(0x82, resp[3]); // RA=1, RCODE=2 (SERVFAIL)
        Assert.Equal(0x00, resp[4]);
        Assert.Equal(0x01, resp[5]); // QDCount = 1
        Assert.Equal(0x00, resp[6]);
        Assert.Equal(0x00, resp[7]); // ANCount = 0
    }

    [Fact]
    public void CreateFormErrResponse_HandlesBothZeroAndOneQuestion()
    {
        byte[] query = DnsPacket.BuildStandardQuery("example.com", DnsPacket.TypeA, 0x4455);
        byte[] resp = DnsPacket.CreateFormErrResponse(query, query.Length);

        Assert.Equal(0x81, resp[2]);
        Assert.Equal(0x81, resp[3]); // RCODE=1 (FORMERR)
        Assert.Equal(0x01, resp[5]); // QDCount=1

        // Paquete de 12 bytes sin preguntas (QDCount = 0)
        byte[] headerOnly = new byte[12];
        headerOnly[0] = 0xAA;
        headerOnly[1] = 0xBB;
        headerOnly[2] = 0x00; // RD=0
        byte[] formErrHeaderOnly = DnsPacket.CreateFormErrResponse(headerOnly, headerOnly.Length);

        Assert.Equal(12, formErrHeaderOnly.Length);
        Assert.Equal(0x80, formErrHeaderOnly[2]); // QR=1, RD=0
        Assert.Equal(0x81, formErrHeaderOnly[3]); // RA=1, RCODE=1
        Assert.Equal(0x00, formErrHeaderOnly[5]); // QDCount=0
    }

    [Fact]
    public void CreateNoDataResponse_SetsRcode0AndZeroAnswers()
    {
        byte[] query = DnsPacket.BuildStandardQuery("mail.google.com", DnsPacket.TypeHTTPS, 0x5566);
        byte[] resp = DnsPacket.CreateNoDataResponse(query, query.Length);

        Assert.Equal(0x81, resp[2]);
        Assert.Equal(0x80, resp[3]); // RA=1, RCODE=0 (NOERROR)
        Assert.Equal(0x01, resp[5]); // QDCount=1
        Assert.Equal(0x00, resp[7]); // ANCount=0
    }

    [Fact]
    public void CreateSyntheticAResponse_GeneratesValidLoopbackAnswer()
    {
        byte[] query = DnsPacket.BuildStandardQuery("mail.google.com", DnsPacket.TypeA, 0x7788);
        byte[] resp = DnsPacket.CreateSyntheticAResponse(query, query.Length, IPAddress.Loopback, 60);

        Assert.NotEmpty(resp);
        var parsed = DnsPacket.Parse(resp, resp.Length);
        Assert.NotNull(parsed);
        Assert.False(parsed.IsQuery);
        Assert.Equal(0x7788, parsed.TransactionId);
        Assert.Equal("mail.google.com", parsed.QuestionName);
        Assert.Single(parsed.Answers);
        Assert.Equal(IPAddress.Loopback, parsed.Answers[0].IpAddress);
        Assert.Equal(60u, parsed.Answers[0].Ttl);

        // IPv6 debe devolver array vacío
        Assert.Empty(DnsPacket.CreateSyntheticAResponse(query, query.Length, IPAddress.IPv6Loopback, 60));
    }

    [Fact]
    public void BuildStandardQuery_RoundTripsThroughParse()
    {
        byte[] query = DnsPacket.BuildStandardQuery("drive.google.com.", DnsPacket.TypeAAAA, 0x9ABC);
        var parsed = DnsPacket.Parse(query, query.Length);

        Assert.NotNull(parsed);
        Assert.Equal(0x9ABC, parsed.TransactionId);
        Assert.True(parsed.IsQuery);
        Assert.True(parsed.RecursionDesired);
        Assert.Equal((ushort)1, parsed.QdCount);
        Assert.Equal("drive.google.com", parsed.QuestionName);
        Assert.Equal(DnsPacket.TypeAAAA, parsed.QuestionType);
        Assert.Equal((ushort)1, parsed.QuestionClass);
    }

    [Fact]
    public void Parse_RejectsLabelGreaterThan63Bytes()
    {
        // Primer label válido ("www") seguido de un label inválido con longitud 0x40 (64 bytes, bits 01xxxxxx)
        byte[] malformed = new byte[]
        {
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, (byte)'w', (byte)'w', (byte)'w',
            0x40, (byte)'a', (byte)'b',
            0x00,
            0x00, 0x01, 0x00, 0x01
        };

        var parsed = DnsPacket.Parse(malformed, malformed.Length);
        Assert.True(parsed == null || string.IsNullOrEmpty(parsed.QuestionName));
    }
}
