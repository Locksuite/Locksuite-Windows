using System;
using System.Collections.Generic;
using System.Text;
using LockSuite.Core;
using Xunit;

namespace LockSuite.Core.Tests;

public class SniParserTests
{
    // Construye una extension SNI (0x0000).
    private static byte[] BuildSniExtension(string hostname)
    {
        var host = Encoding.ASCII.GetBytes(hostname);
        var entry = new List<byte> { 0x00, (byte)(host.Length >> 8), (byte)(host.Length & 0xff) };
        entry.AddRange(host);

        var list = new List<byte> { (byte)(entry.Count >> 8), (byte)(entry.Count & 0xff) };
        list.AddRange(entry);

        var ext = new List<byte> { 0x00, 0x00, (byte)(list.Count >> 8), (byte)(list.Count & 0xff) };
        ext.AddRange(list);
        return ext.ToArray();
    }

    private static byte[] BuildExtension(ushort type, byte[] data)
    {
        var ext = new List<byte>
        {
            (byte)(type >> 8), (byte)(type & 0xff),
            (byte)(data.Length >> 8), (byte)(data.Length & 0xff)
        };
        ext.AddRange(data);
        return ext.ToArray();
    }

    // Construye un Handshake ClientHello (sin record header) con una lista de extensiones.
    private static byte[] BuildHandshake(params byte[][] extensions)
    {
        var extBytes = new List<byte>();
        foreach (var ext in extensions)
            extBytes.AddRange(ext);

        var body = new List<byte>();
        body.AddRange(new byte[] { 0x03, 0x03 });        // client_version
        body.AddRange(new byte[32]);                     // random
        body.Add(0x00);                                  // session_id_len = 0
        body.AddRange(new byte[] { 0x00, 0x02, 0x13, 0x01 }); // cipher_suites (len 2)
        body.AddRange(new byte[] { 0x01, 0x00 });        // compression (len 1, null)
        body.Add((byte)(extBytes.Count >> 8)); body.Add((byte)(extBytes.Count & 0xff)); // extensions_len
        body.AddRange(extBytes);

        var hs = new List<byte> { 0x01,
            (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)(body.Count & 0xff) };
        hs.AddRange(body);
        return hs.ToArray();
    }

    private static byte[] WrapInTlsRecord(byte[] handshake)
    {
        var rec = new List<byte> { 0x16, 0x03, 0x01,
            (byte)(handshake.Length >> 8), (byte)(handshake.Length & 0xff) };
        rec.AddRange(handshake);
        return rec.ToArray();
    }

    // Construye un ClientHello minimo con una extension SNI para el host dado.
    private static byte[] BuildClientHello(string hostname)
        => WrapInTlsRecord(BuildHandshake(BuildSniExtension(hostname)));

    [Theory]
    [InlineData("mitmachim.top")]
    [InlineData("www.google.com")]
    [InlineData("prog.co.il")]
    [InlineData("mail.google.com")]
    public void ExtractsSni(string host)
        => Assert.Equal(host, SniParser.TryParse(BuildClientHello(host)));

    [Theory]
    [InlineData("WWW.Google.COM", "www.google.com")]
    [InlineData("Mail.Google.COM.", "mail.google.com")]
    public void NormalizesHostNameToLowercase(string rawHost, string expected)
        => Assert.Equal(expected, SniParser.TryParse(BuildClientHello(rawHost)));

    [Theory]
    [InlineData("bad host.com")]
    [InlineData("evil\0.com")]
    [InlineData("host/path")]
    [InlineData("host:443")]
    [InlineData(".")]
    public void RejectsInvalidCharactersInHostName(string invalidHost)
    {
        var pkt = BuildClientHello(invalidHost);
        Assert.Null(SniParser.TryParse(pkt));
        var detailed = SniParser.TryParseDetailed(pkt);
        Assert.True(detailed.IsClientHello);
        Assert.Null(detailed.HostName);
        Assert.False(detailed.HasEch);
    }

    [Fact]
    public void RejectsHostNameOver253Chars()
    {
        var tooLong = new string('a', 254);
        var pkt = BuildClientHello(tooLong);
        Assert.Null(SniParser.TryParse(pkt));
        Assert.Null(SniParser.TryParseDetailed(pkt).HostName);
    }

    [Fact]
    public void DetectsEchAfterSni_AndTryParseReturnsNull()
    {
        var pkt = WrapInTlsRecord(BuildHandshake(
            BuildExtension(0x0017, Array.Empty<byte>()),           // extended_master_secret
            BuildSniExtension("public-outer.example.com"),
            BuildExtension(0xFE0D, new byte[] { 0x00, 0x01 })      // encrypted_client_hello
        ));

        Assert.Null(SniParser.TryParse(pkt));
        var detailed = SniParser.TryParseDetailed(pkt);
        Assert.True(detailed.IsClientHello);
        Assert.True(detailed.HasEch);
        Assert.Equal("public-outer.example.com", detailed.HostName);
    }

    [Fact]
    public void DetectsEsniDraftBeforeSni()
    {
        var pkt = WrapInTlsRecord(BuildHandshake(
            BuildExtension(0xFF0E, new byte[] { 0x01, 0x02 }),
            BuildSniExtension("outer.example.com")
        ));

        Assert.Null(SniParser.TryParse(pkt));
        var detailed = SniParser.TryParseDetailed(pkt);
        Assert.True(detailed.IsClientHello);
        Assert.True(detailed.HasEch);
        Assert.Equal("outer.example.com", detailed.HostName);
    }

    [Fact]
    public void MultipleExtensionsBeforeAndAfterSni_AreParsedCorrectly()
    {
        var pkt = WrapInTlsRecord(BuildHandshake(
            BuildExtension(0x000A, new byte[] { 0x00, 0x02, 0x00, 0x1D }), // supported_groups
            BuildExtension(0x000D, new byte[] { 0x00, 0x02, 0x04, 0x03 }), // signature_algorithms
            BuildSniExtension("Docs.Google.COM"),
            BuildExtension(0x0010, new byte[] { 0x00, 0x03, 0x02, 0x68, 0x32 }), // ALPN
            BuildExtension(0x002B, new byte[] { 0x02, 0x03, 0x04 })        // supported_versions
        ));

        Assert.Equal("docs.google.com", SniParser.TryParse(pkt));
        var detailed = SniParser.TryParseDetailed(pkt);
        Assert.True(detailed.IsClientHello);
        Assert.False(detailed.HasEch);
        Assert.Equal("docs.google.com", detailed.HostName);
    }

    [Fact]
    public void TryParseFromHandshake_ParsesReassembledClientHello()
    {
        var hs = BuildHandshake(
            BuildExtension(0x0017, Array.Empty<byte>()),
            BuildSniExtension("drive.google.com"),
            BuildExtension(0x002B, new byte[] { 0x02, 0x03, 0x04 })
        );

        var res = SniParser.TryParseFromHandshake(hs);
        Assert.True(res.IsClientHello);
        Assert.False(res.HasEch);
        Assert.Equal("drive.google.com", res.HostName);
    }

    [Fact]
    public void Truncated_ReturnsNull()
        => Assert.Null(SniParser.TryParse(new byte[] { 0x16, 0x03, 0x01, 0x00, 0x01, 0x01 }));

    [Fact]
    public void Empty_ReturnsNull()
        => Assert.Null(SniParser.TryParse(Array.Empty<byte>()));

    [Fact]
    public void NotHandshake_ReturnsNull()
        => Assert.Null(SniParser.TryParse(new byte[] { 0x17, 0, 0, 0, 0, 0 }));
}
