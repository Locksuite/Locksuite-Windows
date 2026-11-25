using System;
using System.IO;
using LockSuite.Service.Learning;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LockSuite.Service.Tests;

public class LearningManagerTests : IDisposable
{
    private readonly string _tempLogFile;

    public LearningManagerTests()
    {
        _tempLogFile = Path.Combine(Path.GetTempPath(), "locksuite_log_" + Guid.NewGuid().ToString("N") + ".json");
    }

    public void Dispose()
    {
        if (File.Exists(_tempLogFile))
        {
            try { File.Delete(_tempLogFile); } catch { }
        }
    }

    [Fact]
    public void RecordBlocked_RecordsNewDomainAndIncrementsCount()
    {
        var manager = new LearningManager(NullLogger<LearningManager>.Instance, _tempLogFile);

        manager.RecordBlocked("sitio-bloqueado.com", "192.168.1.50");
        manager.RecordBlocked("sitio-bloqueado.com", "192.168.1.50");

        var recent = manager.GetRecent();
        Assert.Single(recent);
        Assert.Equal("sitio-bloqueado.com", recent[0].Domain);
        Assert.Equal(2, recent[0].Count);
        Assert.Equal("192.168.1.50", recent[0].ClientIp);
    }

    [Fact]
    public void Clear_EmptiesRecentList()
    {
        var manager = new LearningManager(NullLogger<LearningManager>.Instance, _tempLogFile);

        manager.RecordBlocked("uno.com");
        manager.RecordBlocked("dos.com");
        Assert.Equal(2, manager.GetRecent().Count);

        manager.Clear();
        Assert.Empty(manager.GetRecent());
    }

    [Fact]
    public void Flush_PersistsToDiskAndReloads()
    {
        using (var manager = new LearningManager(NullLogger<LearningManager>.Instance, _tempLogFile))
        {
            manager.RecordBlocked("persistido.com");
            manager.Flush();
        }

        using var reload = new LearningManager(NullLogger<LearningManager>.Instance, _tempLogFile);
        Assert.Contains(reload.GetRecent(), e => e.Domain == "persistido.com");
    }

    [Fact]
    public void RecordBlocked_EvictsLeastRecentlyUsed_WhenCapacityExceeded()
    {
        using var manager = new LearningManager(NullLogger<LearningManager>.Instance, _tempLogFile);

        manager.RecordBlocked("primero.com");
        for (int i = 1; i <= 198; i++)
        {
            manager.RecordBlocked($"dom{i:D3}.com");
        }

        // Repetir el primero antes de superar los 200 para promoverlo a la cabeza (MRU)
        manager.RecordBlocked("primero.com");

        // Registrar 6 más (205 dominios distintos en total -> 5 evicciones)
        for (int i = 199; i <= 204; i++)
        {
            manager.RecordBlocked($"dom{i:D3}.com");
        }

        var recent = manager.GetRecent(200);
        Assert.Equal(200, recent.Count);
        Assert.Contains(recent, e => e.Domain == "primero.com" && e.Count == 2);
        Assert.DoesNotContain(recent, e => e.Domain == "dom001.com");
    }
}
