using System;
using System.IO;
using LockSuite.Service.Config;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace LockSuite.Service.Tests;

public class ConfigManagerTests : IDisposable
{
    private readonly string _tempConfigFile;

    public ConfigManagerTests()
    {
        _tempConfigFile = Path.Combine(Path.GetTempPath(), "locksuite_cfg_" + Guid.NewGuid().ToString("N") + ".json");
    }

    public void Dispose()
    {
        if (File.Exists(_tempConfigFile))
        {
            try { File.Delete(_tempConfigFile); } catch { }
        }
    }

    [Fact]
    public void Constructor_CreatesDefaultConfig_WhenFileDoesNotExist()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.True(File.Exists(_tempConfigFile));
        var cfg = manager.CurrentConfig;
        Assert.NotEmpty(cfg.Packs);
        Assert.True(manager.IsAllowed("mail.google.com"));
        Assert.True(manager.IsAllowed("drive.google.com"));
        Assert.True(manager.IsAllowed("mercadopago.com.ar"));
        Assert.False(manager.IsAllowed("facebook.com"));

        // Sesion 9: Gmail/Drive permitidos NO abren el buscador de Google ni Gemini.
        Assert.False(manager.IsAllowed("google.com"));
        Assert.False(manager.IsAllowed("www.google.com"));
        Assert.False(manager.IsAllowed("gemini.google.com"));
        Assert.True(manager.IsHardBlocked("www.google.com"));
    }

    [Fact]
    public void Constructor_MigratesLegacyConfig_AndPersistsIt()
    {
        // Config como la escribia v0.3.0: paquete Google con google.com entero.
        File.WriteAllText(_tempConfigFile, """
        {
          "version": 1,
          "failClosed": true,
          "learningMode": true,
          "packs": [
            { "name": "Esenciales del sistema", "enabled": true, "builtIn": true, "domains": [ "time.windows.com" ] },
            { "name": "Google (Gmail, Chat, Drive, Fotos)", "enabled": true, "builtIn": true,
              "domains": [ "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google.com.ar", "googlemail.com" ] },
            { "name": "Sitios de la comunidad", "enabled": true, "builtIn": true, "domains": [ "mitmachim.top", "prog.co.il" ] }
          ]
        }
        """);

        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.True(manager.IsAllowed("mail.google.com"));
        Assert.True(manager.IsAllowed("mitmachim.top"));
        Assert.False(manager.IsAllowed("www.google.com"));
        Assert.False(manager.IsAllowed("google.com.ar"));

        // Quedo guardada migrada: al recargar no hay paquete "Google (...)" y el bloqueo fijo esta.
        string json = File.ReadAllText(_tempConfigFile);
        Assert.DoesNotContain("Google (Gmail, Chat, Drive, Fotos)", json);
        Assert.Contains("\"kosher-block\"", json);

        var reload = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.False(reload.IsAllowed("www.google.com"));
        Assert.True(reload.IsAllowed("drive.google.com"));
    }

    [Fact]
    public void TogglePack_ServicePack_EnablesAndDisablesTheService()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        manager.TogglePack("Gmail", false);
        Assert.False(manager.IsAllowed("mail.google.com"));
        Assert.True(manager.IsAllowed("drive.google.com"));     // Drive sigue permitido

        manager.TogglePack("Gmail", true);
        Assert.True(manager.IsAllowed("mail.google.com"));
        Assert.False(manager.IsAllowed("www.google.com"));
    }

    [Fact]
    public void RemoveDomain_FromBuiltInPack_StaysRemovedAfterReload_AndCanBeRestored()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.True(manager.IsAllowed("keep.google.com"));

        Assert.True(manager.RemoveDomain("keep.google.com"));
        Assert.False(manager.IsAllowed("keep.google.com"));

        // La sincronizacion de presets al recargar no lo vuelve a agregar.
        var reload = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.False(reload.IsAllowed("keep.google.com"));

        // Agregarlo de nuevo lo restituye en su paquete de fabrica.
        Assert.True(reload.AddDomain("keep.google.com"));
        Assert.True(reload.IsAllowed("keep.google.com"));
        var gmail = reload.CurrentConfig.Packs.Find(p => p.Id == "gmail");
        Assert.NotNull(gmail);
        Assert.Contains("keep.google.com", gmail!.Domains);
        Assert.DoesNotContain("keep.google.com", gmail.Excluded);
    }

    [Fact]
    public void AddDomain_ToBuiltInPack_GoesToPersonalizados()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.True(manager.AddDomain("sitio-extra-test.com", "Gmail"));
        Assert.True(manager.IsAllowed("sitio-extra-test.com"));

        var gmail = manager.CurrentConfig.Packs.Find(p => p.Id == "gmail");
        Assert.DoesNotContain("sitio-extra-test.com", gmail!.Domains);
        var custom = manager.CurrentConfig.Packs.Find(p => p.Name == "Personalizados");
        Assert.Contains("sitio-extra-test.com", custom!.Domains);
    }

    [Fact]
    public void AddDomain_ToBlockPack_IsRejected()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.False(manager.AddDomain("cualquiera-test.com", "Bloqueo fijo: buscador de Google y Gemini"));
        Assert.False(manager.IsAllowed("cualquiera-test.com"));
    }

    [Fact]
    public void KosherBlock_WinsOverACustomGoogleDotCom()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.True(manager.AddDomain("google.com"));

        Assert.True(manager.IsAllowed("mail.google.com"));
        Assert.False(manager.IsAllowed("www.google.com"));
        Assert.False(manager.IsAllowed("gemini.google.com"));

        // Si el tutor desactiva el bloqueo fijo, lo que agrego queda habilitado (decision suya).
        manager.TogglePack("Bloqueo fijo: buscador de Google y Gemini", false);
        Assert.True(manager.IsAllowed("www.google.com"));
    }

    [Fact]
    public void AddDomain_AddsNewDomainAndPersists()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.False(manager.IsAllowed("sitio-permitido.org"));

        bool added = manager.AddDomain("sitio-permitido.org");
        Assert.True(added);
        Assert.True(manager.IsAllowed("sitio-permitido.org"));
        Assert.True(manager.IsAllowed("sub.sitio-permitido.org"));

        // Recarga desde disco
        var reloadManager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.True(reloadManager.IsAllowed("sitio-permitido.org"));
    }

    [Fact]
    public void TogglePack_DisablesAndEnablesPack()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.True(manager.IsAllowed("mercadopago.com.ar"));

        manager.TogglePack("Mercado Pago", false);
        Assert.False(manager.IsAllowed("mercadopago.com.ar"));

        manager.TogglePack("Mercado Pago", true);
        Assert.True(manager.IsAllowed("mercadopago.com.ar"));
    }

    [Fact]
    public void RemoveDomain_RemovesDomainFromConfig()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        manager.AddDomain("temporal.com");
        Assert.True(manager.IsAllowed("temporal.com"));

        bool removed = manager.RemoveDomain("temporal.com");
        Assert.True(removed);
        Assert.False(manager.IsAllowed("temporal.com"));
    }

    [Fact]
    public void AddDomain_RejectsInvalidPattern()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.False(manager.AddDomain("com"));
        Assert.False(manager.AddDomain("*"));
        Assert.False(manager.AddDomain("   "));
        Assert.False(manager.IsAllowed("com"));
    }

    [Fact]
    public void SetLearningMode_TogglesAndPersists()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        manager.SetLearningMode(false);
        Assert.False(manager.LearningMode);

        var reload = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.False(reload.LearningMode);
    }

    [Fact]
    public void ActivePatternCount_ReflectsAddedDomain()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        int before = manager.ActivePatternCount;
        Assert.True(before > 0);

        manager.AddDomain("nuevo-dominio-unico-test.com");
        Assert.Equal(before + 1, manager.ActivePatternCount);
    }

    [Fact]
    public void SetAllowLocalNetwork_TogglesAndPersists()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.False(manager.AllowLocalNetwork);   // por defecto la red local está bloqueada

        manager.SetAllowLocalNetwork(true);
        Assert.True(manager.AllowLocalNetwork);

        var reload = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.True(reload.AllowLocalNetwork);
    }

    [Fact]
    public void ConfigChanged_FiresOnAddDomain()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        int fired = 0;
        manager.ConfigChanged += _ => fired++;

        manager.AddDomain("evento-test.com");
        Assert.True(fired >= 1);
    }

    [Fact]
    public void UpdateConfig_SanitizesCustomPackInvalidPatterns()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        var customCfg = manager.CurrentConfig;
        var customPack = new LockSuite.Core.DomainPack
        {
            Name = "Prueba Personalizada",
            Enabled = true,
            BuiltIn = false,
            Domains = new System.Collections.Generic.List<string>
            {
                "valido.com",
                "co.il",            // sufijo publico peligroso
                "com.ar",           // sufijo publico peligroso
                "*invalido.com",    // comodin malformado
                "sub.valido.co.il"  // dominio valido bajo sufijo publico
            }
        };
        customCfg.Packs.Add(customPack);

        manager.UpdateConfig(customCfg);

        var pack = manager.CurrentConfig.Packs.Find(p => p.Name == "Prueba Personalizada");
        Assert.NotNull(pack);
        Assert.Contains("valido.com", pack.Domains);
        Assert.Contains("sub.valido.co.il", pack.Domains);
        Assert.DoesNotContain("co.il", pack.Domains);
        Assert.DoesNotContain("com.ar", pack.Domains);
        Assert.DoesNotContain("*invalido.com", pack.Domains);
    }

    [Fact]
    public void UpdateConfig_SanitizesFakeBuiltInPackWithNullId()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        var cfg = manager.CurrentConfig;
        cfg.Packs.Add(new LockSuite.Core.DomainPack
        {
            Id = null,
            Name = "Falso BuiltIn",
            BuiltIn = true,
            Enabled = true,
            Domains = new System.Collections.Generic.List<string>
            {
                "com",
                "co.il",
                "valido-inyectado.com"
            }
        });

        manager.UpdateConfig(cfg);

        var pack = manager.CurrentConfig.Packs.Find(p => p.Name == "Falso BuiltIn");
        Assert.NotNull(pack);
        Assert.Contains("valido-inyectado.com", pack!.Domains);
        Assert.DoesNotContain("com", pack.Domains);
        Assert.DoesNotContain("co.il", pack.Domains);
    }

    [Fact]
    public void AddDomain_ExcludedFromKosherBlock_DoesNotRestoreInBlockPack()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.True(manager.RemoveDomain("www.google.com"));

        var kosherBefore = manager.CurrentConfig.Packs.Find(p => p.Id == LockSuite.Core.Presets.IdKosherBlock)!;
        Assert.Contains("www.google.com", kosherBefore.Excluded);
        Assert.DoesNotContain("www.google.com", kosherBefore.Domains);

        // Volver a agregarlo NO debe restituirlo en kosher-block; va a Personalizados.
        Assert.True(manager.AddDomain("www.google.com"));

        var kosherAfter = manager.CurrentConfig.Packs.Find(p => p.Id == LockSuite.Core.Presets.IdKosherBlock)!;
        Assert.Contains("www.google.com", kosherAfter.Excluded);
        Assert.DoesNotContain("www.google.com", kosherAfter.Domains);

        var custom = manager.CurrentConfig.Packs.Find(p => p.Name == LockSuite.Core.Presets.CustomPackName)!;
        Assert.Contains("www.google.com", custom.Domains);
    }

    [Fact]
    public void AddDomain_RestoresMultiPackExcludedDomain_AccountsGoogleCom()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        Assert.True(manager.RemoveDomain("accounts.google.com"));

        var targetIds = new[]
        {
            LockSuite.Core.Presets.IdGmail,
            LockSuite.Core.Presets.IdGoogleChat,
            LockSuite.Core.Presets.IdGoogleDrive,
            LockSuite.Core.Presets.IdGooglePhotos,
            LockSuite.Core.Presets.IdProg,
            LockSuite.Core.Presets.IdMitmachim
        };

        foreach (var id in targetIds)
        {
            var pack = manager.CurrentConfig.Packs.Find(p => p.Id == id)!;
            Assert.Contains("accounts.google.com", pack.Excluded);
            Assert.DoesNotContain("accounts.google.com", pack.Domains);
        }

        Assert.True(manager.AddDomain("accounts.google.com"));

        foreach (var id in targetIds)
        {
            var pack = manager.CurrentConfig.Packs.Find(p => p.Id == id)!;
            Assert.DoesNotContain("accounts.google.com", pack.Excluded);
            Assert.Contains("accounts.google.com", pack.Domains);
        }
    }

    [Fact]
    public void AddDomain_WithOutErrorMessage_ReturnsClearErrors()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);

        Assert.False(manager.AddDomain("com", null, out string? invalidErr));
        Assert.False(string.IsNullOrWhiteSpace(invalidErr));

        Assert.False(manager.AddDomain("ejemplo.com", "Bloqueo fijo: buscador de Google y Gemini", out string? blockErr));
        Assert.Equal("No se puede agregar a un paquete de bloqueo.", blockErr);
    }

    [Fact]
    public void ConfigChangedDetailed_ReportsRevokeDynamicIps()
    {
        var manager = new ConfigManager(NullLogger<ConfigManager>.Instance, _tempConfigFile);
        var events = new System.Collections.Generic.List<bool>();
        manager.ConfigChangedDetailed += (_, revoke) => events.Add(revoke);

        manager.AddDomain("detalle-uno.com");          // false
        manager.RemoveDomain("detalle-uno.com");       // true
        manager.TogglePack("Mercado Pago", false);     // true
        manager.TogglePack("Mercado Pago", true);      // false
        manager.SetLearningMode(false);                // false
        manager.SetAllowLocalNetwork(true);            // false
        manager.SetSniInspectionEnabled(false);        // false
        manager.UpdateConfig(manager.CurrentConfig);   // true

        Assert.Equal(new[] { false, true, true, false, false, false, false, true }, events);
        Assert.False(manager.SniInspectionEnabled);
    }
}
