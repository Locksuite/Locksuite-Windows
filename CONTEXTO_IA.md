# Contexto Maestro para IA — LockSuite Windows

> **Única fuente de la verdad del proyecto.** Si el usuario te pidió *"lee el archivo de contexto para IA"*, este archivo te da el panorama completo para empezar a trabajar de inmediato sin escanear todo el repositorio desde cero.
> **No leas `docs/historial/`** salvo que el usuario pida consultar explícitamente un acta o auditoría vieja: todo lo vigente ya está resumido acá.

## 1. Snapshot actual

- **Versión vigente publicada:** `v0.6.1` (2026-11-25) — fuente única en `Program.Version` (`src/LockSuite.Service/Program.cs`) y `MyAppVersion` (`installer/LockSuiteSetup.iss`).
- **Repositorio GitHub oficial:** `https://github.com/Locksuite/Locksuite-Windows` (rama `main`, remoto `origin`).
- **Identidad Git / GitHub CLI:** usuario `Locksuite` (`locksuite@users.noreply.github.com`), autenticado en `gh` con scopes `repo` y `workflow`.
- **Release vigente en GitHub:** `v0.6.1` con `LockSuiteSetup-0.6.1.exe` y `SHA256SUMS.txt`.
- **Suite de tests:** **547/547 verdes** (`432` en `LockSuite.Core.Tests` + `115` en `LockSuite.Service.Tests`).
- **Entorno de desarrollo:** Windows 11 `win-x64`, .NET 8 SDK (`dotnet` o `%USERPROFILE%\.dotnet\dotnet.exe`), Inno Setup 6 (`ISCC.exe`), GitHub CLI (`gh`).
- **Preferencias del usuario:** responder en español y de forma concisa. **No tocar ni referenciar la unidad `F:`.**

---

## 2. Reglas Obligatorias de Cierre de Sesión (SEGUIR SIEMPRE)

Al terminar **cada sesión de trabajo**, antes de dar la respuesta final al usuario, ejecutá este checklist en orden:

1. **Correr toda la suite de tests (sin elevación):**
   ```powershell
   $dotnet = if (Test-Path "$env:USERPROFILE\.dotnet\dotnet.exe") { "$env:USERPROFILE\.dotnet\dotnet.exe" } else { "dotnet" }
   & $dotnet test LockSuite.sln -c Release
   ```
   Debe pasar el **100% en verde**. Correr como usuario estándar para que `WfpManagerTests` opere en modo simulación y no bloquee la red de la PC de desarrollo.
2. **Actualizar este archivo (`CONTEXTO_IA.md`):**
   - Actualizar versión, fecha, conteo de tests y cualquier cambio relevante en arquitectura, archivos, comandos o riesgos residuales.
   - Agregar una fila breve en la **Sección 8 (Historial de versiones y sesiones)** y actualizar la **Sección 9 (Próximo paso)**.
3. **Commitear, subir a GitHub y dejar listo el auto-actualizador desde el programa:**
   - **Si modificaste código, presets, UI, dependencias o instalador (todo lo que cambia el binario o su instalación):**
     1. Incrementá el número semver (`0.5.3` → `0.5.4`, etc.) y ejecutá el script oficial de publicación:
        ```powershell
        powershell -NoProfile -ExecutionPolicy Bypass -File scripts\publish-release.ps1 -Version "<X.Y.Z>" -Notes "<resumen claro de cambios>"
        ```
     2. **Qué hace `publish-release.ps1` y por qué es obligatorio usarlo:**
        - Corre `dotnet test -c Release` al 100%.
        - Actualiza `Program.Version` y `MyAppVersion` en `.iss` (evita bucles de actualización por versión desfasada).
        - Compila `LockSuite.Service` y `LockSuite.UI` self-contained (`win-x64`) hacia `installer\publish\{service,ui}`.
        - Compila `bin\installer\LockSuiteSetup-<X.Y.Z>.exe` con `ISCC.exe`.
        - Genera `bin\installer\SHA256SUMS.txt` (`<sha256_minúsculas>  LockSuiteSetup-<X.Y.Z>.exe`, ASCII sin BOM). **Crítico:** `UpdateManager` exige `SHA256SUMS.txt` y aborta la actualización si falta o no coincide.
        - Ejecuta `git add -A`, `git commit`, `git push origin main` y `gh release create v<X.Y.Z> --repo "Locksuite/Locksuite-Windows"` adjuntando el `.exe` y `SHA256SUMS.txt`.
     3. **Cómo llega a los usuarios instalados:** `UpdateManager.cs` consulta `https://api.github.com/repos/Locksuite/Locksuite-Windows/releases/latest` a los 60s del arranque y cada 4h. Si `remoteVer > Program.Version`, descarga el `.exe` y `SHA256SUMS.txt` a `%ProgramData%\LockSuite\updates`, valida el SHA-256 y ejecuta `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART` como `SYSTEM` (`PrepareToInstall` en el `.iss` frena `LockSuiteService` y cierra `LockSuite.UI.exe` antes de copiar archivos, sin pedir contraseña ni reiniciar el trial).
     4. Verificá después con `gh release view v<X.Y.Z> --repo Locksuite/Locksuite-Windows` (no debe ser `draft` y debe tener ambos assets) y `git status` limpio.
   - **Si SOLO modificaste documentación (sin cambios en `src/` ni `installer/`):**
     - Hacé `git add`, `git commit` descriptivo y `git push origin main`. No generes un nuevo release binario (evita que los clientes bajen ~70 MB idénticos), salvo pedido expreso del usuario. Verificá `git status` limpio.
4. **Seguridad en desarrollo:** **NUNCA** ejecutes `--install`, `--start` ni el instalador con elevación en la PC de desarrollo (el filtro WFP *default-deny* cortaría su internet). Usá una VM aislada para probar el filtro real.

---

## 3. Propósito, filosofía y límites de alcance

LockSuite Windows es un filtro de internet por **lista blanca estricta (default-deny)** para equipos Windows 11 "Kosher" (control parental/comunitario consentido y visible).

- **Modelo de confianza:** cuenta **Administrador** (tutor con contraseña maestra) vs. cuenta **Estándar** (usuario del equipo).
- **Instalación de programas permitida:** el usuario estándar puede instalar y usar cualquier app (el instalador ofrece menú contextual `RunAsInvoker`: *"Instalar en mi usuario (sin administrador)"*). El control es **100% a nivel de red (WFP + DNS)**: cualquier app instalada queda sujeta a la misma lista blanca.
- **Explícitamente AFUERA del alcance (NO implementar):**
  - **Driver de kernel propio (`.sys`):** innecesario; WFP opera en kernel vía `fwpuclnt.dll` sin requerir firma EV/WHQL.
  - **Inspección HTTPS/MITM con CA raíz propia:** no descifrar contenido ni instalar certificados propios (cuando se implemente Fase 2 se hará leyendo SNI en texto plano).
  - **Blindaje anti-administrador u ocultamiento:** el programa es visible; la protección viene de la separación de cuentas, no de técnicas tipo spyware/rootkit que bloqueen al propio admin (`sc stop`).
- **Criterio Kosher con Google:** **NUNCA** habilitar `google.com`, `googleapis.com`, `gstatic.com` ni `googleusercontent.com` completos (abrirían el buscador y Gemini). Cada servicio de Google se habilita con hosts puntuales y existe el paquete prioritario `kosher-block` ("Bloqueo fijo: buscador de Google y Gemini").

---

## 4. Mapa de archivos: qué es relevante y qué es historial

### A. Código y configuración activa (relevante para desarrollo)

| Ruta | Responsabilidad principal |
|---|---|
| `CONTEXTO_IA.md` | **Documento maestro actual.** Leer al inicio y actualizar al cierre de cada sesión. |
| `src/LockSuite.Core/` | Lógica multiplataforma (.NET 8): `DomainMatcher.cs` (sintaxis, sufijos públicos e IPs literales), `WhitelistConfig.cs` (config v2 + `Blocks`/`Excluded`/`AllowLocalNetwork`/`SniInspectionEnabled`), `Presets.cs` (13 paquetes + notas; PKI acotada sin GitHub abierto), `PresetSync.cs` (migración idempotente), `SniParser.cs` (parser TLS + detección ECH/ESNI para Fase 2), `TrialConfig.cs`, `IpcMessages.cs`, `LockSuiteClient.cs` (con verificación de dueño SYSTEM/Admin del pipe). |
| `src/LockSuite.Service/` | Windows Service (`SYSTEM`): `Program.cs` (`Version`, CLI, `depend= BFE`, DI), `Worker.cs` (ciclo vida + hooks), `Wfp/{WfpManager,IWfpManager,NativeMethods,WfpConstants}.cs` (doble sesión, `ALE_USER_ID`, `ALE_AUTH_RECV_ACCEPT`), `Dns/{DnsResolver,DnsPacket,DnsConfigurator}.cs` (UDP/TCP 53, IPv6/DHCP fallback, `SERVFAIL`, ECH strip), `Proxy/SniProxy.cs` (Fase 2 passthrough TLS SNI/HTTP en `127.0.0.1:443/80`), `Ipc/NamedPipeServer.cs`, `Security/{SecurityManager,AclHelper}.cs`, `Config/ConfigManager.cs`, `Learning/LearningManager.cs`, `Trial/TrialManager.cs`, `CaptivePortal/CaptivePortalManager.cs`, `Updates/UpdateManager.cs` (resolución privada de GitHub). |
| `src/LockSuite.UI/` | Cliente WPF de escritorio (instancia única por Mutex + `TrayIconHelper` en bandeja): `MainWindow.xaml(.cs)`, `ViewModels/{MainViewModel,PackViewModel,ViewModelBase}.cs` (buscador, refresco incremental, sincronización de sesión), `Views/{AddDomainDialog,PasswordDialog,TrialEndedDialog}.xaml(.cs)`, `Converters/{AuthConverters,BlockedDomainNoteConverter}.cs`. |
| `tests/` | `LockSuite.Core.Tests` (`432` tests) y `LockSuite.Service.Tests` (`115` tests). Incluyen verificación de layout binario x64/GUIDs/códigos WFP (`WfpManagerTests`), passthrough/anti-ECH/anti-SSRF (`SniProxyTests`), portal cautivo (`CaptivePortalManagerTests`) y round-trip/seguridad IPC (`IpcRoundTripTests`). Las clases de prueba usan `WfpManager(..., forceSimulation: true)` para evitar starvation e instalación real en CI elevado. |
| `installer/LockSuiteSetup.iss` | Instalador Inno Setup 6 (`x64compatible`): páginas de contraseña (`SaveStringToFile` + `Utf8Encode`) y modo de prueba, `icacls` en `%ProgramData%\LockSuite` y `{app}\service`, `SafeBoot\Network`, DoH `off` en Chrome/Edge/Firefox, extensión forzada *"Don't track me Google"* (valor `9051`), tarea `RunAsInvoker` vía PowerShell `-LiteralPath`, `PrepareToInstall` con espera real de parada de servicio, `UninstallRun` y `UninstallDelete`. |
| `scripts/publish-release.ps1` | Script maestro de release local (tests, versionado, publish x64, ISCC, `SHA256SUMS.txt`, git push y `gh release create`). |
| `.github/workflows/build-and-release.yml` | CI/CD en GitHub Actions para tags `v*` o `workflow_dispatch` (mantiene sincronizadas las versiones y genera `SHA256SUMS.txt`). |
| `README.md` y `LockSuite.sln` | Guía general del repo y solución .NET. |

### B. Documentación técnica viva en `docs/` (leer SOLO bajo demanda)

No hace falta leerlos al arrancar; consultalos únicamente cuando trabajes en el tema específico que documentan:
- `docs/ANALISIS_VIABILIDAD.md` — Fundamentos de arquitectura, alcance y diseño de Fase 2 (inspección SNI).
- `docs/ANALISIS_DOMINIOS_SERVICIOS.md` — Tabla host por host de Gmail, Chat, Drive, Fotos, prog.co.il, mitmachim.top y bloqueo fijo (referenciado en `Presets.cs`).
- `docs/ANALISIS_INCOMODIDADES_Y_FALLAS.md` — Análisis de fricciones reales, PKI/OCSP/CRL de CAs, DoH, portal cautivo y red local (referenciado en `CaptivePortalManager.cs`).

### C. Carpeta de historial (`docs/historial/`) — NO RELEER en sesiones normales

Contiene registros superados de las sesiones 1 a 16 ya integrados en el código y en este documento. No los leas salvo consulta histórica explícita:
- `docs/historial/ESTADO.md` (acta anterior de sesiones 1–16)
- `docs/historial/HANDOFF_ANTIGRAVITY.md` (checklists ya ejecutados de sesiones 5, 8, 9 y 11)
- `docs/historial/PROMPT_MAESTRO.md` (plantilla de prompt reemplazada por `CONTEXTO_IA.md`)
- `docs/historial/ANALISIS_TECHLOQ.md` (comparativa inicial vs. Techloq ya absorbida en alcance)
- `docs/historial/REVISION_PRODUCCION.md` (auditoría de sesión 5 ya aplicada)
- `docs/historial/REVISION_AUTOUPDATE.md` (auditoría de sesión 8 ya aplicada)

---

## 5. Arquitectura e invariantes críticas (no romper)

### 5.1 Windows Filtering Platform (`WfpManager.cs`, `NativeMethods.cs`, `WfpConstants.cs`)
- **Doble sesión WFP (fail-closed + autolimpieza):** sesión base **no dinámica** (`flags = 0` cuando `FailClosed=true`, con reintentos `IsTransientBfeError` si BFE tarda en arrancar y dependencia `depend= BFE` en `sc`) para subcapa y filtros base; segunda sesión **siempre dinámica** (`flags = 1`) abierta **solo en `failClosed=true`** para las reglas temporales por IP (autolimpieza ante crash sin romper `--reset-wfp` ni colisionar de tiempo de vida cuando `failClosed=false`). Todas las llamadas a `FwpmEngineOpen0` usan `WfpConstants.RPC_C_AUTHN_WINNT` (`10`) y manejan los códigos oficiales SDK (`FWP_E_ALREADY_EXISTS = 0x80320009`). Parada ordenada (`Worker.StopAsync`) siempre ejecuta `CaptivePortalManager.Dispose()` + `RemoveNrptRedirect()` + `Rollback()`.
- **Idempotencia:** las claves fijas (`BaseFilterKeys`, incluidas claves legacy) se borran por clave antes de recrearse dentro de la transacción.
- **Endurecimiento anti-evasión (`ALE_USER_ID` + inbound default-deny):**
  - Salida por `ALE_APP_ID` de `LockSuite.Service.exe` (puertos `53` UDP/TCP, `443` TCP, `80` TCP en V4 y V6) exige **`FWPM_CONDITION_ALE_USER_ID` = `SYSTEM`** (`S-1-5-18`) + ACL NTFS en `{app}\service` restringida a `SYSTEM`/`Administrators` (impide inyección/hollowing desde usuario estándar).
  - DHCPv4 (`68→67`), DHCPv6 (`546→547`) y NTP (`123→123` V4/V6) exigen `ALE_USER_ID` de servicios de sistema (`SY`/`LS`/`NS`) para impedir túneles UDP desde puertos `<1024`.
  - Capas entrantes `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`: default-deny entrante salvo loopback, DHCP de servicios y (si `AllowLocalNetwork=true`) los 4 rangos privados IPv4.
- **Reglas dinámicas por IP:** `AllowIpTemporary(ip, ttl)` sincronizada con `_rulesLock`, TTL acotado `[180s, 1800s]`, tope `MaxDynamicRules = 4096` con evicción, y revocación inmediata (`RemoveAllDynamicRules`) al quitar dominios o desactivar paquetes.

### 5.2 Resolutor DNS local, NRPT y Proxy SNI Fase 2 (`DnsResolver.cs`, `DnsConfigurator.cs`, `SniProxy.cs`)
- **Listener exclusivo UDP+TCP `127.0.0.1:53`:** `ExclusiveAddressUse = true` (evita hijacking de puerto y detecta conflictos reales), concurrencia acotada (`SemaphoreSlim(256)`), `SIO_UDP_CONNRESET` desactivado y listener paralelo TCP/53 (RFC 1035). Si UDP no enlaza, queda `IsListening=false` y NO aplica NRPT (`IsDnsDown`).
- **Upstreams resilientes y códigos correctos:** `1.1.1.1`/`8.8.8.8` + IPv6 (`2606:4700:4700::1111`/`2001:4860:4860::8888`) + fallback a los DNS originales del adaptador capturados antes de NRPT; reintento automático TCP/53 ante `TC=1`. Ante fallo de red devuelve **`SERVFAIL` (`RCODE=2`)** (no `NXDOMAIN`); ante queries malformadas devuelve `FORMERR`.
- **Anti-envenenamiento, ECH y CNAME:** valida `TransactionId`, cadena CNAME multi-pasada (rechaza si algún CNAME cae en bloqueo fijo `IsHardBlocked`), bloquea registros `HTTPS`/`SVCB` (desactiva ECH/QUIC hints con `NODATA`) y descarta IPs privadas/bogus (anti-SSRF).
- **Fase 2 — Proxy SNI transparente (`SniProxy.cs` en `127.0.0.1:443/80`):** sin descifrar TLS ni instalar CA propia. Cuando está activo (`SniInspectionEnabled=true`), `DnsResolver` devuelve `127.0.0.1` (`AAAA` → `NODATA`) para hosts web (excepto conectividad/NTP/email/STUN en `ShouldUseDirectIp`). `SniProxy` reensambla `ClientHello` multi-registro (incluidos post-cuánticos >1500B), rechaza ECH (`0xFE0D`/`0xFF0E`), valida `IsAllowed(sni)` / cabecera `Host:` única (rechaza `CONNECT`, doble `Host:` y fuerza `Connection: close`), resuelve upstream con protección anti-SSRF y hace passthrough TCP crudo.

### 5.3 IPC Named Pipe (`NamedPipeServer.cs` ↔ `LockSuiteClient.cs` ↔ `MainViewModel.cs`)
- **Pipe `LockSuiteServicePipe`:** `IpcEncoding = new UTF8Encoding(false)` (sin BOM), `BoundedPipeLineReader` con límite de **256 KB** por línea (cierra DoS OOM), máx. 32 clientes simultáneos y timeout inactivo de 30s. `LockSuiteClient` verifica en Windows que el propietario del pipe sea `NT AUTHORITY\SYSTEM` o `Administrators` antes de enviar credenciales (anti-pipe squatting).
- **Los 22 comandos IPC soportados:**
  - Sin auth de tutor: `Ping`, `GetStatus`, `GetConfig`, `GetRecentBlocked`, `Authenticate`, `SetInitialPassword`, `Logout`, `GetTrialStatus`, `DecideTrial`.
  - Requieren `SessionToken` válido (`RequireAuth`): `ChangePassword`, `ClearRecentBlocked`, `SaveConfig` (valida patrones en todo paquete fuera del catálogo, aunque finja `BuiltIn=true`), `TogglePack`, `AddDomain`, `RemoveDomain`, `TestWfp` (diagnóstico no destructivo `RunHealthCheck`), `SetLearningMode`, `SetTrial`, `SetAllowLocalNetwork`, `SetSniInspection`, `StartCaptivePortal`, `EndCaptivePortal`.

### 5.4 Seguridad, permisos y endurecimiento de evasión
- **Contraseña (`SecurityManager.cs`):** mínimo 6 caracteres, PBKDF2-SHA256 (100.000 iteraciones, sal 16B) cifrado con DPAPI (`LocalMachine`) en `auth.dat`. Lockout progresivo real (sin resetear contador al vencer lockout): 5 fallos → 60s, 10 → 5 min, 15 → 15 min. Tokens CSPRNG de 256 bits renovables por 15 min.
- **ACL NTFS (`AclHelper.cs` y `.iss`):** `%ProgramData%\LockSuite` y `{app}\service` tienen herencia removida (`/inheritance:r`) y acceso exclusivo a `SYSTEM` y `Administrators`.
- **Auto-update (`UpdateManager.cs`):** consulta y descarga GitHub usando `SocketsHttpHandler.ConnectCallback` privado (restringido a `api.github.com`, `github.com`, `*.githubusercontent.com` resueltos vía `DnsResolver`), verifica `SHA256SUMS.txt` (borra el `.exe` si falla), sanitiza nombre y lanza con `UseShellExecute = false`.
- **Safe Boot y Navegadores:** `SafeBoot\Network\LockSuiteService`, DoH `off` en Chrome/Edge/Firefox, extensión *"Don't track me Google"* con valor `9051` (sin colisionar con `"1"`), `RunAsInvoker` con PowerShell `-LiteralPath`.

### 5.5 Motor de dominios, Presets y Modo de prueba / Portal cautivo
- **Sintaxis (`DomainMatcher.cs`):** rechaza TLDs sueltos, >75 sufijos públicos multi-parte (incluso tras comodín como `a*.co.il`) e IPs literales puras.
- **Catálogo (`Presets.cs`, 13 IDs) y `PresetSync.cs`:** `system` ya **no** abre `github.com`/`githubusercontent.com` ni raíces completas de CAs (acotado a subdominios PKI reales; dominios retirados figuran en `LegacyDomains` para migración limpia). `AddDomain` nunca restituye en paquetes de bloqueo.
- **Modo de prueba y Portal cautivo:** `TrialManager` acota `durationMinutes` (`[1, 525600]`) y usa `UseShellExecute = false`; `CaptivePortalManager` aborta sin tocar NRPT si no hay direcciones locales, revoca sus reglas WFP al terminar (`End`/`Dispose`) y limpia caché DNS.

### 5.6 Rutas en equipo cliente y CLI del servicio (`Program.cs`)
- **Instalación:** `C:\Program Files\LockSuite\{service,ui}` | **Datos protegidos:** `%ProgramData%\LockSuite\{config,logs,updates}`.
- **CLI de `LockSuite.Service.exe`:** `--install`, `--uninstall`, `--start`, `--stop`, `--set-password-file <ruta>`, `--set-trial <min> [prompt|autoremove] [tutorlock]`, `--trial-status`, `--reset-wfp`, `--run` / `--console` / `--test-wfp`.

---

## 6. Comandos rápidos de desarrollo y diagnóstico

```powershell
# Compilar y correr toda la suite de tests (usuario estándar, sin elevación)
& "$env:USERPROFILE\.dotnet\dotnet.exe" test LockSuite.sln -c Release

# Publicar nueva versión (compila, testea, empaqueta, genera SHA256SUMS, commitea, pushea y crea Release)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\publish-release.ps1 -Version "0.6.1" -Notes "Descripcion"

# Verificar release publicado en GitHub
gh release view v0.6.0 --repo Locksuite/Locksuite-Windows

# Diagnóstico / rescate en VM (como Administrador)
sc.exe query LockSuiteService
Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'LockSuiteDNS' }
"C:\Program Files\LockSuite\service\LockSuite.Service.exe" --trial-status
"C:\Program Files\LockSuite\service\LockSuite.Service.exe" --reset-wfp
```

---

## 7. Riesgos residuales conocidos y backlog

1. **Firma de código Authenticode:** `UpdateManager` verifica `SHA256SUMS.txt` y restringe descargas a GitHub, pero falta verificar firma Authenticode (`WinVerifyTrust`) cuando se cuente con certificado de firma.
2. **Tráfico SNI fuera de 443/80 y Apps nativas con `AllowLocalNetwork=true`:** protocolos no-HTTP/TLS o tráfico local hacia otro dispositivo con proxy (ej. hotspot del celular) siguen sujetos al alcance inherente de red local si el tutor activa `AllowLocalNetwork`.
3. **Empaquetado offline de la extensión *"Don't track me Google"*:** reduciría la dependencia de `clients2.google.com` / `addons.mozilla.org` en `browser-updates`.
4. **Validación en VM real:** probar el instalador `v0.6.0` (UTF-8, `SniProxy` en `127.0.0.1:443/80`, `ALE_USER_ID`, portal cautivo real, Google Docs *"Insertar imagen → Buscar en la web"*) y verificar actualización automática desde `v0.5.3` → `v0.6.0`.
5. **Límites documentados inherentes:** portal cautivo alojado en IP pública; reloj CMOS muy desfasado (W32Time rechaza corregir); reCAPTCHA servido desde `www.google.com/recaptcha` (`www.google.com` sigue en `kosher-block`).

---

## 8. Historial de versiones y sesiones

| Versión / Fecha | Hito principal |
|---|---|
| `v0.1.0` (2026-10-20/21) | Diseño inicial, Core (`DomainMatcher`, `SniParser`, `WhitelistConfig`), Servicio Windows (WFP, DNS, DPAPI, IPC), UI WPF e instalador Inno Setup. |
| `v0.2.0` (2026-10-21) | Hardening de concurrencia (`PatternSnapshot`, `Interlocked`), WFP idempotente y fail-closed, `UpdateManager`, `publish-release.ps1` y CI/CD (73 tests). |
| `v0.3.0` (2026-10-21) | Modo de prueba (`TrialManager` + `TrialEndedDialog`), menú `RunAsInvoker`, Ayuda/FAQ, verificación SHA-256 obligatoria en auto-update y ACL NTFS. |
| `v0.4.0` (2026-10-21) | Tarjetas "Permitir" por servicio, sintaxis `=host` y `lh*.x.com`, bloqueo fijo `kosher-block`, `PresetSync`, notas en bloqueados (365 tests). |
| `v0.4.1` (2026-10-21) | Fix deadlock BOM en Named Pipe IPC, guard de arranque UI, NRPT condicional si DNS escucha, instalador x64 y `SIO_UDP_CONNRESET` (372 tests). |
| `v0.5.0` (2026-10-27) | Fix crítico de puntero `FWP_VALUE0.uint64` (evitaba caída a modo simulación), hosts PKI/OCSP/CRL, DoH off, portal cautivo, red local, NTP/DHCPv6, flush DNS, desactivar StartupHooks (436 tests). |
| `v0.5.1` (2026-10-31) | Política forzada de extensión *"Don't track me Google"* en Chrome/Edge/Firefox para enlaces `google.com/url` sin abrir Google Search (439 tests). |
| `v0.5.2` (2026-11-03) | Fix de structs WFP x64 (`72B`/`200B`) y GUIDs/constantes del Windows SDK, puertos estrictos en AppID del servicio, anti-envenenamiento DNS y `SafeBoot\Network` (441 tests). |
| `v0.5.3` (2026-11-04) | Migración completa de GitHub y auto-actualizador al repositorio oficial `Locksuite/Locksuite-Windows` + publicación v0.5.3 (441/441 tests). |
| Docs (2026-11-24) | Consolidación de contexto en `CONTEXTO_IA.md` y archivo de documentación histórica en `docs/historial/` (441/441 tests). |
| `v0.6.0` (2026-11-25) | Auditoría integral y cierre de bugs/evasiones: `SniProxy` Fase 2 transparente (`443`/`80`, anti-ECH/SSRF/Host-smuggling), doble sesión WFP + `ALE_USER_ID` + `ALE_AUTH_RECV_ACCEPT` + `depend= BFE`, GitHub aislado en `UpdateManager`, DNS `ExclusiveAddressUse` + TCP/53 + IPv6/DHCP fallback + `SERVFAIL`, IPC anti-squatting + límite 256 KB, lockout progresivo real, UI con bandeja/instancia única/buscador/sesión sincronizada, e instalador UTF-8 + ACL `{app}\service` (546/546 tests). |
| `v0.6.1` (2026-11-25) | Fix crítico WFP en kernel: `FwpmEngineOpen0` ahora usa `RPC_C_AUTHN_WINNT` (`10`) en lugar de `0` (evitaba `ERROR_NOT_SUPPORTED` y caída silenciosa a simulación tras 7.5s de reintentos), códigos oficiales `FWP_E_ALREADY_EXISTS = 0x80320009` / `IsTransientBfeError`, sesión dinámica secundaria solo en `failClosed=true` (con fallback), cierre graceful en `SniProxy` y `forceSimulation: true` en tests para evitar starvation e instalación real en CI elevado (547/547 tests). |

---

## 9. Próximo paso

1. Probar `v0.6.1` (y el upgrade automático desde `v0.5.3` / `v0.6.0`) en una VM Windows 11 aislada verificando `SniProxy`, WFP real en modo kernel (`RPC_C_AUTHN_WINNT` + `ALE_USER_ID`), portal cautivo real y Google Docs.
2. Evaluar firma Authenticode para el instalador y empaquetado local de la extensión del navegador.
