# Contexto Maestro para IA — LockSuite Windows

> **Única fuente de la verdad del proyecto.** Si el usuario te pidió *"lee el archivo de contexto para IA"*, este archivo te da el panorama completo para empezar a trabajar de inmediato sin escanear todo el repositorio desde cero.
> **No leas `docs/historial/`** salvo que el usuario pida consultar explícitamente un acta o auditoría vieja: todo lo vigente ya está resumido acá.

## 1. Snapshot actual

- **Versión vigente publicada:** `v0.5.3` (2026-11-04) — fuente única en `Program.Version` (`src/LockSuite.Service/Program.cs`) y `MyAppVersion` (`installer/LockSuiteSetup.iss`).
- **Repositorio GitHub oficial:** `https://github.com/Locksuite/Locksuite-Windows` (rama `main`, remoto `origin`).
- **Identidad Git / GitHub CLI:** usuario `Locksuite` (`locksuite@users.noreply.github.com`), autenticado en `gh` con scopes `repo` y `workflow`.
- **Release vigente en GitHub:** `v0.5.3` con `LockSuiteSetup-0.5.3.exe` y `SHA256SUMS.txt`.
- **Suite de tests:** **441/441 verdes** (`376` en `LockSuite.Core.Tests` + `65` en `LockSuite.Service.Tests`).
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
| `src/LockSuite.Core/` | Lógica multiplataforma (.NET 8): `DomainMatcher.cs` (sintaxis + sufijos públicos), `WhitelistConfig.cs` (config v2 + `Blocks`/`Excluded`/`AllowLocalNetwork`), `Presets.cs` (13 paquetes + notas), `PresetSync.cs` (migración idempotente), `SniParser.cs` (parser TLS para Fase 2), `TrialConfig.cs`, `IpcMessages.cs`, `LockSuiteClient.cs`. |
| `src/LockSuite.Service/` | Windows Service (`SYSTEM`): `Program.cs` (`Version`, CLI, DI), `Worker.cs` (ciclo vida + hooks), `Wfp/{WfpManager,IWfpManager,NativeMethods,WfpConstants}.cs`, `Dns/{DnsResolver,DnsPacket,DnsConfigurator}.cs`, `Ipc/NamedPipeServer.cs`, `Security/{SecurityManager,AclHelper}.cs`, `Config/ConfigManager.cs`, `Learning/LearningManager.cs`, `Trial/TrialManager.cs`, `CaptivePortal/CaptivePortalManager.cs`, `Updates/UpdateManager.cs`. |
| `src/LockSuite.UI/` | Cliente WPF de escritorio: `MainWindow.xaml(.cs)`, `ViewModels/{MainViewModel,PackViewModel,ViewModelBase}.cs`, `Views/{AddDomainDialog,PasswordDialog,TrialEndedDialog}.xaml(.cs)`, `Converters/{AuthConverters,BlockedDomainNoteConverter}.cs`. |
| `tests/` | `LockSuite.Core.Tests` (`376` tests) y `LockSuite.Service.Tests` (`65` tests). Incluyen verificación de layout binario x64/GUIDs WFP (`WfpManagerTests`) y round-trip IPC (`IpcRoundTripTests`). |
| `installer/LockSuiteSetup.iss` | Instalador Inno Setup 6 (`x64compatible`): páginas de contraseña y modo de prueba, `icacls` en `%ProgramData%\LockSuite`, `SafeBoot\Network`, DoH `off` en Chrome/Edge/Firefox, extensión forzada *"Don't track me Google"*, tarea `RunAsInvoker`, `PrepareToInstall` para upgrades silenciosos, `UninstallRun` (`--stop`, `--uninstall`, `--reset-wfp`) y `UninstallDelete`. |
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
- **Fail-closed y parada ordenada:** abre sesión WFP **no dinámica** (`flags = 0` cuando `FailClosed=true`) en capas `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` bajo la subcapa propia `LockSuiteSubLayerGuid`. Si el proceso muere por crash, los filtros persisten bloqueando la red (el servicio tiene `sc failure` con auto-reinicio). Una parada ordenada (`Worker.StopAsync`) **siempre** ejecuta `RemoveNrptRedirect()` + `Rollback()`.
- **Idempotencia:** las 15 claves de filtro fijas (`BaseFilterKeys`: 9 base dentro de la transacción + 6 permisos aditivos) se borran por clave antes de recrearse. Nunca acumulan duplicados.
- **Filtros base en transacción:** Loopback V4/V6, DHCPv4 (`LOCAL_PORT=68` → `REMOTE_PORT=67`), DNS local (`127.0.0.1:53`), salida por `ALE_APP_ID` de `LockSuite.Service.exe` **restringida a puertos** `53` (UDP/TCP), `443` (TCP) y `80` (TCP) —impide tunelizar puertos arbitrarios usando el ejecutable del servicio—, y filtros de bloqueo total V4/V6.
- **Permisos aditivos *best-effort* (fuera de transacción base):** NTP (`UDP 123`, `LOCAL_PORT=123`), DHCPv6 (`UDP 547`, `LOCAL_PORT=546`), y Red Local opcional (4 rangos privados IPv4 `10/8`, `172.16/12`, `192.168/16`, `169.254/16` con `FWP_V4_ADDR_MASK`, conmutable en vivo). Un fallo aquí nunca tira la subcapa a modo simulación.
- **Reglas dinámicas por IP:** `AllowIpTemporary(ip, ttl)` con TTL mínimo de **180s** y barrido de expiración cada **5s**. Si falla `FwpmEngineOpen0` (sin elevación) pasa a `_isSimulationMode = true`.
- **Invariantes P/Invoke x64 (testeadas en `WfpManagerTests`):** `FWP_VALUE0.uint64` es un puntero `UINT64*` (usar `CreateWeight` con `AllocHGlobal`), `FWPM_SUBLAYER0` mide **72 bytes**, `FWPM_FILTER0` mide **200 bytes**, y los GUIDs/enums (`FWP_MATCH_FLAGS_ALL_SET=6`, `FWP_BYTE_ARRAY16_TYPE=11`, `FWP_BYTE_BLOB_TYPE=12`, `FWP_V4_ADDR_MASK=0x100`) deben coincidir con el Windows SDK (`fwpmu.h`/`fwptypes.h`).

### 5.2 Resolutor DNS local y NRPT (`DnsResolver.cs`, `DnsConfigurator.cs`)
- **Listener UDP `127.0.0.1:53`:** concurrencia acotada con `SemaphoreSlim(256, 256)`, `SIO_UDP_CONNRESET` desactivado (evita error 10054), backoff de 50ms en errores de socket, reintentos tolerantes al enlazar (3×). Si el puerto 53 está ocupado (Docker/WSL/VPN), queda `IsListening=false`, **no aplica NRPT** (no corta internet) y la UI muestra cartel ámbar (`IsDnsDown`).
- **NRPT:** `DnsConfigurator` remueve/agrega la regla con comentario `LockSuiteDNS` en una sola invocación a PowerShell. Ante `ConfigManager.ConfigChanged`, ejecuta `ipconfig /flushdns` (`FlushDnsCache`) para limpiar NXDOMAIN cacheados.
- **Anti-envenenamiento DNS:** `QueryUpstreamAsync` usa `1.1.1.1` / `8.8.8.8` con socket UDP conectado (`ConnectAsync`), valida coincidencia exacta de `TransactionId`, valida que las respuestas coincidan con el dominio consultado o su cadena **CNAME** legítima, y descarta IPs especiales/bogus (loopback, `0.0.0.0/8`, broadcast `255.255.255.255`, multicast).

### 5.3 IPC Named Pipe (`NamedPipeServer.cs` ↔ `LockSuiteClient.cs` ↔ `MainViewModel.cs`)
- **Pipe `LockSuiteServicePipe`:** `IpcEncoding = new UTF8Encoding(false)` (**SIN BOM**) y `AutoFlush = false` con `FlushAsync()` explícito; timeout de lectura inactiva de 30s en servidor. *Nunca usar `Encoding.UTF8` por defecto* (emitir BOM sincrónicamente en pipes sin buffer provoca deadlock).
- **`MainViewModel`:** refresco cada 3s protegido con `Interlocked.Exchange(ref _refreshing, 1)` y retorno inmediato si `GetStatusAsync()` devuelve `null`.
- **Los 20 comandos IPC soportados:**
  - Sin auth de tutor: `Ping`, `GetStatus`, `GetConfig`, `GetRecentBlocked`, `Authenticate`, `SetInitialPassword` (solo si aún no existe contraseña), `GetTrialStatus`, `DecideTrial` (conservar siempre permitido; quitar exige vencimiento y además tutor si `tutorlock` está activo).
  - Requieren `SessionToken` válido de tutor (`RequireAuth`): `ChangePassword`, `ClearRecentBlocked`, `SaveConfig` (valida patrones en paquetes custom), `TogglePack`, `AddDomain`, `RemoveDomain`, `TestWfp`, `SetLearningMode`, `SetTrial`, `SetAllowLocalNetwork`, `StartCaptivePortal`, `EndCaptivePortal`.

### 5.4 Seguridad, permisos y endurecimiento de evasión
- **Contraseña (`SecurityManager.cs`):** PBKDF2-SHA256 (100.000 iteraciones, sal 16B) cifrado con DPAPI (`DataProtectionScope.LocalMachine`) en `%ProgramData%\LockSuite\config\auth.dat`. Lockout progresivo: 5 fallos → 60s, 10 fallos → 5 min; al expirar reinicia el contador. Sesiones de 15 min renovables.
- **ACL NTFS (`AclHelper.cs` y `.iss`):** `%ProgramData%\LockSuite` y subcarpetas (`config`, `logs`, `updates`) tienen herencia removida (`/inheritance:r`) y acceso exclusivo a `SYSTEM` (`*S-1-5-18`) y `Administrators` (`*S-1-5-32-544`).
- **Anti-inyección:** `<RuntimeHostConfigurationOption Include="System.StartupHookProvider.IsSupported" Value="false" />` en `LockSuite.Service.csproj` bloquea `DOTNET_STARTUP_HOOKS`.
- **Safe Boot:** entrada `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\LockSuiteService` para que el filtro arranque también en Modo Seguro con red.
- **Navegadores (directivas en `.iss`):**
  - **DoH desactivado** en Chrome, Edge y Firefox (`DnsOverHttpsMode="off"`, Firefox `Enabled=0`/`Locked=1`) para no bypassear el DNS local.
  - **Enlace `google.com/url?q=...`:** Chrome, Edge y Firefox instalan forzosamente la extensión *"Don't track me Google"* (endpoints `clients2.google.com`, `clients2.googleusercontent.com`, `addons.mozilla.org`, `addons.cdn.mozilla.net` habilitados en `browser-updates`) para desenvolver redirecciones de Gmail/Chat hacia Drive sin abrir `www.google.com`.

### 5.5 Motor de dominios, Presets y Modo de prueba / Portal cautivo
- **Sintaxis (`DomainMatcher.cs`):** `x.com` (sitio + subdominios), `*.x.com` (solo subdominios), `=x.com` (solo host exacto), `lh*.x.com` / `*-docs.x.com` (comodín en una única etiqueta). `IsValidPattern` bloquea TLDs sueltos y lista >60 sufijos públicos multi-parte (`co.il`, `com.ar`, `co.uk`, etc.). Evaluación: `MatchesAny(whitelist) && !MatchesAny(blocklist)`.
- **Catálogo de fábrica (`Presets.cs`, 13 IDs) y `PresetSync.cs`:** `system` (incluye PKI OCSP/CRL/AIA de CAs principales + `lencr.org`/`amazontrust.com`/`pki.goog`/`ctldl.windowsupdate.com` + `github.com`/`githubusercontent.com`), `kosher-block` (`Blocks=true`), `gmail`, `google-chat`, `google-drive`, `google-photos`, `prog`, `mitmachim`, `mercadopago`, `windows-update`, `web-commons`, `captcha` (`challenges.cloudflare.com`, `hcaptcha.com`, `recaptcha.net`), `browser-updates`. `PresetSync` migra configs v1→v2, respeta `excluded` (lo quitado por el tutor no vuelve) y conserva extras en `"Personalizados"`.
- **Modo de prueba (`TrialManager.cs`) y Portal cautivo (`CaptivePortalManager.cs`):** trial en `trial.json` (`Prompt` fail-closed por defecto, `AutoRemove`, `TutorLock`); portal cautivo por ventana de 1–15 min (default 5 min) abre solo IPs privadas de gateway/DNS de la red actual y suspende NRPT temporalmente sin apagar WFP.

### 5.6 Rutas en equipo cliente y CLI del servicio (`Program.cs`)
- **Instalación:** `C:\Program Files\LockSuite\{service,ui}` | **Datos protegidos:** `%ProgramData%\LockSuite\{config,logs,updates}`.
- **CLI de `LockSuite.Service.exe`:** `--install`, `--uninstall`, `--start`, `--stop`, `--set-password-file <ruta>`, `--set-trial <min> [prompt|autoremove] [tutorlock]`, `--trial-status`, `--reset-wfp`, `--run` / `--console` / `--test-wfp`.

---

## 6. Comandos rápidos de desarrollo y diagnóstico

```powershell
# Compilar y correr toda la suite de tests (usuario estándar, sin elevación)
& "$env:USERPROFILE\.dotnet\dotnet.exe" test LockSuite.sln -c Release

# Publicar nueva versión (compila, testea, empaqueta, genera SHA256SUMS, commitea, pushea y crea Release)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\publish-release.ps1 -Version "0.5.4" -Notes "Descripcion"

# Verificar release publicado en GitHub
gh release view v0.5.3 --repo Locksuite/Locksuite-Windows

# Diagnóstico / rescate en VM (como Administrador)
sc.exe query LockSuiteService
Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'LockSuiteDNS' }
"C:\Program Files\LockSuite\service\LockSuite.Service.exe" --trial-status
"C:\Program Files\LockSuite\service\LockSuite.Service.exe" --reset-wfp
```

---

## 7. Riesgos residuales conocidos y backlog

1. **Fase 2 — Inspección de SNI en WFP (prioridad técnica alta):** varios sitios/servicios detrás de la misma IP (Google, Cloudflare) hoy comparten IP temporal una vez autorizada. `SniParser.cs` ya está implementado y testeado en Core; falta integrarlo a nivel de flujo/callout o capa compatible en el servicio para validar el SNI TLS en texto plano.
2. **Aislar GitHub del paquete `system`:** actualmente `github.com` y `githubusercontent.com` están en `system` para el auto-update, lo que los deja visibles en navegador. Mejora pendiente: que `UpdateManager` resuelva GitHub por su cuenta aprovechando las reglas por `ALE_APP_ID` del servicio y quitar GitHub de la lista blanca general.
3. **Firma de código Authenticode:** `UpdateManager` verifica `SHA256SUMS.txt`, lo cual protege contra corrupción o MITM, pero no contra un compromiso de la cuenta de GitHub. Pendiente verificar firma Authenticode (`WinVerifyTrust`) cuando se cuente con certificado.
4. **Hardening adicional WFP/DNS:** mover las reglas dinámicas por IP a una segunda sesión WFP dinámica (autolimpieza ante crash) y agregar soporte TCP/53 al DNS local para respuestas truncadas (`TC=1`).
5. **Validación pendiente en VM y pulido UI:** verificar en Google Docs *"Insertar imagen → Buscar en la web"*, probar portal cautivo real, añadir buscador en Lista Blanca y refresco incremental de "Bloqueados recientes".
6. **Límites documentados inherentes:** portal cautivo alojado en IP pública; reloj CMOS muy desfasado (W32Time rechaza corregir); reCAPTCHA servido desde `www.google.com/recaptcha` (`www.google.com` sigue en `kosher-block`).

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

---

## 9. Próximo paso

1. Verificar en los equipos cliente que tengan instalado `v0.5.3` (enlazado a `Locksuite/Locksuite-Windows`) que las auto-actualizaciones y el filtrado kernel WFP funcionan en producción y probar las validaciones pendientes en VM de la Sección 7.5.
2. Evaluar e implementar la **Fase 2 (inspección SNI)** usando `SniParser.cs` para cerrar el hueco de IPs compartidas (Google / Cloudflare), y evaluar aislar GitHub del paquete `system`.
