# LockSuite Windows

Programa para Windows 11 que bloquea todo el acceso a internet de una computadora salvo una lista blanca de dominios definida por un administrador (`v0.5.3`). Pensado para instalarse en equipos "Kosher" administrados por un tutor.

## Documentos del proyecto

- [`CONTEXTO_IA.md`](./CONTEXTO_IA.md) — **documento maestro para IA** (arquitectura, invariantes, estado actual, reglas de cierre, release y auto-update). Al iniciar una conversación nueva, alcanza con indicar *"lee el archivo de contexto para IA"*.
- [`docs/ANALISIS_VIABILIDAD.md`](./docs/ANALISIS_VIABILIDAD.md) — arquitectura elegida, alcance y diseño de Fase 2 (inspección SNI).
- [`docs/ANALISIS_DOMINIOS_SERVICIOS.md`](./docs/ANALISIS_DOMINIOS_SERVICIOS.md) — análisis host por host de los servicios permitidos y bloqueo fijo de Google Search/Gemini.
- [`docs/ANALISIS_INCOMODIDADES_Y_FALLAS.md`](./docs/ANALISIS_INCOMODIDADES_Y_FALLAS.md) — catálogo de casos límite, certificados PKI/OCSP/CRL, DoH, portal cautivo y red local.
- [`docs/historial/`](./docs/historial/) — archivo histórico de sesiones anteriores (actas y auditorías ya aplicadas; no es necesario releerlo en sesiones normales).

## Idea general

- Una cuenta de **administrador** (el tutor) y una cuenta **estándar** (quien usa el equipo).
- **Windows Filtering Platform (WFP)** bloquea todo el tráfico saliente por defecto (*fail-closed*, IPv4 e IPv6).
- Un **resolutor DNS local** (`127.0.0.1:53` vía NRPT) solo resuelve dominios de la lista blanca y abre reglas WFP temporales para esas IPs; el resto recibe `NXDOMAIN`.
- Interfaz de escritorio (**WPF .NET 8**) protegida con contraseña maestra (PBKDF2 + DPAPI) para gestionar servicios, dominios y modo aprendizaje.
- Todo corre como servicio de Windows (`SYSTEM`), se instala con **Inno Setup** y se auto-actualiza desde [Locksuite/Locksuite-Windows](https://github.com/Locksuite/Locksuite-Windows).

## Qué NO incluye, a propósito

No hay driver de kernel propio (`.sys`), no hay inspección TLS/MITM con certificado raíz propio, ni se intenta bloquear al propio administrador de Windows. El detalle técnico está en `docs/ANALISIS_VIABILIDAD.md`.

## Flujo de trabajo con IA

Al iniciar una conversación nueva, indicá **"lee el archivo de contexto para IA"** (`CONTEXTO_IA.md`). Al finalizar cada sesión, el agente debe correr los tests, actualizar `CONTEXTO_IA.md`, commitear y subir todo a GitHub (y publicar release con `scripts/publish-release.ps1` si hubo cambios en el programa o instalador).
