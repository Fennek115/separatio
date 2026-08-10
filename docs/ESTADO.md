# ESTADO — la central de intel

> **Punto de entrada del proyecto Intel/Separatio.** Si estás empezando una sesión, leé esto primero.

Última actualización: **2026-08-10** (consolidación: la documentación de Separatio se movió acá desde
`~/Projects/Motherbase`, que vuelve a ser lo que era — el proyecto del host Proxmox).

---

## Las dos cadenas

Este proyecto tiene **dos cadenas de fases** que corrieron en momentos distintos y que conviene no
mezclar:

| Cadena | Qué es | Dónde |
|---|---|---|
| **F0 → F4** | Las fases originales: levantar el pipeline, sumarle fuentes, darle un sensor propio, y exponerlo como MCP | [`fases/`](fases/) — este archivo las resume |
| **F-A → F-I** | El **rework** interno de Separatio (2026-08-09): store, triage de cuota, observabilidad, deuda técnica | [`REWORK-ESTADO.md`](REWORK-ESTADO.md) — allá vive el detalle |

La regla que hace que esto funcione, heredada del proyecto madre:

> **Verificar contra la máquina, no contra el documento.** Los documentos describen intenciones; el
> servidor describe hechos. Si no coinciden, **gana la máquina** y se corrige el documento.

---

## Cadena principal — F0 a F4

| Fase | Qué es | Estado |
|---|---|---|
| **F0** | [Rescatar y encender Separatio](fases/F0-separatio.md) | ◐ **Desplegado y automatizado.** Corre en el **LXC 113 `intel`** de motherbase: timer diario 07:00 + semanal lunes 08:00, secretos en `/etc/intel/intel.env`, informes publicados al share. **Corren las dos semanas del criterio de cierre** (2026-08-08 → ~**22-ago**) |
| **F1** | *(no es de este proyecto)* | El host Proxmox — vive en `~/Projects/Motherbase` |
| **F2** | [Fuentes nuevas: leak sites + MCP oficiales](fases/F2-fuentes.md) | ☑ **Hecha el 2026-08-08** — enricher de Ransomware.live + onion-lookup de CIRCL, y `.mcp.json` con HIBP y AbuseIPDB |
| **F3** | [Honeypot y dato propio](fases/F3-honeypot.md) | ☑ **Operativo desde el 2026-08-10.** Dos sensores expuestos en Oracle, colector cada 6 h al store. **El as-built es privado** — ver abajo |
| **F4** | [MCP propio sobre el corpus](fases/F4-mcp-corpus.md) | ☐ **La única fase con trabajo por construir.** Esperando corpus; el rework ya le dejó hecha la capa de consulta |

### Qué falta, en concreto

1. **F0** cierra solo el ~22-ago si el pipeline no se cae. No hay trabajo, hay que esperar.
2. **F-D** (reincidencia) espera que una IP vuelva un segundo día. **F-F** (YARA) espera un binario de
   verdad: los 327 payloads del corpus son cuerpos de peticiones a la API de Docker, ninguno pasa de
   705 B.
3. **F4** es lo único construible, y necesita más corpus. Medido el 2026-08-10: 7 días de informes,
   128 IOCs, 1.078 observaciones.

---

## ⚠️ Qué NO vive acá, y por qué

**Este repo es público** (`github.com/Fennek115/separatio`). Eso fija una frontera que hay que
respetar al mover documentación:

| Vive acá (público) | Vive en Motherbase (privado, sin git) |
|---|---|
| El **diseño** del sensor ([`fases/F3-honeypot.md`](fases/F3-honeypot.md)) | El **as-built** del sensor: `Motherbase/honeypot/` |
| Arquitectura, fases, casos de estudio | Qué IP es cada honeypot, las IPs públicas de casa, las claves SSH, la topología de la LAN |

**El motivo no es pudor, es operacional:** publicar "la IP X es mi honeypot" **quema el sensor**. El
proyecto ya había decidido (2026-08-08, `Motherbase/honeypot/CONTRIBUIR.md`) no contribuir a
plataformas públicas justamente porque correlacionar un `first_seen` permite deducir cuál de tus
objetivos es un honeypot; publicar la IP directamente es la versión burda del mismo error. Los
as-builts también contienen las **dos IPs públicas de casa**.

> **Regla para sesiones futuras:** si un documento nombra una IP pública, una instancia de Oracle, una
> clave SSH o un puerto de administración del sensor, **no entra a este repo**. Va a Motherbase.

---

## Los documentos

| Documento | Cuándo abrirlo |
|---|---|
| **`ESTADO.md`** (este) | Siempre, primero |
| [`REWORK-ESTADO.md`](REWORK-ESTADO.md) | Para tocar código de Separatio: estado del rework, protocolo de sesión, as-builts de F-A…F-I |
| [`ARQUITECTURA.md`](ARQUITECTURA.md) | El plan de fondo de la central de intel: capas, fuentes, decisiones y por qué |
| [`CAPAS-Y-FUENTES.md`](CAPAS-Y-FUENTES.md) | Qué fuente cubre qué capa, y las restricciones de cuota de cada una |
| [`PLAN-REWORK.md`](PLAN-REWORK.md) | El diseño del rework (el *qué* y el *por qué*) |
| [`IMPROVEMENTS.md`](IMPROVEMENTS.md) | Backlog técnico |
| [`DEPLOY.md`](DEPLOY.md) | As-built del despliegue en el CT 113 |
| [`fases/`](fases/) | Para ejecutar: una fase por sesión |
| [`casos/ft-correction.md`](casos/ft-correction.md) | Caso de estudio cerrado: phishing sobre WordPress comprometido (IOCs + regla YARA) |

**El host, la LAN y el hardware** están en `~/Projects/Motherbase`. **El laptop** (`thinkfox`), el
vault y la recuperación ante desastres, en `~/Projects/IAsysadmin`.

---

## Decisiones ya tomadas (no re-litigar)

| Decisión | Por qué |
|---|---|
| **Ollama local descartado** | 3,5 h por corrida en CPU y 7,2 GB de pico. Se va a proveedor cloud |
| **No construir un cerebro CTI nuevo** | Separatio ya tenía el 80%: KEV, EPSS, IPsum, OpenPhish, ipcheck, correlación determinista, histórico |
| **`darknet-mcp-server` descartado** | Abandonado a las 8 h; `tor_search_onion` devuelve `[]` siempre sin error; rate limiter errado 120× |
| **MCP no en el cron** | Su valor es que un LLM elija tools en runtime; en batch es overhead puro. Se usa al revés: servir el corpus propio (F4) |
| **Los honeypots son para estudio personal — no se contribuye a plataformas públicas** | Puede quemar el sensor, expone identidad, y un pipeline automático se gana el baneo. El esfuerzo se corre al lado entrante: enriquecer lo capturado |
| **El corpus de `reports/` no se respalda** | El CT se reconstruye desde git + `intel.env` (decisión del usuario, 2026-08-08) |
