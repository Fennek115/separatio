# Central de inteligencia — capas, fuentes y dónde encaja cada cosa

Escrito el 2026-08-07 a partir de conversaciones del usuario sobre arquitectura de intel y edge
computing. **Es un documento de diseño/visión**, no de estado — nada de acá está implementado todavía.
Alimenta la sesión de *rediseño de `~/Projects/Intel/`* que ya está pendiente (ver `CLAUDE.md`).

> **Regla heredada:** verificar contra la máquina, no contra el documento. Y una específica de acá:
> **Separatio ya es el cerebro CTI** — no se construye una plataforma nueva. Las fuentes nuevas entran
> como *enrichers* del pipeline existente, salvo que haya una razón fuerte para lo contrario.
> (Decidido en `Motherbase/INTEL-ARQUITECTURA.md` §2: "Separatio ya tiene el 80%".)

---

## El modelo de 4 capas

La idea central que ordena todo: **no mezclar noticias con IOCs, ni montar plataformas pesadas;
consumir APIs livianas cuando hacen falta.** Cuatro capas con roles distintos:

| Capa | Qué es | Cómo entra | Dónde vive |
|---|---|---|---|
| **1. Noticias / análisis** | Blogs, medios, reportes APT en prosa | RSS → Miniflux (CT 112) → Separatio Stage 1–4 | Ya funciona |
| **2. IOCs accionables** | Indicadores crudos (IPs, hashes, URLs maliciosas) para **cruzar**, no para leer | Enrichers de Separatio (Stage 2.7) + correlación | Parcial (IPsum/OpenPhish ya) |
| **3. Enriquecimiento bajo demanda** | Scoring/contexto puntual sobre un IOC o campaña | API/SDK llamada desde el pipeline cuando la necesita | Por construir |
| **4. Dato propio** | Lo que ataca a *tu* infra (honeypot) | Pull SSH desde casa → enricher | **Construido 2026-08-08** (honeypot en Oracle VM1; `enrichers/honeypot.py` + `tools/pull_honeypot.sh`). Toggle `honeypot` OFF hasta que el pull traiga dato real — ver `Motherbase/honeypot/DEPLOY.md` |

**La sinergia real:** Miniflux dice *qué está pasando*; los feeds de IOC dan *indicadores para cruzar*;
el enriquecimiento agrega *contexto*; el honeypot valida *qué de todo eso te toca a vos*.

---

## Fuentes nuevas, mapeadas a dónde encajan en Separatio

Separatio ya tiene el modelo de extensión perfecto para esto (de su `CLAUDE.md`):
> *"Add a source = new `enrichers/*.py` subclass + register in `build_enrichers()` + toggle in
> `config.ENRICHERS`. No pipeline/analyzer edits."*

Así que casi todo esto son **enrichers nuevos**, no una arquitectura nueva.

### Capa 2 — IOCs accionables (nuevos enrichers de Stage 2.7)

| Fuente | Qué aporta | API key | Cómo entra |
|---|---|---|---|
| **abuse.ch completo** (URLhaus, ThreatFox, MalwareBazaar, Feodo, SSLBL) | La columna vertebral de IOCs. `ipcheck` ya toca URLhaus/ThreatFox — falta el resto | Auth-key gratis (2024+) | Enricher(s) nuevos, o extender `ipcheck` |
| **IPsum** | 30+ blocklists de IP en un `.txt` con score de ocurrencias | No | **Ya está** (`IpsumEnricher`) |
| **FireHOL IP Lists** | 400+ feeds curados con histórico | No | Enricher nuevo (mismo patrón que IPsum) |
| **DigitalSide (osint.digitalside.it)** | Sale en STIX2/CSV/MISP | No | Enricher nuevo |
| **jamesbrine.com.au** (referefref) | **Feed de honeypots internacionales**, CSV+STIX2 diario. Cruzar "¿las IPs que me pegan a mí también le pegan a su red global?" | No | Enricher nuevo — **alto valor**, es dato de sensor real |

### Capa 3 — Enriquecimiento bajo demanda (no son feeds; se consultan puntualmente)

| Fuente | Qué aporta | Cómo entra |
|---|---|---|
| **GreyNoise Community** | Distingue "ruido de internet" (scanners masivos) de algo dirigido. Clave contra falsos positivos del honeypot | ⚠️ **Sin clave**: GreyNoise no emite keys a correos Proton (bloqueado). Necesita otro correo o queda fuera |
| **Pulsedive** | Scoring comunitario de riesgo sobre feeds OSINT | Feed/API — enricher o consulta on-demand |
| **WorldMonitor CII** (worldmonitor.app) | Country Instability Index geopolítico. Correlacionar: pico de ataques desde un país que escala en el CII = contexto de campaña | SDK Python / MCP público. **No self-hostear el dashboard** (pesa 10x, WebGL, no entra en el ThinkPad) — solo consumir el SDK |

### El puente que falta — extracción de IOCs de reportes (OCR de imágenes)

El gap real: muchos blogs de threat intel meten los IOCs en **capturas de pantalla**, que el parser
de texto de Separatio **no ve hoy**. **AIOCRIOC** (referefref, `github.com/referefref/aiocrioc`,
Apache-2.0) resuelve eso con OCR + LLM.

**Decisión tras leer su fuente (2026-08-07): reimplementar la idea, NO vendorizar la herramienta.**

- AIOCRIOC es un script CLI de ~1 archivo (`extract.py`), **atado a OpenAI** (`gpt-4-turbo-preview`,
  SDK `openai`), sin frontera de función reutilizable (toma una URL, escribe a disco, imprime). Su
  mitad de LLM se descartaría igual porque Separatio usa Claude.
- Lo único genuinamente reutilizable son ~15 líneas: **sacar los `<img>` del HTML del artículo →
  OCR con Tesseract (`pytesseract`) → concatenar ese texto al prompt de extracción que Separatio
  YA corre con Claude.** No hace falta una segunda llamada LLM por imagen (la ventana de contexto de
  Claude lo cubre), ni un segundo proveedor, ni una dependencia nueva más allá de `pytesseract` +
  el binario `tesseract` + `Pillow`.
- **Cómo entra:** enricher/etapa nueva en Stage 1–2 (antes de la extracción), no en Stage 2.7.
  Maneja tanto `<img>` remotas como `data:` base64 (igual que hace `download_images` del original).

Esto es lo de **mejor relación esfuerzo/valor** de todas las fuentes nuevas: gap concreto, ~15 líneas,
cero infra nueva, todo dentro del pipeline Claude existente. **Es por donde arrancar.**

### Lo que NO agregar

- **A Miniflux**: nada de feeds de IOC crudos — ahogarían las noticias. Miniflux es solo capa 1.
- **Plataformas pesadas**: MISP / OpenCTI / Yeti — descartadas en este hardware (ya evaluado). Yeti
  usa ArangoDB que crece en RAM; no hay headroom.
- **WorldMonitor self-hosted**: solo el SDK/MCP bajo demanda.

---

## La pregunta abierta de arquitectura: ¿edge (Cloudflare) o local (Separatio)?

La conversación proponía un "cerebro" en **Cloudflare Worker → D1 → R2** para ingerir los feeds de
IOC. Hay que decidir esto con cuidado, porque **se solapa con lo que Separatio ya hace**:

- **A favor del edge (Worker + D1):** corre siempre, aunque el laptop esté apagado; tira los feeds
  24/7; almacén de IOCs consultable; usa infra gratis y es un buen ejercicio de aprendizaje.
- **En contra / a tener en cuenta:** Separatio **ya ingiere IPsum y correlaciona localmente** (KEV,
  EPSS, actores, IOCs) con Python liviano — el argumento "no cargar el ThinkPad" no aplica tanto
  porque Separatio no es pesado. Duplicar la ingesta en dos lados (edge + local) es complejidad.

**Recomendación para la sesión de rediseño:** decidir *dónde vive el almacén de IOCs* —
- Si Separatio corre en un CT/timer fijo → el almacén local (SQLite, ya existe `history.json`) alcanza
  y el Worker+D1 es redundante.
- El Worker+D1 se justifica sobre todo como **capa 4** (recolector del honeypot siempre-encendido) o
  como **API pública de enriquecimiento**, no como duplicado de la correlación que Separatio ya hace.

No cerrar esto sin resolver primero la reestructuración de `~/Projects/Intel/` (ver `CLAUDE.md`).

### Usos concretos de edge/Workers en este proyecto

Más allá del recolector del honeypot, dónde el free tier de Cloudflare (Workers + Cron + D1 + KV +
R2) aporta de verdad. **Restricción clave:** un Worker **no llega a la LAN privada** sin un túnel
(`cloudflared`) — así que sirve para lo que mira hacia afuera o para cachear/servir, no para tocar
los CTs directamente.

1. **Agregador de feeds siempre-encendido (capa 2).** Un Worker con Cron tira abuse.ch / IPsum /
   FireHOL / jamesbrine cada X horas, dedup/normaliza y deja un único JSON en KV/D1. El pipeline (o
   el laptop) baja **un** blob cacheado en vez de pegarle a 5 APIs, y los feeds siguen frescos aunque
   el laptop esté apagado. Es el mismo patrón que el recolector del honeypot, generalizado.
2. **API/lookup de IOCs + informe, accesible desde el teléfono sin exponer la casa.** D1 guarda los
   IOCs y el briefing diario; el Worker sirve consultas read-only. Desacopla "leer mi intel desde
   afuera" de "abrir puertos en casa". (Con Cloudflare Access adelante para que sea solo tuyo.)
3. **Relay de notificaciones.** Un Worker recibe webhooks (del honeypot, de CrowdSec, de Wazuh) y
   los reenvía a Telegram/email. La lógica de aviso vive afuera, siempre-encendida, sin credenciales
   en la máquina sacrificable.
4. **R2 como offsite de lo crítico.** 10 GB gratis: no entran los 167 G de datos, pero **sí** los
   configs y exports chicos que hoy no tienen copia fuera del equipo (ver el gap de F1). Cifrar antes
   de subir.
5. **Cache de enriquecimiento (capa 3).** Worker Cron refresca KEV/EPSS/GreyNoise-community en KV
   para que el pipeline lea un cache tibio en vez de pegarle en vivo en cada corrida.

### CrowdSec ↔ Separatio — los 3 puntos de integración

Si para el monitoreo se usa **CrowdSec** (plan en `Motherbase/LABS-PLAN.md` §3.5), se integra en tres
lugares distintos, y juntos cierran el círculo *detección → inteligencia → detección*:

1. **CrowdSec → Separatio (capa 4, dato propio).** Un enricher nuevo lee la Local API de CrowdSec y
   trae las IPs que te atacaron/baneó, y las cruza contra los feeds (IPsum, abuse.ch, jamesbrine):
   *¿la IP que me baneó es actor conocido / le pega también a la red global?*
   - `cscli decisions list -o json` (simple, por CLI/SSH), **o**
   - REST LAPI: `GET http://<lapi>:8080/v1/decisions` con header `X-Api-Key` (un bouncer key que se
     emite con `cscli bouncers add separatio`). También `cscli alerts list -o json` da el *scenario*
     que disparó (SSH bruteforce, http-scan…), que es contexto extra para el informe.
   - Encaja como enricher de Stage 2.7 (mismo patrón que `IpsumEnricher`).

2. **Separatio → CrowdSec (feedback loop, lo más potente).** Las IPs que Separatio correlaciona con
   alta confianza (en ≥N feeds) se **empujan como blocklist propia** a CrowdSec, que las banea:
   - `cscli decisions add --ip <ip> --duration 24h --reason "separatio-corr"`, **o**
   - servir un `.txt` de IPs (p. ej. desde el Worker agregador) y consumirlo como *blocklist* con el
     componente `crowdsec-blocklist-mirror` / una fuente custom.
   - Así tu inteligencia se vuelve **bloqueo activo**. (Cobra sentido real cuando haya un servicio
     expuesto o el honeypot — hoy sin exposición el bloqueo no tiene tráfico que filtrar.)

3. **CrowdSec CTI API (capa 3, enriquecimiento on-demand).** CrowdSec tiene su propia API de threat
   intel (tier *community/smoke* gratis, con límite diario de consultas) que da reputación y
   clasificación de una IP. Otro enricher posible, en la misma capa que GreyNoise/Pulsedive.
   Verificar límites actuales antes de depender de ella.

**CrowdSec + honeypot = dos sensores de capa 4** (dato propio), ambos consumibles por Separatio.

---

## La decisión inmediata que quedó pendiente en la conversación

Por dónde empezar a construir, dos caminos (los dos útiles, pero uno da datos y el otro mejora el
informe que ya recibís):

1. **Ingesta de IOCs** (capa 2): sumar los enrichers nuevos (abuse.ch completo, FireHOL, DigitalSide,
   jamesbrine) → da indicadores para correlacionar. Encaja directo en el modelo de Stage 2.7.
2. **Enriquecimiento de tus noticias** (el puente): extender el pipeline con **AIOCRIOC** para sacar
   IOCs de los reportes (incluidas imágenes) → mejora el informe existente y tapa un gap real.

Mi lectura: **(2) AIOCRIOC es la de mejor relación esfuerzo/valor** — es un gap concreto (IOCs en
imágenes que hoy se pierden), no depende de infra nueva, y encaja como un enricher más. (1) es más
fuentes del mismo tipo que ya tenés. Pero es decisión del usuario.

---

## Puntos de unión con Motherbase (cuando todo esté corriendo)

Esto vive en `~/Projects/Intel/` por ahora, pero se une con el proyecto Proxmox en:

- **Honeypot (capa 4)** = fase **F3** de Motherbase. El sensor (Beelzebub, no Cowrie) iría en una VM
  de Oracle **reconstruida y aislada**, con recolección **pull** (casa se conecta y trae logs; el
  honeypot no guarda credenciales que apunten a casa). Prerrequisito ya cumplido: bajamos `wg0` en F1.
- **Lab de detección (Wazuh)** = track FL de Motherbase. Si se corre Wazuh *manager-only* en un LXC,
  sus alertas son otra fuente de **dato propio** que puede alimentar esta central.
- **Dónde corre Separatio** = Paso 5 de F0, aún sin decidir (CT nuevo vs timer en `thinkfox`). Tras F1
  hay ~5 GiB libres + zram, así que sumar el CT del pipeline ya es seguro.

**Prioridad declarada por el usuario (2026-08-07):** primero la central de intel (defensa); el red
team (redirector, C2, payload server) queda para después, no es prioridad.
