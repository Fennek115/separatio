# F4 — MCP propio sobre el corpus

**Estado:** ☐ Pendiente · **Prerrequisitos:** F0 + **corpus**; F3 para el tool que más importa

> **Objetivo:** poder interrogar en lenguaje natural todo lo que Separatio acumuló, en vez de grepear
> carpetas fechadas.

> **Corregido el 2026-08-10.** Este documento se escribió antes del rework y daba por hacer cosas que
> el rework ya construyó por otros motivos. En corto: **la capa de consulta ya existe** (F-B1/F-B2
> dejaron el store SQLite, F-D dejó `separatio/store/queries.py`), así que F4 se reduce a la fachada
> MCP; y las rutas que citaba (`threat intel/`, `output-threatintel/`) ya no existen.

---

## ¿Ya está hecho?

```bash
# La fachada MCP: esto es lo que falta
ls ~/Projects/Intel/separatio/mcp_server.py ~/Projects/Intel/.mcp.json 2>/dev/null

# La capa de consulta: esto YA está (F-B1/F-B2/F-D)
ls ~/Projects/Intel/separatio/store/queries.py ~/Projects/Intel/data/archivo.db

# ¿Cuánto corpus hay? (días de informes, y el store)
ls ~/Projects/Intel/separatio/reports/ | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
sqlite3 ~/Projects/Intel/data/archivo.db \
  'select (select count(*) from ioc), (select count(*) from observation);'
```

## Lo que el rework ya dejó hecho — no rehacer

El plan original decía *"escribir primero las consultas como módulo Python normal (`queries.py`) y
envolverlas después"*. **Eso ya está**, y no se hizo para F4 sino para F-C/F-D:

| Ya existe | Qué da |
|---|---|
| `data/archivo.db` (F-B1) | SQLite en WAL, 5 tablas: `ioc` / `observation` / `enrichment` / `payload` / `meta` |
| `separatio/store/models.py` (F-B1) | Capa de acceso sin ORM: `upsert_ioc`, `ioc_row`, `add_observation`, `recent_ips`, `get_cached`, `quota_used`… |
| `separatio/store/queries.py` (F-D) | `ip_recurrence`, `payload_history`, `hassh_fanout`, `top_recurrent` |
| `separatio/store/ingest.py` (F-B2) | Punto único de escritura, idempotente |
| `separatio/store/backfill.py` (F-B2) | Reconstruye el store desde `by-date/*/` |

**Consecuencia:** ya no hay que diseñar el modelo de datos ni escribir SQL desde cero. Varios tools de
abajo son una línea sobre `queries.py`. Los que faltan (`buscar_ioc` histórico sobre los CSV,
`actor_timeline`, `cve_contexto`, `buscar_reporte`) se agregan **ahí mismo**, no en un módulo nuevo.

---

## Contexto necesario

Es **la inversión** de lo que se descartó antes: no consumir MCP desde el pipeline, sino **servir el
corpus propio como MCP**.

El razonamiento es el mismo aplicado al revés. El valor de MCP es la descubribilidad dinámica —que un
LLM lea `tools/list` y decida qué llamar—. En el cron eso vale cero porque ya se sabe qué consultar.
Pero **investigando un caso no se sabe de antemano qué se va a preguntar**, y ahí es donde paga.

Hoy el corpus existe pero es inconsultable: archivos por día en carpetas fechadas. *"¿Cuándo vi esta
IP por primera vez?"* requiere grepear a mano.

### Qué datos hay (todo ya se genera)

| Fuente | Contenido |
|---|---|
| `reports/YYYY-MM-DD/iocs/iocs-*.csv` y `.json` | Una fila por IOC: `date, ioc, type, severity, title, feed, cves` |
| `reports/history.json` | Registro diario (~200 B/día): actores, CVEs, tipos de amenaza. **Ya es serie temporal** |
| `summaries-cache-YYYY-MM-DD.json` | `ArticleSummary`: `threat_type, severity, actors, CVEs, affected_systems, IOCs` |
| `separatio/reports/YYYY-MM-DD/reports/*.md` | Los informes en prosa |
| **`data/archivo.db`** (F-B1/F-B2) | **El store: IOCs, observaciones por sensor, enrichment cacheado, payloads.** Es la fuente principal desde el rework — el resto es histórico |
| *(vía F3)* logs del honeypot | El dato propio, ya ingerido al store por `tools/pull_honeypot.sh` |

---

## Diseño

### Tools a exponer

| Tool | Devuelve | Sobre qué se apoya |
|---|---|---|
| `buscar_ioc(valor)` | apariciones: fecha, feed, severidad, CVEs | `models.ioc_row` + CSV históricos |
| `primera_vez(ioc)` | primera observación en todo el corpus | `ioc.first_seen` — **ya existe** |
| `reincidencia(ip)` | días vistos, ventana, sensores | `queries.ip_recurrence` — **ya existe** |
| `actor_timeline(nombre)` | días en que apareció, CVEs y campañas | falta (sobre `summaries-cache`) |
| `cve_contexto(cve)` | KEV, EPSS, quién lo reportó, cuándo | falta (sobre `history.json` + CSV) |
| `cruce_honeypot(desde,hasta)` | IOCs de las noticias que **además** tocaron el sensor | `observation` + IOCs del día ← **el que justifica todo** |
| `buscar_reporte(texto)` | búsqueda sobre los `.md` generados | falta |

`cruce_honeypot` es lo que no da ningún feed comprado. Ya hubo un caso real que lo demuestra: una misma IP le pegó a
Cowrie en un sensor **y** estaba baneada por el CrowdSec del otro, el mismo día — correlación
cruzada entre hosts, invisible sin el cruce. (El IOC concreto no se cita acá a propósito: este repo
es público y el proyecto no publica indicadores propios correlacionables. Está en el as-built.)

### Cómo

**FastMCP, solo lectura.** Transporte **stdio local**, registrado en el `.mcp.json` de
`~/Projects/Intel/`. **Nunca expuesto a la red.**

La fachada MCP **no lleva lógica**: cada tool es un envoltorio fino sobre `separatio/store/queries.py`.
Las consultas que falten se agregan **ahí**, no en el server — así siguen sirviendo igual para un CLI,
para el digest semanal o para cualquier script, y el MCP no se convierte en un sitio donde vive
lógica que nadie testea.

---

## ⚠️ El riesgo a diseñar desde el principio

**Tras F3 el corpus va a contener texto controlado por atacantes**: user-agents y URIs de los logs del
honeypot, notas de rescate y descripciones de leak sites. Un MCP que sirva ese texto crudo hacia un
agente es un **vector de prompt injection de reentrada** — el mismo problema que se le criticó al
`darknet-mcp-server`, pero autoinfligido.

Mitigaciones, baratas si se hacen desde el diseño:

- Exponer **campos normalizados y tipados**, no cuerpos crudos. Un IOC, una fecha, un nombre de actor
  — no el HTML ni el body del POST.
- **Truncar** todo campo de texto libre a un largo fijo.
- **Ningún tool que resuelva una URL** del corpus. Ni `claim_url`, ni `magnet`, ni la URI del log.
- Mantener el criterio del pipeline: lo determinista nunca pasa datos crudos al modelo.

---

## Prerrequisito real: corpus

**No tiene sentido con tres informes.** Con dos semanas empieza a servir; con tres meses más el dato
del honeypot, es una herramienta de verdad. Por eso está último.

**Medido el 2026-08-10:** 7 días de informes (4 al 10 de agosto) y el store con **128 IOCs / 1.078
observaciones / 327 payloads**, creciendo rápido desde que se expusieron los honeypots. Está en el
umbral de "empieza a servir", no todavía en el de "herramienta de verdad".

---

## Verificación

- [ ] Las consultas nuevas viven en `store/queries.py` y funcionan **standalone**, sin MCP de por medio
- [ ] Cada consulta nueva tiene test, como el resto de `store/`
- [ ] El server responde `tools/list` desde Claude Code al abrir `~/Projects/Intel/`
- [ ] `buscar_ioc` con una IP conocida devuelve sus apariciones históricas
- [ ] `cruce_honeypot` reproduce el caso del 2026-08-10 (misma IP: Cowrie en un sensor + CrowdSec en el otro)
- [ ] Ningún tool acepta una URL como entrada ni la resuelve
- [ ] Los campos de texto libre vienen truncados

## Al terminar

1. Marcar F4 como ☑ en [`../ESTADO.md`](../ESTADO.md).
2. Documentar los tools en el `README.md` de Separatio.
