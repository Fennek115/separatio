# IMPROVEMENTS — Revisión de arquitectura y mejoras

> Revisión del pipeline de Threat Intelligence (junio 2026): hallazgos de la
> auditoría de código, mejoras ya implementadas, integración del proyecto
> `ipcheck` como capa de enrichment, nuevas fuentes gratuitas, y un roadmap
> priorizado de los refactors pendientes.

---

## 1. Resumen ejecutivo

La arquitectura por etapas del pipeline es sólida: el correlator determinista
(KEV/EPSS), el trending histórico, el ruteo por fases y el cache/resume están
bien diseñados. Las mejoras se concentran en **escalabilidad** (facilitar sumar
fuentes nuevas) y en **robustez operacional** (que un blip de red o un proveedor
caído no rompa ni vacíe el informe).

Esta iteración entregó:

1. **Capa de enrichment de IOCs (Stage 2.7)** — sistema de plugins para cruzar
   los IOCs del día contra fuentes externas. Resuelve a la vez la modularidad,
   la integración de `ipcheck` y la incorporación de feeds nuevos.
2. **`ipcheck` refactorizado a librería** (`ip_enricher.py`) — importable, sin
   estado global, reutilizado por el pipeline vía el enricher `ip_reputation`.
3. **Fixes de base** — rutas absolutas, escritura atómica del historial,
   reintentos de red con backoff, y fail-fast en Stage 2.
4. **Suite de tests** (`pytest`) para todo el código determinista nuevo.
5. **Roadmap** de los refactors grandes pendientes (sección 6).

---

## 2. Hallazgos de la auditoría

| # | Hallazgo | Ubicación | Estado |
|---|----------|-----------|--------|
| 1 | `pipeline.py` concentra lógica de negocio (dedup, detección de tipo de IOC, export, ruteo) además de orquestar | `pipeline.py` | Roadmap (§6.3) |
| 2 | Acoplamiento de proveedores LLM: `if provider == …` en `_llm_chat` + streaming Ollama duplicado en `generate_report` y `generate_phase_report` | `analyzer.py:285,480,880` | **Hecho** (§6.1) |
| 3 | Rutas relativas (`./reports`) → bajo cron desde otro cwd, dispersaban reports y reseteaban `history.json` | `config.py` | **Hecho** (§4.1) |
| 4 | Errores tragados: Stage 2 seguía a generación de informe aunque fallaran todos los resúmenes | `pipeline.py:stage2_summarize` | **Hecho** (§4.4) |
| 5 | Sin reintentos de red en Miniflux / KEV / EPSS | `miniflux_client.py`, `correlator.py` | **Hecho** (§4.3) |
| 6 | Escritura no atómica de `history.json` → riesgo de truncado/corrupción | `history.py:save_history` | **Hecho** (§4.2) |
| 7 | `reporter.py`: CSS/HTML como strings de Python + parser Markdown por regex frágil | `reporter.py:93-652` | Roadmap (§6.2) |
| 8 | Sin tests; código difícil de testear por imports globales | (todo el repo) | **Parcial** (§5) |
| 9 | `config.py` como singleton global importado en todos lados | `config.py` | Roadmap (§6.4) |

---

## 3. Capa de enrichment de IOCs (Stage 2.7) — NUEVO

### Idea

El patrón del correlator (descargar un feed y cruzar por coincidencia exacta) es
el mismo que necesitan las mejores fuentes gratuitas de reputación. Se generalizó
en una **capa de plugins** con dos familias de enrichers:

- **Feeds planos sin API key** (rápidos, deterministas): IPsum, OpenPhish, …
- **APIs por-IOC con key y rate-limit**: `ipcheck` (AbuseIPDB/VT/GreyNoise/…).

### Flujo

```
Stage 2.5 correlator → CorrelationContext
        │
        ▼ Stage 2.7 — enrichment.py + enrichers/
  collect_iocs(summaries)            # IOCs normalizados → feeds
        │
        ├─ IpsumEnricher       (IPs maliciosas, sin key)
        ├─ OpenPhishEnricher   (URLs/dominios phishing, sin key)
        └─ IpReputationEnricher(ipcheck: AbuseIPDB/VT/GreyNoise/…, con key) [off]
        │
        ▼ EnrichmentContext.format_for_prompt()
  → se anexa a CorrelationContext.extra_blocks
  → llega al prompt de Stage 3 (sin tocar firmas de analyzer.py)
```

La etapa completa está envuelta en `try/except` en `pipeline.stage27_enrich`:
**un fallo de enrichment nunca rompe el run**.

### Archivos

| Archivo | Rol |
|---|---|
| `enrichment.py` | Núcleo: `Enricher` (ABC), `EnrichmentContext`, `IocVerdict`, `run_enrichment`, helpers `ioc_kind`/`normalize_ioc`/`collect_iocs` |
| `enrichers/__init__.py` | `build_enrichers(config)` — factory que lee los toggles |
| `enrichers/ipsum.py` | IPs en listas públicas agregadas (IPsum) |
| `enrichers/openphish.py` | URLs/dominios de phishing activo (OpenPhish) |
| `enrichers/ip_reputation.py` | Enrichment de IPs vía la librería `ipcheck` |

### Cómo agregar una fuente nueva

1. Crear `enrichers/mifuente.py` con una subclase de `Enricher` que implemente
   `name` y `enrich(iocs, ctx)`.
2. Registrarla en `enrichers/__init__.py:build_enrichers`.
3. Agregar su toggle en `config.ENRICHERS`.

No se toca `pipeline.py` ni `analyzer.py`.

### Configuración (`config.py`)

```python
ENRICHMENT_ENABLED = True
ENRICHERS = {"ipsum": True, "openphish": True, "ip_reputation": False}
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IPSUM_MIN_SCORE = 3
OPENPHISH_URL = "https://openphish.com/feed.txt"
IPCHECK_DIR = "/home/dust115/projects/tools/ipcheck"
ENRICH_MAX_IPS = 25
ENRICH_VT_SLEEP = 15
```

> `ip_reputation` está **off por defecto**: consume cuota de API y respeta el
> rate-limit de VirusTotal (~15s por IP que llega a Nivel 3). Activarlo solo con
> las keys configuradas en el entorno y entendiendo el costo en tiempo.

---

## 4. Fixes de base implementados

### 4.1 Rutas absolutas (`config.py`)
`PROJECT_ROOT = Path(__file__).resolve().parent`. `OUTPUT_DIR` y `HISTORY_FILE`
se anclan ahí. El pipeline produce los mismos paths sin importar el cwd (cron).

### 4.2 Escritura atómica del historial (`history.py`)
`save_history` serializa a `.tmp`, hace `fsync` y `os.replace` (atómico en POSIX).
Un crash o un run concurrente ya no pueden dejar `history.json` truncado.

### 4.3 Reintentos de red (`net.py`)
Helper sin dependencias (`request_with_retry`) con backoff exponencial; reintenta
ante `ConnectionError`/`Timeout` y status 429/5xx, no ante 4xx. Aplicado a
`MinifluxClient._get/_put` y a los fetch de KEV/EPSS en `correlator.py`.

### 4.4 Fail-fast en Stage 2 (`pipeline.py`)
Si ≥ `STAGE2_FAIL_FAST_THRESHOLD` (default 0.5) de los artículos falla al
resumirse, el pipeline aborta con un error claro en vez de gastar horas en
Stage 3 para producir un informe vacío (típico de proveedor LLM caído o key
inválida).

---

## 5. Tests (`pytest`)

Suite determinista, sin red ni API keys (HTTP monkeypatcheado). `pip install pytest`.

| Repo | Archivo | Cubre |
|---|---|---|
| threat-intel | `tests/test_enrichment.py` | `ioc_kind`, `normalize_ioc`, `collect_iocs`, contexto, aislamiento de fallos de enrichers |
| threat-intel | `tests/test_net.py` | reintentos 5xx/conexión, no-retry en 4xx |
| threat-intel | `tests/test_history.py` | escritura atómica, lectura tolerante a corrupción |
| ipcheck | `tests/test_ip_enricher.py` | `risk_level`, `decidir_nivel`, `debe_pasar_nivel3`, cascada de niveles, cuota VT, `disabled` |

```bash
cd "threat intel" && python3 -m pytest tests/ -q   # 14 passed
cd tools/ipcheck   && python3 -m pytest tests/ -q   # 10 passed
```

---

## 6. Roadmap — refactors grandes pendientes

Documentados aquí en vez de ejecutados de golpe: son cambios extensos sobre un
sistema en producción (cron 03:00) cuya verificación requiere Ollama/keys cloud
+ Miniflux en vivo. Conviene hacerlos uno por uno con tests antes/después.

### 6.1 Abstracción de proveedores LLM  ✅ *hecho 2026-08-09 (F-G/G-5)*
- **Problema:** `_llm_chat` (`analyzer.py:285-369`) hace dispatch por `if provider ==`,
  y la rama de streaming de Ollama está **duplicada** en `generate_report`
  (`:480`) y `generate_phase_report` (`:880`).
- **Hecho**: paquete `separatio/providers/` con `LLMProvider` (ABC), `chat()` +
  `chat_stream()` (la base cae a `chat()`; sólo `OllamaProvider` la
  sobreescribe — es el único proveedor que streamea de verdad), subclases
  `OllamaProvider`/`AnthropicProvider`/`OpenAIProvider`/`GeminiProvider` y
  `get_provider(name, ollama_host="")` (factory). `analyzer._llm_chat` quedó en
  6 líneas de cuerpo; `generate_report`/`generate_phase_report` comparten
  `_llm_chat_stream` para la rama Ollama en vez de reimplementar el loop.
  `analyzer.py` 1241 → 1154 líneas. Un quirk preexistente (`generate_report`
  nunca logueaba el consumo de Ollama en el manifiesto, a diferencia de
  `generate_phase_report`) se preservó tal cual — arreglarlo habría cambiado
  la salida. As-built en [`fases/F-G.md`](fases/F-G.md).
- **Verificación**: 36 tests nuevos (18 `test_providers.py` con cada SDK
  reemplazado por un doble — `openai`/`google-generativeai` ni siquiera están
  instalados — + 18 `test_analyzer_llm.py` con un `FakeProvider`) y una
  llamada real contra Claude (única API viva hoy; Ollama es legacy sin
  servidor) ejercitando `_llm_chat`/`generate_phase_report`/
  `generate_synthesis_report` de punta a punta.

### 6.2 Reporter: plantillas + Markdown real  *(prioridad media)*
- **Problema:** `reporter.py:93-524` tiene CSS/HTML como strings de Python y
  `markdown_to_html_body` (`:527-652`) parsea Markdown con regex frágiles ante
  variaciones de salida del LLM.
- **Propuesta:** mover plantillas a `templates/*.html.j2` (Jinja2) y reemplazar el
  parser por la librería `markdown` (o `mistune`). Mantener el CSS de paginado A4.
- **Verificación:** render de un informe de ejemplo fijo → comparar estructura HTML.

### 6.3 Modularizar `pipeline.py`  ✅ *hecho 2026-08-09 (F-G/G-3)*
- Extraer de `pipeline.py`: `dedup_by_cves`→`deduplicator.py`; `_detect_ioc_type`
  + `export_iocs`→`ioc_processor.py` (reusar `enrichment.ioc_kind`); ruteo por
  fases→`router.py`. `pipeline.py` queda solo como orquestador.
- **Hecho así**, con una salvedad: reusar `enrichment.ioc_kind` habría cambiado la
  columna `type` de `iocs.csv` (colapsa md5/sha1/sha256 en `hash`), así que las dos
  funciones quedaron separadas y documentadas. 985 → 839 líneas. As-built en
  [`fases/F-G.md`](fases/F-G.md).

### 6.4 Configuración inyectable  *(prioridad baja)*
- Migrar `config.py` a `pydantic.BaseSettings` (o un dataclass `Settings`) e
  inyectarlo en las firmas (`stage1_fetch(client, settings)`) en vez de importar
  el módulo global. Habilita tests parametrizados y múltiples configs.

### 6.5 Enriquecer el export de IOCs  ✅ *hecho 2026-08-09 (F-G/G-4)*
- Hoy `export_iocs` corre antes de Stage 2.7. Reordenar (o re-exportar) para
  incluir `EnrichmentContext.export_rows()` en el CSV/JSON de IOCs, de modo que
  el veredicto de reputación quede junto a cada IOC.
- **Hecho**: las llamadas se movieron a después de `stage27_enrich` y cada fila
  lleva una columna `reputation`. As-built en [`fases/F-G.md`](fases/F-G.md).

---

## 7. Integración con `ipcheck`

`ipcheck` se refactorizó a una librería importable (`ip_enricher.py`) sin estado
global, sin `load_dotenv` en import y sin colores en la lógica. El CLI
(`ip_threat_checker.py`) conserva su comportamiento delegando las consultas HTTP
a la librería. Detalle en `tools/ipcheck/CLAUDE.md`.

El pipeline la consume vía `enrichers/ip_reputation.py`, que importa
`ip_enricher` desde `config.IPCHECK_DIR` (acoplamiento por ruta, sin instalar
paquete). Superficie usada: `ApiKeys.from_env()` + `IpEnricher(keys).enrich(ip)`.

### Próximo paso natural (MISP)
Esta capa de enrichment es la base de la extensión MISP planeada: un
`MispEnricher` (push de IOCs corroborados+enriquecidos a una instancia MISP) y un
`enricher` que consulte MISP como fuente encajan en `enrichers/` sin tocar el core.
