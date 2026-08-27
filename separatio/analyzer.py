"""
analyzer.py — Etapas 2 y 3 del pipeline.
"""

import json
import logging
import re
import time
from collections import Counter
from dataclasses import dataclass, field

from separatio import runlog
from separatio.providers import get_provider

logger = logging.getLogger(__name__)

# Topes por defecto si `config.PROMPT_CAPS` no los trae. Desde F-I el valor real
# vive en config.py, en un solo lugar y medido contra el manifiesto — acá sólo
# quedan los mínimos para que el módulo funcione importado suelto (tests).
_CAP_DEFAULTS = {"iocs_per_article": 20}


def _cap(name: str) -> int:
    """Tope de prompt, leído de config **en cada llamada**.

    Leerlo al importar lo congelaría: el A/B de F-I compara dos valores del
    mismo tope sobre el mismo caché, y los tests lo cambian por monkeypatch."""
    from separatio import config
    caps = getattr(config, "PROMPT_CAPS", {}) or {}
    return int(caps.get(name, _CAP_DEFAULTS.get(name, 10)))


# ─────────────────────────────────────────────────────────
# TIPOS DE DATOS
# ─────────────────────────────────────────────────────────

@dataclass
class ArticleSummary:
    """Resultado del análisis individual de un artículo."""
    article_id: int
    title: str
    url: str
    feed_title: str
    feed_category: str
    published_at: str

    threat_type: str = ""
    severity: str = ""
    severity_score: int = 0
    actors: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)
    summary: str = ""
    iocs: list[str] = field(default_factory=list)
    # F-I: tres campos que hasta ahora vivían enterrados en la prosa de
    # `summary`, donde el correlator no los podía cruzar ni history trendear.
    # Con default_factory/default para que un caché viejo (sin estas claves)
    # siga cargando — `--report-only` sobre el caché de ayer no puede explotar.
    attack_techniques: list[str] = field(default_factory=list)
    exploitation_status: str = "unknown"   # active | poc | none | unknown
    confidence: str = "media"              # alta | media | baja
    error: str | None = None


_SEVERITY_SCORE: dict[str, int] = {
    "Crítica": 5, "Critical": 5,
    "Alta": 4,    "High": 4,
    "Media": 3,   "Medium": 3,
    "Baja": 2,    "Low": 2,
    "Informativa": 1, "Informational": 1,
}


# ─────────────────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────────────────

SUMMARY_SYSTEM_PROMPT = """Eres un analista de ciberseguridad experto en Threat Intelligence.
Analiza artículos de seguridad y extrae información estructurada en JSON.
Responde ÚNICAMENTE con el objeto JSON, sin explicaciones ni markdown."""


def build_summary_prompt(title: str, content: str,
                         feed: str, category: str) -> str:
    return f"""Analiza este artículo de ciberseguridad y extrae los campos pedidos.

FUENTE: {feed} [{category}]
TÍTULO: {title}
CONTENIDO:
{content}

Responde SOLO con este JSON (sin bloques markdown, sin texto adicional):
{{
  "threat_type": "tipo de amenaza (ej: Ransomware, APT, CVE, Phishing, DDoS, Supply Chain, Malware, Vulnerability, Data Breach, Hacktivism, Otro)",
  "severity": "Crítica|Alta|Media|Baja|Informativa",
  "actors": ["máx 5 actores/grupos/países conocidos, vacío si no aplica"],
  "cves": ["máx 10 CVE-XXXX-XXXXX mencionados, vacío si no hay"],
  "affected_systems": ["máx 5 sistemas/productos/sectores más relevantes"],
  "summary": "Análisis técnico en 4-5 oraciones en español: qué ocurrió, cómo funciona la técnica/vulnerabilidad (TTPs/MITRE), sistemas o sectores afectados, nivel de explotación activa, e impacto potencial.",
  "iocs": ["máx 10 IPs, dominios, hashes SHA256/MD5, URLs o firmas de red mencionados explícitamente"],
  "attack_techniques": ["IDs MITRE ATT&CK explícitos, ej: T1566.001. Vacío si no se mencionan. NO los inventes ni los infieras"],
  "exploitation_status": "active|poc|none|unknown  (active = explotación in-the-wild reportada; poc = existe PoC/exploit público; none = sin explotación conocida; unknown = el artículo no lo dice)",
  "confidence": "alta|media|baja  (tu confianza en esta extracción, dado lo explícito que sea el artículo)"
}}"""


# Esquema de salida estructurada de Stage 2 (F-I). Cuatro límites de la API que
# el esquema respeta:
#   1. Todo objeto necesita `additionalProperties: false` y su `required`.
#   2. Los topes ("máx 5 actores") NO se pueden expresar: las restricciones
#      numéricas y de longitud no están soportadas — siguen en el texto del
#      prompt, no acá.
#   3. La primera petición con un esquema nuevo paga una compilación; después se
#      cachea 24 h. Con una corrida diaria eso se paga todos los días: es un
#      costo fijo chico, pero hay que saberlo antes de sorprenderse en el manifiesto.
#   4. Si la respuesta se trunca por max_tokens el JSON puede quedar incompleto
#      igual — por eso el reintento por JSONDecodeError se conserva como red.
ARTICLE_SUMMARY_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "threat_type":         {"type": "string"},
        "severity":            {"type": "string",
                                "enum": ["Crítica", "Alta", "Media", "Baja", "Informativa"]},
        "actors":              {"type": "array", "items": {"type": "string"}},
        "cves":                {"type": "array", "items": {"type": "string"}},
        "affected_systems":    {"type": "array", "items": {"type": "string"}},
        "summary":             {"type": "string"},
        "iocs":                {"type": "array", "items": {"type": "string"}},
        "attack_techniques":   {"type": "array", "items": {"type": "string"}},
        "exploitation_status": {"type": "string",
                                "enum": ["active", "poc", "none", "unknown"]},
        "confidence":          {"type": "string", "enum": ["alta", "media", "baja"]},
    },
    "required": [
        "threat_type", "severity", "actors", "cves", "affected_systems",
        "summary", "iocs", "attack_techniques", "exploitation_status", "confidence",
    ],
    "additionalProperties": False,
}


REPORT_SYSTEM_PROMPT = """Eres un analista senior de Cyber Threat Intelligence con 15 años de experiencia en SOC, CERT y Red Team.
Redactas briefings ejecutivos de seguridad claros, técnicamente precisos y accionables.
Tu análisis incluye siempre: contexto de campaña, TTPs (frameworkMITRE ATT&CK cuando aplique), impacto real vs. teórico, y priorización por riesgo operacional.
Escribe en español profesional. No uses frases genéricas como "es importante parchear" sin justificar el riesgo concreto."""


def _build_pre_analysis(summaries: list[ArticleSummary]) -> str:
    """
    Pre-computa estadísticas que el modelo usaría en su bloque <think>.
    Inyectarlas explícitamente permite desactivar thinking sin perder calidad.
    """
    sev_order = ["Crítica", "Alta", "Media", "Baja", "Informativa"]
    sev_dist  = Counter(s.severity for s in summaries)
    sev_line  = " | ".join(
        f"{s}: {sev_dist[s]}" for s in sev_order if sev_dist.get(s)
    )

    cve_counts = Counter(
        cve for s in summaries for cve in s.cves
    )
    top_cves_line = ", ".join(
        f"{cve} ({n} fuentes)" for cve, n in cve_counts.most_common(8)
    ) or "ninguno"

    type_counts = Counter(s.threat_type for s in summaries if s.threat_type)
    top_types_line = ", ".join(
        f"{t} ({n})" for t, n in type_counts.most_common(6)
    )

    critical_high = [s for s in summaries if s.severity_score >= 4][:8]
    priority_lines = "\n".join(
        f"  - [{s.severity}] {s.title[:80]} ({s.feed_title})"
        for s in critical_high
    ) or "  - Ninguno"

    return (
        f"ANÁLISIS PREVIO (calculado por código — úsalo como base estructural):\n"
        f"  Distribución de severidad: {sev_line}\n"
        f"  CVEs más reportados: {top_cves_line}\n"
        f"  Tipos de amenaza dominantes: {top_types_line}\n"
        f"  Artículos Críticos/Altos ({len(critical_high)}):\n"
        f"{priority_lines}"
    )


def build_report_prompt(summaries: list[ArticleSummary],
                        date_str: str, language: str = "español",
                        correlation=None, trending=None,
                        article_limit: int | None = None,
                        enrichment=None) -> str:
    # summaries ya llegan ordenados por severity_score desc desde generate_report.
    # Recortamos al límite para controlar el tamaño del prompt de Stage 3.
    prompt_summaries = summaries[:article_limit] if article_limit else summaries
    omitted = len(summaries) - len(prompt_summaries)
    runlog.record_drop("analyzer._format_phase_items",
                       shown=len(prompt_summaries), total=len(summaries),
                       detail="informe consolidado")

    items = []
    for i, s in enumerate(prompt_summaries, 1):
        cves_str     = ", ".join(s.cves) if s.cves else "ninguno"
        actors_str   = ", ".join(s.actors) if s.actors else "no identificados"
        affected_str = ", ".join(s.affected_systems) if s.affected_systems else "no especificado"
        iocs_str     = ", ".join(s.iocs[:_cap("iocs_per_article")]) if s.iocs else "ninguno"
        runlog.record_drop("analyzer.build_report_prompt.iocs",
                           shown=min(_cap("iocs_per_article"), len(s.iocs)),
                           total=len(s.iocs), detail=s.title[:40])
        items.append(
            f"[{i}] [{s.severity}] [{s.threat_type}]\n"
            f"    Título: {s.title}\n"
            f"    Fuente: {s.feed_title} ({s.feed_category}) | URL: {s.url}\n"
            f"    CVEs: {cves_str}\n"
            f"    Actores: {actors_str} | Afectados: {affected_str}\n"
            f"    IOCs: {iocs_str}\n"
            f"    Análisis: {s.summary}"
        )

    unique_feeds = len(set(s.feed_title for s in summaries))

    # pre_analysis usa TODOS los artículos del día para estadísticas correctas,
    # aunque el prompt solo envíe los top N al modelo.
    pre_analysis = _build_pre_analysis(summaries)
    omitted_note = (
        f"\n(Nota: se muestran los {len(prompt_summaries)} artículos de mayor severidad. "
        f"Los {omitted} restantes —todos de severidad Media/Baja/Informativa— "
        f"están incluidos en las estadísticas del bloque de pre-análisis.)\n"
        if omitted else ""
    )

    ctx_block = _context_blocks(correlation, trending, enrichment, None)

    return f"""Fecha del informe: {date_str}
Total de artículos analizados: {len(summaries)} de {unique_feeds} fuentes
{pre_analysis}
{ctx_block}{omitted_note}
ARTÍCULOS ANALIZADOS ({len(prompt_summaries)} de {len(summaries)} — top por severidad):
{chr(10).join(items)}

---
Genera DOS informes separados en {language}. Usa EXACTAMENTE estos marcadores de sección:

===VULNERABILITY_BRIEFING===

# Vulnerability Briefing — {date_str}

## Resumen de Vulnerabilidades
(3 párrafos: (1) panorama del día — total de CVEs, distribución de severidad, fuentes principales; (2) CVEs con explotación activa confirmada o alta probabilidad, con contexto de por qué son críticos; (3) urgencia de parcheo y ventana de exposición típica para estas vulnerabilidades)

## CVEs Críticos y Altos
(Tabla con TODOS los CVEs Críticos y Altos reales mencionados en los artículos. Columnas: Sistema Afectado | CVE | CVSS/Severidad | Explotabilidad | Vector de Ataque | Fuente | Acción Inmediata. En la columna Fuente usa el formato markdown [nombre_feed](URL) con la URL exacta del artículo del listado.)

## Análisis Técnico de Vulnerabilidades Prioritarias
(Para cada CVE crítico: párrafo de 3-4 oraciones explicando el vector técnico de explotación, condiciones necesarias, impacto concreto si se explota, y si hay evidencia de explotación in-the-wild. Termina cada párrafo con la referencia: [Fuente](URL_del_artículo).)

## Parches Prioritarios
(Lista ordenada por urgencia. Para cada ítem: sistema, CVE, razón específica de prioridad, y enlace de referencia usando la URL exacta del artículo correspondiente en formato markdown [Fuente](URL). Todas las URLs están disponibles en el campo URL de cada artículo del listado anterior.)

===THREAT_INTEL_DIGEST===

# Threat Intelligence Digest — {date_str}

## Resumen Ejecutivo
(3-4 párrafos: (1) panorama general del día con nivel de alerta; (2) tendencias dominantes observadas en TTPs y tipos de amenaza; (3) actores más activos y sus objetivos; (4) recomendación estratégica para equipos de seguridad basada en los patrones del día)

## Amenazas Críticas y Altas
(Por cada amenaza Crítica o Alta: párrafo con título en negrita, descripción técnica del ataque o campaña incluyendo TTPs/MITRE cuando aplique, sistemas o sectores objetivo, indicadores de compromiso disponibles, y nivel de madurez/sofisticación del actor)

## Actividad de Actores de Amenaza
(Por cada actor mencionado explícitamente: párrafo con nombre, atribución conocida (país/grupo), TTPs característicos observados en esta campaña, objetivos o víctimas reportadas, y nivel de confianza en la atribución)

## Indicadores de Compromiso (IOCs)
(Si hay IOCs en los artículos: tabla o lista agrupada por tipo — IPs maliciosas | Dominios C2 | Hashes de malware | URLs de distribución. Solo IOCs explícitamente mencionados en las fuentes)

## Contexto Regional LATAM
(Amenazas o incidentes con impacto en América Latina. Si los hay: detallar qué países, sectores afectados, y qué medidas tomar. Si no hay impacto directo, analizar qué amenazas del día tienen mayor probabilidad de propagarse a la región y por qué.)

## Resumen por Categoria
(Tabla: Categoría | Cantidad | Severidad Máxima | Tendencia vs. día típico)

## Acciones Recomendadas
(5-7 acciones concretas y priorizadas para equipos de seguridad, ordenadas por urgencia. Para cada acción: qué hacer, por qué es urgente, y métricas de éxito o criterio de cierre)

===END===

REGLAS CRÍTICAS:
- No inventes CVEs, actores, IOCs ni datos que no aparezcan en los artículos analizados.
- Si las correlaciones verificadas incluyen CVEs marcados como KEV o corroborados por múltiples fuentes, menciónalos explícitamente como confirmados.
- Evita frases genéricas sin sustancia técnica. Cada sección debe aportar información que un analista SOC pueda usar directamente.
- Mantén los marcadores ===VULNERABILITY_BRIEFING===, ===THREAT_INTEL_DIGEST=== y ===END=== exactamente como están.
- {_LIMITS_RULE}

---
*Fuentes: {len(summaries)} artículos de {unique_feeds} feeds especializados*
"""


# ─────────────────────────────────────────────────────────
# HELPERS INTERNOS
# ─────────────────────────────────────────────────────────

def _strip_llm_output(text: str) -> str:
    """Elimina bloques <think> y fences de markdown del output del modelo."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _effort_for(phase: str, model: str, efforts: dict | None = None) -> str | None:
    """`output_config.effort` de la fase, o None si no corresponde.

    **Haiku 4.5 no acepta `effort`** (400): las fases latam/general y Stage 2
    corren en Haiku, así que quedan afuera por modelo y no por nombre de fase —
    si mañana latam pasa a Sonnet, hereda el effort sin tocar esta función."""
    from separatio import config
    if "haiku" in (model or "").lower():
        return None
    if efforts is None:
        efforts = getattr(config, "PHASE_EFFORT", {}) or {}
    return (efforts or {}).get(phase)


# Truncation signals per provider
_TRUNCATED = {"length", "max_tokens", "MAX_TOKENS", "RECITATION"}


def _log_usage(provider: str, in_tok: int, out_tok: int, finish: str, max_tokens: int,
               stage: str = "?", model: str = "", duration_s: float = 0.0) -> None:
    """Registra el consumo de una llamada al LLM.

    Hasta F-H esto era `logger.debug` con `basicConfig(level=INFO)`: el coste de
    una corrida no aparecía en ningún lado. Ahora va a INFO y además al
    manifiesto, donde se suma por corrida.
    """
    pct = int(out_tok / max_tokens * 100) if max_tokens else 0
    msg = (f"  tokens [{stage}]: {in_tok} in / {out_tok} out "
           f"({pct}% of limit, finish={finish}, {duration_s:.1f}s)")
    if finish in _TRUNCATED:
        logger.warning(f"TRUNCADO — output cortado por límite de tokens. {msg}")
    else:
        logger.info(msg)
    runlog.record_llm(stage=stage, model=model or provider,
                      in_tok=in_tok, out_tok=out_tok, finish=finish,
                      max_tokens=max_tokens, duration_s=duration_s)


def _llm_chat(
    system: str,
    user: str,
    provider: str,
    model: str,
    max_tokens: int,
    temperature: float = 0.1,
    ollama_host: str = "",
    timeout: int = 120,
    thinking: bool = False,
    num_ctx: int = 4096,
    num_threads: int = 0,
    stage: str = "?",
    output_schema: dict | None = None,
    effort: str | None = None,
) -> str:
    """Llamada LLM unificada para todos los proveedores. Devuelve texto limpio.

    `stage` sólo etiqueta la llamada en el log y el manifiesto (F-H).
    `output_schema` y `effort` son de la API de Claude (F-I) y se ignoran en el
    resto de los proveedores: `output_schema` garantiza JSON válido contra el
    esquema (sólo lo usa Stage 2 — las fases 3 y 4 producen Markdown) y `effort`
    regula la profundidad de razonamiento. **Haiku 4.5 no acepta `effort`**: el
    llamador decide, acá sólo se pasa lo que llegue.

    El dispatch por proveedor vive en `separatio/providers/` (F-G/G-5) — acá
    sólo queda pedirle el proveedor a la fábrica y loguear el consumo."""
    t0 = time.monotonic()
    prov = get_provider(provider, ollama_host)
    result = prov.chat(
        system=system, user=user, model=model, max_tokens=max_tokens,
        temperature=temperature, timeout=timeout, thinking=thinking,
        num_ctx=num_ctx, num_threads=num_threads,
        output_schema=output_schema, effort=effort,
    )
    _log_usage(provider, result.in_tok, result.out_tok, result.finish, max_tokens,
               stage=stage, model=model, duration_s=time.monotonic() - t0)
    return _strip_llm_output(result.text)


def _llm_chat_stream(
    system: str,
    user: str,
    provider: str,
    model: str,
    max_tokens: int,
    temperature: float = 0.1,
    ollama_host: str = "",
    timeout: int = 120,
    thinking: bool = False,
    num_ctx: int = 4096,
    num_threads: int = 0,
    on_token=None,
):
    """Como `_llm_chat`, pero streaming (sólo Ollama lo necesita de verdad —
    ver `providers.base.LLMProvider.chat_stream`). No loguea el consumo: cada
    llamador decide si y cómo lo hace, porque `generate_report` y
    `generate_phase_report` no lo hacían igual (ver G-5 en `docs/fases/F-G.md`
    — `generate_report` nunca llamó `_log_usage` para Ollama, y este refactor
    no puede cambiar eso). Devuelve el `ChatResult` crudo, ya con el texto
    despojado de `<think>`/fences."""
    prov = get_provider(provider, ollama_host)
    result = prov.chat_stream(
        system=system, user=user, model=model, max_tokens=max_tokens,
        temperature=temperature, timeout=timeout, thinking=thinking,
        num_ctx=num_ctx, num_threads=num_threads, on_token=on_token,
    )
    result.text = _strip_llm_output(result.text)
    return result


# ─────────────────────────────────────────────────────────
# FUNCIONES PRINCIPALES
# ─────────────────────────────────────────────────────────

def summarize_article(
    article_id: int, title: str, content: str,
    feed_title: str, feed_category: str,
    url: str, published_at: str,
    model: str, ollama_host: str,
    timeout: int = 180,
    thinking: bool = False,
    num_ctx: int = 2048,
    num_threads: int = 0,
    max_retries: int = 1,
    provider: str = "ollama",
    max_tokens: int = 600,
) -> ArticleSummary:
    summary = ArticleSummary(
        article_id=article_id, title=title, url=url,
        feed_title=feed_title, feed_category=feed_category,
        published_at=published_at,
    )
    prompt = build_summary_prompt(title, content, feed_title, feed_category)

    # Salida estructurada sólo donde existe (Claude). Con esquema, el JSON viene
    # garantizado y el reintento de abajo deja de dispararse: eso es lo que se
    # verifica en el manifiesto — cero reintentos en una corrida normal.
    from separatio import config as _cfg
    schema = (ARTICLE_SUMMARY_SCHEMA
              if provider == "claude" and getattr(_cfg, "STAGE2_STRUCTURED_OUTPUT", False)
              else None)

    for attempt in range(max_retries + 1):
        try:
            raw = _llm_chat(
                system=SUMMARY_SYSTEM_PROMPT,
                user=prompt,
                provider=provider,
                model=model,
                stage="stage2",
                output_schema=schema,
                max_tokens=max_tokens,
                temperature=0.1,
                ollama_host=ollama_host,
                timeout=timeout,
                thinking=thinking,
                num_ctx=num_ctx,
                num_threads=num_threads,
            )
            data = json.loads(raw)

            summary.threat_type      = data.get("threat_type", "Otro")
            summary.severity         = data.get("severity", "Informativa")
            summary.actors           = data.get("actors", [])
            summary.cves             = data.get("cves", [])
            summary.affected_systems = data.get("affected_systems", [])
            summary.summary          = data.get("summary", "")
            summary.iocs             = data.get("iocs", [])
            # `.get()` con default y no indexación: un modelo sin esquema (o un
            # proveedor que no lo soporta) puede omitir los campos nuevos.
            summary.attack_techniques   = data.get("attack_techniques", [])
            summary.exploitation_status = data.get("exploitation_status", "unknown")
            summary.confidence          = data.get("confidence", "media")
            summary.severity_score   = _SEVERITY_SCORE.get(summary.severity, 1)
            return summary

        except json.JSONDecodeError as e:
            runlog.bump_count("stage2_reintentos_json")
            if attempt < max_retries:
                logger.warning(
                    f"JSON inválido para '{title[:50]}', "
                    f"reintentando ({attempt + 1}/{max_retries})"
                )
                continue
            logger.warning(
                f"JSON inválido para '{title[:50]}' "
                f"tras {max_retries + 1} intentos: {e}"
            )
            summary.error = str(e)

        except Exception as e:
            logger.error(f"Error al resumir '{title[:50]}': {e}")
            summary.summary = title
            summary.error   = str(e)
            return summary

    return summary


def unload_model(model: str, ollama_host: str) -> None:
    """Fuerza la descarga del modelo de RAM antes del swap a la siguiente etapa."""
    import ollama
    try:
        client = ollama.Client(host=ollama_host)
        client.chat(
            model=model,
            messages=[{"role": "user", "content": " "}],
            keep_alive=0,
        )
        logger.info(f"Modelo descargado de RAM: {model}")
    except Exception as e:
        logger.warning(f"No se pudo descargar el modelo '{model}': {e}")


def generate_report(
    summaries: list[ArticleSummary],
    date_str: str,
    model: str,
    ollama_host: str,
    language: str = "español",
    timeout: int = 300,
    thinking: bool = True,
    num_ctx: int = 16384,
    num_threads: int = 0,
    correlation=None,
    trending=None,
    max_tokens: int = 3500,
    provider: str = "ollama",
    article_limit: int | None = None,
    enrichment=None,
) -> str:
    sorted_summaries = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    prompt = build_report_prompt(sorted_summaries, date_str, language, correlation,
                                 trending, article_limit, enrichment)

    try:
        if provider == "ollama":
            # Streaming para evitar timeout en generaciones largas en CPU-only.
            # timeout aplica entre chunks, no al total.
            def _on_token(total: int) -> None:
                if total % 100 == 0:
                    logger.info(f"  Generando informe... {total} tokens")

            result = _llm_chat_stream(
                system=REPORT_SYSTEM_PROMPT,
                user=prompt,
                provider=provider,
                model=model,
                max_tokens=max_tokens,
                temperature=0.3,
                ollama_host=ollama_host,
                timeout=timeout,
                thinking=thinking,
                num_ctx=num_ctx,
                num_threads=num_threads,
                on_token=_on_token,
            )
            logger.info(f"  Informe generado: {result.out_tok} tokens")
            return result.text

        else:
            # Cloud providers responden en segundos — no necesitan streaming.
            result = _llm_chat(
                system=REPORT_SYSTEM_PROMPT,
                user=prompt,
                provider=provider,
                model=model,
                max_tokens=max_tokens,
                temperature=0.3,
                stage="stage3",
            )
            logger.info(f"  Informe generado ({provider})")
            return result

    except Exception as e:
        logger.error(f"Error generando informe: {e}")
        return f"# Error al generar el informe\n\n{e}"


def build_weekly_prompt(
    summaries: list[ArticleSummary],
    dates: list[str],
    week_label: str,
    language: str = "español",
    enrichment=None,
) -> str:
    from collections import Counter

    start_date = dates[0] if dates else ""
    end_date   = dates[-1] if dates else ""

    sev_order = ["Crítica", "Alta", "Media", "Baja", "Informativa"]
    sev_dist  = Counter(s.severity for s in summaries)
    sev_line  = " | ".join(f"{s}: {sev_dist[s]}" for s in sev_order if sev_dist.get(s))

    cve_counts   = Counter(cve for s in summaries for cve in s.cves)
    actor_counts = Counter(a for s in summaries for a in s.actors)
    type_counts  = Counter(s.threat_type for s in summaries if s.threat_type)

    top_cves   = ", ".join(f"{c} ({n}x)" for c, n in cve_counts.most_common(15)) or "ninguno"
    top_actors = ", ".join(f"{a} ({n}x)" for a, n in actor_counts.most_common(10)) or "ninguno"
    top_types  = ", ".join(f"{t} ({n})" for t, n in type_counts.most_common(6))

    all_iocs = list({ioc for s in summaries for ioc in s.iocs})[:30]

    # Muestra hasta 40 resúmenes de mayor severidad
    top_summaries = sorted(summaries, key=lambda s: s.severity_score, reverse=True)[:40]
    items = []
    for i, s in enumerate(top_summaries, 1):
        cves_str = ", ".join(s.cves) if s.cves else "ninguno"
        items.append(
            f"[{i}] [{s.severity}] [{s.threat_type}] {s.title[:80]}\n"
            f"    Fuente: {s.feed_title} | Fecha: {s.published_at[:10]}\n"
            f"    CVEs: {cves_str}"
        )

    # El enrichment llegaba a las cuatro fases diarias desde F-I, pero el weekly
    # no corría Stage 2.7 en absoluto: se generaba sólo con las cachés de Stage 2.
    ctx_block = _context_blocks(None, None, enrichment, "weekly")

    return f"""Eres un analista senior de threat intelligence elaborando el resumen semanal consolidado.

SEMANA: {week_label} ({start_date} → {end_date}) — {len(dates)} días analizados
TOTAL DE ARTÍCULOS: {len(summaries)}
DISTRIBUCIÓN DE SEVERIDAD: {sev_line}
CVEs MÁS FRECUENTES: {top_cves}
ACTORES MÁS ACTIVOS: {top_actors}
TIPOS DE AMENAZA DOMINANTES: {top_types}
IOCs RELEVANTES: {', '.join(all_iocs[:20]) or 'ninguno'}
{ctx_block}
ARTÍCULOS MÁS RELEVANTES DE LA SEMANA:
{chr(10).join(items)}

---
Genera el informe semanal en {language}. Usa este formato exacto:

# Weekly Threat Intelligence Digest — {week_label}

## Resumen Ejecutivo
(3-4 párrafos: panorama general de la semana, nivel de alerta global, comparativa implícita con una semana típica, y recomendación estratégica principal)

## CVEs Prioritarios de la Semana
(Tabla: CVE | Sistemas Afectados | CVSS/Severidad | Frecuencia en fuentes | Estado de explotación | Acción)

## Actores de Amenaza Activos
(Por actor con ≥2 apariciones: nombre, tipo/origen, campañas observadas esta semana, TTPs, objetivos)

## Tendencias y Patrones
(Qué tipos de ataque dominaron la semana, qué sectores fueron más atacados, patrones de TTP emergentes o recurrentes)

## IOCs de la Semana
(Lista consolidada de IOCs más significativos agrupados por tipo)

## Contexto Regional LATAM
(Amenazas con impacto en América Latina esta semana; si no hay directas, qué amenazas de la semana tienen mayor probabilidad de afectar la región)

## Recomendaciones para la Próxima Semana
(5 acciones priorizadas basadas en las tendencias observadas)

REGLAS:
- No inventes datos. Usa solo lo presente en los artículos.
- Prioriza lo que apareció en múltiples fuentes o tuvo alta severidad.
- Escribe para un CISO que tiene 5 minutos para leer el informe.
---
*Fuentes: {len(summaries)} artículos de {len(set(s.feed_title for s in summaries))} feeds — {len(dates)} días*
"""


# ─────────────────────────────────────────────────────────
# MULTI-PHASE PROMPTS (Stage 3 especializado)
# ─────────────────────────────────────────────────────────

VULN_SYSTEM_PROMPT = """Eres un analista de vulnerabilidades con especialización en gestión de parches, CVSS, EPSS y CISA KEV.
Tu foco: CVEs con explotación activa o alta probabilidad de explotación, vectores técnicos, ventanas de exposición y priorización de remediation.
Redactas tablas precisas y análisis técnicos accionables para equipos de patch management y SOC.
Escribe en español profesional. No uses frases genéricas sin sustancia técnica."""

THREAT_SYSTEM_PROMPT = """Eres un analista senior de Cyber Threat Intelligence especializado en APTs, ransomware y análisis de campañas.
Tu foco: TTPs (MITRE ATT&CK), atribución de actores, IOCs técnicos y análisis de campañas activas.
Redactas perfiles de actores y análisis de campaña que permiten a un SOC detectar y responder.
Escribe en español profesional. Incluye siempre referencias a técnicas ATT&CK cuando estén disponibles en los datos."""

LATAM_SYSTEM_PROMPT = """Eres un analista de threat intelligence especializado en América Latina, con conocimiento del contexto regulatorio, sectores críticos (banca, gobierno, telecomunicaciones, infraestructura crítica) y actores que operan en la región.
Redactas inteligencia relevante para CISOs y equipos de seguridad de organizaciones latinoamericanas.
Escribe en español. Si los artículos están en inglés, traduce y contextualiza para el ecosistema LATAM."""

GENERAL_SYSTEM_PROMPT = """Eres un editor de briefing ejecutivo de ciberseguridad. Tu rol: sintetizar noticias y tendencias de la industria en contexto útil para dirección y equipos de seguridad.
Conciso, claro, sin jerga innecesaria. Escribe en español profesional."""

SYNTHESIS_SYSTEM_PROMPT = """Eres un CISO con 20 años de experiencia. Recibes los análisis especializados de tu equipo de threat intelligence y los sintetizas en un resumen ejecutivo cross-domain.
Tu objetivo: conectar vulnerabilidades, campañas activas y contexto regional en un único narrative accionable para dirección.
Escribe en español. Sé directo y orientado a la acción. No repitas detalles que ya están en los análisis especializados."""


def _format_phase_items(summaries: list[ArticleSummary],
                        article_limit: int | None = None,
                        phase: str = "") -> tuple[list, list[str]]:
    top = summaries[:article_limit] if article_limit else summaries
    # Dos recortes distintos y ambos silenciosos hasta F-H: artículos que no
    # entran a la fase (esto sí se declara en el prompt) e IOCs por artículo
    # (esto no se declaraba en ningún lado).
    runlog.record_drop("analyzer._format_phase_items",
                       shown=len(top), total=len(summaries),
                       detail=phase or "fase")
    cap = _cap("iocs_per_article")
    items = []
    for i, s in enumerate(top, 1):
        cves_str     = ", ".join(s.cves)            if s.cves            else "ninguno"
        actors_str   = ", ".join(s.actors)          if s.actors          else "no identificados"
        affected_str = ", ".join(s.affected_systems) if s.affected_systems else "no especificado"
        iocs_str     = ", ".join(s.iocs[:cap]) if s.iocs else "ninguno"
        # El detalle lleva la fase adelante para que el bloque de cobertura de
        # F-I pueda declarar sólo los recortes de SU fase y no los de las otras.
        runlog.record_drop("analyzer._format_phase_items.iocs",
                           shown=min(cap, len(s.iocs)), total=len(s.iocs),
                           detail=f"{phase or 'fase'}: {s.title[:40]}")
        items.append(
            f"[{i}] [{s.severity}] [{s.threat_type}]\n"
            f"    Título: {s.title}\n"
            f"    Fuente: {s.feed_title} | URL: {s.url}\n"
            f"    CVEs: {cves_str} | Actores: {actors_str}\n"
            f"    Afectados: {affected_str} | IOCs: {iocs_str}\n"
            f"{_format_extras(s)}"
            f"    Análisis: {s.summary}"
        )
    return top, items


_EXPLOIT_LABEL = {
    "active":  "explotación activa reportada in-the-wild",
    "poc":     "PoC/exploit público disponible",
    "none":    "sin explotación conocida",
    "unknown": "",
}


def _format_extras(s: ArticleSummary) -> str:
    """Línea de los campos estructurados de F-I. Se omite si no hay nada que
    decir: un `unknown` sin técnicas no aporta y sí ocupa tokens."""
    partes = []
    if s.attack_techniques:
        partes.append("ATT&CK: " + ", ".join(s.attack_techniques))
    etiqueta = _EXPLOIT_LABEL.get(getattr(s, "exploitation_status", "") or "", "")
    if etiqueta:
        partes.append(f"Explotación: {etiqueta}")
    if getattr(s, "confidence", "") in ("baja",):
        partes.append("Confianza de la extracción: BAJA (tratar con cautela)")
    return f"    {' | '.join(partes)}\n" if partes else ""


# Registro del producto. El modelo escribe lo que se le da: si el prompt le habla
# de "corridas" y "artículos procesados", el informe sale narrando la telemetría
# del pipeline en vez del panorama de amenazas. Medido en la corrida del
# 2026-08-10: «La corrida de hoy procesó 41 artículos…», «según la clasificación
# provista», y —lo peor— «El equipo no encontró incidentes LATAM», que inventa un
# sujeto colectivo que no existe.
_DOCTRINE_RULE = (
    "REGISTRO: escribís como analista de inteligencia de amenazas, no como una "
    "herramienta narrando su propia ejecución.\n"
    "(a) Nunca menciones el pipeline, la corrida, el caché, los prompts, los feeds "
    "ni el conteo de artículos procesados. Decí «durante el período de reporte», no "
    "«la corrida de hoy procesó N artículos». Los números de amenaza (cuántos CVEs, "
    "qué distribución de severidad, cuántas víctimas) SÍ van: son sustancia, no "
    "telemetría de la colección.\n"
    "(b) No inventes un sujeto colectivo: no existe «el equipo» ni «nuestros "
    "analistas». Usá voz impersonal: «no se identificó», «se observó».\n"
    "(c) Usá lenguaje estimativo calibrado para lo que es inferencia y no hecho "
    "observado: «es casi seguro» (>95%), «es muy probable» (80-95%), «es probable» "
    "(55-80%), «es poco probable» (20-45%), «es muy improbable» (<20%). No inventes "
    "porcentajes numéricos: usá la expresión, no la cifra.\n"
    "(d) Distinguí CONFIANZA de PROBABILIDAD. La confianza (alta/media/baja) mide la "
    "calidad y corroboración de las fuentes; la probabilidad mide qué tan factible es "
    "el hecho. Son ejes independientes: se puede tener confianza alta en que algo es "
    "poco probable. Cuando emitas un juicio que va más allá de lo reportado, marcá "
    "ambos."
)

# Regla común a las cinco salidas: lo que el bloque COBERTURA declara como
# faltante tiene que llegar al informe. Sin esto el modelo *sabe* lo que le falta
# pero el lector no, que es exactamente el agujero que F-I viene a tapar.
# El nombre de la sección es doctrina, no capricho: «brecha de colección» dice
# que no se miró; «limitación» se lee como que se miró y no había nada.
_LIMITS_RULE = (
    "Si el bloque COBERTURA Y BRECHAS DE COLECCIÓN declara faltantes (una fuente "
    "caída u omitida, reporting recortado o sólo-título), cerrá el informe con una "
    "línea «**Brechas de colección:** …» nombrándolos en una oración, en términos de "
    "qué NO se pudo verificar —no de qué hizo la herramienta. Si no hay faltantes "
    "declarados, omití esa línea por completo."
)

_STYLE_RULES = f"{_DOCTRINE_RULE}\n{_LIMITS_RULE}"


def _context_blocks(correlation=None, trending=None, enrichment=None,
                    phase: str | None = None) -> str:
    """Los bloques de contexto que anteceden al listado de artículos.

    Desde F-I el `enrichment` es un parámetro propio y no viaja de contrabando
    dentro de `CorrelationContext.extra_blocks`: así llega a las **cuatro**
    fases sin arrastrar KEV/EPSS a LATAM, que ahí es ruido.

    El bloque de cobertura va **último**, pegado al listado: es lo que el modelo
    tiene que tener presente al escribir, no un preámbulo que se diluye."""
    bloques = []
    if correlation is not None and correlation.has_signals():
        bloques.append(correlation.format_for_prompt())
    if enrichment is not None and enrichment.has_signals():
        bloque = enrichment.format_for_prompt(cap=_cap("verdicts_per_source"))
        if bloque:
            bloques.append(bloque)
    if trending is not None and trending.has_data():
        bloques.append(trending.format_for_prompt())
    cobertura = runlog.coverage_block(phase)
    if cobertura:
        bloques.append(cobertura)
    return "\n" + "\n\n".join(bloques) + "\n" if bloques else ""


def build_vuln_prompt(summaries: list[ArticleSummary], date_str: str,
                      correlation=None, article_limit: int | None = 50,
                      enrichment=None) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    top, items = _format_phase_items(sorted_s, article_limit, "vulnerability")

    sev_dist  = Counter(s.severity for s in summaries)
    sev_line  = " | ".join(f"{s}: {sev_dist[s]}" for s in ["Crítica","Alta","Media","Baja","Informativa"] if sev_dist.get(s))
    cve_cnt   = Counter(cve for s in summaries for cve in s.cves)
    top_cves  = ", ".join(f"{c} ({n}x)" for c, n in cve_cnt.most_common(10)) or "ninguno"
    ctx_block = _context_blocks(correlation, None, enrichment, "vulnerability")

    return f"""Fecha: {date_str}
Artículos de vulnerabilidades: {len(summaries)} | Severidad: {sev_line}
CVEs más mencionados: {top_cves}
{ctx_block}
ARTÍCULOS:
{chr(10).join(items)}

---
Genera el Vulnerability Briefing en español. Usa este formato exacto:

# Vulnerability Briefing — {date_str}

## Panorama del Día
(2-3 párrafos: (1) total CVEs, distribución de severidad, fuentes clave; (2) CVEs en KEV o con EPSS > 0.4; (3) urgencia de parcheo y ventana de exposición estimada)

## CVEs Críticos y Altos
(Tabla con TODOS los CVEs Críticos y Altos. Columnas: Sistema Afectado | CVE | CVSS/Severidad | EPSS | KEV | Explotabilidad | Vector de Ataque | Fuente | Acción Inmediata. Columna Fuente: [feed](URL) con la URL exacta del artículo.)

## Análisis Técnico de CVEs Prioritarios
(Por cada CVE crítico: párrafo con vector técnico de explotación, condiciones necesarias, impacto concreto, evidencia in-the-wild. Termina con [Fuente](URL).)

## Parches Prioritarios
(Lista ordenada por urgencia: sistema, CVE, razón específica de prioridad, [Fuente](URL).)

REGLAS: No inventes CVEs ni datos. CVEs en KEV: señálalos explícitamente como confirmados. Usa las URLs exactas del campo URL de cada artículo.
{_STYLE_RULES}"""


def build_threat_prompt(summaries: list[ArticleSummary], date_str: str,
                        correlation=None, trending=None,
                        article_limit: int | None = 35,
                        enrichment=None) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    top, items = _format_phase_items(sorted_s, article_limit, "threat_intel")

    actor_cnt  = Counter(a for s in summaries for a in s.actors)
    top_actors = ", ".join(f"{a} ({n}x)" for a, n in actor_cnt.most_common(8)) or "ninguno"
    type_cnt   = Counter(s.threat_type for s in summaries if s.threat_type)
    top_types  = ", ".join(f"{t} ({n})" for t, n in type_cnt.most_common(5))
    ctx_block  = _context_blocks(correlation, trending, enrichment, "threat_intel")

    return f"""Fecha: {date_str}
Artículos de threat intel / hacking: {len(summaries)} | Actores activos: {top_actors}
Tipos dominantes: {top_types}
{ctx_block}
ARTÍCULOS:
{chr(10).join(items)}

---
Genera el Threat Intelligence Digest en español. Usa este formato exacto:

# Threat Intelligence Digest — {date_str}

## Panorama de Amenazas
(2-3 párrafos: actores más activos, TTPs dominantes observados, nivel de sofisticación y coordinación)

## Campañas y Actores Activos
(Por cada actor/campaña destacada: párrafo con nombre, tipo/origen, TTPs MITRE ATT&CK cuando aplique, objetivos o víctimas reportadas, IOCs disponibles, nivel de confianza en atribución. Incluye [Fuente](URL).)

## IOCs de la Jornada
(Tabla o lista agrupada: IPs maliciosas | Dominios C2 | Hashes de malware | URLs de distribución. Solo IOCs explícitamente mencionados en fuentes.)

## Detección y Respuesta
(5-7 acciones concretas para SOC/CERT: búsquedas SIEM sugeridas, bloqueos de IOCs, hunting queries basadas en TTPs observados)

REGLAS: No inventes actores ni IOCs. Si hay actores persistentes en trending, señálalos. Incluye fuente para cada IOC.
{_STYLE_RULES}"""


def build_latam_prompt(summaries: list[ArticleSummary], date_str: str,
                       article_limit: int | None = 60,
                       enrichment=None) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    top, items = _format_phase_items(sorted_s, article_limit, "latam")
    # LATAM recibe enrichment pero NO correlación: KEV/EPSS acá es ruido.
    ctx_block = _context_blocks(None, None, enrichment, "latam")

    return f"""Fecha: {date_str}
Artículos con relevancia LATAM: {len(summaries)}
{ctx_block}
ARTÍCULOS:
{chr(10).join(items)}

---
Genera el análisis regional en español. Usa este formato exacto:

# Contexto Regional LATAM — {date_str}

## Incidentes y Amenazas Directas en la Región
(Lo que ocurrió directamente en países de América Latina: países afectados, sectores, actores, fuente. Si no hay incidentes directos hoy, indicarlo explícitamente.)

## Amenazas Globales con Impacto Regional Probable
(De los artículos del día, cuáles tienen mayor probabilidad de afectar organizaciones latinoamericanas. Argumenta con base en: sectores objetivo del actor, TTPs compatibles con el perfil tecnológico de la región, presencia conocida del actor en LATAM.)

## Sectores en Mayor Riesgo Hoy
(Análisis breve por sector: banca/finanzas, gobierno, telecomunicaciones, infraestructura crítica)

## Recomendaciones para Organizaciones LATAM
(3-5 acciones concretas considerando el contexto regulatorio local y el stack tecnológico predominante en la región)

REGLAS: Sé específico sobre países cuando los datos lo permitan. No extrapoles incidentes globales a LATAM sin justificación. Si hay poco material LATAM directo, es válido indicarlo y enfocarse en las amenazas globales más relevantes para la región.
{_STYLE_RULES}"""


def build_general_prompt(summaries: list[ArticleSummary], date_str: str,
                         article_limit: int | None = 20,
                         enrichment=None) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    _top, items = _format_phase_items(sorted_s, article_limit, "general")
    ctx_block = _context_blocks(None, None, enrichment, "general")

    return f"""Fecha: {date_str}
Artículos generales de ciberseguridad: {len(summaries)}
{ctx_block}
ARTÍCULOS:
{chr(10).join(items)}

---
Genera el panorama general en español. Usa este formato exacto:

# Panorama General de Ciberseguridad — {date_str}

## Noticias Destacadas
(Las 5-8 noticias más relevantes: qué pasó, por qué importa para equipos de seguridad, impacto esperado. [Fuente](URL) para cada una.)

## Tendencias y Contexto de Industria
(Patrones observados: cambios regulatorios, nuevas técnicas emergentes, movimientos del ecosistema relevantes)

REGLAS: Prioriza noticias con impacto operacional directo sobre noticias corporativas. Sé conciso — este briefing es para dirección.
{_STYLE_RULES}"""


def build_synthesis_prompt(phase_outputs: dict[str, str], date_str: str,
                           total_articles: int, provider: str = "api") -> str:
    phase_labels = {
        "vulnerability": "VULNERABILITY BRIEFING",
        "threat_intel":  "THREAT INTELLIGENCE",
        "latam":         "CONTEXTO LATAM",
        "general":       "PANORAMA GENERAL",
    }
    # Ollama: excerpt shorter to fit 16K ctx; API providers: more context for better correlations
    excerpt_len = 1500 if provider == "ollama" else 3000
    sections = ""
    for phase in ["vulnerability", "threat_intel", "latam", "general"]:
        if phase not in phase_outputs:
            continue
        label   = phase_labels.get(phase, phase.upper())
        excerpt = phase_outputs[phase][:excerpt_len]
        if len(phase_outputs[phase]) > excerpt_len:
            excerpt += "\n...[ver informe completo de la fase]"
        sections += f"\n--- {label} ---\n{excerpt}\n"

    # La síntesis ve la cobertura de TODA la corrida (phase=None): es el texto
    # que el usuario lee primero, así que es donde más importa que los faltantes
    # estén declarados.
    cobertura = runlog.coverage_block()
    cobertura = f"\n{cobertura}\n" if cobertura else ""

    return f"""Fecha: {date_str}
Volumen de reporting analizado (diagnóstico interno, NO citar en el informe): {total_articles}
Fases completadas: {', '.join(phase_outputs.keys())}
{cobertura}
RESÚMENES ESPECIALIZADOS DE HOY:
{sections}

---
Genera el RESUMEN EJECUTIVO cross-domain en español. Usa este formato exacto:

# Resumen Ejecutivo — {date_str}

## Nivel de Alerta: [CRÍTICO / ALTO / MEDIO / BAJO]
(1 párrafo: justificación del nivel. El factor principal que determina la alerta de hoy.)

## Juicios Clave
(3-5 juicios numerados, cada uno en una o dos oraciones. Un juicio es una AFIRMACIÓN
ANALÍTICA sobre lo que está pasando o va a pasar — no un resumen de una noticia.
Cerrá cada uno con «(Confianza: alta/media/baja)» y usá lenguaje estimativo calibrado
para la parte que sea inferencia. Si un juicio depende de una sola fuente sin
corroborar, la confianza NO puede ser alta.)

## Prioridad #1 — Acción Inmediata
(3-4 frases: la amenaza o vulnerabilidad más urgente del día. Qué hacer hoy, quién es responsable operacionalmente, cómo verificar que se ejecutó.)

## Correlaciones Cross-Dominio
(2-3 párrafos: conexiones entre los análisis. ¿Hay actores explotando CVEs del briefing de vulnerabilidades? ¿IOCs del threat intel aparecen en contexto LATAM? ¿Patrones que cambian la priorización de parches?)

## Recomendación Estratégica
(1 párrafo para dirección/CISO: tendencia dominante, posicionamiento recomendado, qué vigilar en los próximos 7 días)

REGLAS: NO repitas detalles de los análisis especializados — el lector los tiene disponibles. Enfócate en CONEXIONES y PANORAMA GLOBAL. Si no hay correlaciones claras, indícalo honestamente.
{_STYLE_RULES}"""


def generate_phase_report(
    phase: str,
    summaries: list[ArticleSummary],
    date_str: str,
    model: str,
    ollama_host: str,
    language: str = "español",
    timeout: int = 300,
    thinking: bool = False,
    num_ctx: int = 16384,
    num_threads: int = 0,
    max_tokens: int = 2500,
    provider: str = "ollama",
    article_limit: int | None = None,
    correlation=None,
    trending=None,
    enrichment=None,
    settings=None,
) -> str:
    """Genera el informe de una fase especializada (vuln / threat_intel / latam / general).

    `settings` (un `Settings`, F-G/G-2) sólo aporta `PHASE_EFFORT`; sin él se lee
    del `config` global, como antes."""
    SYSTEMS = {
        "vulnerability": VULN_SYSTEM_PROMPT,
        "threat_intel":  THREAT_SYSTEM_PROMPT,
        "latam":         LATAM_SYSTEM_PROMPT,
        "general":       GENERAL_SYSTEM_PROMPT,
    }
    # Cada fase recibe lo que le sirve: correlación (KEV/EPSS) sólo a
    # vulnerability y threat_intel; **enrichment a las cuatro** (F-I, cambio 3);
    # trending sólo a threat_intel.
    BUILDERS = {
        "vulnerability": lambda: build_vuln_prompt(summaries, date_str, correlation,
                                                   article_limit, enrichment),
        "threat_intel":  lambda: build_threat_prompt(summaries, date_str, correlation,
                                                     trending, article_limit, enrichment),
        "latam":         lambda: build_latam_prompt(summaries, date_str, article_limit,
                                                    enrichment),
        "general":       lambda: build_general_prompt(summaries, date_str, article_limit,
                                                      enrichment),
    }
    if phase not in SYSTEMS:
        logger.warning(f"Fase desconocida '{phase}' — usando prompt general")
        phase = "general"

    system_prompt = SYSTEMS[phase]
    prompt        = BUILDERS[phase]()
    t0            = time.monotonic()

    try:
        if provider == "ollama":
            def _on_token(total: int) -> None:
                if total % 100 == 0:
                    logger.info(f"  [{phase}] Generando... {total} tokens")

            result = _llm_chat_stream(
                system=system_prompt,
                user=prompt,
                provider=provider,
                model=model,
                max_tokens=max_tokens,
                temperature=0.3,
                ollama_host=ollama_host,
                timeout=timeout,
                thinking=thinking,
                num_ctx=num_ctx,
                num_threads=num_threads,
                on_token=_on_token,
            )
            _log_usage("ollama", result.in_tok, result.out_tok, result.finish, max_tokens,
                       stage=f"phase:{phase}", model=model,
                       duration_s=time.monotonic() - t0)
            logger.info(f"  [{phase}] Generado: {result.out_tok} tokens (finish={result.finish})")
            return result.text
        else:
            result = _llm_chat(
                system=system_prompt,
                user=prompt,
                provider=provider,
                model=model,
                stage=f"phase:{phase}",
                max_tokens=max_tokens,
                temperature=0.3,
                ollama_host=ollama_host,
                timeout=timeout,
                thinking=thinking,
                num_ctx=num_ctx,
                num_threads=num_threads,
                effort=_effort_for(phase, model,
                                   settings.PHASE_EFFORT if settings is not None else None),
            )
            logger.info(f"  [{phase}] Generado ({provider})")
            return result
    except Exception as e:
        logger.error(f"Error en fase '{phase}': {e}")
        return f"# Error en fase {phase}\n\n{e}"


def generate_synthesis_report(
    phase_outputs: dict[str, str],
    date_str: str,
    total_articles: int,
    model: str,
    ollama_host: str,
    language: str = "español",
    timeout: int = 300,
    thinking: bool = False,
    num_ctx: int = 16384,
    num_threads: int = 0,
    max_tokens: int = 1500,
    provider: str = "ollama",
    settings=None,
) -> str:
    """Stage 4: síntesis maestra cross-domain a partir de los outputs de las 4 fases."""
    prompt = build_synthesis_prompt(phase_outputs, date_str, total_articles, provider)
    try:
        result = _llm_chat(
            system=SYNTHESIS_SYSTEM_PROMPT,
            user=prompt,
            provider=provider,
            model=model,
            stage="synthesis",
            max_tokens=max_tokens,
            temperature=0.2,
            ollama_host=ollama_host,
            timeout=timeout,
            thinking=thinking,
            num_ctx=num_ctx,
            num_threads=num_threads,
            effort=_effort_for("synthesis", model,
                               settings.PHASE_EFFORT if settings is not None else None),
        )
        logger.info(f"  [synthesis] Generado ({provider})")
        return result
    except Exception as e:
        logger.error(f"Error en síntesis: {e}")
        return f"# Error en síntesis\n\n{e}"


def generate_weekly_report(
    summaries: list[ArticleSummary],
    dates: list[str],
    week_label: str,
    model: str,
    ollama_host: str,
    language: str = "español",
    timeout: int = 300,
    thinking: bool = True,
    num_ctx: int = 16384,
    num_threads: int = 0,
    max_tokens: int = 4000,
    provider: str = "ollama",
    enrichment=None,
) -> str:
    prompt = build_weekly_prompt(summaries, dates, week_label, language, enrichment)

    try:
        result = _llm_chat(
            system=REPORT_SYSTEM_PROMPT,
            user=prompt,
            provider=provider,
            model=model,
            stage="weekly",
            max_tokens=max_tokens,
            temperature=0.3,
            ollama_host=ollama_host,
            timeout=timeout,
            thinking=thinking,
            num_ctx=num_ctx,
            num_threads=num_threads,
        )
        logger.info(f"  Informe semanal generado ({provider})")
        return result
    except Exception as e:
        logger.error(f"Error generando informe semanal: {e}")
        return f"# Error al generar el informe semanal\n\n{e}"
