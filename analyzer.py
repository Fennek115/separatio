"""
analyzer.py — Etapas 2 y 3 del pipeline.
"""

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


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
  "iocs": ["máx 10 IPs, dominios, hashes SHA256/MD5, URLs o firmas de red mencionados explícitamente"]
}}"""


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
                        article_limit: int | None = None) -> str:
    # summaries ya llegan ordenados por severity_score desc desde generate_report.
    # Recortamos al límite para controlar el tamaño del prompt de Stage 3.
    prompt_summaries = summaries[:article_limit] if article_limit else summaries
    omitted = len(summaries) - len(prompt_summaries)

    items = []
    for i, s in enumerate(prompt_summaries, 1):
        cves_str     = ", ".join(s.cves) if s.cves else "ninguno"
        actors_str   = ", ".join(s.actors) if s.actors else "no identificados"
        affected_str = ", ".join(s.affected_systems) if s.affected_systems else "no especificado"
        iocs_str     = ", ".join(s.iocs[:8]) if s.iocs else "ninguno"
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

    correlation_block = ""
    if correlation is not None and correlation.has_signals():
        correlation_block = f"\n{correlation.format_for_prompt()}\n"

    trending_block = ""
    if trending is not None and trending.has_data():
        trending_block = f"\n{trending.format_for_prompt()}\n"

    return f"""Fecha del informe: {date_str}
Total de artículos analizados: {len(summaries)} de {unique_feeds} fuentes
{pre_analysis}
{correlation_block}{trending_block}{omitted_note}
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


def _build_options(num_ctx: int, num_predict: int,
                   temperature: float, num_threads: int) -> dict:
    options: dict = {
        "temperature": temperature,
        "num_predict": num_predict,
        "num_ctx": num_ctx,
    }
    if num_threads > 0:
        options["num_thread"] = num_threads
    return options


def _get_api_key(provider: str) -> str:
    import config
    keys = {
        "claude": getattr(config, "ANTHROPIC_API_KEY", ""),
        "openai": getattr(config, "OPENAI_API_KEY", ""),
        "gemini": getattr(config, "GEMINI_API_KEY", ""),
    }
    key = keys.get(provider, "")
    if not key:
        raise ValueError(
            f"API key para '{provider}' no configurada. "
            f"Revisa config.py o la variable de entorno correspondiente."
        )
    return key


# Truncation signals per provider
_TRUNCATED = {"length", "max_tokens", "MAX_TOKENS", "RECITATION"}


def _log_usage(provider: str, in_tok: int, out_tok: int, finish: str, max_tokens: int) -> None:
    pct = int(out_tok / max_tokens * 100) if max_tokens else 0
    msg = f"  tokens: {in_tok} in / {out_tok} out ({pct}% of limit, finish={finish})"
    if finish in _TRUNCATED:
        logger.warning(f"TRUNCADO — output cortado por límite de tokens. {msg}")
    else:
        logger.debug(msg)


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
) -> str:
    """Llamada LLM unificada para todos los proveedores. Devuelve texto limpio."""
    if provider == "ollama":
        import ollama
        client = ollama.Client(host=ollama_host, timeout=timeout)
        options = _build_options(num_ctx, max_tokens, temperature, num_threads)
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            think=thinking,
            options=options,
        )
        in_tok  = response.get("prompt_eval_count", 0)
        out_tok = response.get("eval_count", 0)
        done_reason = response.get("done_reason", "stop")
        _log_usage(provider, in_tok, out_tok, done_reason, max_tokens)
        return _strip_llm_output(response["message"]["content"])

    elif provider == "claude":
        import anthropic
        client = anthropic.Anthropic(api_key=_get_api_key("claude"))
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        _log_usage(provider, response.usage.input_tokens, response.usage.output_tokens,
                   response.stop_reason, max_tokens)
        return _strip_llm_output(response.content[0].text)

    elif provider == "openai":
        import openai
        client = openai.OpenAI(api_key=_get_api_key("openai"))
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        usage  = response.usage
        finish = response.choices[0].finish_reason
        _log_usage(provider, usage.prompt_tokens, usage.completion_tokens, finish, max_tokens)
        return _strip_llm_output(response.choices[0].message.content)

    elif provider == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=_get_api_key("gemini"))
        gemini_model = genai.GenerativeModel(
            model_name=model,
            system_instruction=system,
        )
        response = gemini_model.generate_content(
            user,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        meta   = response.usage_metadata
        finish = response.candidates[0].finish_reason.name if response.candidates else "UNKNOWN"
        _log_usage(provider, meta.prompt_token_count, meta.candidates_token_count, finish, max_tokens)
        return _strip_llm_output(response.text)

    else:
        raise ValueError(f"Provider desconocido: {provider!r}. Opciones: ollama, claude, openai, gemini")


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

    for attempt in range(max_retries + 1):
        try:
            raw = _llm_chat(
                system=SUMMARY_SYSTEM_PROMPT,
                user=prompt,
                provider=provider,
                model=model,
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
            summary.severity_score   = _SEVERITY_SCORE.get(summary.severity, 1)
            return summary

        except json.JSONDecodeError as e:
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
) -> str:
    sorted_summaries = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    prompt = build_report_prompt(sorted_summaries, date_str, language, correlation, trending, article_limit)

    try:
        if provider == "ollama":
            import ollama
            # Streaming para evitar timeout en generaciones largas en CPU-only.
            # timeout aplica entre chunks, no al total.
            client  = ollama.Client(host=ollama_host, timeout=timeout)
            options = _build_options(num_ctx, num_predict=max_tokens,
                                     temperature=0.3, num_threads=num_threads)
            stream = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                think=thinking,
                options=options,
                stream=True,
            )
            tokens: list[str] = []
            total = 0
            for chunk in stream:
                token = chunk["message"]["content"]
                if token:
                    tokens.append(token)
                    total += 1
                    if total % 100 == 0:
                        logger.info(f"  Generando informe... {total} tokens")
            logger.info(f"  Informe generado: {total} tokens")
            return _strip_llm_output("".join(tokens))

        else:
            # Cloud providers responden en segundos — no necesitan streaming.
            result = _llm_chat(
                system=REPORT_SYSTEM_PROMPT,
                user=prompt,
                provider=provider,
                model=model,
                max_tokens=max_tokens,
                temperature=0.3,
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

    return f"""Eres un analista senior de threat intelligence elaborando el resumen semanal consolidado.

SEMANA: {week_label} ({start_date} → {end_date}) — {len(dates)} días analizados
TOTAL DE ARTÍCULOS: {len(summaries)}
DISTRIBUCIÓN DE SEVERIDAD: {sev_line}
CVEs MÁS FRECUENTES: {top_cves}
ACTORES MÁS ACTIVOS: {top_actors}
TIPOS DE AMENAZA DOMINANTES: {top_types}
IOCs RELEVANTES: {', '.join(all_iocs[:20]) or 'ninguno'}

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
                        article_limit: int | None = None) -> tuple[list, list[str]]:
    top = summaries[:article_limit] if article_limit else summaries
    items = []
    for i, s in enumerate(top, 1):
        cves_str     = ", ".join(s.cves)            if s.cves            else "ninguno"
        actors_str   = ", ".join(s.actors)          if s.actors          else "no identificados"
        affected_str = ", ".join(s.affected_systems) if s.affected_systems else "no especificado"
        iocs_str     = ", ".join(s.iocs[:8])        if s.iocs            else "ninguno"
        items.append(
            f"[{i}] [{s.severity}] [{s.threat_type}]\n"
            f"    Título: {s.title}\n"
            f"    Fuente: {s.feed_title} | URL: {s.url}\n"
            f"    CVEs: {cves_str} | Actores: {actors_str}\n"
            f"    Afectados: {affected_str} | IOCs: {iocs_str}\n"
            f"    Análisis: {s.summary}"
        )
    return top, items


def build_vuln_prompt(summaries: list[ArticleSummary], date_str: str,
                      correlation=None, article_limit: int | None = 50) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    top, items = _format_phase_items(sorted_s, article_limit)

    sev_dist  = Counter(s.severity for s in summaries)
    sev_line  = " | ".join(f"{s}: {sev_dist[s]}" for s in ["Crítica","Alta","Media","Baja","Informativa"] if sev_dist.get(s))
    cve_cnt   = Counter(cve for s in summaries for cve in s.cves)
    top_cves  = ", ".join(f"{c} ({n}x)" for c, n in cve_cnt.most_common(10)) or "ninguno"
    corr_block = f"\n{correlation.format_for_prompt()}\n" if correlation and correlation.has_signals() else ""
    omitted    = len(summaries) - len(top)
    note       = f"\n(Se muestran {len(top)} artículos de mayor severidad; {omitted} adicionales cubiertos en estadísticas.)\n" if omitted else ""

    return f"""Fecha: {date_str}
Artículos de vulnerabilidades: {len(summaries)} | Severidad: {sev_line}
CVEs más mencionados: {top_cves}
{corr_block}{note}
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

REGLAS: No inventes CVEs ni datos. CVEs en KEV: señálalos explícitamente como confirmados. Usa las URLs exactas del campo URL de cada artículo."""


def build_threat_prompt(summaries: list[ArticleSummary], date_str: str,
                        correlation=None, trending=None,
                        article_limit: int | None = 35) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    top, items = _format_phase_items(sorted_s, article_limit)

    actor_cnt  = Counter(a for s in summaries for a in s.actors)
    top_actors = ", ".join(f"{a} ({n}x)" for a, n in actor_cnt.most_common(8)) or "ninguno"
    type_cnt   = Counter(s.threat_type for s in summaries if s.threat_type)
    top_types  = ", ".join(f"{t} ({n})" for t, n in type_cnt.most_common(5))
    corr_block  = f"\n{correlation.format_for_prompt()}\n" if correlation and correlation.has_signals() else ""
    trend_block = f"\n{trending.format_for_prompt()}\n"    if trending and trending.has_data()        else ""
    omitted     = len(summaries) - len(top)
    note        = f"\n(Se muestran {len(top)} artículos; {omitted} adicionales de menor severidad.)\n" if omitted else ""

    return f"""Fecha: {date_str}
Artículos de threat intel / hacking: {len(summaries)} | Actores activos: {top_actors}
Tipos dominantes: {top_types}
{corr_block}{trend_block}{note}
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

REGLAS: No inventes actores ni IOCs. Si hay actores persistentes en trending, señálalos. Incluye fuente para cada IOC."""


def build_latam_prompt(summaries: list[ArticleSummary], date_str: str,
                       article_limit: int | None = 60) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    top, items = _format_phase_items(sorted_s, article_limit)

    return f"""Fecha: {date_str}
Artículos con relevancia LATAM: {len(summaries)}

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

REGLAS: Sé específico sobre países cuando los datos lo permitan. No extrapoles incidentes globales a LATAM sin justificación. Si hay poco material LATAM directo, es válido indicarlo y enfocarse en las amenazas globales más relevantes para la región."""


def build_general_prompt(summaries: list[ArticleSummary], date_str: str,
                         article_limit: int | None = 20) -> str:
    sorted_s = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    _top, items = _format_phase_items(sorted_s, article_limit)

    return f"""Fecha: {date_str}
Artículos generales de ciberseguridad: {len(summaries)}

ARTÍCULOS:
{chr(10).join(items)}

---
Genera el panorama general en español. Usa este formato exacto:

# Panorama General de Ciberseguridad — {date_str}

## Noticias Destacadas
(Las 5-8 noticias más relevantes: qué pasó, por qué importa para equipos de seguridad, impacto esperado. [Fuente](URL) para cada una.)

## Tendencias y Contexto de Industria
(Patrones observados: cambios regulatorios, nuevas técnicas emergentes, movimientos del ecosistema relevantes)

REGLAS: Prioriza noticias con impacto operacional directo sobre noticias corporativas. Sé conciso — este briefing es para dirección."""


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

    return f"""Fecha: {date_str}
Total artículos procesados: {total_articles}
Fases completadas: {', '.join(phase_outputs.keys())}

RESÚMENES ESPECIALIZADOS DE HOY:
{sections}

---
Genera el RESUMEN EJECUTIVO cross-domain en español. Usa este formato exacto:

# Resumen Ejecutivo — {date_str}

## Nivel de Alerta: [CRÍTICO / ALTO / MEDIO / BAJO]
(1 párrafo: justificación del nivel. El factor principal que determina la alerta de hoy.)

## Prioridad #1 — Acción Inmediata
(3-4 frases: la amenaza o vulnerabilidad más urgente del día. Qué hacer hoy, quién es responsable operacionalmente, cómo verificar que se ejecutó.)

## Correlaciones Cross-Dominio
(2-3 párrafos: conexiones entre los análisis. ¿Hay actores explotando CVEs del briefing de vulnerabilidades? ¿IOCs del threat intel aparecen en contexto LATAM? ¿Patrones que cambian la priorización de parches?)

## Recomendación Estratégica
(1 párrafo para dirección/CISO: tendencia dominante, posicionamiento recomendado, qué vigilar en los próximos 7 días)

REGLAS: NO repitas detalles de los análisis especializados — el lector los tiene disponibles. Enfócate en CONEXIONES y PANORAMA GLOBAL. Si no hay correlaciones claras, indícalo honestamente."""


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
) -> str:
    """Genera el informe de una fase especializada (vuln / threat_intel / latam / general)."""
    SYSTEMS = {
        "vulnerability": VULN_SYSTEM_PROMPT,
        "threat_intel":  THREAT_SYSTEM_PROMPT,
        "latam":         LATAM_SYSTEM_PROMPT,
        "general":       GENERAL_SYSTEM_PROMPT,
    }
    BUILDERS = {
        "vulnerability": lambda: build_vuln_prompt(summaries, date_str, correlation, article_limit),
        "threat_intel":  lambda: build_threat_prompt(summaries, date_str, correlation, trending, article_limit),
        "latam":         lambda: build_latam_prompt(summaries, date_str, article_limit),
        "general":       lambda: build_general_prompt(summaries, date_str, article_limit),
    }
    if phase not in SYSTEMS:
        logger.warning(f"Fase desconocida '{phase}' — usando prompt general")
        phase = "general"

    system_prompt = SYSTEMS[phase]
    prompt        = BUILDERS[phase]()

    try:
        if provider == "ollama":
            import ollama
            client  = ollama.Client(host=ollama_host, timeout=timeout)
            options = _build_options(num_ctx, num_predict=max_tokens,
                                     temperature=0.3, num_threads=num_threads)
            stream  = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": prompt},
                ],
                think=thinking,
                options=options,
                stream=True,
            )
            tokens: list[str] = []
            total = 0
            last_chunk: dict = {}
            for chunk in stream:
                last_chunk = chunk
                token = chunk["message"]["content"]
                if token:
                    tokens.append(token)
                    total += 1
                    if total % 100 == 0:
                        logger.info(f"  [{phase}] Generando... {total} tokens")
            done_reason = last_chunk.get("done_reason", "stop")
            in_tok = last_chunk.get("prompt_eval_count", 0)
            _log_usage("ollama", in_tok, total, done_reason, max_tokens)
            logger.info(f"  [{phase}] Generado: {total} tokens (finish={done_reason})")
            return _strip_llm_output("".join(tokens))
        else:
            result = _llm_chat(
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
) -> str:
    """Stage 4: síntesis maestra cross-domain a partir de los outputs de las 4 fases."""
    prompt = build_synthesis_prompt(phase_outputs, date_str, total_articles, provider)
    try:
        result = _llm_chat(
            system=SYNTHESIS_SYSTEM_PROMPT,
            user=prompt,
            provider=provider,
            model=model,
            max_tokens=max_tokens,
            temperature=0.2,
            ollama_host=ollama_host,
            timeout=timeout,
            thinking=thinking,
            num_ctx=num_ctx,
            num_threads=num_threads,
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
) -> str:
    prompt = build_weekly_prompt(summaries, dates, week_label, language)

    try:
        result = _llm_chat(
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
        )
        logger.info(f"  Informe semanal generado ({provider})")
        return result
    except Exception as e:
        logger.error(f"Error generando informe semanal: {e}")
        return f"# Error al generar el informe semanal\n\n{e}"
