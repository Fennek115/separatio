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
  "actors": ["lista de actores/grupos/países conocidos, vacío si no aplica"],
  "cves": ["lista de CVE-XXXX-XXXXX mencionados, vacío si no hay"],
  "affected_systems": ["sistemas/productos/sectores afectados"],
  "summary": "Análisis técnico en 4-5 oraciones en español: qué ocurrió, cómo funciona la técnica/vulnerabilidad (TTPs/MITRE), sistemas o sectores afectados, nivel de explotación activa, e impacto potencial.",
  "iocs": ["IPs, dominios, hashes SHA256/MD5, URLs o firmas de red mencionados explícitamente"]
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
                        correlation=None, trending=None) -> str:
    items = []
    for i, s in enumerate(summaries, 1):
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

    pre_analysis = _build_pre_analysis(summaries)

    correlation_block = ""
    if correlation is not None and correlation.has_signals():
        correlation_block = f"\n{correlation.format_for_prompt()}\n"

    trending_block = ""
    if trending is not None and trending.has_data():
        trending_block = f"\n{trending.format_for_prompt()}\n"

    return f"""Fecha del informe: {date_str}
Total de artículos analizados: {len(summaries)} de {unique_feeds} fuentes
{pre_analysis}
{correlation_block}{trending_block}
ARTÍCULOS ANALIZADOS:
{chr(10).join(items)}

---
Genera DOS informes separados en {language}. Usa EXACTAMENTE estos marcadores de sección:

===VULNERABILITY_BRIEFING===

# 🔒 Vulnerability Briefing — {date_str}

## Resumen de Vulnerabilidades
(3 párrafos: (1) panorama del día — total de CVEs, distribución de severidad, fuentes principales; (2) CVEs con explotación activa confirmada o alta probabilidad, con contexto de por qué son críticos; (3) urgencia de parcheo y ventana de exposición típica para estas vulnerabilidades)

## ⚠️ CVEs Críticos y Altos
(Tabla con TODOS los CVEs Críticos y Altos reales mencionados en los artículos. Columnas: Sistema Afectado | CVE | CVSS/Severidad | Explotabilidad | Vector de Ataque | Acción Inmediata)

## 🔬 Análisis Técnico de Vulnerabilidades Prioritarias
(Para cada CVE crítico: párrafo de 3-4 oraciones explicando el vector técnico de explotación, condiciones necesarias, impacto concreto si se explota, y si hay evidencia de explotación in-the-wild)

## 🔑 Parches Prioritarios
(Lista ordenada por urgencia. Para cada ítem: sistema, CVE, razón específica de prioridad, y enlace de referencia si está disponible en los datos)

===THREAT_INTEL_DIGEST===

# 🕵️ Threat Intelligence Digest — {date_str}

## Resumen Ejecutivo
(3-4 párrafos: (1) panorama general del día con nivel de alerta; (2) tendencias dominantes observadas en TTPs y tipos de amenaza; (3) actores más activos y sus objetivos; (4) recomendación estratégica para equipos de seguridad basada en los patrones del día)

## 🔴 Amenazas Críticas y Altas
(Por cada amenaza Crítica o Alta: párrafo con título en negrita, descripción técnica del ataque o campaña incluyendo TTPs/MITRE cuando aplique, sistemas o sectores objetivo, indicadores de compromiso disponibles, y nivel de madurez/sofisticación del actor)

## 👤 Actividad de Actores de Amenaza
(Por cada actor mencionado explícitamente: párrafo con nombre, atribución conocida (país/grupo), TTPs característicos observados en esta campaña, objetivos o víctimas reportadas, y nivel de confianza en la atribución)

## 🦠 Indicadores de Compromiso (IOCs)
(Si hay IOCs en los artículos: tabla o lista agrupada por tipo — IPs maliciosas | Dominios C2 | Hashes de malware | URLs de distribución. Solo IOCs explícitamente mencionados en las fuentes)

## 🌎 Contexto Regional LATAM
(Amenazas o incidentes con impacto en América Latina. Si los hay: detallar qué países, sectores afectados, y qué medidas tomar. Si no hay impacto directo, analizar qué amenazas del día tienen mayor probabilidad de propagarse a la región y por qué.)

## 📋 Resumen por Categoría
(Tabla: Categoría | Cantidad | Severidad Máxima | Tendencia vs. día típico)

## ✅ Acciones Recomendadas
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
                max_tokens=600,
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
) -> str:
    sorted_summaries = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    prompt = build_report_prompt(sorted_summaries, date_str, language, correlation, trending)

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
