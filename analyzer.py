"""
analyzer.py — Etapas 2 y 3 del pipeline.
  - Etapa 2: resumen estructurado de cada artículo (qwen3.5:4b, thinking=False)
  - Etapa 3: informe consolidado de threat intelligence (qwen3.5:9b, thinking=True)
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
import ollama

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

    # Campos extraídos por el modelo
    threat_type: str = ""
    severity: str = ""
    severity_score: int = 0
    actors: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    affected_systems: list[str] = field(default_factory=list)
    summary: str = ""
    iocs: list[str] = field(default_factory=list)
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────
# PROMPTS
# ─────────────────────────────────────────────────────────

SUMMARY_SYSTEM_PROMPT = """Eres un analista de ciberseguridad experto.
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
  "actors": ["lista de actores/grupos conocidos, vacío si no aplica"],
  "cves": ["lista de CVE-XXXX-XXXXX mencionados, vacío si no hay"],
  "affected_systems": ["sistemas/productos/sectores afectados"],
  "summary": "Resumen conciso en 2-3 oraciones en español sobre la amenaza o vulnerabilidad.",
  "iocs": ["IPs, dominios, hashes u otros IoCs si se mencionan explícitamente"]
}}"""


REPORT_SYSTEM_PROMPT = """Eres un analista senior de Cyber Threat Intelligence.
Redactas briefings ejecutivos de seguridad claros, precisos y accionables.
Escribe en español profesional."""

def build_report_prompt(summaries: list[ArticleSummary],
                        date_str: str, language: str = "español") -> str:
    items = []
    for i, s in enumerate(summaries, 1):
        cves_str     = ", ".join(s.cves) if s.cves else "ninguno"
        actors_str   = ", ".join(s.actors) if s.actors else "no identificados"
        affected_str = ", ".join(s.affected_systems[:3]) if s.affected_systems else "no especificado"
        items.append(
            f"[{i}] [{s.severity}] [{s.threat_type}]\n"
            f"    Título: {s.title}\n"
            f"    Fuente: {s.feed_title} ({s.feed_category})\n"
            f"    CVEs: {cves_str} | Actores: {actors_str} | Afectados: {affected_str}\n"
            f"    Resumen: {s.summary}"
        )

    return f"""Fecha del informe: {date_str}
Total de artículos analizados: {len(summaries)}

ARTÍCULOS ANALIZADOS:
{chr(10).join(items)}

---
Genera un INFORME DE INTELIGENCIA DE AMENAZAS completo en {language} con esta estructura exacta:

# 🛡️ Threat Intelligence Briefing — {date_str}

## Resumen Ejecutivo
(2-3 párrafos: panorama general del día, tendencias principales, nivel de alerta global)

## 🔴 Amenazas Críticas y Altas
(Lista detallada de los ítems con severidad Crítica o Alta, agrupados por tipo)

## 🟡 Vulnerabilidades Destacadas
(CVEs relevantes con sistema afectado, CVSS si se mencionó, y acción recomendada)

## 🕵️ Actividad de Actores de Amenaza
(Grupos APT, cibercriminales o hacktivistas con actividad reportada hoy)

## 🌎 Contexto Regional LATAM
(Mencionar específicamente cualquier amenaza o incidente que afecte a América Latina)

## 📋 Resumen por Categoría
(Tabla o lista: cuántos ítems por categoría — Ransomware, APT, CVEs, Phishing, etc.)

## ✅ Acciones Recomendadas
(3-5 acciones concretas y priorizadas para equipos de seguridad basadas en las amenazas del día)

---
*Fuentes: {len(summaries)} artículos de {len(set(s.feed_title for s in summaries))} feeds especializados*
"""


# ─────────────────────────────────────────────────────────
# FUNCIONES PRINCIPALES
# ─────────────────────────────────────────────────────────

def summarize_article(article_id: int, title: str, content: str,
                      feed_title: str, feed_category: str,
                      url: str, published_at: str,
                      model: str, ollama_host: str,
                      timeout: int = 180,
                      thinking: bool = False,
                      num_ctx: int = 2048) -> ArticleSummary:
    """
    Etapa 2: extracción JSON con qwen3.5:4b.

    thinking=False → responde directamente sin cadena de razonamiento.
    Correcto para extracción JSON repetitiva: más rápido y output más limpio.
    num_ctx=2048   → KV cache pequeño, ahorra RAM durante los resúmenes en paralelo.
    """
    summary = ArticleSummary(
        article_id=article_id,
        title=title,
        url=url,
        feed_title=feed_title,
        feed_category=feed_category,
        published_at=published_at,
    )

    prompt = build_summary_prompt(title, content, feed_title, feed_category)

    try:
        client = ollama.Client(host=ollama_host)

        options = {
            "temperature": 0.1,
            "num_predict": 400,
            "num_ctx": num_ctx,
        }
        # qwen3.5 acepta el parámetro "think" para desactivar el modo razonamiento
        if not thinking:
            options["think"] = False

        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SUMMARY_SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            options=options,
        )
        raw = response["message"]["content"].strip()

        # Limpiar bloques <think>...</think> por si el modelo los genera igual
        raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
        # Limpiar bloques markdown
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

        data = json.loads(raw)

        summary.threat_type      = data.get("threat_type", "Otro")
        summary.severity         = data.get("severity", "Informativa")
        summary.actors           = data.get("actors", [])
        summary.cves             = data.get("cves", [])
        summary.affected_systems = data.get("affected_systems", [])
        summary.summary          = data.get("summary", "")
        summary.iocs             = data.get("iocs", [])

        severity_map = {
            "Crítica": 5, "Critical": 5,
            "Alta": 4, "High": 4,
            "Media": 3, "Medium": 3,
            "Baja": 2, "Low": 2,
            "Informativa": 1, "Informational": 1,
        }
        summary.severity_score = severity_map.get(summary.severity, 1)

    except json.JSONDecodeError as e:
        logger.warning(f"JSON inválido para '{title[:50]}': {e}")
        summary.summary = f"Error de parsing: {raw[:200] if 'raw' in dir() else 'sin respuesta'}"
        summary.error = str(e)
    except Exception as e:
        logger.error(f"Error al resumir '{title[:50]}': {e}")
        summary.summary = title
        summary.error = str(e)

    return summary


def generate_report(summaries: list[ArticleSummary],
                    date_str: str,
                    model: str,
                    ollama_host: str,
                    language: str = "español",
                    timeout: int = 300,
                    thinking: bool = True,
                    num_ctx: int = 16384) -> str:
    """
    Etapa 3: informe consolidado con qwen3.5:9b.

    thinking=True  → el modelo razona internamente antes de redactar.
    Produce informes más coherentes, mejor priorización y síntesis.
    num_ctx=16384  → necesario para recibir todos los resúmenes del día.
    """
    sorted_summaries = sorted(summaries, key=lambda s: s.severity_score, reverse=True)
    prompt = build_report_prompt(sorted_summaries, date_str, language)

    try:
        client = ollama.Client(host=ollama_host)

        options = {
            "temperature": 0.3,
            "num_predict": 2000,
            "num_ctx": num_ctx,
        }
        if thinking:
            options["think"] = True

        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": REPORT_SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            options=options,
        )

        content = response["message"]["content"].strip()
        # Eliminar bloques <think> del output final (son internos del modelo)
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        return content

    except Exception as e:
        logger.error(f"Error generando informe: {e}")
        return f"# Error al generar el informe\n\n{e}"
