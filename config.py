"""
config.py — Configuración central del pipeline de análisis de amenazas.
Edita este archivo antes de ejecutar el pipeline.

Infraestructura:
  - Proxmox host: i7-10510U (4C/8T), 15.3GB RAM total
  - LXC 111 (ollama):   4 cores, 10GB RAM  → IP a configurar
  - LXC 112 (miniflux): IP a configurar    → puerto 8080
  - Pipeline corre en LXC 112 (o en el host directamente)
"""

import os

# ─────────────────────────────────────────────
# LLM PROVIDER
# ─────────────────────────────────────────────
# Opciones: "ollama" | "claude" | "openai" | "gemini"
PROVIDER = "ollama"

# Nombres de modelo según el proveedor elegido:
#   ollama  → "qwen3.5:4b" / "qwen3.5:9b"
#   claude  → "claude-haiku-4-5-20251001" / "claude-sonnet-4-6"
#   openai  → "gpt-4.1-mini" / "gpt-4.1"         ← recomendado: 200K TPM, 1M ctx; gpt-4o tiene 30K TPM (insuficiente con 120 arts)
#   gemini  → "gemini-2.0-flash" / "gemini-2.5-pro"

# API keys — lee de variable de entorno o edita directamente aquí
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")

# ─────────────────────────────────────────────
# MINIFLUX
# ─────────────────────────────────────────────
MINIFLUX_URL      = "http://localhost:8080"   # Si pipeline corre en LXC 112
#MINIFLUX_URL     = "http://<IP_LXC_112>:8080"  # Si corre en otro lugar
MINIFLUX_USERNAME = "threat_user"
MINIFLUX_PASSWORD = "changeme"
# Recomendado: usar API token en vez de user/pass
# MINIFLUX_API_TOKEN = "tu-api-token"  # Settings → API Keys en Miniflux UI

# Máximo de artículos a procesar por ejecución
MAX_ARTICLES = 120

# Marcar artículos como leídos en Miniflux tras procesarlos
MARK_AS_READ = True

# ─────────────────────────────────────────────
# MODELOS OLLAMA
# Hardware: LXC 111 — 4 cores i7-10510U, 10GB RAM, CPU-only
#
# Modelo          Tamaño    RAM usada   Rol
# qwen3.5:4b      ~2.7 GB   ~3.2 GB     Etapa 2: extracción JSON rápida
# qwen3.5:9b      ~6.6 GB   ~7.2 GB     Etapa 3: síntesis y redacción
#
# Estrategia: swap secuencial — nunca cargados a la vez.
# Peak RAM: 7.2 GB → margen de ~2.8 GB dentro del LXC.
# ─────────────────────────────────────────────
OLLAMA_HOST = "http://<IP_LXC_111>:11434"  # ← Cambiar por IP real del LXC 111

# Etapa 2: extracción JSON por artículo (modelo rápido, thinking=false)
SUMMARY_MODEL = "qwen3.5:4b"

# Etapa 3: informe consolidado (modelo de calidad, thinking=true)
REPORT_MODEL  = "qwen3.5:9b"

# Qwen3.5 soporta toggle de thinking. True = el modelo razona antes de responder.
# Etapa 2 → False (queremos JSON directo, sin overhead de razonamiento)
# Etapa 3 → True  (queremos que planifique el informe antes de escribirlo)
SUMMARY_THINKING = False
REPORT_THINKING  = False

# Workers paralelos para Etapa 2.
# Con CPU-only Ollama serializa las requests al mismo modelo aunque lleguen en paralelo.
# PARALLEL_WORKERS=1 evita que el segundo worker agote su timeout esperando en cola.
# Subir a 2 solo si el LXC puede procesar requests en paralelo (GPU o Ollama concurrente).
PARALLEL_WORKERS = 1

# Contexto por etapa (optimiza uso de RAM del KV cache)
# Etapa 2: artículos de entrada son cortos, 2K tokens es suficiente
# Etapa 3: necesita ver todos los resúmenes del día, usar 16K
SUMMARY_CTX = 2048
REPORT_CTX  = 16384

# Threads de CPU para Ollama (configurar también en systemd override del LXC)
# 4 cores físicos en el LXC — dejar 1 para el OS del LXC
OLLAMA_NUM_THREADS = 3   # Referencial, se configura en el LXC directamente

# ─────────────────────────────────────────────
# FILTROS DE CONTENIDO
# ─────────────────────────────────────────────
MIN_CONTENT_LENGTH  = 200   # Descartar artículos con menos de N caracteres
MIN_CVSS_FOR_HIGHLIGHT = 7.0  # Solo resaltar CVEs con CVSS ≥ este valor

# Tokens máximos de contenido por artículo enviados a Stage 2.
# Con Ollama (num_ctx=2048): máx ~800 (prompt + contenido + respuesta JSON deben caber).
# Con cloud providers (OpenAI/Claude/Gemini): 2000-3000 para capturar IOCs y TTPs del cuerpo completo.
ARTICLE_MAX_TOKENS = 800

# Categorías del OPML a incluir (None = todas las 5 categorías)
# Opciones: "Cibersecurity", "Hacking & Research", "Threat Intel", "Vulnerability", "LATAM"
FEED_CATEGORIES = None

# Máximo de artículos a tomar por feed por ejecución.
# Evita que feeds de alto volumen (MSRC ~2975, Black Hills ~909) monopolicen el batch.
# None = sin límite por feed (solo aplica MAX_ARTICLES global).
PER_FEED_LIMIT = 10

# ─────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────
OUTPUT_DIR = "./reports"

# Formato de salida: "markdown" | "html" | "both" (md+html) | "pdf" | "all" (md+html+pdf)
OUTPUT_FORMAT = "both"

# Idioma del informe final
REPORT_LANGUAGE = "español"

# ─────────────────────────────────────────────
# TIMEOUTS Y REINTENTOS
# ─────────────────────────────────────────────
HTTP_TIMEOUT    = 15   # segundos para web scraping

# Etapa 2: qwen3.5:4b sin thinking — ~2 min por artículo en i7-10510U
SUMMARY_TIMEOUT = 240

# Etapa 3: qwen3.5:9b — el primer chunk puede tardar 20-30 min mientras el modelo
# carga 7.2 GB en RAM en CPU-only. El timeout aplica ENTRE chunks, no al total.
REPORT_TIMEOUT  = 2400

MAX_RETRIES    = 2     # reintentos si falla la extracción de contenido

# ─────────────────────────────────────────────
# CORRELATOR (Stage 2.5)
# ─────────────────────────────────────────────

# Dominios cuyas URLs bloquean el scraping (403 u otros).
# El extractor omite el fetch y usa el contenido del RSS directamente.
NO_SCRAPE_DOMAINS = {
    "vulners.com",
    "sploitus.com",
}

# CISA KEV — catálogo oficial de CVEs explotados activamente en producción.
CISA_KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL      = "https://api.first.org/data/v1/epss"
KEV_FETCH_TIMEOUT = 15   # segundos (aplica también al fetch de EPSS)

# ─────────────────────────────────────────────
# HISTÓRICO Y TRENDING (Stage 2.6)
# ─────────────────────────────────────────────
# Archivo JSON con registro compacto por día (~200 bytes/día, ~73KB/año).
# El LLM solo recibe un bloque compacto de los últimos TREND_WINDOW_DAYS días.
HISTORY_FILE      = "./reports/history.json"
TREND_WINDOW_DAYS = 14   # días de ventana para calcular tendencias

# ─────────────────────────────────────────────
# REPORTES
# ─────────────────────────────────────────────

# Tokens máximos para Stage 3.
# Con cloud providers (OpenAI/Claude/Gemini): 8000 da reportes detallados sin costo significativo.
# Con Ollama CPU-only: bajar a 3500-4000 para no exceder el tiempo de generación.
# Nota: gpt-4o en Tier 1 tiene 30K TPM — con 120 artículos el input ya son ~20K tokens,
#       más los output_tokens supera el límite. Usar gpt-4.1-mini (200K TPM) para Stage 3.
REPORT_MAX_TOKENS = 8000

# Máximo de artículos enviados al prompt de Stage 3.
# Stage 3 recibe los top N por severidad. Los artículos restantes están cubiertos
# por el bloque de pre-análisis estadístico (distribución de severidad, tipos, etc.).
# Con 80 artículos el input del prompt es ~15K tokens — manejable para cualquier provider.
# None = sin límite (usa todos los artículos del día).
REPORT_ARTICLE_LIMIT = 80

# True → genera vuln-briefing-* y threat-digest-* además del threat-briefing-* completo
SPLIT_REPORTS = True

# ─────────────────────────────────────────────
# MULTI-PHASE REPORTS (Stage 3 → 4 fases + síntesis maestra)
# ─────────────────────────────────────────────
# True  → 4 fases especializadas secuenciales (Vuln / Threat Intel / LATAM / General)
#          + Stage 4 síntesis cross-domain. Recomendado para cloud providers.
# False → prompt único consolidado (legacy, compatible con Ollama CPU-only)
PHASE_REPORTS = True

# Mapeo fase → categorías de Miniflux.
# Categorías no listadas → fase "general" por fallback automático.
# Agregar feeds nuevos en Miniflux no requiere tocar código:
# basta con que el feed use una categoría ya mapeada aquí,
# o agregar la categoría nueva a la fase deseada.
PHASE_CATEGORY_MAP = {
    "vulnerability": ["Vulnerability"],
    "threat_intel":  ["Threat Intel", "Hacking & Research"],
    "latam":         ["LATAM"],
    "general":       ["Cibersecurity"],
}

# Modelo por fase. None → usa REPORT_MODEL como fallback.
#
# OpenAI:
#   "vulnerability": "gpt-4.1",      "threat_intel": "gpt-4.1",
#   "latam":         "gpt-4.1-mini", "general":      "gpt-4.1-mini",
#   "synthesis":     "gpt-4.1"
#
# Claude:
#   "vulnerability": "claude-sonnet-4-6",        "threat_intel": "claude-sonnet-4-6",
#   "latam":         "claude-haiku-4-5-20251001", "general":      "claude-haiku-4-5-20251001",
#   "synthesis":     "claude-opus-4-7"            # síntesis cross-domain se beneficia del modelo más potente
#
# Gemini:
#   "vulnerability": "gemini-2.5-pro",    "threat_intel": "gemini-2.5-pro",
#   "latam":         "gemini-2.0-flash",  "general":      "gemini-2.0-flash",
#   "synthesis":     "gemini-2.5-pro"
#
# Ollama GPU: dejar todos en None → usa REPORT_MODEL para todas las fases
PHASE_MODELS: dict = {
    "vulnerability": None,
    "threat_intel":  None,
    "latam":         None,
    "general":       None,
    "synthesis":     None,
}

# Tokens máximos de salida por fase
PHASE_MAX_TOKENS: dict = {
    "vulnerability": 2500,
    "threat_intel":  2500,
    "latam":         1500,
    "general":       1000,
    "synthesis":     1500,
}

# Máximo de artículos enviados al prompt de cada fase (top N por severidad)
PHASE_ARTICLE_LIMITS: dict = {
    "vulnerability": 50,
    "threat_intel":  35,
    "latam":         60,
    "general":       20,
}
