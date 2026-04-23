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
#   openai  → "gpt-4o-mini" / "gpt-4o"
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

# Formato de salida: "markdown", "html", o "both"
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
KEV_FETCH_TIMEOUT = 15   # segundos

# ─────────────────────────────────────────────
# REPORTES
# ─────────────────────────────────────────────

# Tokens máximos para Stage 3 (con think=False todos los tokens van al reporte)
# ~2500-3500 tokens para un informe normal; 6000 da margen en Patch Tuesday / días activos
REPORT_MAX_TOKENS = 6000

# True → genera vuln-briefing-* y threat-digest-* además del threat-briefing-* completo
SPLIT_REPORTS = True
