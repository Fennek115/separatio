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
from pathlib import Path

# Raíz del proyecto: el directorio que contiene este config.py.
# Las rutas de salida se anclan aquí para que el pipeline funcione igual sea
# cual sea el cwd (p.ej. ejecutado desde cron en otro directorio) — antes las
# rutas relativas dispersaban los reports y reseteaban history.json.
PROJECT_ROOT = Path(__file__).resolve().parent

# ─────────────────────────────────────────────
# LLM PROVIDER
# ─────────────────────────────────────────────
# Opciones: "ollama" | "claude" | "openai" | "gemini"
PROVIDER = "claude"

# Nombres de modelo según el proveedor elegido:
#   ollama  → "qwen3.5:4b" / "qwen3.5:9b"
#   claude  → "claude-haiku-4-5-20251001" / "claude-sonnet-5"
#   openai  → "gpt-4.1-mini" / "gpt-4.1"         ← recomendado: 200K TPM, 1M ctx; gpt-4o tiene 30K TPM (insuficiente con 120 arts)
#   gemini  → "gemini-2.0-flash" / "gemini-2.5-pro"

# API keys — lee de variable de entorno o edita directamente aquí
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")

# ─────────────────────────────────────────────
# MINIFLUX
# ─────────────────────────────────────────────
MINIFLUX_URL      = "http://192.168.1.7:8080"   # CT 112 (miniflux) — desde el laptop o cualquier CT
MINIFLUX_USERNAME = None
MINIFLUX_PASSWORD = None
# Auth por API token (Settings → API Keys en Miniflux). Vive en ~/Projects/Intel/.env;
# pipeline.py lo carga con load_dotenv() antes de importar este módulo.
MINIFLUX_API_TOKEN = os.getenv("MINIFLUX_API_TOKEN", "")

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
SUMMARY_MODEL = "claude-haiku-4-5-20251001"

# Etapa 3: informe consolidado (modelo de calidad, thinking=true)
REPORT_MODEL  = "claude-sonnet-5"

# Qwen3.5 soporta toggle de thinking. True = el modelo razona antes de responder.
# Etapa 2 → False (queremos JSON directo, sin overhead de razonamiento)
# Etapa 3 → True  (queremos que planifique el informe antes de escribirlo)
SUMMARY_THINKING = False
REPORT_THINKING  = False

# Workers paralelos para Etapa 2.
# Cloud providers procesan en paralelo sin problema → 8.
# Con CPU-only Ollama serializa las requests al mismo modelo aunque lleguen en paralelo:
# ahí PARALLEL_WORKERS=1 evita que el segundo worker agote su timeout esperando en cola.
PARALLEL_WORKERS = 8

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
ARTICLE_MAX_TOKENS = 2500

# Tokens máximos del JSON de salida por artículo en Stage 2.
# Ollama: 600 (ajustado a num_ctx=2048 — prompt+contenido+respuesta deben caber).
# Cloud:  900 — artículos largos (USN, Patch Tuesday) listan 50+ paquetes y se cortan con 600.
SUMMARY_MAX_TOKENS = 900

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
OUTPUT_DIR = str(PROJECT_ROOT / "reports")

# Formato de salida: "markdown" | "html" | "both" (md+html) | "pdf" | "all" (md+html+pdf)
OUTPUT_FORMAT = "both"

# Idioma del informe final
REPORT_LANGUAGE = "español"

# ─────────────────────────────────────────────
# TIMEOUTS Y REINTENTOS
# ─────────────────────────────────────────────
HTTP_TIMEOUT    = 15   # segundos para web scraping (por operación de socket)

# Tope TOTAL de reloj por fetch de artículo (Stage 1). HTTP_TIMEOUT no acota el
# tiempo total: un servidor que gotea bytes o un Retry-After grande (urllib3 lo
# respeta durmiendo) pueden colgar el run indefinidamente — visto 2026-08-08,
# 37 min dormido. Superado el tope, el fetch se abandona y el artículo cae al
# fallback del feed/título.
FETCH_HARD_TIMEOUT = 45

# Etapa 2: qwen3.5:4b sin thinking — ~2 min por artículo en i7-10510U
SUMMARY_TIMEOUT = 240

# Etapa 3: qwen3.5:9b — el primer chunk puede tardar 20-30 min mientras el modelo
# carga 7.2 GB en RAM en CPU-only. El timeout aplica ENTRE chunks, no al total.
REPORT_TIMEOUT  = 2400

MAX_RETRIES    = 2     # reintentos si falla la extracción de contenido

# Fail-fast de Stage 2: si esta fracción (o más) de los artículos falla al
# resumirse, el pipeline aborta en vez de generar un informe vacío en Stage 3.
# Protege contra fallos sistémicos (proveedor LLM caído, API key inválida).
STAGE2_FAIL_FAST_THRESHOLD = 0.5

# ─────────────────────────────────────────────
# CORRELATOR (Stage 2.5)
# ─────────────────────────────────────────────

# Dominios cuyas URLs bloquean el scraping (403 u otros).
# El extractor omite el fetch y usa el contenido del RSS directamente.
NO_SCRAPE_DOMAINS = {
    "vulners.com",
    "sploitus.com",
    "wiz.io",       # bloquea scrapers con 403
}

# CISA KEV — catálogo oficial de CVEs explotados activamente en producción.
CISA_KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL      = "https://api.first.org/data/v1/epss"
KEV_FETCH_TIMEOUT = 15   # segundos (aplica también al fetch de EPSS)

# ─────────────────────────────────────────────
# ENRICHMENT EXTERNO DE IOCs (Stage 2.7)
# ─────────────────────────────────────────────
# Capa de plugins que cruza los IOCs extraídos (IPs, dominios, URLs) contra
# fuentes externas de reputación. La etapa está envuelta en try/except en el
# pipeline: cualquier fallo se registra pero NO rompe el run.
ENRICHMENT_ENABLED = True

# Toggle por enricher.
#   ipsum / openphish → feeds planos sin API key (rápidos, deterministas)
#   ip_reputation     → consulta APIs vía la librería ipcheck (requiere keys
#                       en el entorno y respeta el rate-limit de VirusTotal:
#                       ~15s por IP que llega a Nivel 3 → lento). Off por defecto.
ENRICHERS = {
    "ipsum":          True,
    "openphish":      True,
    "ip_reputation":  True,
    "ransomware_live": True,
    "onion_lookup":   True,
}

IPSUM_URL       = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
IPSUM_MIN_SCORE = 3      # nº mínimo de listas públicas que reportan la IP
OPENPHISH_URL   = "https://openphish.com/feed.txt"

# ip_reputation (librería ipcheck, paquete del monorepo):
ENRICH_MAX_IPS  = 25     # tope de IPs consultadas por API (protege cuota)
ENRICH_VT_SLEEP = 15     # segundos entre IPs que alcanzan Nivel 3 (rate-limit VT)

# ransomware_live (leak sites vía Ransomware.live, clearnet — F2 del proyecto):
# UNA llamada por run; el free tier es 1 req/min por endpoint y sus ToS prohíben
# evadirlo con reintentos. Datos con atribución obligatoria ("Source:
# Ransomware.live") y sin uso comercial. Nunca guardar screenshot/claim_url.
RANSOMWARELIVE_URL        = "https://api.ransomware.live/v2/recentvictims"
RANSOMWARE_LOOKBACK_HOURS = 26   # ventana de "víctimas nuevas" (margen sobre 24h)
RANSOMWARE_MAX_VICTIMS    = 15   # tope de líneas que entran al prompt de síntesis

# onion_lookup (metadatos de .onion vía CIRCL/AIL, sin tocar Tor):
ONIONLOOKUP_URL = "https://onion.ail-project.org/api/lookup"
ONIONLOOKUP_MAX = 10     # tope de lookups por run (lo normal es 0 .onion/día)

# ─────────────────────────────────────────────
# HISTÓRICO Y TRENDING (Stage 2.6)
# ─────────────────────────────────────────────
# Archivo JSON con registro compacto por día (~200 bytes/día, ~73KB/año).
# El LLM solo recibe un bloque compacto de los últimos TREND_WINDOW_DAYS días.
HISTORY_FILE      = str(PROJECT_ROOT / "reports" / "history.json")
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
#   "vulnerability": "claude-sonnet-5",           "threat_intel": "claude-sonnet-5",
#   "latam":         "claude-haiku-4-5-20251001", "general":      "claude-haiku-4-5-20251001",
#   "synthesis":     "claude-opus-5"              # síntesis cross-domain se beneficia del modelo más potente
#
# Gemini:
#   "vulnerability": "gemini-2.5-pro",    "threat_intel": "gemini-2.5-pro",
#   "latam":         "gemini-2.0-flash",  "general":      "gemini-2.0-flash",
#   "synthesis":     "gemini-2.5-pro"
#
# Ollama GPU: dejar todos en None → usa REPORT_MODEL para todas las fases
PHASE_MODELS: dict = {
    "vulnerability": "claude-sonnet-5",
    "threat_intel":  "claude-sonnet-5",
    "latam":         "claude-haiku-4-5-20251001",
    "general":       "claude-haiku-4-5-20251001",
    "synthesis":     "claude-opus-5",
}

# Tokens máximos de salida por fase
# Ollama CPU: bajar ~40% (ver README para tabla completa por proveedor)
PHASE_MAX_TOKENS: dict = {
    # En Sonnet 5 / Opus 5 el thinking va activo por defecto y max_tokens tapa
    # thinking + texto: los valores viejos (4500/3000/1800/1500/2000, sin
    # thinking) truncaban el 100% de las fases. Con 9000/6000/3600 las fases
    # grandes seguían llenando el límite — estos valores ya no truncan.
    # No pasar de ~16000 sin streaming (timeout HTTP del SDK).
    "vulnerability": 16000,
    "threat_intel":  12000,
    "latam":         8000,
    "general":       3000,
    "synthesis":     4000,
}

# Máximo de artículos enviados al prompt de cada fase (top N por severidad)
PHASE_ARTICLE_LIMITS: dict = {
    "vulnerability": 50,
    "threat_intel":  35,
    "latam":         60,
    "general":       20,
}
