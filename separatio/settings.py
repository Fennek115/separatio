"""
settings.py — La configuración del pipeline, como un objeto inyectable.

Hasta F-G/G-2 esto vivía en `config.py` como constantes de módulo, y todo el
código las leía del global. Eso funciona en producción (hay una sola config)
pero hace los tests incómodos: para probar con otro valor hay que hacer
`monkeypatch.setattr(config, ...)`, y el patrón se había empezado a rodear a
mano —`hygiene.build_classifier(config=None)` con su helper `cfg(name, default)`
es de F-A, y F-B/F-C lo repitieron— precisamente porque no se podía inyectar.

Ahora la fuente de verdad es este `Settings`: un dataclass **congelado**, con
todos los valores por defecto, que se construye desde el entorno con
`Settings.from_env()` y se especializa con `.derive(...)`.

`config.py` sigue existiendo y sigue exponiendo cada nombre a nivel de módulo
(es una fachada sobre `Settings.from_env()`), así que los ~187 accesos del tipo
`config.MAX_ARTICLES` que había en el repo siguen funcionando sin tocarse, y el
`monkeypatch.setattr(config, ...)` de los tests también.

**Por qué los campos van en MAYÚSCULAS**, contra la costumbre de Python: hay dos
sitios que leen la config **por nombre dinámico** —`hygiene.build_classifier`
(`getattr(config, name, default)`) y `setup_check` (`getattr(config, key, "")`)—
así que renombrar a snake_case los rompería en silencio. Además mantiene el diff
del refactor en lo estructural y no en 187 renombres.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, Mapping

# Raíz del proyecto: el directorio que contiene este módulo.
# Las rutas de salida se anclan aquí para que el pipeline funcione igual sea
# cual sea el cwd (p.ej. ejecutado desde cron en otro directorio) — antes las
# rutas relativas dispersaban los reports y reseteaban history.json.
PROJECT_ROOT = Path(__file__).resolve().parent

# Raíz del MONOREPO (un nivel arriba del paquete): ahí viven `data/`, `tools/` y
# `tests/`, que no son del paquete `separatio` sino del repo.
REPO_ROOT = PROJECT_ROOT.parent

# El único feed de IPsum con score por línea (ver el comentario de IPSUM_URL).
# Se necesita como constante de módulo porque LOCAL_LISTS lo reusa en su default.
_IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"


def env_bool(name: str, default: bool, env: Mapping[str, str] | None = None) -> bool:
    """Toggle por entorno, para poder apagar algo en el CT sin editar código."""
    source = os.environ if env is None else env
    v = source.get(name)
    return default if v is None else v.strip().lower() not in ("0", "false", "no", "off", "")


@dataclass(frozen=True)
class Settings:
    """Configuración completa del pipeline. Inmutable: usar `.derive(...)`.

    Los valores por defecto de acá son los que corren en producción. Lo que
    puede venir del entorno lo aplica `from_env()`, no el default del campo,
    para que construir un `Settings()` a secas en un test sea determinista y no
    dependa de qué variables tenga puestas la máquina que corre los tests.
    """

    # ── Rutas ────────────────────────────────────────────────
    PROJECT_ROOT: Path = PROJECT_ROOT
    REPO_ROOT: Path = REPO_ROOT

    # ── LLM provider ─────────────────────────────────────────
    # Opciones: "ollama" | "claude" | "openai" | "gemini"
    PROVIDER: str = "claude"

    # API keys — las puebla `from_env()` desde el entorno (el `.env` lo carga el
    # entry point con load_dotenv antes de importar config).
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # ── Miniflux ─────────────────────────────────────────────
    MINIFLUX_URL: str = "http://192.168.1.7:8080"   # CT 112
    MINIFLUX_USERNAME: str | None = None
    MINIFLUX_PASSWORD: str | None = None
    MINIFLUX_API_TOKEN: str = ""

    MAX_ARTICLES: int = 120        # máximo de artículos por ejecución
    MARK_AS_READ: bool = True      # marcarlos como leídos tras procesarlos

    # ── Modelos ──────────────────────────────────────────────
    # Ollama es legacy: el CT 111 ya no existe.
    OLLAMA_HOST: str = "http://<IP_LXC_111>:11434"
    SUMMARY_MODEL: str = "claude-haiku-4-5-20251001"   # Stage 2: extracción JSON
    REPORT_MODEL: str = "claude-sonnet-5"              # Stage 3: informe

    # Qwen3.5 soporta toggle de thinking. Stage 2 → False (JSON directo).
    SUMMARY_THINKING: bool = False
    REPORT_THINKING: bool = False

    # Cloud providers procesan en paralelo sin problema → 8. Con CPU-only Ollama
    # hay que bajarlo a 1: serializa las requests y el 2º worker agota su timeout
    # esperando en cola.
    PARALLEL_WORKERS: int = 8

    SUMMARY_CTX: int = 2048
    REPORT_CTX: int = 16384
    OLLAMA_NUM_THREADS: int = 3    # referencial, se configura en el LXC

    # ── Filtros de contenido ─────────────────────────────────
    MIN_CONTENT_LENGTH: int = 200        # descartar artículos más cortos
    MIN_CVSS_FOR_HIGHLIGHT: float = 7.0

    # Tokens de contenido por artículo a Stage 2. Ollama (num_ctx=2048): ~800.
    # Cloud: 2000-3000 para capturar IOCs y TTPs del cuerpo completo.
    ARTICLE_MAX_TOKENS: int = 2500

    # Tokens del JSON de salida por artículo. Cloud: 900 — los artículos largos
    # (USN, Patch Tuesday) listan 50+ paquetes y se cortan con 600.
    SUMMARY_MAX_TOKENS: int = 900

    # Categorías del OPML a incluir (None = las 5).
    FEED_CATEGORIES: list[str] | None = None

    # Evita que feeds de alto volumen (MSRC ~2975, Black Hills ~909) monopolicen
    # el batch. None = sin límite por feed.
    PER_FEED_LIMIT: int | None = 10

    # ── Salida ───────────────────────────────────────────────
    OUTPUT_DIR: str = str(PROJECT_ROOT / "reports")

    # ── Observabilidad de la corrida (F-H — separatio/runlog.py) ──
    # El log estaba en append sin rotación: 188 KB creciendo, con todas las
    # corridas mezcladas. 5 MB × 5 acota el disco del CT (512 MiB).
    LOG_MAX_BYTES: int = 5_242_880
    LOG_BACKUP_COUNT: int = 5
    LOG_LEVEL: str = "INFO"

    # ── Topes de prompt (F-I) ────────────────────────────────
    # Los topes viejos venían de la era Ollama con num_ctx=2048. Con Sonnet 5 a
    # $3 por millón de entrada, 10.000 tokens extra por fase cuestan 3 centavos:
    # el tope ya no se justifica por costo, sólo si el informe empeora por ruido.
    # Lo que exceda se registra como recorte (F-H) y se declara en COBERTURA (F-I).
    PROMPT_CAPS: dict = field(default_factory=lambda: {
        "verdicts_per_source":  60,   # era 25 (ENRICH_PROMPT_MAX_PER_SOURCE)
        "iocs_per_article":     20,   # era 8  hardcodeado en analyzer.py
        "trending_actors":      12,   # era 8  hardcodeado en history.py
        "trending_new_actors":  12,   # era 8  hardcodeado en history.py
        "trending_cves":        10,   # era 6  hardcodeado en history.py
        "trending_deltas":       8,   # era 5  hardcodeado en history.py
    })

    # PHASE_ARTICLE_LIMITS no entra en PROMPT_CAPS a propósito: ese recorte sí es
    # sustantivo (50 artículos de vulns es un prompt distinto a 120) y ya se
    # declaraba en el prompt antes de F-I.

    # Esfuerzo de razonamiento por fase (`output_config.effort`). Sólo Sonnet 5 /
    # Opus 5 lo aceptan: **Haiku 4.5 devuelve 400 si se le pasa `effort`**, así
    # que Stage 2 y las fases latam/general quedan afuera.
    PHASE_EFFORT: dict = field(default_factory=lambda: {
        "vulnerability": "high",
        "threat_intel":  "high",
        "synthesis":     "high",
    })

    # Stage 2 pedía el JSON por prompt y reintentaba ante JSONDecodeError — cada
    # reintento es una llamada pagada de más. El reintento se conserva como red.
    STAGE2_STRUCTURED_OUTPUT: bool = True

    # "markdown" | "html" | "both" | "pdf" | "all"
    OUTPUT_FORMAT: str = "both"
    REPORT_LANGUAGE: str = "español"

    # ── Timeouts y reintentos ────────────────────────────────
    HTTP_TIMEOUT: int = 15    # por operación de socket

    # Tope TOTAL de reloj por fetch (Stage 1). HTTP_TIMEOUT no acota el total: un
    # servidor que gotea bytes o un Retry-After grande (urllib3 lo respeta
    # durmiendo) cuelgan el run — visto 2026-08-08, 37 min dormido.
    FETCH_HARD_TIMEOUT: int = 45

    SUMMARY_TIMEOUT: int = 240    # Stage 2
    REPORT_TIMEOUT: int = 2400    # Stage 3, ENTRE chunks del stream, no al total
    MAX_RETRIES: int = 2

    # Si esta fracción o más de los artículos falla al resumirse, el pipeline
    # aborta en vez de generar un informe vacío (proveedor caído, key inválida).
    STAGE2_FAIL_FAST_THRESHOLD: float = 0.5

    # ── Correlator (Stage 2.5) ───────────────────────────────
    # Dominios que bloquean el scraping: se usa el contenido del RSS directo.
    NO_SCRAPE_DOMAINS: set = field(default_factory=lambda: {
        "vulners.com",
        "sploitus.com",
        "wiz.io",       # bloquea scrapers con 403
    })

    CISA_KEV_URL: str = ("https://www.cisa.gov/sites/default/files/feeds/"
                         "known_exploited_vulnerabilities.json")
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    KEV_FETCH_TIMEOUT: int = 15   # aplica también al fetch de EPSS

    # ── Enrichment externo de IOCs (Stage 2.7) ───────────────
    # La etapa está envuelta en try/except en el pipeline: cualquier fallo se
    # registra pero NO rompe el run.
    ENRICHMENT_ENABLED: bool = True

    ENRICHERS: dict = field(default_factory=lambda: {
        "ipsum":          True,
        "openphish":      True,
        "ip_reputation":  True,
        "ransomware_live": True,
        "onion_lookup":   True,
        "honeypot":       False,   # F3: prender cuando el pull traiga dato real
        "malwarebazaar":  True,    # punto-5: ON (ABUSECH_API_KEY; no-op si falta)
        "honeypot_recon": True,    # F-C: ON desde 2026-08-10 (hay tráfico real)
    })

    # NO usar levels/3.txt acá: verificado por HTTP en F-E (2026-08-09) que esos
    # ficheros vienen sin score por línea — el plan de la fase asumía que sí y no
    # era así ("gana la máquina"). El score que necesita LocalLists.lookup() para
    # el detail de IPsum sólo existe en el agregado `ipsum.txt` (IP<TAB>score).
    IPSUM_URL: str = _IPSUM_URL
    IPSUM_MIN_SCORE: int = 3      # nº mínimo de listas públicas que la reportan
    OPENPHISH_URL: str = "https://openphish.com/feed.txt"

    # ip_reputation (librería ipcheck, paquete del monorepo):
    ENRICH_MAX_IPS: int = 25      # tope de IPs consultadas por API
    ENRICH_VT_SLEEP: int = 15     # segundos entre IPs de Nivel 3 (rate-limit VT)

    # ransomware_live: UNA llamada por run; el free tier es 1 req/min por endpoint
    # y sus ToS prohíben evadirlo con reintentos. Atribución obligatoria
    # ("Source: Ransomware.live"), sin uso comercial, nunca guardar
    # screenshot/claim_url.
    RANSOMWARELIVE_URL: str = "https://api.ransomware.live/v2/recentvictims"
    RANSOMWARE_LOOKBACK_HOURS: int = 26   # margen sobre 24h
    RANSOMWARE_MAX_VICTIMS: int = 15      # tope de líneas al prompt de síntesis

    # onion_lookup (metadatos de .onion vía CIRCL/AIL, sin tocar Tor):
    ONIONLOOKUP_URL: str = "https://onion.ail-project.org/api/lookup"
    ONIONLOOKUP_MAX: int = 10     # lo normal es 0 .onion/día

    # honeypot (dato propio, capa 4 — F3): lo alimenta tools/pull_honeypot.sh.
    HONEYPOT_DATA: str = str(REPO_ROOT / "data" / "honeypot" / "attackers.json")
    HONEYPOT_MAX_NOTES: int = 10

    # honeypot_recon (F-C): el enricher inverso — "esta IP me pegó, ¿es actor
    # conocido o ruido de internet?", sobre las IPs del store. GreyNoise sin API
    # key mide 25 consultas por SEMANA (cabecera x-ratelimit-limit, verificado
    # 2026-08-09; su doc dice "10/día" y no es así) y los 404 también consumen
    # cuota — de ahí el margen de 5.
    QUOTAS: dict = field(default_factory=lambda: {
        "greynoise":  {"limit": 20, "window": "week"},
        "virustotal": {"limit": 400, "window": "day"},
        "abuseipdb":  {"limit": 800, "window": "day"},
        "otx":        {"limit": 500, "window": "day"},
    })
    RECON_WINDOW_HOURS: int = 26   # margen sobre 24h
    RECON_MAX_ESCALATE: int = 5    # IPs que escalan a la cascada por corrida

    # reincidencia (F-D — separatio/store/queries.py): misma ventana que
    # TREND_WINDOW_DAYS, por coherencia del informe. HASSH_MIN_IPS=3: por debajo
    # es ruido de clientes SSH comunes (el OpenSSH de una distro popular comparte
    # HASSH entre usuarios legítimos sin relación entre sí).
    RECURRENCE_WINDOW_DAYS: int = 14
    HASSH_MIN_IPS: int = 3
    HASSH_WINDOW_DAYS: int = 30

    # TTL del cache de enrichment por fuente (`enrichment.expires_at`, F-B1).
    # GreyNoise coincide con su ventana de cuota; el resto no cambia en horas.
    ENRICH_TTL_DAYS: dict = field(default_factory=lambda: {
        "greynoise":  7,
        "abuseipdb":  30,
        "virustotal": 30,
        "otx":        30,
    })

    # ── Higiene de la entrada (F-A — separatio/hygiene.py) ───
    # Sin esto el dato propio es ruido propio: la primera corrida del colector
    # reportó como "atacante" al laptop del usuario. Dos categorías distintas:
    # las IPs propias se DESCARTAN (no son dato) y los escáneres de investigación
    # se ETIQUETAN (son dato, pero no son un ataque).

    # IPs/CIDR propias, separadas por coma. Va por entorno y NO acá porque el
    # repo es público y son la dirección de casa. En el CT: /etc/intel/intel.env.
    OWN_IPS: str = ""

    # La IP pública de casa es dinámica: una allowlist estática se pudre en
    # silencio y el dataset se vuelve a contaminar. Una petición por corrida la
    # mantiene sola; si falla se usa el último valor cacheado (fail-open).
    OWN_IP_RESOLVE: bool = True
    OWN_IP_RESOLVE_URL: str = "https://api.ipify.org"
    OWN_IP_RESOLVE_TIMEOUT: int = 5
    OWN_IP_CACHE: str = str(REPO_ROOT / "data" / "own_ips.auto")

    # Escáneres de investigación (Censys, Shodan, Shadowserver…): CIDR publicadas
    # + PTR. El PTR es el que no se pudre —dicen literalmente quiénes son— y
    # cuesta una consulta DNS por IP nueva, sin cuota.
    SCANNER_CLASSIFY: bool = True
    SCANNER_PTR_LOOKUP: bool = True
    SCANNER_PTR_TIMEOUT: int = 3     # segundos por PTR (thread daemon abandonado)
    SCANNER_PTR_MAX: int = 500       # tope de consultas por corrida

    # ── El store (F-B1 — separatio/store/) ───────────────────
    # SQLite y no Yeti/MISP: el CT 113 tiene 512 MiB (ArangoDB no entra), MISP
    # resuelve un problema de compartición que acá no existe, y sqlite3 es stdlib.
    # El toggle apaga el store entero: `open_store()` devuelve None y todo lo que
    # lo use sigue sin él — sirve para descartarlo como causa de un problema en
    # el CT sin editar código.
    STORE_ENABLED: bool = True
    STORE_PATH: str = str(REPO_ROOT / "data" / "archivo.db")
    STORE_RETENTION_DAYS: int = 180   # sólo se poda `observation`

    # ── Listas locales (F-E — separatio/lists.py) ────────────
    # El filtro gratis: pertenencia de IPs en cuatro blocklists agregadas, en
    # memoria (array('I') + bisect, 4 bytes por IP), para achicar el residuo
    # antes de que el enricher inverso (F-C) gaste las 25 consultas semanales de
    # GreyNoise. No es un Enricher.
    LOCAL_LISTS_ENABLED: bool = True
    FEED_CACHE_DIR: str = str(REPO_ROOT / "data" / "feeds")
    FEED_TTL_HOURS: int = 12   # vencida ⇒ redescarga; fallo de red ⇒ se usa igual
    LOCAL_LISTS: dict = field(default_factory=lambda: {
        # más se parece a nuestro sensor: SSH/Telnet/portscan de honeypots
        # reales, no reportes de terceros. TLP:White, no comercial.
        "jamesbrine":     "https://jamesbrine.com.au/iplist.txt",
        "ipsum":          _IPSUM_URL,   # el único con score por línea
        "firehol_tor":    ("https://raw.githubusercontent.com/firehol/"
                           "blocklist-ipsets/master/tor_exits.ipset"),
        "firehol_level1": ("https://raw.githubusercontent.com/firehol/"
                           "blocklist-ipsets/master/firehol_level1.netset"),
    })

    # malwarebazaar (abuse.ch): cruza hashes del día y marca la familia. Señal
    # fuerte si el hash ADEMÁS está en el corpus del honeypot propio. Auth-Key
    # UNIFICADA de abuse.ch (la misma que usa ipcheck para ThreatFox/URLhaus),
    # con FAILOVER: primaria ABUSECH_API_KEY, secundaria ABUSECH_API_KEY_2.
    MALWAREBAZAAR_URL: str = "https://mb-api.abuse.ch/api/v1/"
    MALWAREBAZAAR_AUTH_KEYS: list = field(default_factory=list)
    MALWAREBAZAAR_CORPUS: str = str(REPO_ROOT / "data" / "honeypot" / "hashes.log")
    MALWAREBAZAAR_MAX: int = 25   # tope de lookups por run

    # ── Histórico y trending (Stage 2.6) ─────────────────────
    # ~200 bytes/día, ~73 KB/año. El LLM sólo recibe un bloque compacto de los
    # últimos TREND_WINDOW_DAYS días, no el fichero entero.
    HISTORY_FILE: str = str(PROJECT_ROOT / "reports" / "history.json")
    TREND_WINDOW_DAYS: int = 14

    # ── Reportes ─────────────────────────────────────────────
    REPORT_MAX_TOKENS: int = 8000

    # Stage 3 recibe los top N por severidad; el resto está cubierto por el
    # bloque de pre-análisis estadístico. None = sin límite.
    REPORT_ARTICLE_LIMIT: int | None = 80

    # True → genera vuln-briefing-* y threat-digest-* además del completo
    SPLIT_REPORTS: bool = True

    # ── Multi-phase reports (Stage 3 → 4 fases + síntesis) ───
    # True  → 4 fases especializadas + Stage 4 síntesis cross-domain (cloud).
    # False → prompt único consolidado (legacy, Ollama CPU-only).
    PHASE_REPORTS: bool = True

    # Fase → categorías de Miniflux. Las no listadas caen a "general".
    # Agregar feeds nuevos no requiere tocar código: basta con que usen una
    # categoría ya mapeada, o agregar la categoría nueva a la fase deseada.
    PHASE_CATEGORY_MAP: dict = field(default_factory=lambda: {
        "vulnerability": ["Vulnerability"],
        "threat_intel":  ["Threat Intel", "Hacking & Research"],
        "latam":         ["LATAM"],
        "general":       ["Cibersecurity"],
    })

    # Modelo por fase. None → usa REPORT_MODEL como fallback.
    PHASE_MODELS: dict = field(default_factory=lambda: {
        "vulnerability": "claude-sonnet-5",
        "threat_intel":  "claude-sonnet-5",
        "latam":         "claude-haiku-4-5-20251001",
        "general":       "claude-haiku-4-5-20251001",
        "synthesis":     "claude-opus-5",   # se beneficia del modelo más potente
    })

    # En Sonnet 5 / Opus 5 el thinking va activo por defecto y max_tokens tapa
    # thinking + texto: los valores viejos (4500/3000/1800/1500/2000) truncaban
    # el 100% de las fases. No pasar de ~16000 sin streaming (timeout del SDK).
    PHASE_MAX_TOKENS: dict = field(default_factory=lambda: {
        "vulnerability": 16000,
        "threat_intel":  12000,
        "latam":         8000,
        "general":       3000,
        "synthesis":     4000,
    })

    # Artículos enviados al prompt de cada fase (top N por severidad)
    PHASE_ARTICLE_LIMITS: dict = field(default_factory=lambda: {
        "vulnerability": 50,
        "threat_intel":  35,
        "latam":         60,
        "general":       20,
    })

    # ── Construcción ─────────────────────────────────────────

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Los defaults de arriba, con lo que venga del entorno aplicado encima.

        `env` se puede inyectar (los tests le pasan un dict) en vez de leer
        `os.environ`. Sólo estos campos miran el entorno: son los que no pueden
        estar en el repo (claves, la IP de casa) más los toggles que existen para
        poder apagar algo en el CT sin editar código.
        """
        src: Mapping[str, str] = os.environ if env is None else env

        auth_keys = [k for k in (
            src.get("ABUSECH_API_KEY"),
            src.get("ABUSECH_API_KEY_2"),
            src.get("MALWAREBAZAAR_AUTH_KEY"),
        ) if k]

        return cls(
            ANTHROPIC_API_KEY=src.get("ANTHROPIC_API_KEY", ""),
            OPENAI_API_KEY=src.get("OPENAI_API_KEY", ""),
            GEMINI_API_KEY=src.get("GEMINI_API_KEY", ""),
            MINIFLUX_API_TOKEN=src.get("MINIFLUX_API_TOKEN", ""),
            OWN_IPS=src.get("OWN_IPS", ""),
            OWN_IP_RESOLVE=env_bool("OWN_IP_RESOLVE", True, src),
            SCANNER_CLASSIFY=env_bool("SCANNER_CLASSIFY", True, src),
            SCANNER_PTR_LOOKUP=env_bool("SCANNER_PTR_LOOKUP", True, src),
            STORE_ENABLED=env_bool("STORE_ENABLED", True, src),
            LOCAL_LISTS_ENABLED=env_bool("LOCAL_LISTS_ENABLED", True, src),
            # Mira el entorno desde el 2026-08-10, y entra en la definición de
            # arriba ("un toggle para apagar algo en el CT sin editar código"):
            # el CT publica los informes por copyparty y quiere PDF, el laptop
            # no. Hasta ese día el README lo documentaba como configurable y no
            # lo era, así que producción llevaba desde el principio sin generar
            # un solo PDF — el default "both" es md+html y `_write_pdf` no se
            # llamaba nunca. El default no se repite acá a propósito: sale del
            # campo de arriba, así no pueden divergir. Los valores válidos los
            # valida `reporter`, que es donde el logging ya está configurado.
            OUTPUT_FORMAT=src.get("OUTPUT_FORMAT", cls.OUTPUT_FORMAT),
            MALWAREBAZAAR_AUTH_KEYS=auth_keys,
        )

    def derive(self, **overrides: Any) -> "Settings":
        """Una copia con algunos campos cambiados.

        Es lo que reemplazó a mutar el módulo `config` en caliente: hasta G-2,
        `--dry-run` hacía `config.OUTPUT_DIR = .../dryrun` y `--categories` hacía
        `config.FEED_CATEGORIES = [...]`, con el efecto colateral de cambiárselo
        a todo el proceso.
        """
        unknown = set(overrides) - {f.name for f in fields(self)}
        if unknown:
            raise TypeError(f"Settings no tiene el campo/s: {sorted(unknown)}")
        return replace(self, **overrides)

    def as_dict(self) -> dict[str, Any]:
        """Los campos como dict — lo usa la fachada de `config.py`."""
        return {f.name: getattr(self, f.name) for f in fields(self)}
