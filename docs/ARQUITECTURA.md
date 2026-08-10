# Central de intel — plan completo

Escrito el **2026-08-07**, revisado con todo lo verificado ese día contra el servidor, contra el
código de Separatio y contra fuentes externas. Reemplaza a la versión anterior de este archivo.

Ordena en una sola arquitectura: el pipeline **Separatio** (`~/Projects/Intel/threat intel`), la
librería **ipcheck**, el honeypot, las VMs de Oracle, Cloudflare, y las fuentes nuevas de leak sites.

Documentos hermanos: [`LABS-PLAN.md`](LABS-PLAN.md) (qué entra en este hardware),
[`HARDENING-PLAN.md`](HARDENING-PLAN.md) §1.4 (memoria y zram),
[`honeypot/PLAN.md`](honeypot/PLAN.md), [`redteam-lab-context/ESTADO-Y-REDISENO.md`](redteam-lab-context/ESTADO-Y-REDISENO.md).

---

## 1. Estado verificado

### Lo que existe y funciona

**Separatio es un proyecto serio.** Pipeline de 4 etapas + correlación determinista + histórico +
enriquecimiento pluggable, con tests, escritura atómica del historial, reintentos con backoff,
fail-fast, y salida a MD/HTML/PDF con Report ID y SHA-256 de integridad. Repo:
`github.com/Fennek115/separatio`.

**ipcheck es una librería importable** (`ip_enricher.py`), sin estado global, sin `load_dotenv` en
import. Consulta AbuseIPDB, VirusTotal, GreyNoise, OTX, URLhaus, ThreatFox y Shodan InternetDB.

### Lo que no corre

| Comprobación | Resultado |
|---|---|
| CT 111 (`ollama`) del README | **No existe** — `pct list` va 110 → 112 |
| CT del pipeline | **No existe**; `/opt/` en CT 112 vacío |
| Cron en CT 112 / en `thinkfox` | **Ninguno** |
| Última salida | `output-threatintel/2026-04-26/` — hace 3 meses |
| Tor local (el `.env` apunta a `127.0.0.1:9050`) | **Inactivo**, sin puerto SOCKS escuchando |

### Lo que está roto o desalineado (todo verificado)

**1. El trabajo de junio está sin commitear.** `enrichers/`, `enrichment.py`, `net.py`, `tests/` e
`IMPROVEMENTS.md` figuran como **untracked**, y hay 7 archivos modificados sin commit. El último
commit del repo (`9f5345e`) no los tiene. **Existe solo en el working tree de este laptop.**

**2. `config.py` está en un estado que no puede arrancar:**

```python
PROVIDER    = "ollama"
OLLAMA_HOST = "http://<IP_LXC_111>:11434"   # ← placeholder literal, sin reemplazar
MINIFLUX_URL = "http://localhost:8080"      # ← asume correr dentro del CT 112
PHASE_REPORTS = True                        # ← la doc dice False para Ollama CPU
ARTICLE_MAX_TOKENS = 800                    # ← tuning de Ollama; cloud quiere 2000-3000
PARALLEL_WORKERS = 1                        # ← ídem
```

**3. `ip_reputation` no podría funcionar aunque lo encendieras.** Cuatro desajustes:

| Problema | Detalle |
|---|---|
| Ruta muerta | `IPCHECK_DIR = "/home/dust115/projects/tools/ipcheck"` **no existe**. Real: `/home/dust/Projects/Intel/ipcheck`. El enricher aborta con *"Configura IPCHECK_DIR en config.py"* |
| Nombre de variable | `ipcheck` lee `ABUSECH_API_KEY`; el `.env` define `ABUSECH_AUTH_KEY` → auth de abuse.ch vacía **en silencio** |
| Clave faltante | `VIRUSTOTAL_API_KEY` no está en el `.env`, y `ipcheck` la consulta |
| Nadie carga el `.env` | `ipcheck` documenta que **no** llama a `load_dotenv` ("el caller decide"); Separatio usa `os.getenv` y no tiene `python-dotenv` en `requirements.txt` |

**4. El OPML nuevo no encaja con el ruteo de fases.** `feeds.opml` (editado hoy, **56 feeds**) usa
las categorías `Cibersecurity`, `Hacking`, `Threat Intel`, `Vulnerability`. Pero:

```python
PHASE_CATEGORY_MAP = {
    "threat_intel": ["Threat Intel", "Hacking & Research"],  # el OPML dice "Hacking"
    "latam":        ["LATAM"],                                # ya no existe en el OPML
}
```

Los feeds de `Hacking` caen al fallback `general`, donde reciben el prompt de *editor de noticias* en
vez del de *analista APT* y —lo grave— **la fase `general` no recibe `CorrelationContext` ni
`TrendingContext`**, así que pierden KEV, EPSS, correlación de CVEs y actores. La sección LATAM sale
vacía.

---

## 2. La tesis: no construir un cerebro, encender el que hay

El "cerebro CTI en Python + SQLite" que se discutió en otra conversación **ya existe en un 80 %**:

| Propuesta | Estado real en Separatio |
|---|---|
| Ingesta de CISA KEV | ✅ `correlator.py` Stage 2.5 |
| Scoring de explotabilidad | ✅ EPSS de FIRST.org, chunking de 400 CVEs |
| IPsum para cruzar IPs | ✅ `enrichers/ipsum.py`, sin API key |
| OTX / URLhaus / ThreatFox / GreyNoise / AbuseIPDB / VT / Shodan | ✅ `enrichers/ip_reputation.py` vía `ipcheck` — **apagado y roto**, ver §1 |
| Phishing | ✅ `enrichers/openphish.py` |
| Correlación entre fuentes | ✅ Determinista, **sin LLM** — CVEs/IOCs/actores en ≥2 fuentes |
| Histórico y tendencias | ✅ `history.py`, ventana de 14 días |
| Export para SIEM | ✅ `iocs-*.csv` y `.json` cada run |
| Alertas a Telegram | ❌ |
| Feeds de leak sites de ransomware | ❌ |
| **Ingesta del honeypot** | ❌ **El único agregado realmente nuevo** |

Y hay una razón de diseño para no migrar a MISP/OpenCTI/Yeti más allá de la RAM: **el correlator es
determinista**. No le pasa nada al LLM — es matching exacto de CVE, defang de IOCs y dedup de actores
por regex. Eso es más confiable que un grafo que hay que curar a mano.

### Arquitectura por capas

| Capa | Qué entra | Por dónde | Estado |
|---|---|---|---|
| Noticias y análisis | 40 feeds RSS curados | Miniflux (CT 112) → Stage 1 | ✅ |
| Correlación determinista | CISA KEV, EPSS, PoC signals | `correlator.py` | ✅ |
| Enriquecimiento de IOCs | IPsum, OpenPhish, ipcheck | `enrichers/` Stage 2.7 | ✅ arreglado en F0 (2026-08-08) |
| Leak sites de ransomware | Ransomware.live (+ onion-lookup CIRCL para `.onion`) | `enrichers/ransomware.py` y `onionlookup.py` — F2 | ✅ 2026-08-08. RansomLook quedó anotado como complemento futuro (puente `misp_uuid` → MispEnricher) |
| **Datos propios** | Honeypot (Cowrie + Nginx) | **enricher nuevo**, por *pull* | ❌ (F3) |
| Salida | MD/HTML/PDF + IOC CSV/JSON | `reporter.py` | ✅ |

Además de las capas del pipeline, desde F2 hay **dos MCP de investigación manual** (HIBP hosted y
AbuseIPDB por `uvx`) registrados en el `.mcp.json` de `~/Projects/Intel/` — solo existen al trabajar
en esa carpeta, nunca en el cron (§5.3).

**Regla:** los feeds de IOC crudos **no entran a Miniflux**. Miniflux es para prosa que va a leer un
LLM. Los indicadores entran por la capa de enriquecimiento, que es determinista.

---

## 3. Fase 0 — Rescatar y encender

Nada nuevo hasta que esto corra solo. El éxito de esta fase es **un reporte que aparece solo durante
dos semanas seguidas**, no un feature.

### 0.1 Commitear y empujar (primero que nada)

```bash
cd ~/Projects/Intel/"threat intel"
git add enrichers/ enrichment.py net.py tests/ requirements-dev.txt IMPROVEMENTS.md
git add CLAUDE.md README.md config.py correlator.py history.py miniflux_client.py pipeline.py
git status                 # revisar que .env, reports/ y __pycache__ NO entren
git commit -m "Add IOC enrichment layer (Stage 2.7), network retries, fail-fast and tests"
git push origin main
```

Comprobá el `.gitignore` antes: no debe subir `.env`, `reports/`, `output-threatintel/`,
`__pycache__/`, `.pytest_cache/`.

### 0.2 Decidir el proveedor de LLM: cloud

Ollama local queda descartado por evidencia propia y del host: son ~3.5 h por corrida en CPU, con
~7.2 GB de pico de RAM en un host de 16 GB que está sobrecomprometido al 99.8 %, y el CT 111 ya no
existe. La conclusión coincide con lo que ya observaste probándolo.

El código **ya es provider-agnostic**: es cambiar `PROVIDER` y los modelos. Al hacerlo, revisá que
los nombres de modelo estén vigentes — el README todavía menciona `claude-sonnet-4-6` y
`claude-opus-4-7`, que ya no son los actuales. Los modelos vigentes de Claude son **`claude-opus-5`**,
**`claude-sonnet-5`** y **`claude-haiku-4-5-20251001`**. Ruteo razonable por fase: Sonnet 5 para
`vulnerability` y `threat_intel`, Haiku 4.5 para `latam` y `general`, y el más fuerte para
`synthesis`.

Y subí lo que estaba bajado por Ollama: `ARTICLE_MAX_TOKENS` a 2000–3000 (captura listas de IOCs
completas), `PARALLEL_WORKERS` a 8, `PHASE_REPORTS = True`.

### 0.3 Arreglar el ruteo de categorías

Elegí una de las dos y aplicala antes de la primera corrida:

- **En Miniflux**: renombrar la categoría `Hacking` → `Hacking & Research` y crear `LATAM`.
- **En `config.py`**: cambiar el `PHASE_CATEGORY_MAP` a los nombres nuevos y decidir si la fase
  `latam` se elimina o se alimenta de otra categoría.

La segunda es más rápida; la primera conserva la fase LATAM, que era un diferenciador real del
informe.

### 0.4 Arreglar `ip_reputation`

```python
# config.py
IPCHECK_DIR = "/home/dust/Projects/Intel/ipcheck"
ENRICHERS = {"ipsum": True, "openphish": True, "ip_reputation": True}
```

Y resolver las claves. Lo más limpio es **un solo `.env` que cargue el pipeline**:

1. Mover `~/Projects/Intel/.env` a donde corra el pipeline, o apuntar a él con una variable.
2. Agregar `python-dotenv` a `requirements.txt` y un `load_dotenv()` **explícito en `pipeline.py`**
   (no en `config.py`, para no tener efectos en tiempo de import — respetá el criterio que ya tenía
   `ipcheck`).
3. Renombrar `ABUSECH_AUTH_KEY` → `ABUSECH_API_KEY`, **o** cambiar `ipcheck` para que lea el nombre
   que ya tenés. Una de las dos, no las dos.
4. Agregar `VIRUSTOTAL_API_KEY` si vas a usar VT — ojo que el free tier son 4 req/min y 500/día, y
   `ENRICH_VT_SLEEP=15` ya está puesto para respetarlo.

**Un aviso concreto sobre GreyNoise:** no emite API keys a dominios de correo gratuitos, y **Proton
está en su lista de bloqueo**. Con `franco.cchavarria@protonmail.com` no vas a poder registrarte. O
usás otro correo, o asumís que ese enricher queda sin clave (la API community igual da algo).

### 0.5 Correr y automatizar

```bash
python setup_check.py
python pipeline.py --dry-run          # valida los 56 feeds sin gastar tokens
python pipeline.py --limit 5          # end-to-end real
python pipeline.py                    # corrida completa
```

Después, cron. Con proveedor cloud son ~5 min por corrida, así que una diaria cubre todo:

```cron
0 7 * * *  cd /opt/threat-pipeline && ./venv/bin/python pipeline.py >> /var/log/threat-pipeline.log 2>&1
0 8 * * 1  cd /opt/threat-pipeline && ./venv/bin/python pipeline.py --weekly >> /var/log/threat-pipeline.log 2>&1
```

**Dónde correrlo:** un CT Debian chico (1 vCPU, 512 MB) es suficiente con proveedor cloud — ya no
hace falta el CT de 10 GB para Ollama. Si preferís no sumar contenedores dado el sobrecompromiso,
corre igual de bien en `thinkfox` con un timer de systemd, a costa de que el laptop tiene que estar
encendido a esa hora.

---

## 4. Fase 1 — El host, en paralelo

Estos son de `HARDENING-PLAN.md` y sostienen todo lo demás:

1. **zram** (§1.4) — hoy los 10 CTs tienen `swap: 512` sobre un host **sin swap**: 5 GiB ficticios.
   AdGuardHome ya murió por OOM dos veces.
2. **Bajar las cuotas sobredimensionadas** — karakeep 4096 M para usar 1052, actualbudget 2048 para 81.
3. **Proteger los servicios de PVE del OOM** (`OOMScoreAdjust=-900`).
4. **Backup del CT 103** — el subnet-router sigue fuera de todo job.
5. **Bajar `wg0`** y cerrar `PasswordAuthentication`.
6. **Quitar el `--delete`** del rsync quincenal de `nvme-data/cloud`.

---

## 5. Fase 2 — Fuentes nuevas

### 5.1 El veredicto sobre `badchars/darknet-mcp-server`: no lo uses

El repo es real (MIT, TypeScript, 302 estrellas, 66 tools sobre 16 fuentes) y su **intención es
legítima**: son las mismas fuentes que usa cualquier SOC — HIBP, IntelX, OTX, AbuseIPDB, abuse.ch,
GreyNoise, Pulsedive, Hudson Rock, Vulners, ransomware.live, RansomLook, PhishTank, CIRCL. No tiene
catálogo de mercados ni funcionalidad de compra; los leak sites los consulta de segunda mano por APIs
clearnet.

El problema es la ejecución y el abandono:

| Hallazgo | Verificado |
|---|---|
| **Abandonado a las ~8 horas** | 7 commits, todos entre el 2026-06-23 y el 24. Nada en `main` desde entonces |
| `tor_search_onion` **siempre devuelve `[]`** | Ahmia exige un token de formulario rotativo; el parser no encuentra nada y **devuelve lista vacía en vez de error** |
| `tor_fetch_onion` no soporta `https://` | El validador acepta `https:` pero el fetcher hardcodea `http.get` |
| Rate limiter de ransomware.live **errado por 120x** | El código asume 2 req/s; la API aplica **1 req/minuto** |
| El CLI documentado **no existe** | `npx darknet-mcp-server --tool …` cuelga; `main()` solo maneja `--help`, `--list`, `--check-tor` |
| El meta-tool **inventa nombres de tools** | Reporta `hibpBreaches`, `threatfoxIoc`… cuando los reales son `breachList`, `threatfoxGetIocs` |

**Lo descalificante es que falla en silencio**, que es la peor propiedad posible en una herramienta de
inteligencia: te dice "no hay nada" cuando la búsqueda nunca corrió. Sumale que correrlo implica
ejecutar código de un solo autor, sin revisión, **con todas tus API keys en el entorno del proceso**.

Riesgo aparte, y este es de criterio más que de código: los 2 tools que sí usan Tor meten hasta
50.000 caracteres de HTML crudo de un hidden service dentro del contexto del modelo, sin denylist ni
filtrado. Eso es un vector de **prompt injection** de manual — el contenido de un leak site
controlado por un actor criminal entrando como texto de confianza en tu agente.

### 5.2 Lo que sí: monitoreo de leak sites por clearnet

No necesitás Tor ni tocar leak sites directamente, que además es la postura correcta desde una IP
doméstica. Verificado en vivo el 2026-08-07:

| Fuente | API sin key | Estado | Uso |
|---|---|---|---|
| **[ransomware.live](https://www.ransomware.live) v2** | Sí | Activo, dato más nuevo `2026-08-07T16:30` | Base |
| **[RansomLook](https://www.ransomlook.io)** | Sí, 49 endpoints | Commit del **2026-08-06** | Complemento |
| [onion-lookup (CIRCL)](https://github.com/ail-project/onion-lookup) | Sí, sin restricciones | Activo | Enriquecimiento |
| **ransomwatch** | — | 🔴 **ARCHIVADO** | **No usar** |

⚠️ **Trampa con ransomwatch:** está archivado pero su `posts.json` **sigue devolviendo HTTP 200**, y
el registro más nuevo es del **2025-06-16**. Un monitor que solo mire el código de estado creería que
funciona mientras consume datos congelados hace 14 meses.

**Rate limits que importan:** ransomware.live v2 es gratis y sin key pero aplica **1 req/minuto por
endpoint, en serio** (segunda llamada consecutiva → 429). Hay un tier **PRO gratuito con registro**
(500.000 llamadas/mes). Si vas a hacer polling, pedí la key PRO — evadir el límite con reintentos es
justo lo que prohíben los ToS.

**Obligaciones que hay que respetar y son baratas:** atribución `"Source: Ransomware.live"` (su
licencia es no comercial con atribución). Y por GDPR: los feeds devuelven campos `screenshot` que
apuntan a capturas de leak sites con datos personales de víctimas — **guardá metadatos, no imágenes**,
y que el pipeline **nunca resuelva** los campos `claim_url` (.onion) ni `magnet`.

Encaja como un enricher más, y responde una pregunta buena: *¿alguna víctima publicada hoy es de mi
región o mi sector?*

**Dos enganches con cosas que ya tenés:**

- **ransomware.live sirve reglas YARA por grupo** en `/yara/<group>`. Ya escribiste una regla YARA a
  mano en el caso `ft-correction` ([`casos/ft-correction.md`](casos/ft-correction.md)); esto te da un
  corpus para el mismo flujo de detección sin escribirlas una por una.
- **RansomLook expone un campo `misp_uuid`** en sus perfiles de actores. `IMPROVEMENTS.md` §7 ya
  plantea un `MispEnricher` como "próximo paso natural" — si algún día montás MISP, ese campo es el
  puente directo, sin trabajo de reconciliación.

Y un detalle de criterio: RansomLook tiene en su código una función `_audit_torrent()` con el
comentario *"Record who accessed what, for LEA traceability"* — **auditan quién consulta sus
endpoints de torrent**. Quedate en los de lectura, que es lo único que necesitás.

### 5.3 MCP: cuándo sí y cuándo no

**Para el cron, llamá las APIs directo con `httpx`. MCP no aporta nada ahí.** El valor de MCP es que
un LLM elija qué tool invocar en runtime; si tu pipeline ya sabe qué endpoints consultar, MCP te
agrega un proceso Node por corrida (el servidor es stdio-only), un handshake JSON-RPC de discovery, y
respuestas que son JSON serializado *dentro de un campo de texto* que hay que volver a parsear.

**Para trabajo interactivo y exploratorio sí tiene sentido**, y ahí conviene quedarse con los
oficiales del vendor:

| Fuente | Servidor | Nota |
|---|---|---|
| **HIBP** | Hosted en `haveibeenpwned.com/mcp` | El más limpio: no instalás nada. Breaches públicos y Pwned Passwords **sin autenticación** |
| **AbuseIPDB** | `uvx mcp-server-abuseipdb` | Oficial, actualizado el 2026-08-03. Free tier: 1.000 checks/día |
| **VirusTotal** | [`google/mcp-security`](https://github.com/google/mcp-security) | Oficial de Google |
| **MISP** | [`MISP/misp-mcp`](https://github.com/MISP/misp-mcp) | Oficial, para cuando montes MISP |
| **Censys** | Hosted | 100 créditos/mes que expiran — un agente los quema en una sesión |

Evitá los wrappers de `pipeworx-io`: cubren muchas fuentes pero son v0.1.0 con 0 estrellas publicados
todos el mismo día, y su modo remoto hace pasar **tus API keys por su gateway**.

#### ☐ PENDIENTE (Fase 2) — Dos MCP oficiales para investigación manual

Hoy no hay **ningún** MCP configurado (`~/.claude.json` y `~/.claude/settings.json`: `mcpServers`
vacío; no hay `.mcp.json` en ningún proyecto). Partida limpia.

Esto **no toca el pipeline**: es para cuando estás vos sentado investigando un caso —como fue
`ft-correction`— y querés preguntar en lenguaje natural en vez de armar `curl`. Coste de
infraestructura: cero.

| Servidor | Cómo | Por qué este |
|---|---|---|
| **HIBP** | Hosted en `haveibeenpwned.com/mcp` — **no instalás nada** | Único vendor con entrada propia en el registry oficial (`io.github.troyhunt/hibp`). 17 tools; los de breaches públicos y Pwned Passwords andan **sin autenticación** |
| **AbuseIPDB** | `uvx mcp-server-abuseipdb` (efímero, no queda instalado) | Oficial del vendor, actualizado el 2026-08-03. **1.000 checks/día gratis** — el mejor tier del ecosistema. La key ya la tenés en el `.env` |

Se registran en un `.mcp.json` dentro de `~/Projects/Intel/`, no global — así solo existen cuando
trabajás en ese proyecto.

**Lo que no conviene sumar acá:** VirusTotal (4 req/min, 500/día — se agota en una sesión de agente),
Censys (100 créditos/mes que las llamadas MCP consumen), y GreyNoise, que directamente **no emite
API keys a Proton**, así que no es una opción para vos.

**Criterio general para no repetir el error del `darknet-mcp-server`:** un MCP server corre con tus
API keys en el entorno de su proceso. Usá solo servidores del vendor de la fuente, o escritos por
vos. Nunca un agregador de terceros que junte diez claves en un proceso que no auditaste.

---

## 6. Fase 3 — El honeypot y el dato propio

Esta es la pieza que convierte el proyecto de "otro agregador de feeds" en algo tuyo.

1. **Honeypot en Oracle VM1**, VCN propia, egress default-deny, catch-all Nginx (no T-Pot). Ver
   [`honeypot/PLAN.md`](honeypot/PLAN.md) y `LABS-PLAN.md` §2. Requiere haber bajado `wg0` antes.
2. **Recolección por *pull***: un cron en casa se conecta por SSH saliente y trae los logs con
   `rsync`. **El honeypot no guarda ninguna credencial ni URL que apunte a vos.** Si lo comprometen,
   no ganaron nada más que la máquina.
3. **`enrichers/honeypot.py`** — un archivo. La interfaz ya existe; del propio `CLAUDE.md` de
   Separatio: *"Add a source = new `enrichers/*.py` subclass + register in `build_enrichers()` +
   toggle in `config.ENRICHERS` (no pipeline/analyzer edits)."*

Responde dos preguntas que hoy nadie contesta:

- **¿Alguna IP, hash o dominio de las noticias de hoy me tocó a mí?** ← esto es lo que justifica todo
- ¿Los que me atacan aparecen en IPsum/GreyNoise, o son nuevos?

**Los logs vienen de una máquina hostil: se tratan como datos no confiables.** Parseo estricto, nada
de `eval`, y cuidado con el log injection en user-agent y URI — por eso `escape=json` en la config de
Nginx del plan del honeypot.

**Quick win previo (`IMPROVEMENTS.md` §6.5):** hoy `export_iocs` corre **antes** de Stage 2.7, así
que el veredicto de reputación no queda en el CSV/JSON de IOCs. Reordenarlo (o re-exportar) es barato
y hace el export mucho más útil para el cruce con el honeypot.

---

## 6.bis Fase 4 — Separatio expuesto como MCP server propio

☐ **PENDIENTE.** Esta es la integración de MCP que sí vale, y es **la inversión de todo lo anterior**:
no consumir MCP desde el pipeline, sino **servir tu propio corpus como MCP** para poder interrogarlo.

### Por qué acá sí paga y en el cron no

El valor de MCP es la descubribilidad dinámica: que un LLM lea `tools/list` y decida qué llamar. En
el cron eso vale cero porque ya sabés qué endpoints querés. Pero investigando **no sabés de antemano
qué vas a preguntar** — y ahí es exactamente donde el patrón encaja.

Hoy el corpus existe pero es inconsultable: son archivos por día en disco. Preguntas simples como
*"¿cuándo vi esta IP por primera vez?"* o *"¿qué actores aparecieron en el honeypot y en las noticias
el mismo día?"* requieren hoy grepear a mano por carpetas fechadas.

### Qué datos hay para exponer (todo ya se genera)

| Fuente | Contenido |
|---|---|
| `reports/YYYY-MM-DD/iocs/iocs-*.csv` y `.json` | Una fila por IOC único: `date, ioc, type, severity, title, feed, cves` |
| `reports/history.json` | Registro compacto diario (~200 B/día): actores, CVEs y tipos de amenaza. **Ya es una serie temporal** |
| `summaries-cache-YYYY-MM-DD.json` | `ArticleSummary` por artículo: `threat_type, severity, actors, CVEs, affected_systems, IOCs` |
| `output-threatintel/YYYY-MM-DD/reports/*.md` | Los informes en prosa |
| *(tras Fase 3)* logs del honeypot traídos por pull | El dato propio |

### Tools que tendría sentido exponer

```
buscar_ioc(valor)          → todas las apariciones: fecha, feed, severidad, CVEs asociados
primera_vez(ioc)           → fecha de primera observación en todo el corpus
actor_timeline(nombre)     → días en que apareció, CVEs y campañas asociadas
cve_contexto(cve)          → KEV, EPSS, fuentes que lo reportaron, fecha
cruce_honeypot(desde,hasta)→ IOCs de las noticias que además tocaron tu sensor   ← el que justifica todo
buscar_reporte(texto)      → búsqueda sobre los .md generados
```

`cruce_honeypot` es el que no puede darte ningún feed comprado.

### Cómo

**FastMCP, ~150 líneas, solo lectura.** Lee los mismos archivos que el pipeline escribe; no duplica
lógica ni toca el core. Transporte **stdio local**, registrado en el `.mcp.json` de
`~/Projects/Intel/` — **nunca expuesto a la red**.

Escribí primero las funciones de consulta como módulo Python normal (`queries.py`) y después
envolvelas en el MCP. Así te sirven igual para un CLI, para el reporte semanal o para cualquier
script, y el MCP queda como una fachada fina.

### Prerrequisito real: corpus

**No tiene sentido con tres informes.** Con dos semanas empieza a servir; con tres meses de historia
más datos del honeypot, es una herramienta de verdad. Por eso está en Fase 4 y no antes: depende de
que la Fase 0 lleve tiempo corriendo y, para el tool que más importa, de la Fase 3.

### ⚠️ El riesgo que hay que diseñar desde el principio

**Tras la Fase 3, tu corpus va a contener texto controlado por atacantes**: user-agents y URIs de los
logs del honeypot, notas de rescate y descripciones de leak sites. Un MCP server que sirva ese texto
crudo hacia un agente es un **vector de prompt injection de reentrada** — el mismo problema que le
señalé al `darknet-mcp-server`, pero autoinfligido.

Mitigaciones, que son baratas si se hacen desde el diseño:

- Exponer **campos normalizados y tipados**, no cuerpos crudos. Un IOC, una fecha, un nombre de actor
  — no el HTML ni el body del POST.
- **Truncar** todo campo de texto libre a un largo fijo.
- **Ningún tool que resuelva una URL** del corpus. Ni `claim_url`, ni `magnet`, ni la URI del log.
- Mantener el criterio que ya tenés en el pipeline: lo determinista (correlator, enrichers) nunca
  pasa datos crudos al modelo.

---

## 7. Riesgos transversales

### 7.1 La cuenta de Cloudflare (el más serio)

El wildcard `*.fennek.org` es Let's Encrypt de vida corta (~6 días) y lo renueva npmplus (CT 102)
**por DNS-01 con la API de Cloudflare**. Si esa misma cuenta se usa para el Worker + R2 que entrega
payloads de Sliver con fingerprinting de sandboxes, **un abuse report o una acción de TOS te tumba la
renovación del certificado**, y en menos de una semana se cae el HTTPS de todos tus servicios,
incluida la webUI de Proxmox.

Además `fennek.org` está registrado a tu nombre: atar entrega de payloads a la cuenta de tu dominio
personal viola tu propio principio de separación de capas.

**Regla: cuenta, dominio y registrante separados.** Y **comprobá dónde está hoy
`edgedeliverynodes.app`** — si comparte cuenta con `fennek.org`, el riesgo ya es presente.

> Alcance: la lógica de fingerprinting para evadir sandboxes y analistas es detección-evasión. Acá la
> trato solo como problema de aislamiento de cuentas, que es donde toca tu infraestructura personal.

### 7.2 Prompt injection desde fuentes hostiles

El pipeline mete texto de terceros en prompts. Con feeds RSS el riesgo es bajo. **Con logs de
honeypot y contenido de leak sites es alto**: son texto que un atacante controla. Mantené el patrón
que ya tenés —**el correlator y los enrichers son deterministas y nunca pasan datos al LLM**— y que
lo que llegue al prompt desde esas fuentes sean campos normalizados y acotados, no cuerpos crudos.

### 7.3 Legal y de datos

- **Atribución obligatoria** en ransomware.live (no comercial) y HIBP/Ransomfeed (CC BY 4.0).
- **GDPR**: guardá metadatos, nunca screenshots de víctimas. Retención definida.
- No resolver `claim_url` ni `magnet`.

---

## 8. Orden de ejecución, resumido

| # | Qué | Por qué ahora |
|---|---|---|
| 1 | `git commit` + `push` de Separatio | El trabajo de junio existe en un solo disco |
| 2 | zram + cuotas + `OOMScoreAdjust` | El host está al 99.8 % y ya hubo OOM |
| 3 | Backup del CT 103, bajar `wg0`, quitar el `--delete` | Pendientes de P1 que sostienen todo |
| 4 | Proveedor cloud + arreglar categorías + arreglar `ip_reputation` | Lo mínimo para que el pipeline corra |
| 5 | Cron y **dos semanas de corridas sin tocar nada** | La prueba de que funciona |
| 6 | Enricher de ransomware.live / RansomLook | Fuente nueva barata, sin Tor |
| 6.b | MCP de HIBP + AbuseIPDB para investigación manual (§5.3) | Coste cero, no toca el pipeline |
| 7 | Honeypot + `enrichers/honeypot.py` | El dato propio |
| 8 | Reordenar `export_iocs` (quick win) | Hace útil el cruce del paso 7 |
| 9 | **MCP propio sobre el corpus de Separatio** (§6.bis) | Requiere corpus: sin meses de historia no sirve |

**Aplazado a propósito:** SQLite/D1, alertas a Telegram, AIOCRIOC, WorldMonitor CII, MISP, feeds bulk
(FireHOL, jamesbrine), nodo Termux. Todos son razonables; ninguno vale nada hasta que el paso 5 esté
cumplido.

---

## 9. Qué no se pudo verificar

- Si `edgedeliverynodes.app` comparte cuenta de Cloudflare con `fennek.org`. **Comprobalo**: de eso
  depende si §7.1 es un riesgo futuro o presente.
- Si el pipeline llegó a correr con los enrichers de junio (la evidencia dice que no).
- Estado actual de las dos VMs de Oracle — la última verificación es del 2026-08-03.
- Rate limits oficiales de OTX (LevelBlue no los publica) y ToS del tier gratuito de Hudson Rock.
- Si el `.env` tiene claves válidas hoy: solo verifiqué que las variables estén definidas, no que las
  claves funcionen. `INTELX_API_KEY`, `PULSEDIVE_API_KEY` y `VULNERS_API_KEY` no las usa ningún
  enricher actual de Separatio — son del MCP.
