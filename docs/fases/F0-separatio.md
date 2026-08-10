# F0 — Rescatar y encender Separatio

**Estado:** ☐ Pendiente · **Prerrequisitos:** ninguno · **Bloquea:** F2, F4

> **Objetivo:** que el pipeline de threat intel produzca un informe solo, todos los días, durante dos
> semanas seguidas. Ese es el criterio de éxito — no un feature nuevo.

---

## ¿Ya está hecho?

```bash
# 1. ¿El trabajo está a salvo? (debe salir vacío)
git -C ~/Projects/Intel/"threat intel" status --short

# 2. ¿Hay salida reciente? (debe haber una carpeta de los últimos días)
ls -t ~/Projects/Intel/"threat intel"/output-threatintel/ | head -3

# 3. ¿Está automatizado?
crontab -l 2>/dev/null | grep -i pipeline
ssh proxmox 'pct exec 112 -- crontab -l 2>/dev/null | grep -i pipeline'

# 4. ¿El config puede arrancar? (PROVIDER no debe ser ollama con host placeholder)
grep -E "^PROVIDER|^OLLAMA_HOST|^IPCHECK_DIR" ~/Projects/Intel/"threat intel"/config.py
```

**Al 2026-08-07 (mañana):** git sucio con 5 archivos untracked, última salida `2026-04-26`, sin cron
en ningún lado, `PROVIDER = "ollama"` con `OLLAMA_HOST = "http://<IP_LXC_111>:11434"` (placeholder literal).

**Al 2026-08-07 (después):** **Pasos 1, 2 y 4 hechos.**
- Paso 1: commit `376b77d` empujado a `origin/main` (20 archivos, +1164). Se agregaron `.env` y
  `.claude/settings.local.json` al `.gitignore`. Identidad git del repo (local, no global):
  `dust <dust@thinkfox.localdomain>`, siguiendo el patrón del equipo anterior.
- Paso 2: `PROVIDER = "claude"` con los modelos vigentes, workers 8, tokens de cloud. Commit `3d6813d`.
- Paso 4: `IPCHECK_DIR` corregido, `ABUSECH_API_KEY` renombrado en el `.env`, `load_dotenv()` en
  `pipeline.py`, `python-dotenv` en requirements, los 3 enrichers encendidos. Venv creado en el repo
  con requirements + anthropic; los 14 tests de junio pasan. VT queda fuera (sin clave).
- Paso 3: **opción (a) aplicada.** En Miniflux (CT 112, `192.168.1.7:8080`): `Hacking` → `Hacking &
  Research` (id 7) y `LATAM` creada (id 63, **sin feeds todavía**). Se creó un API token
  `separatio-pipeline` (los feeds viven bajo `admin`; el `threat_user` del config no existía) y quedó
  como `MINIFLUX_API_TOKEN` en el `.env`. `config.py` apunta a la IP real y autentica por token —
  verificado con un GET a `/v1/categories` desde el laptop. Commit `32412b8`.
- Paso 5: **diferido por decisión del usuario.** Antes de elegir dónde corre quiere repensar la
  arquitectura de `~/Projects/Intel/` (unificar los repos, separar por módulos). El contexto quedó
  listo en el `CLAUDE.md` del repo de Separatio para trabajar desde esa carpeta.
- **Falta:** `ANTHROPIC_API_KEY` en `~/Projects/Intel/.env` (la tiene que poner el usuario),
  asignar feeds a `LATAM`, la decisión de arquitectura/dónde corre, y Paso 6 (correr y automatizar).

**Al 2026-08-08:** el rediseño de arquitectura (lo que difería el Paso 5) **se hizo**:
`~/Projects/Intel/` es ahora un monorepo (historia de Separatio preservada, ipcheck por subtree)
con paquetes `separatio` + `ipcheck`, entry points, un solo `.env` y 24 tests. Los feeds quedaron
verificados por API (40 feeds, 0 errores, LATAM con 6) y **hubo primera corrida real**:
`separatio/reports/2026-08-08/` con informe MD/HTML, IOCs e `history.json`. El detalle vivo está
en el `CLAUDE.md` de `~/Projects/Intel/` (incluye un incidente con el `--dry-run` viejo, ya
corregido, y un bug de cuelgue en Stage 1 sin timeout).
**Al 2026-08-08 (después):** push hecho, cuelgue de Stage 1 **arreglado** (`FETCH_HARD_TIMEOUT`
45s de reloj por fetch, con tests), y **Pasos 5 y 6 ejecutados**: el pipeline corre en el
**LXC 113 `intel`** de `motherbase` (Debian 13, 1 vCPU, 512 MiB, `192.168.1.55`, creado con el
helper de community-scripts en modo desatendido), timers systemd diario 07:00 + semanal lunes
08:00 con `Persistent=true`, código en `/opt/intel/app`, secretos en `/etc/intel/intel.env`
root:600. Verificación del despliegue: 28 tests, `separatio-check` bajo las condiciones del
service y `--dry-run --limit 5` — todo OK. Hubo timers en el laptop unas horas ese día; se
desmontaron (las pruebas van en contenedores). As-built y operación en
`~/Projects/Intel/docs/DEPLOY.md`; CT anotado en `../INVENTARIO.md`.
**Falta para cerrar F0:** key definitiva (una línea de `/etc/intel/intel.env`; el usuario la
pone al salir de pruebas), decidir si el 113 entra a los jobs de backup, y las **dos semanas de
corridas solas — ya corren** desde la primera corrida automática del CT.

---

## Contexto necesario

Separatio es un pipeline maduro —4 etapas, correlación determinista sin LLM, histórico de 14 días,
enriquecimiento pluggable, salida a MD/HTML/PDF con Report ID y SHA-256— que **corrió por última vez
en abril**. En junio se le agregó una capa entera de enriquecimiento con tests que **nunca se ejecutó
en producción**.

No hay que construir nada nuevo. Hay que rescatar el código, arreglar cuatro desajustes y encenderlo.

Detalle completo en [`../INTEL-ARQUITECTURA.md`](../INTEL-ARQUITECTURA.md) §1 y §3.

---

## Paso 1 — Commitear y empujar *(lo más urgente de todo el proyecto)*

Todo lo de junio existe **solo en el working tree de este laptop**: `enrichers/`, `enrichment.py`,
`net.py`, `tests/`, `requirements-dev.txt`, `IMPROVEMENTS.md`, más 7 archivos modificados. El último
commit del remoto (`9f5345e`) no los tiene.

```bash
cd ~/Projects/Intel/"threat intel"

cat .gitignore          # confirmar que ignora .env, reports/, output-threatintel/, __pycache__/
git status --short      # revisar la lista antes de agregar

git add enrichers/ enrichment.py net.py tests/ requirements-dev.txt IMPROVEMENTS.md
git add CLAUDE.md README.md config.py correlator.py history.py miniflux_client.py pipeline.py
git commit -m "Add IOC enrichment layer (Stage 2.7), network retries, fail-fast and tests"
git push origin main
```

⚠️ **Antes de `git add`, verificar que no entre ninguna clave.** El `.env` vive en
`~/Projects/Intel/.env` (fuera del repo), pero conviene mirar que `config.py` no tenga claves
hardcodeadas — el diseño es que se leen por `os.getenv()`.

---

## Paso 2 — Pasar a proveedor cloud

Ollama local queda descartado: ~3.5 h por corrida en CPU, ~7.2 GB de pico en un host de 16 GB
sobrecomprometido, y el CT 111 ya no existe. El usuario ya lo probó y llegó a la misma conclusión.

El código **ya es provider-agnostic**. En `config.py`:

```python
PROVIDER           = "claude"          # o "openai" / "gemini"
SUMMARY_MODEL      = "claude-haiku-4-5-20251001"
REPORT_MODEL       = "claude-sonnet-5"
ARTICLE_MAX_TOKENS = 2500              # estaba en 800 por Ollama
PARALLEL_WORKERS   = 8                 # estaba en 1 por Ollama
PHASE_REPORTS      = True

PHASE_MODELS = {
    "vulnerability": "claude-sonnet-5",
    "threat_intel":  "claude-sonnet-5",
    "latam":         "claude-haiku-4-5-20251001",
    "general":       "claude-haiku-4-5-20251001",
    "synthesis":     "claude-opus-5",
}
```

⚠️ **El README y los comentarios de `config.py` traen nombres de modelo viejos** (`claude-sonnet-4-6`,
`claude-opus-4-7`). Los vigentes son **`claude-opus-5`**, **`claude-sonnet-5`** y
**`claude-haiku-4-5-20251001`**. Actualizar también los comentarios para no volver a tropezar.

La clave se exporta como `ANTHROPIC_API_KEY` — `config.py` la lee con `os.getenv()`.

---

## Paso 3 — Arreglar el ruteo de categorías

`feeds.opml` (editado el 2026-08-07, **56 feeds**) usa `Cibersecurity`, `Hacking`, `Threat Intel`,
`Vulnerability`. Pero `PHASE_CATEGORY_MAP` espera `"Hacking & Research"` y `"LATAM"`.

**Consecuencia si no se arregla:** los feeds de `Hacking` caen al fallback `general`, donde reciben el
prompt de *editor de noticias* en vez del de *analista APT* y —lo grave— **la fase `general` no
recibe `CorrelationContext` ni `TrendingContext`**, así que pierden KEV, EPSS y correlación de
actores. La sección LATAM sale vacía.

Elegir **una**:

- **(a) En Miniflux:** renombrar la categoría `Hacking` → `Hacking & Research` y crear `LATAM`.
  Conserva la fase LATAM, que era un diferenciador real del informe.
- **(b) En `config.py`:** ajustar `PHASE_CATEGORY_MAP` a los nombres nuevos y decidir si la fase
  `latam` se elimina. Más rápido.

---

## Paso 4 — Arreglar `ip_reputation`

Está apagado, y **no funcionaría aunque se encendiera**. Cuatro desajustes encadenados:

| Problema | Arreglo |
|---|---|
| `IPCHECK_DIR = "/home/dust115/projects/tools/ipcheck"` **no existe** → el enricher aborta al importar | `IPCHECK_DIR = "/home/dust/Projects/Intel/ipcheck"` |
| `ipcheck` lee `ABUSECH_API_KEY`; el `.env` define `ABUSECH_AUTH_KEY` → auth vacía **en silencio** | Renombrar en el `.env` **o** en `ipcheck`. Una sola de las dos |
| `VIRUSTOTAL_API_KEY` no está en el `.env` y `ipcheck` la consulta | Agregarla, o asumir que VT queda fuera |
| **Nadie carga el `.env`** — `ipcheck` documenta que no llama a `load_dotenv`; Separatio usa `os.getenv` sin `python-dotenv` | Agregar `python-dotenv` a `requirements.txt` y un `load_dotenv()` **explícito en `pipeline.py`**, no en `config.py` (evita efectos en tiempo de import — es el criterio que ya tenía `ipcheck`) |

Y encender:

```python
ENRICHERS = {"ipsum": True, "openphish": True, "ip_reputation": True}
```

**Aviso sobre GreyNoise:** no emite API keys a dominios de correo gratuitos, y **Proton está en su
lista de bloqueo**. Con `franco.cchavarria@protonmail.com` no se puede registrar. O se usa otro
correo, o ese enricher queda sin clave.

**Sobre VirusTotal:** free tier son 4 req/min y 500/día. `ENRICH_VT_SLEEP = 15` y
`ENRICH_MAX_IPS = 25` ya están puestos para respetarlo — no subirlos.

---

## Paso 5 — Decidir dónde corre

Con proveedor cloud una corrida son ~5 min, así que ya no hace falta el CT de 10 GB para Ollama.

| Opción | A favor | En contra |
|---|---|---|
| **CT Debian nuevo (1 vCPU, 512 MB)** | Corre solo, no depende del laptop | Suma un CT a un host sobrecomprometido al 99.8% — hacer **después de F1** |
| **En `thinkfox` con timer de systemd** | Cero impacto en el servidor | El laptop tiene que estar encendido a esa hora |

Si se elige el CT, `MINIFLUX_URL` apunta a la IP del CT 112. Si se elige el laptop, también (no
`localhost`, que es lo que dice hoy el config).

---

## Paso 6 — Correr y automatizar

```bash
python setup_check.py                 # diagnóstico: provider, claves, Miniflux
python pipeline.py --dry-run          # valida los 56 feeds sin gastar tokens
python pipeline.py --limit 5          # end-to-end real, barato
python pipeline.py                    # corrida completa
```

Después el cron (~5 min por corrida con cloud, todas las categorías en una):

```cron
0 7 * * *  cd /opt/threat-pipeline && ./venv/bin/python pipeline.py >> /var/log/threat-pipeline.log 2>&1
0 8 * * 1  cd /opt/threat-pipeline && ./venv/bin/python pipeline.py --weekly >> /var/log/threat-pipeline.log 2>&1
```

---

## Verificación

- [ ] `git status --short` sale vacío y el remoto tiene los commits
- [ ] `python setup_check.py` pasa sin errores
- [ ] Se genera `output-threatintel/YYYY-MM-DD/` con el PDF, los `.md`/`.html` y los `iocs-*.csv/json`
- [ ] En el log de la corrida aparece Stage 2.7 con los tres enrichers activos
- [ ] La sección LATAM del informe **no** está vacía (si se eligió la opción (a) del paso 3)
- [ ] `reports/history.json` crece un registro por día

**El criterio real de cierre de F0: dos semanas de informes generados solos, sin intervención.**

---

## Al terminar

1. Marcar F0 como ☑ en [`../ESTADO.md`](../ESTADO.md) y acá arriba.
2. Actualizar el `README.md` de Separatio: el CT 111 de Ollama ya no existe y la sección de
   infraestructura describe algo que no está.
3. Anotar en [`../INVENTARIO.md`](../INVENTARIO.md) el CT nuevo si se creó uno.
4. F2 y F4 quedan desbloqueadas.
