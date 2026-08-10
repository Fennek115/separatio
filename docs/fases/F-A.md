# F-A · Higiene de la entrada

> Estado: **☑ hecha el 2026-08-09** · Prerrequisito de todas las demás fases.
> Diseño: [`../PLAN-REWORK.md`](../PLAN-REWORK.md) §F-A · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)

## Objetivo

Que el dato propio deje de ser ruido propio: separar, **antes de gastar un byte de análisis**, lo
que somos nosotros mismos, lo que son escáneres de investigación, y lo que de verdad es
desconocido.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
venv/bin/python -c "from separatio.hygiene import IpClassifier; \
  print(IpClassifier(use_ptr=False).classify('162.142.125.7'))"   # → ('scanner', 'censys')
grep -c 'OWN_IPS' .env                                            # → 1
venv/bin/pytest tests/test_hygiene.py tests/test_honeypot_collector.py -q | tail -1
python3 -c "import json;print('hygiene' in json.load(open('data/honeypot/attackers.json')))"
#   → False mientras el colector no haya vuelto a correr con el código nuevo
```

## Contexto mínimo

La primera corrida del colector reportó como **atacante al laptop del propio usuario**: el 100 %
del dataset propio era ruido propio. Y en cuanto los honeypots se expongan, Shodan, Censys,
Shadowserver y los crawlers académicos van a ser una fracción enorme del tráfico.

Las dos categorías **no significan lo mismo y por eso no se tratan igual**:

- **IPs propias** → se descartan. No son dato.
- **Escáneres legítimos** → se **etiquetan**. Que Shadowserver te escanee es información válida;
  meterlo en `iocs.csv` como indicador de compromiso, no.

## Qué se hizo

### 1. El consolidador salió del heredoc

`tools/pull_honeypot.sh` tenía **270 líneas de Python dentro de un heredoc**: imposible de testear.
Se movieron **verbatim** a `separatio/honeypot_collector.py` (`consolidate(raw, out, window,
classifier=None)`), y el script quedó en **52 líneas**: los SSH y una llamada.

```bash
PYTHONPATH="$REPO_ROOT" "${PYTHON:-python3}" -m separatio.honeypot_collector "$RAW_DIR" "$OUT_DIR" "$WINDOW"
```

Sólo stdlib a propósito: el colector corre en el CT 113 con el `python3` del sistema, sin venv.

### 2. `separatio/hygiene.py` — el clasificador

`IpClassifier.classify(ip) → ("self" | "scanner" | "unknown", nombre)`, con dos clasificadores en
orden de coste:

| Clasificador | Cobertura | Nota |
|---|---|---|
| CIDR publicadas | **sólo Censys** (16 bloques /24) | Se buscaron las de Shadowserver, Rapid7 y ONYPHE: Shadowserver **no publica** IPs ni netblocks (sólo un correo de opt-out), Rapid7 Sonar corre en **EC2 con IPs no estáticas**. Medido el 2026-08-09 |
| PTR (rDNS) | 18 proyectos | **Es el que no se pudre**: el PTR dice literalmente quién es. Verificado en vivo: `162.142.125.1 → 1.125.142.162.censys-scanner.com`, `71.6.135.131 → soda.census.shodan.io`, `89.248.165.1 → recyber.net` |

El PTR corre **en un thread daemon con tope de reloj** (`SCANNER_PTR_TIMEOUT`, 3 s):
`socket.gethostbyaddr` no acepta timeout y resuelve por libc. Es el mismo patrón que
`extractor.fetch_url_content` — el proyecto ya se colgó 37 min por un fetch sin tope duro.

### 3. Las IPs propias se mantienen solas

La IP pública de casa es dinámica: una allowlist estática se pudre en silencio y el dataset se
vuelve a contaminar, que es exactamente el fallo que esta fase existe para evitar.

- `OWN_IPS` en el entorno (acepta IPs y CIDR) — **no** en el repo, que es público.
- Más `resolve_public_ip()`: **una** petición por corrida, 5 s de timeout, **fail-open hacia el
  último valor cacheado** en `data/own_ips.auto`. Seguir excluyendo la IP vieja es mucho menos malo
  que volver a contar el laptop como atacante.
- Apagable sin tocar código: `OWN_IP_RESOLVE=0` en el entorno.

### 4. Qué sale por cada clase

| Clase | `attackers.json` | `iocs.csv` | `events.jsonl` |
|---|---|---|---|
| `self` | **excluida**, sólo contada | no | **excluida** |
| `scanner` | `"class": "scanner"`, `"scanner_name": "censys"` | **no** — no es un IOC | sí (pasó, es dato) |
| `unknown` | `"class": "unknown"` | sí | sí |

Clave nueva de nivel superior:

```json
"hygiene": {"self_excluded": 1, "self_hits": 2, "self_ips": [...],
            "scanners": {"censys": ["..."]}, "unknown_ips": 0}
```

Y `enrichers/honeypot.py` **ya no emite el `IocVerdict` de señal fuerte para escáneres**: que
Censys te escanee y además salga en una noticia no es correlación, es el ruido de fondo de internet.

### 5. Rutas ancladas (hallazgo lateral)

`config.PROJECT_ROOT` es `separatio/`, no la raíz del repo — pero `HONEYPOT_DATA` y
`MALWAREBAZAAR_CORPUS` eran cadenas **relativas** (`"data/honeypot/…"`) que sólo resolvían si el
cwd era la raíz. Se agregó `REPO_ROOT` y ambas pasaron a absolutas.

## Criterio de hecho

**Una corrida del pull sobre datos con la IP del laptop la excluye, y un test lo fija con un
fixture.** ✅

## As-built — salida real (2026-08-09)

### Suite completa

```
$ venv/bin/pytest tests/ -q
73 passed in 4.70s
```

42 previos (intactos) + **31 nuevos** (`test_hygiene.py` 20, `test_honeypot_collector.py` 11).

### El refactor no cambió la salida

Con la higiene neutralizada (`OWN_IPS= OWN_IP_RESOLVE=0 SCANNER_CLASSIFY=0`), contra la salida del
script **antes** de tocarlo, sobre los mismos `raw/`:

```
  attackers.json idéntico al de antes del refactor: False
  iocs.csv idéntico: True
  events.jsonl idéntico: True

$ # única diferencia en attackers.json:
solo en el viejo: {}
solo en el nuevo: {'class': 'unknown'}
```

La única diferencia es el campo `class` que agrega esta fase. El movimiento fue equivalente.

### La higiene sobre el dato real del sensor

```
$ NO_PULL=1 OUT_DIR=<tmp> RAW_DIR=<raw del 2026-08-08> ./tools/pull_honeypot.sh 720
[pull] higiene: 1 IP(s) propia(s) descartada(s) (2 hits) · 0 escáner(es) etiquetado(s)
[pull] 0 IPs atacantes públicas (0 vistas por >1 sensor, 0 sin clasificar)

 hygiene: {"self_excluded": 1, "self_hits": 2, "self_ips": ["<redactada>"],
           "scanners": {}, "unknown_ips": 0}
 attackers: []
```

El único "atacante" que tenía el corpus era el laptop. Ahora el dataset queda **vacío**, que es la
respuesta correcta: no había ni un ataque real.

### La autoresolución funciona (y de más)

Se descubrió corriendo la verificación: con `OWN_IPS` vacío pero `OWN_IP_RESOLVE=1`, la corrida
**igual** excluyó al laptop, porque resolvió la IP pública en vivo. De ahí salió el toggle por
entorno — sin él no había forma de verificar el refactor de forma limpia.

### El pipeline sigue vivo

```
$ venv/bin/separatio-check
  ✅  Conexión Miniflux API  (usuario: threat_intel)
  ✅  Directorio de salida  (/home/dust/Projects/Intel/separatio/reports)
🎉 Todo listo.

$ venv/bin/separatio --dry-run --limit 5
  PIPELINE COMPLETADO ✓
  FULL_MARKDOWN: .../separatio/reports/dryrun/2026-08-09/reports/threat-briefing-2026-08-09.md
```

### Rutas, ya absolutas

```
REPO_ROOT       /home/dust/Projects/Intel
HONEYPOT_DATA   /home/dust/Projects/Intel/data/honeypot/attackers.json
MB_CORPUS       /home/dust/Projects/Intel/data/honeypot/hashes.log
OWN_IP_CACHE    /home/dust/Projects/Intel/data/own_ips.auto
```

### As-built del despliegue al CT 113 (2026-08-10)

`OWN_IPS` quedó en `/etc/intel/intel.env` (root:600, backup previo en
`intel.env.bak-preF-A`), con las **dos** IPs propias del `.env` del laptop. El colector ya corre
el código nuevo — salida literal de `systemctl start honeypot-pull.service`:

```
[pull] VM1 (Cowrie/Nginx/CrowdSec) desde ubuntu@… (ventana 24h)...
[pull] VM2 (Beelzebub, servicios golosos) desde ubuntu@…
[pull] higiene: 0 IP(s) propia(s) descartada(s) (0 hits) · 0 escáner(es) etiquetado(s)
[pull] 0 IPs atacantes públicas (0 vistas por >1 sensor, 0 sin clasificar)
[pull]   store: 0 IOCs nuevos, 0 observaciones nuevas, 0 payload(s) nuevo(s)
Result=success · ExecMainStatus=0 · 1.236s CPU, 17.6M memory peak
```

La línea `[pull] higiene:` es la prueba de que F-A está activa; la línea `[pull] store:` lo es de
F-B2. Los ceros son correctos: los honeypots **siguen sin exponer**, así que la ventana de 24 h no
trajo un solo atacante (`"attackers": []` en los dos snapshots de `by-date/`).

### ⚠️ Hallazgo del despliegue: `pytest` escribe en el store de producción

**El paso de verificación que este mismo documento pedía —`venv/bin/pytest tests/ -q` dentro de
`/opt/intel/app`— contaminó `data/archivo.db` con datos de fixture.** Se detectó porque el store del
CT apareció con 3 IOCs y 3 observaciones cuando los dos snapshots de disco tienen `attackers: []`:

```
ioc: 162.142.125.7 (scanner/censys) · 45.9.148.99 (unknown) · 45.9.148.52 (unknown)
observation: sensor 'vm1-web', service 'web', detail 'GET /.env'   ×3
```

Son literalmente las constantes de `tests/test_honeypot_collector.py` (`CENSYS`, `ATACANTE`,
`PROPIA`). La causa: desde F-B2, `consolidate()` escribe al store con
`store.db.store()` **sin parámetro de ruta**, así que resuelve al default
`REPO_ROOT/data/archivo.db`; los tests le pasan un `out` en `tmp_path` pero **no redirigen el
store**. Cada corrida de la suite acumula: el store del laptop tenía `times_seen` 50/57/42 y 150
observaciones de fixture, más un `hassh` llamado `abc123`.

**Consecuencia documental:** la verificación de F-C dice *"verificada con las 2 IPs candidatas
reales del store (`45.9.148.99`, `45.9.148.52`)"* — **no son reales, son fixtures**. Lo mismo vale
para cualquier conclusión sacada del store del laptop.

Se corrigió el store del CT reconstruyéndolo desde disco (invariante 3), con backup en
`data/archivo.db.bak-contaminado`:

```
$ rm data/archivo.db && python -m separatio.store.backfill
backfill: 2 carpeta(s), 0 IOC(s) nuevo(s), 0 observación(es) nueva(s), 1 payload(s) nuevo(s)
ioc 0 · observation 0 · payload 1 · enrichment 0 · meta schema_version=1
```

**El bug de código sigue abierto** (ver `../REWORK-ESTADO.md` §Bugs abiertos). Hasta que se
arregle: **no correr `pytest` dentro de `/opt/intel/app`**.

## Ficheros

**Nuevos:** `separatio/hygiene.py` · `separatio/honeypot_collector.py` · `tests/test_hygiene.py` ·
`tests/test_honeypot_collector.py`
**Modificados:** `tools/pull_honeypot.sh` (323→52 líneas) · `separatio/config.py` ·
`separatio/enrichers/honeypot.py` · `.env` · `.env.example`

## Pendientes que deja

### 1. Desplegar al CT 113 — ☑ **hecho el 2026-08-10** (ver as-built del despliegue, abajo)

Ojo con el paso de la variable: `honeypot-pull.service` corre con `User=intel` y
`EnvironmentFile=`, así que `OWN_IPS` tiene que estar en `/etc/intel/intel.env`, no en un `.env`
del clone (no hay).

### 2. `data/honeypot/` local sigue sucio

No se re-consolidó a propósito: hacerlo crearía un snapshot `by-date/2026-08-09/` a partir de logs
del 2026-08-08, que sería archivo falso. Se limpia solo en el próximo pull real tras el despliegue.

### 3. La lista de escáneres se pudre

`SCANNER_CIDRS` sólo cubre Censys y las CIDR rotan. El PTR compensa, pero conviene revisar la lista
cuando los honeypots estén expuestos y haya tráfico real de escáneres para contrastar — es la
primera vez que este código va a ver uno de verdad.

### 4. Fuga previa de IPs propias en el repo público

`tools/pull_honeypot.sh` traía la IP pública de casa **en claro** desde el commit `8a53bad`, en un
repo público. Se redactó en esta fase (queda en el historial de git, no se reescribió). Los
documentos nuevos usan `OWN_IPS` y no el literal.
