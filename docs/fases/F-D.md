# F-D · Memoria temporal: reincidencia

> Estado: **☑ código y tests hechos el 2026-08-09 — verificación en vivo pendiente (sin tráfico SSH)** · Depende de: **F-C** (y por tanto F-B1/F-B2)
> Diseño: [`../PLAN-REWORK.md`](../PLAN-REWORK.md) §F-D · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Completamente especificada. Ejecutar y documentar.**

## Objetivo

Convertir datos en conocimiento: poder afirmar **"esta IP volvió 5 de los últimos 14 días"**, que
es la diferencia entre escaneo de fondo y alguien que insiste.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
q() { [ -s data/archivo.db ] && sqlite3 data/archivo.db "$1" || echo "→ sin store"; }

q "select value, kind, days_seen, times_seen from ioc order by days_seen desc limit 10"
q "select count(*) from ioc where days_seen >= 2"
q "select count(*) from ioc where kind='hassh'"
grep -rn "reincident\|days_seen" separatio/enrichers/ 2>/dev/null
grep -rln "volvió\|reincidente" separatio/reports/*/reports/*.md 2>/dev/null | tail -3
```

## Contexto mínimo

Con el store poblado esto es **casi gratis**: `days_seen` ya lo mantiene la ingesta de F-B2 y el
HASSH ya entra como IOC propio. Esta fase es sobre todo **consultas y redacción**: convertir filas
en frases que el LLM pueda usar.

Tres afirmaciones nuevas, y la tercera es la que ninguna fuente externa puede dar.

## Pasos

### 1. `separatio/store/queries.py` — las consultas, literales

```python
def ip_recurrence(conn, ip: str, window_days: int = 14) -> dict | None:
    """{'days_seen': 5, 'window_days': 14, 'first_seen': '...', 'times_seen': 41}"""
```
```sql
SELECT i.value, i.first_seen, i.times_seen,
       COUNT(DISTINCT substr(o.ts, 1, 10)) AS days_in_window
  FROM ioc i JOIN observation o ON o.ioc = i.value
 WHERE i.value = ?
   AND o.ts >= datetime('now', ?)        -- p.ej. '-14 day'
 GROUP BY i.value;
```

```python
def payload_history(conn, sha256: str) -> dict | None:
    """{'first_seen': '2026-07-02', 'times_seen': 4, 'family': 'Mirai'}"""
```
```sql
SELECT sha256, first_seen, last_seen, times_seen, family, yara_hits
  FROM payload WHERE sha256 = ?;
```

```python
def hassh_fanout(conn, min_ips: int = 2, window_days: int = 30) -> list[dict]:
    """[{'hassh': 'xx', 'ips': ['1.2.3.4', ...], 'n_ips': 12, 'days_seen': 6}]"""
```
```sql
SELECT h.value AS hassh,
       COUNT(DISTINCT o.action) AS n_ips,
       h.days_seen,
       GROUP_CONCAT(DISTINCT o.action) AS ips
  FROM ioc h JOIN observation o ON o.ioc = h.value
 WHERE h.kind = 'hassh'
   AND o.ts >= datetime('now', ?)
 GROUP BY h.value
HAVING n_ips >= ?
 ORDER BY n_ips DESC;
```

> El `action` de las observaciones de HASSH es `"from <ip>"` — así lo escribe la ingesta de F-B2.
> Si en F-B2 se eligió otro formato, esta consulta se ajusta y **se anota en el as-built**.

```python
def top_recurrent(conn, limit: int = 10, window_days: int = 14) -> list[dict]:
    """Las IPs más reincidentes de la ventana. Alimenta la nota de contexto."""
```

### 2. Extender `enrichers/honeypot_recon.py`

Tres puntos de inserción, todos sobre lo que F-C ya construyó:

- **Prioridad del residuo:** `days_seen` ya era el primer criterio de orden en F-C. Acá pasa a
  usar `ip_recurrence()` en vez del campo plano, para contar dentro de la ventana.
- **Detalle de los veredictos:** el `IocVerdict` de señal fuerte suma la reincidencia al `detail`:

  ```
  "volvió 5 de los últimos 14 días; no figura en ninguna blocklist;
   GreyNoise no la ve escanear internet"
  ```

  Ese enunciado es, literalmente, el criterio de cierre del rework.
- **Notas nuevas**, una por tipo de reincidencia:

  ```python
  ctx.add_note(self.name, "IP reincidente: 190.x.x.x volvió 5 de los últimos 14 días (41 hits)")
  ctx.add_note(self.name, "payload ya conocido: 3fa2… desde el 2026-07-02, visto 4 veces")
  ctx.add_note(self.name, "HASSH b4f1… visto desde 12 IPs distintas en 30 días "
                          "— mismo cliente SSH, huella de botnet")
  ```

### 3. El HASSH es la pieza propia

Es el fingerprint del cliente SSH — el "JA3" del SSH — y es **robusto al cambio de IP**. El
colector ya lo extrae de los eventos de kex de Cowrie (`honeypot_collector.py`, sección VM1
Cowrie) y lo exporta a `iocs.csv` como `hassh-md5`, pero **nadie lo correlaciona**.

Un mismo HASSH desde 40 IPs distintas es la huella de una botnet, y **eso ninguna blocklist te lo
dice**: las blocklists son listas de IPs, y la IP es justo lo que el atacante rota.

Umbral propuesto: `HASSH_MIN_IPS = 3` en `config.py`. Por debajo de eso es ruido de clientes SSH
comunes (OpenSSH de una distro popular comparte HASSH entre usuarios legítimos).

### 4. Configuración

```python
RECURRENCE_WINDOW_DAYS = 14    # misma ventana que TREND_WINDOW_DAYS, por coherencia del informe
HASSH_MIN_IPS          = 3
HASSH_WINDOW_DAYS      = 30
```

### 5. `tests/test_store_queries.py`

| Test | Qué fija |
|---|---|
| `test_ip_recurrence_cuenta_dias_distintos` | 3 observaciones el mismo día ⇒ 1; en 3 días ⇒ 3 |
| `test_ip_recurrence_respeta_la_ventana` | Una observación de hace 20 días no cuenta en 14 |
| `test_ip_recurrence_devuelve_none_si_no_existe` | IP desconocida |
| `test_payload_history_devuelve_first_seen` | Con `times_seen` acumulado |
| `test_hassh_fanout_agrupa_por_fingerprint` | 1 HASSH desde 3 IPs ⇒ `n_ips == 3` |
| `test_hassh_fanout_respeta_min_ips` | Con `min_ips=3`, uno de 2 IPs no sale |
| `test_hassh_fanout_no_cuenta_la_misma_ip_dos_veces` | `DISTINCT` funciona |
| `test_top_recurrent_ordena_por_days_seen` | |
| `test_el_veredicto_incluye_la_reincidencia` | El `detail` del `IocVerdict` trae "volvió N de los últimos M días" |

Todo en `:memory:` con datos sembrados.

## Criterio de hecho

**El informe cita al menos una reincidencia real y el dato se verifica a mano con SQL.**

```bash
# El informe del día tiene que contener una frase de reincidencia
grep -i "volvió\|reincident\|HASSH" separatio/reports/$(date +%F)/reports/*.md

# Y el número tiene que salir de acá
sqlite3 data/archivo.db "select value, days_seen, times_seen from ioc
                          where days_seen >= 2 order by days_seen desc limit 5"
```

> ⚠️ **Aviso operativo:** hoy hay **0 eventos de Cowrie con HASSH** (el sensor no está expuesto) y
> 0 payloads. La fase se **construye y testea con fixtures**, pero el criterio de hecho sobre dato
> real no se puede cumplir hasta que haya tráfico SSH. Si se llega acá antes de la exposición: se
> cierra la parte de código y tests, y **la verificación en vivo queda como pendiente explícito** —
> no se declara hecha con datos sintéticos.

## As-built

**Bloque "¿Ya está hecho?" al arrancar (2026-08-09)**, contra `data/archivo.db` real:

```
$ sqlite3 data/archivo.db "select value, kind, days_seen, times_seen from ioc order by days_seen desc limit 10"
45.9.148.52|ip|1|10
45.9.148.99|ip|1|14
162.142.125.7|ip|1|12
$ sqlite3 data/archivo.db "select count(*) from ioc where days_seen >= 2"
0
$ sqlite3 data/archivo.db "select count(*) from ioc where kind='hassh'"
0
$ grep -rn "reincident\|days_seen" separatio/enrichers/
separatio/enrichers/honeypot_recon.py:132:            -int(r.get("days_seen") or 0),   # F-C: el days_seen plano, sin ventana
```

Confirmó lo que ya avisaba `REWORK-ESTADO.md`: nada de F-D estaba hecho, y el store real no
tiene reincidencia ni HASSH todavía (0 eventos de Cowrie con HASSH, el sensor no está expuesto).

**Código y tests, ejecutados tal como estaban especificados** — sin desvíos del documento:

- `separatio/store/queries.py`: `ip_recurrence`, `payload_history`, `hassh_fanout`, `top_recurrent`
  — las cuatro consultas literales del plan, exportadas desde `separatio.store` (`from separatio.store
  import queries`, igual que `models`).
- `separatio/enrichers/honeypot_recon.py`, tres puntos de inserción sobre lo que F-C ya tenía:
  - la prioridad del residuo usa `queries.ip_recurrence()` (días dentro de `RECURRENCE_WINDOW_DAYS`)
    en vez del `days_seen` plano de la fila (que es de la vida entera del indicador);
  - `_emit_signal` ahora recibe `conn`/`now` y le antepone `"volvió N de los últimos M días; "` al
    `detail` de todo veredicto de señal fuerte (cache, escalada y sin-cascada por igual);
  - `_recurrence_notes()` nuevo: una nota `"IP reincidente: …"` por cada IP no-escáner con
    `days_seen >= 2` en la ventana (tope 5, vía `top_recurrent`), una nota `"payload ya conocido: …"`
    por cada payload con `times_seen > 1` visto en un avistamiento de la ventana, y una nota
    `"HASSH … huella de botnet"` por cada fingerprint que exceda `HASSH_MIN_IPS`.
- `config.py`: `RECURRENCE_WINDOW_DAYS = 14`, `HASSH_MIN_IPS = 3`, `HASSH_WINDOW_DAYS = 30`, cableadas
  en `enrichers/__init__.py` (factory de `HoneypotReconEnricher`).
- `tests/test_store_queries.py`: las 9 pruebas de la tabla del plan, todas contra `:memory:` con
  datos sembrados (la última, `test_el_veredicto_incluye_la_reincidencia`, instancia el enricher
  entero con dobles de GreyNoise/cascada, como ya hace `test_honeypot_recon.py`).

```
$ venv/bin/pytest tests/ -q
180 passed in 4.59s
```

(171 antes de F-D + 9 nuevos = 180. Ningún test de F-C se tocó ni se rompió — la firma de
`_emit_signal` cambió pero sólo la usan `_run`/`_escalate`, no los tests, que llaman a `_run()`.)

**Smoke test manual** (no forma parte de la suite, sólo verificación de humo con los tres tipos de
nota juntos — `:memory:`, dobles de red): confirmó que las tres notas y el veredicto con reincidencia
se emiten juntos sin excepciones:

```
IP reincidente: 40.0.0.1 volvió 3 de los últimos 14 días (0 hits)
payload ya conocido: ffffffff… desde 2026-07-30, visto 2 veces
HASSH aaaaaaaa… visto desde 3 IPs distintas en 30 días — mismo cliente SSH, huella de botnet
---verdicts---
40.0.0.1 | volvió 3 de los últimos 14 días; no figura en jamesbrine/IPsum/FireHOL; GreyNoise no la ve escanear internet
```

(el "(0 hits)" es un artefacto del script de humo, que sembró observaciones con `upsert_ioc(...,
count=False)` directo en vez de pasar por `ingest_run()` — en producción `times_seen` lo lleva la
ingesta real de F-B2.)

**Regresión del pipeline**: `venv/bin/separatio --dry-run` corrió limpio (28 s, 59/59 resumidos, 0
fallidos, aislado en `reports/dryrun/`) — el enricher construye igual con el toggle en su valor por
defecto (`honeypot_recon: False`), y se verificó por separado que `build_enrichers()` lo instancia
con los tres parámetros nuevos (`recurrence_window_days=14`, `hassh_min_ips=3`,
`hassh_window_days=30`) cuando el toggle está en `True`.

**⚠️ Criterio de hecho NO cumplido sobre dato real** (tal como avisaba el documento): el store de
producción sigue sin ninguna IP con `days_seen >= 2` ni HASSH — 0 tráfico SSH real contra el sensor
todavía. Se cierra la parte de código y tests; **la verificación en vivo (una frase de reincidencia
citada en el informe del día, respaldada por la consulta SQL) queda pendiente explícito** hasta que
el honeypot reciba tráfico SSH repetido. No se declara hecha con datos sintéticos, según la letra del
documento.

## Pendientes que deja

1. ⚠️ **Verificación en vivo bloqueada por falta de tráfico SSH real** (ver aviso operativo arriba):
   cuando el sensor Cowrie empiece a ver reincidencia real, correr el bloque del criterio de hecho
   (`grep` sobre el informe del día + la consulta SQL de `ioc`) y pegar la salida acá.
2. `honeypot_recon` sigue en `False` (decisión del usuario, gasta cuota real de GreyNoise) — F-D no
   cambia esa decisión, sólo mejora lo que el enricher va a decir el día que se prenda.
3. Falta desplegar al CT 113 junto con el resto de fases pendientes (ver `CLAUDE.md` §Pendiente #0)
   — `queries.py` no trae variables de entorno nuevas, `git pull` alcanza.
