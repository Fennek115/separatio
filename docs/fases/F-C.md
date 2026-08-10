# F-C · El enricher inverso y el triage de cuota

> Estado: **☑ hecha el 2026-08-09** · Depende de: **F-B1**, **F-B2**, **F-E**
> Diseño: [`../PLAN-REWORK.md`](../PLAN-REWORK.md) §5 · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> Es la pieza central del rework: la que responde la pregunta de estudio.

## Objetivo

Poder preguntar **"esta IP me pegó, ¿es actor conocido o ruido de internet?"** gastando la cuota
sólo en las que pueden ser señal.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
q() { [ -s data/archivo.db ] && sqlite3 data/archivo.db "$1" || echo "→ sin store"; }

ls separatio/enrichers/honeypot_recon.py 2>/dev/null || echo "→ no existe el enricher inverso"
grep -n "honeypot_recon" separatio/config.py separatio/enrichers/__init__.py 2>/dev/null
grep -n "QUOTAS" separatio/config.py 2>/dev/null || echo "→ sin presupuesto declarativo"
q "select source, count(*) from enrichment group by source"
grep -n "honeypot-recon" separatio/reports/pipeline.log 2>/dev/null | tail -8
```

## Contexto mínimo

**El gap concreto:** `enrichment.run_enrichment()` (`separatio/enrichment.py:185`) hace
`iocs = collect_iocs(summaries)` — el universo a enriquecer son los indicadores que salen en los
**artículos del día**. Las IPs que atacan el honeypot nunca pasan por la cascada de `ipcheck`,
salvo que casualmente salgan en una noticia.

**No es una capacidad nueva.** `ipcheck/ip_enricher.py` ya sabe consultar las 8 fuentes. Lo que
falta es invocarla con las IPs del honeypot y **en un orden que respete la cuota**.

> **`enrichers/honeypot.py` se conserva tal cual.** Hace la pregunta inversa (IOC de noticia → ¿me
> pegó?) y ambas valen. **No refactorizar uno dentro del otro.**

### La restricción que manda sobre todo el diseño

**GreyNoise sin API key da 25 consultas por SEMANA** — cabecera `x-ratelimit-limit: 25`, ventana de
7 días, medido el 2026-08-09, no lo que dice su documentación ("10 por día"). Y **los 404 también
consumen cuota**. Su doc excluye explícitamente a ProtonMail del acceso con key, así que registrarse
con el correo del usuario no sirve de nada.

Con 25/semana, **cada consulta desperdiciada es el 4 % del presupuesto semanal**.

### Las dos ideas que hay que tener claras al implementar

**Un acierto en blocklist NO es una señal interesante — es la definición de ruido.** Que una IP
esté en IPsum significa que atacó a mucha otra gente: confirma que sos *uno más* en la lista. Por
eso el paso de listas locales **termina** el procesamiento en vez de escalarlo: ya sabés lo que
necesitás saber, y gratis.

**Lo valioso de GreyNoise es el resultado NEGATIVO.** Si una IP te pegó y GreyNoise no la ve
escanear internet, eso es lo único disponible que se parece a "esto podría ir dirigido a mí".
Ninguna blocklist puede dar esa señal porque sólo contienen positivos.

## Pasos

### 1. El triage, paso por paso

```
recent_ips(conn, hours=26, origin="honeypot")        ← F-B1, sobre el store
  │
  ├─ 0. HIGIENE      klass == "self"     → ya no llegan (F-A las excluye en el colector)
  │                  klass == "scanner"  → DESCARTAR. Coste 0.
  │                     Que Censys te escanee no es un ataque; ya está etiquetado.
  │
  ├─ 1. CACHE        get_cached(conn, ip, "greynoise")  → reutilizar. Coste 0.
  │                     Es el corazón del ahorro: la misma IP vuelve todos los días.
  │
  ├─ 2. LISTAS       LocalLists.lookup(ip)  → si hay hits: NOTA y TERMINAR. Coste 0.
  │                     "ruido conocido, N listas". NO se consulta ninguna API.
  │
  └─ 3. RESIDUO      las que no están en ninguna lista  ← el subconjunto interesante
          │
          ├─ ordenar por interés (ver abajo)
          ├─ recortar a lo que permita el presupuesto: QUOTAS − quota_used(conn, …)
          ├─ check_greynoise(ip)              ← UNA llamada, suelta
          │     ├─ noise=True  → "escáner masivo conocido". put_cached. Fin.
          │     └─ noise=False → SEÑAL FUERTE. Escala:
          │            IpEnricher(ApiKeys.from_env()).enrich(ip)   ← la cascada completa
          └─ put_cached(...) de todo lo consultado
```

**Orden de interés del residuo** (el primer criterio que desempata gana):

1. `days_seen` descendente — la reincidencia es la señal más fuerte que tenemos (F-D la refina).
2. Envió payload (`observation.payload_sha256 IS NOT NULL`) — pasó de escanear a intentar algo.
3. Vista por más de un sensor (VM1 + VM2) — no es un barrido de un solo puerto.
4. `times_seen` descendente.

### 2. La cascada de `ipcheck` NO se usa entera

`IpEnricher.enrich()` (`ipcheck/ip_enricher.py:476`) arranca llamando a ip-api + GreyNoise + Shodan
**siempre**. Acá el orden lo manda la cuota, así que:

```python
from ipcheck.ip_enricher import ApiKeys, IpEnricher, check_greynoise

# Paso 3a — una llamada suelta, la más cara en términos de presupuesto
gn = check_greynoise(ip, True, timeout=10)

# Paso 3b — sólo el resultado negativo escala a la cascada completa
if gn and gn.get("status") == "ok" and not gn.get("noise"):
    session = IpEnricher(ApiKeys.from_env(), disabled={"greynoise"})   # ya la consultamos
    full = session.enrich(ip)
```

`disabled={"greynoise"}` es autoritativo (`ip_enricher.py:468`): la llamada **no se hace**, así que
no se paga dos veces la misma IP.

**Pacing de VirusTotal:** igual que `enrichers/ip_reputation.py:76` — `time.sleep(ENRICH_VT_SLEEP)`
sólo si `full["level_reached"] == 3` y `not session.vt_quota_exhausted`.

### 3. El presupuesto, declarativo y contado contra el store

En `config.py`:

```python
QUOTAS = {                      # consultas máximas por ventana
    "greynoise":  {"limit": 20, "window": "week"},   # medido: 25/sem sin key. Margen de 5
    "virustotal": {"limit": 400, "window": "day"},
    "abuseipdb":  {"limit": 800, "window": "day"},
    "otx":        {"limit": 500, "window": "day"},
}
RECON_WINDOW_HOURS = 26     # margen sobre 24h, igual que RANSOMWARE_LOOKBACK_HOURS
RECON_MAX_ESCALATE = 5      # tope de IPs que escalan a la cascada completa por corrida
```

El consumo se cuenta con **`quota_used(conn, source, window=…)`** (F-B1), o sea desde
`enrichment.fetched_at`. **No en una variable en memoria**: así el presupuesto sobrevive a
reinicios y es real. Si `quota_used >= limit`, la fuente se salta con un log explícito — no se
consulta y no se falla.

### 4. TTL del cache por fuente

| Fuente | TTL | Por qué |
|---|---|---|
| GreyNoise | **7 días** | Coincide con su ventana de cuota y con su lookback |
| AbuseIPDB / OTX / VirusTotal | 30 días | La reputación de una IP no cambia en horas |
| Listas locales | *no van al cache* | Se redescargan enteras cada 12 h (F-E); no son consultas por IOC |
| MalwareBazaar por hash | **nunca expira** (`ttl_days=None`) | Un SHA-256 no cambia de familia |

Va en `config.py` como `ENRICH_TTL_DAYS = {"greynoise": 7, "abuseipdb": 30, ...}`.

### 5. `separatio/enrichers/honeypot_recon.py`

```python
class HoneypotReconEnricher(Enricher):
    name = "honeypot-recon"

    def __init__(self, window_hours=26, max_escalate=5, quotas=None,
                 ttl_days=None, vt_sleep=15): ...

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        """Ignora `iocs` a propósito: su universo son las IPs del store, no las
        de las noticias. Es la dirección inversa del cruce."""
```

Registro en `enrichers/__init__.py:build_enrichers`, siguiendo el patrón que ya existe:

```python
    if toggles.get("honeypot_recon"):
        from separatio.enrichers.honeypot_recon import HoneypotReconEnricher
        enrichers.append(HoneypotReconEnricher(
            window_hours=getattr(config, "RECON_WINDOW_HOURS", 26),
            max_escalate=getattr(config, "RECON_MAX_ESCALATE", 5),
            quotas=getattr(config, "QUOTAS", {}),
            ttl_days=getattr(config, "ENRICH_TTL_DAYS", {}),
            vt_sleep=getattr(config, "ENRICH_VT_SLEEP", 15),
        ))
```

Y el toggle en `config.ENRICHERS`, **arrancando en `False`** — se prende cuando esté verificado. Es
el patrón del proyecto y funciona.

**El store se abre en modo lectura** salvo para `put_cached`: el enricher es el único punto donde
el pipeline escribe, y sólo en la tabla `enrichment`.

### 6. Qué emite al informe

Dos cosas, y la segunda es la que importa:

```python
# (1) Notas de contexto — el desglose del triage, para que el LLM tenga el marco
ctx.add_note(self.name, "38 IPs atacaron el honeypot en las últimas 26 h: "
                        "6 escáneres de investigación, 24 en listas públicas, "
                        "8 sin antecedentes.")

# (2) LA señal fuerte — un IocVerdict por cada IP que no está en ninguna lista
#     y que GreyNoise no ve escanear internet
ctx.add(IocVerdict(
    ioc=ip, kind="ip", source=self.name,
    label="posible actividad dirigida",
    detail="no figura en jamesbrine/IPsum/FireHOL; GreyNoise no la ve escanear "
           "internet; 4 hits en ssh+redis desde 2 sensores",
))
```

### 7. El log del triage (es el criterio de hecho)

Una línea por etapa, con números:

```
  [honeypot-recon] ventana 26h: 38 IPs del store
  [honeypot-recon]   escáneres descartados:      6  (censys 4, shodan 2)
  [honeypot-recon]   resueltas por cache:       19  (0 consultas)
  [honeypot-recon]   en listas locales:          5  (jamesbrine 5, ipsum 3, tor 1)
  [honeypot-recon]   residuo:                    8  → presupuesto GreyNoise 20/sem, usadas 3
  [honeypot-recon]   consultadas:                8  → 7 noise=true, 1 noise=FALSE
  [honeypot-recon]   escaladas a cascada:        1  (VT/AbuseIPDB/OTX)
  [honeypot-recon]   señal fuerte:               1
```

### 8. `tests/test_honeypot_recon.py` — sin red

| Test | Qué fija |
|---|---|
| `test_los_escaneres_no_consumen_cuota` | Una IP con `klass='scanner'` ⇒ 0 llamadas a GreyNoise |
| `test_el_cache_evita_la_consulta` | IP con `enrichment` fresca ⇒ 0 llamadas |
| `test_el_cache_vencido_si_consulta` | Con `fetched_at` de hace 8 días ⇒ 1 llamada |
| `test_un_acierto_en_lista_local_termina` | IP en jamesbrine ⇒ 0 llamadas, nota emitida |
| `test_solo_el_residuo_llega_a_greynoise` | 3 en listas + 2 residuo ⇒ exactamente 2 llamadas |
| `test_noise_false_emite_señal_fuerte` | `IocVerdict` con label de actividad dirigida |
| `test_noise_true_no_emite_veredicto` | Sólo nota |
| `test_solo_noise_false_escala_a_la_cascada` | `IpEnricher.enrich` llamado 1 vez, no 5 |
| `test_la_cuota_agotada_frena_las_consultas` | `quota_used` ≥ límite ⇒ 0 llamadas, log |
| `test_el_presupuesto_sale_del_store` | Se cuenta desde `enrichment`, no de una variable |
| `test_orden_de_prioridad_del_residuo` | Reincidente + con payload va primero |
| `test_max_escalate_acota_la_cascada` | 10 con `noise=false` y `max_escalate=5` ⇒ 5 cascadas |
| `test_sin_store_el_enricher_no_hace_nada` | `open_store` devuelve `None` ⇒ return limpio, sin excepción |
| `test_greynoise_no_se_consulta_dos_veces` | `disabled={"greynoise"}` en la cascada |

`check_greynoise` e `IpEnricher` monkeypatcheados; store en `:memory:` prepoblado.

## Criterio de hecho

Con datos reales del honeypot:

1. El log muestra **el desglose completo del triage** (las 7 líneas de arriba, con números reales).
2. `sqlite3 data/archivo.db "select source, count(*) from enrichment where fetched_at > date('now','-7 day') group by source"`
   **coincide con las consultas que muestra el log**. Si no coinciden, el presupuesto está mal
   contado y la fase no está hecha.
3. `venv/bin/pytest tests/ -q` verde y `separatio --dry-run` intacto.

> Si el honeypot todavía no tiene tráfico real, la fase se puede **construir y testear** pero se
> cierra con el desglose sobre datos sintéticos y se anota como pendiente la verificación en vivo.

## As-built

**Implementado:** `separatio/enrichers/honeypot_recon.py` (`HoneypotReconEnricher`), registrado en
`enrichers/__init__.py:build_enrichers` con toggle `config.ENRICHERS["honeypot_recon"]` (arranca en
`False`). `config.QUOTAS`, `config.RECON_WINDOW_HOURS`, `config.RECON_MAX_ESCALATE` y
`config.ENRICH_TTL_DAYS` nuevos en `config.py`, tal como especificaba el plan.

**Un cambio sobre lo planificado, documentado acá porque "gana la máquina":** `models.recent_ips`
(F-B1) no traía `sensors` ni `has_payload` — necesarios para el 2º y 3er criterio de prioridad del
residuo (§1). Se extendió la consulta (dos columnas agregadas: `COUNT(DISTINCT o.sensor)` y
`MAX(o.payload_sha256 IS NOT NULL)`), aditivo y sin romper `test_recent_ips_filtra_por_ventana_y_origen`
de F-B1. Segundo cambio: el constructor de `HoneypotReconEnricher` gana un parámetro `lists=None`
que no estaba en la firma del plan — inyectar `LocalLists` (o un doble en los tests) evita que cada
test dispare la descarga real de 1 M de IPs; sin store real, nadie más lo necesita.

**Tercer ajuste sobre el diseño:** el plan no especificaba qué pasa con las IPs `noise=False` que
exceden `max_escalate`. Se resolvió así — no se pierden en silencio: emiten igual el veredicto
"posible actividad dirigida" pero sin el detalle de la cascada (`ipcheck` no se llama para ellas), y
el recorte queda registrado con `runlog.record_drop("enrichers.honeypot_recon.cascada", …)`.

**Los 14 tests de `tests/test_honeypot_recon.py` pasan** (nombres ASCII, sin tildes, por consistencia
con el resto del repo — no cambia lo que fijan). Suite completa: **171 tests** (157 + 14),
`venv/bin/pytest tests/ -q` verde.

**Verificado con datos reales del store** (`data/archivo.db`, cargado por el colector antes de esta
sesión): 3 IOCs — `162.142.125.7` (Censys, `klass=scanner`) y dos IPs `unknown`
(`45.9.148.99`, `45.9.148.52`). Corrida real (`LocalLists` real, 1,08 M de IPs cargadas y sin
coincidencias para ninguna de las dos), con `_check_greynoise`/`_cascade` **mockeados a propósito**
—no se gastó cuota real de GreyNoise sin confirmación explícita del usuario—, ejecutada sobre una
conexión sin commit (no se escribió nada en el store real: verificado con
`sqlite3 data/archivo.db "select * from enrichment"` → vacío después de la corrida). Log real:

```
    lists: cargadas {'jamesbrine': 1064397, 'ipsum': 113228, 'firehol_tor': 1414, 'firehol_level1': 4606, '_ram_mb': 4.86}
    [honeypot-recon] ventana 26h: 3 IPs del store
    [honeypot-recon]   escáneres descartados: 1
    [honeypot-recon]   resueltas por cache: 0 (0 consultas)
    [honeypot-recon]   en listas locales: 0
    [honeypot-recon]   residuo: 2 → presupuesto week 20, usadas 0
    [honeypot-recon]   consultadas: 2 → 0 noise=true, 2 noise=FALSE
    [honeypot-recon]   escaladas a cascada: 2
    [honeypot-recon]   señal fuerte: 2
```

`venv/bin/separatio --dry-run` corrió limpio con el toggle todavía en `False` (35 s, 59/59 resúmenes,
0 fallidos, status `ok`) — el criterio "el pipeline nunca se rompe por una fase nueva" se sostiene.

**Lo que falta para el criterio de hecho completo:** el punto 2 (contrastar
`select source, count(*) from enrichment … group by source` contra el log) requiere una corrida real
con el toggle en `True` y GreyNoise real — no se hizo en esta sesión por la misma razón que el mock:
gastar las 20 consultas semanales reservadas es una decisión del usuario, no una que tome sola una
sesión de verificación. Queda como pendiente explícito (abajo).

## Pendientes que deja

1. **Prender `honeypot_recon` en `config.ENRICHERS` y correr una vez con GreyNoise real** (fuera de
   esta sesión, a pedido del usuario): confirma el punto 2 del criterio de hecho —que
   `quota_used` contra `enrichment` coincida con lo que muestra el log— y consume cuota real por
   primera vez. Con el store actual (2 IPs candidatas) el gasto sería de 2/20 semanales.
2. Desplegar al CT 113 (mismo `git pull`, sin variables nuevas — `QUOTAS`/`RECON_*`/`ENRICH_TTL_DAYS`
   están todos con default en `config.py`).
3. Decidir si `ENRICHERS["honeypot"]` (el enricher directo, F3) también se prende cuando haya más
   tráfico real — sigue en `False` por la misma razón de siempre (esperar dato real, no sintético).
4. F-D (reincidencia) puede afinar el criterio 1 del orden de prioridad del residuo (`days_seen`);
   hoy es un conteo simple, no una serie temporal.
