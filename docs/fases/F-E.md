# F-E · Listas locales: el filtro que no cuesta cuota

> Estado: **☐ pendiente — sesión 3** · Depende de: **F-B1** (cachea el cruce)
> **Adelantada respecto del plan original**: se ejecuta *antes* que F-C, porque es lo que achica el
> residuo sobre el que F-C gasta las 25 consultas semanales de GreyNoise.
> Evidencia: [`../CAPAS-Y-FUENTES.md`](../CAPAS-Y-FUENTES.md) · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Completamente especificada. Ejecutar y documentar.**

## Objetivo

Poder responder **gratis** "¿esta IP ya la reportó alguien más?" sobre 1,08 millones de indicadores,
dentro del presupuesto de RAM del CT 113. Todo lo que caiga acá **no llega** al paso caro.

## ¿Ya está hecho?

```bash
cd ~/Projects/Intel
ls separatio/lists.py 2>/dev/null || echo "→ no existe el servicio de listas"
ls -la data/feeds/ 2>/dev/null || echo "→ sin cache de feeds"
venv/bin/python -c "
from separatio.lists import LocalLists
l = LocalLists.from_config(); l.load()
print(l.stats()); print(l.lookup('185.220.101.1'))"
```

## Contexto mínimo

**La conclusión que ordena esta fase: las blocklists agregadas son casi el mismo fichero.**
Solapamientos medidos el 2026-08-09: IPsum L3 ∩ AbuseIPDB 30d = **98,0 %**; CINS ∩ IPsum L1 =
89,1 %. Sumar una cuarta blocklist agregada no aporta nada — todas responden la misma pregunta.

Por eso entran **cuatro fuentes y sólo cuatro**, cada una por un motivo distinto. Verificadas por
HTTP el **2026-08-09**:

| Fuente | URL | Medido hoy | Rol |
|---|---|---|---|
| **jamesbrine** | `https://jamesbrine.com.au/iplist.txt` | 200, 15,2 MB, **1.063.843 líneas** | Base local. Es el feed que **más se parece a nuestro sensor**: SSH/Telnet/portscan de honeypots reales, no reportes de terceros. TLP:White, no comercial |
| **IPsum L3** | `…/stamparm/ipsum/master/levels/3.txt` | 200, **16.782 líneas** | Score de confianza: cada línea trae en cuántas listas aparece. Ya está la URL en `config.IPSUM_URL` |
| **FireHOL tor_exits** | `…/firehol/blocklist-ipsets/master/tor_exits.ipset` | 200, **1.445 líneas** | Señal **distinta**: anonimización, no reputación |
| **FireHOL level1** | `…/firehol/blocklist-ipsets/master/firehol_level1.netset` | 200, **4.638 líneas** (CIDR) | Señal de **infraestructura**: bogons y secuestros, no de conducta |

**Descartadas con evidencia, no volver a discutirlas:** CINS (89 % redundante y capado en 15.000),
DigitalSide (**muerto**: no responde, último commit 2024-10-18), Pulsedive (sin bulk gratis, ToS
prohíben automatización *y* redistribución), Feodo Tracker y SSLBL (**5 y 1** entradas útiles).

### El problema de RAM, ya resuelto

El CT 113 tiene **512 MiB** y ahí adentro corre también el pipeline con el cliente LLM. Medido en
este laptop con 1.063.680 IPs (`tracemalloc`):

| Estructura | RAM | Veredicto |
|---|---|---|
| `set` de strings (`"1.2.3.4"`) | **91,3 MB** | Descartada: es el 18 % de la RAM del CT para una sola lista |
| `set` de enteros | 33,6 MB | Mejor, pero sigue siendo caro |
| **`array('I')` ordenado + `bisect`** | **4,3 MB** | ✅ **Esto es lo que se implementa** — 4 bytes por IP |

Coste de consulta medido: **100.000 lookups en 75 ms** (0,75 µs cada uno). No hay que elegir entre
memoria y velocidad.

Esto convierte el "hay que medirlo" del plan original en una decisión ya tomada. La verificación de
la fase sigue siendo medirlo **en el CT**, no acá.

## Pasos

### 1. `separatio/lists.py` — el servicio de pertenencia

**No es un `Enricher`.** Los enrichers cruzan los IOCs de las *noticias*; esto es un servicio de
consulta que F-C va a usar sobre las IPs del *honeypot*. Va suelto, no en `enrichers/`.

```python
@dataclass
class ListHit:
    source: str            # jamesbrine | ipsum | firehol_tor | firehol_level1
    detail: str = ""       # p.ej. "reportada en 7 listas" (IPsum trae score)

class LocalLists:
    """Pertenencia de IPs en listas locales. array('I') + bisect: 4 bytes por IP."""

    @classmethod
    def from_config(cls, config=None) -> "LocalLists": ...

    def load(self, *, force: bool = False) -> None:
        """Descarga lo vencido y carga todo en memoria. Fail-open (ver abajo)."""

    def lookup(self, ip: str) -> list[ListHit]:
        """Todas las listas en las que aparece la IP. Lista vacía = el residuo interesante."""

    def stats(self) -> dict:
        """{'jamesbrine': 1063843, 'ipsum': 16782, ...} + RAM aproximada. Va al log."""
```

Estructuras internas:

- **IPs sueltas** (jamesbrine, IPsum, tor_exits): `array('I')` ordenado, consulta con
  `bisect_left`. IPsum guarda además un `dict` sólo con los scores de las que superan
  `IPSUM_MIN_SCORE` — son 16.782, no 1 M, así que el dict no pesa.
- **Redes** (`firehol_level1.netset`, y las líneas CIDR de tor_exits): lista ordenada de tuplas
  `(inicio, fin)` como enteros + `bisect` sobre los inicios. 4.638 entradas: irrelevante en RAM.
- Todo IPv4. Una IPv6 devuelve lista vacía sin romperse (hoy los sensores no ven IPv6).

### 2. Descarga y cache

```python
FEED_CACHE_DIR = REPO_ROOT / "data" / "feeds"     # gitignored, como el resto de data/
FEED_TTL_HOURS = 12
```

- Descarga con **`net.get_with_retry`**, que ya existe (`separatio/net.py:71`) y reintenta ante
  429/5xx con backoff. No escribir un cliente HTTP nuevo.
- Cache a `data/feeds/<nombre>.txt`; se re-descarga si el `mtime` tiene más de 12 h.
- **Fail-open, en este orden:** si la descarga falla se usa la copia en disco **aunque esté
  vencida**; si tampoco hay copia, esa lista queda vacía y se loguea. Una lista caída no puede
  romper el pipeline — el efecto es que llega más residuo a F-C, que es degradación, no fallo.
- **User-Agent de navegador** en todas las peticiones: medido el 2026-08-08, el STIX de jamesbrine
  devuelve **403 con el UA por defecto de curl**. `iplist.txt` hoy no lo exige, pero el mismo
  servidor sí, así que se manda igual.

### 3. `separatio/config.py`

```python
LOCAL_LISTS_ENABLED = _env_bool("LOCAL_LISTS_ENABLED", True)
FEED_CACHE_DIR      = str(REPO_ROOT / "data" / "feeds")
FEED_TTL_HOURS      = 12
LOCAL_LISTS = {
    "jamesbrine":     "https://jamesbrine.com.au/iplist.txt",
    "ipsum":          IPSUM_URL,   # ya existe; apuntar a levels/3.txt
    "firehol_tor":    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset",
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
}
```

> ⚠️ **`IPSUM_URL` hoy apunta a `ipsum.txt` (L1, 113k IPs), no a `levels/3.txt` (16,7k).** El
> enricher `IpsumEnricher` filtra por `IPSUM_MIN_SCORE=3` en memoria, así que el resultado es
> equivalente pero baja 7 veces más datos. Cambiarlo a `levels/3.txt` es parte de esta fase.

### 4. `tests/test_lists.py` — con fixtures locales, sin red

| Test | Qué fija |
|---|---|
| `test_lookup_encuentra_ip_en_lista_plana` | Fixture de 5 IPs |
| `test_lookup_devuelve_vacio_para_el_residuo` | Una IP que no está en ninguna |
| `test_lookup_acumula_varias_listas` | Una IP en jamesbrine + IPsum ⇒ 2 `ListHit` |
| `test_ipsum_reporta_el_score` | El `detail` trae "reportada en N listas" |
| `test_netset_matchea_por_rango` | `10.0.0.0/8` contiene `10.1.2.3`, no `11.0.0.1` |
| `test_frontera_de_rango` | Primera y última IP del rango dentro; la siguiente fuera |
| `test_ipv6_no_rompe` | Devuelve `[]` |
| `test_linea_malformada_se_ignora` | Basura en el feed ⇒ se salta, no explota |
| `test_cache_vencido_se_redescarga` | `mtime` viejo ⇒ pide; reciente ⇒ no pide (HTTP monkeypatcheado) |
| `test_fallo_de_red_usa_cache_vencido` | Descarga rota + copia vieja ⇒ carga la vieja |
| `test_sin_red_ni_cache_la_lista_queda_vacia` | Y el resto de las listas siguen funcionando |

Patrón de HTTP monkeypatcheado igual que `tests/test_enrichment.py` y `tests/test_net.py`.

## Criterio de hecho

**El cruce corre dentro del presupuesto de RAM del CT, medido y no supuesto:**

```bash
# 1. En el laptop: cuánta RAM ocupa cargar las 4 listas de verdad
venv/bin/python -c "
import tracemalloc; tracemalloc.start()
from separatio.lists import LocalLists
l = LocalLists.from_config(); l.load()
print(l.stats())
print('RAM:', tracemalloc.get_traced_memory()[0]/1e6, 'MB')"

# 2. En el CT 113, con techo duro: tiene que NO morir
ssh proxmox 'pct exec 113 -- systemd-run --scope -p MemoryMax=120M --quiet \
  /opt/intel/app/venv/bin/python -c "
from separatio.lists import LocalLists
l = LocalLists.from_config(); l.load(); print(l.stats())"'

# 3. Y la suite
venv/bin/pytest tests/ -q
```

El número real medido en el CT va al as-built. Si no entra en 120 M se sube el techo y se anota;
lo que **no** vale es cerrar la fase sin el número.

## As-built

*(vacío hasta el cierre — la salida de los tres comandos, con la RAM real del CT)*

## Pendientes que deja

*(a completar. Previsible: `data/feeds/` suma ~15 MB al disco del CT (3,2 G libres, no es problema)
y el primer `load()` del día baja 15 MB — anotar si hay que espaciar la descarga)*

## Nota de licencias

- **jamesbrine:** TLP:White, *"free to use in any form for non-commercial purposes"* — encaja
  exacto con el uso de estudio personal.
- **FireHOL: no hay fichero `LICENSE` en el repo.** Cada ipset hereda la licencia de su fuente
  original y algunas son restrictivas. **No tratarlo como un bloque** y no redistribuir los datos.
- **IPsum:** ya integrado desde antes.
