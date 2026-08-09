# F-F · YARA sobre el corpus

> Estado: **☐ bloqueada — falta corpus real** · Depende de: **F-B1/F-B2** (dónde guardar) y de que
> los honeypots estén expuestos
> Diseño: [`../PLAN-REWORK.md`](../PLAN-REWORK.md) §F-F · Índice: [`../REWORK-ESTADO.md`](../REWORK-ESTADO.md)
>
> **Especificada. No arranca hasta que el bloqueo se levante.**

## Objetivo

Clasificar estáticamente los payloads que el honeypot captura y dejar el resultado consultable en
`payload.yara_hits`.

## ¿Ya está hecho? — y el bloqueo

```bash
cd ~/Projects/Intel
q() { [ -s data/archivo.db ] && sqlite3 data/archivo.db "$1" || echo "→ sin store"; }

ls data/honeypot/payloads/ 2>/dev/null | wc -l      # ← EL BLOQUEO: cuántos payloads hay
wc -l data/honeypot/hashes.log 2>/dev/null || echo "→ sin índice de corpus"
q "select count(*), count(yara_hits) from payload"
ls rules/ 2>/dev/null || echo "→ sin reglas propias"
venv/bin/python -c "import yara; print(yara.__version__)" 2>/dev/null || echo "→ sin yara-python"
```

**Medido el 2026-08-09: no hay corpus.** `data/honeypot/payloads/` no existe y `hashes.log`
tampoco. La única corrida real del colector (`by-date/2026-08-08/`) es anterior a los commits que
generan payloads, y el único tráfico registrado era el laptop del usuario — que desde F-A ni
siquiera entra al dataset.

**Esta fase no arranca hasta que haya material.** Correr YARA sobre cero ficheros no enseña nada.
La exposición de los honeypots está diferida por la AUP de Oracle y es independiente de este plan
(ver `~/Projects/Motherbase/honeypot/`).

**Umbral sugerido para desbloquear:** ≥ 50 payloads únicos en el corpus, con al menos 2 sensores
representados. Por debajo de eso las reglas se ajustan a ruido.

## Pasos (para cuando toque)

### 1. Dependencia opcional

```toml
# pyproject.toml
[project.optional-dependencies]
yara = ["yara-python>=4.5"]
```

Se instala con `pip install -e '.[dev,yara]'`. **Opcional a propósito**: si el binario no está, el
despliegue del CT no se rompe. El CT tiene 512 MiB y cada dependencia pesa.

El import va **diferido dentro de la función**, igual que hace `enrichers/ip_reputation.py:38` con
`ipcheck` — así el módulo se puede importar y testear sin la librería.

### 2. `separatio/yara_scan.py`

```python
def compile_rules(rules_dir: str | Path) -> "yara.Rules | None":
    """Compila todas las .yar/.yara del directorio. None si falta yara-python
    o si no hay reglas. Una regla que no compila se saltea con warning: nunca
    se aborta por una regla mal escrita."""

def scan_payload(rules, path: str | Path, timeout: int = 10) -> list[str]:
    """Nombres de las reglas que matchearon. Lista vacía si ninguna."""

def scan_new_payloads(conn, rules, corpus_dir: str | Path,
                      limit: int | None = None) -> dict:
    """Escanea SÓLO los payloads con yara_hits IS NULL en el store.
    Escribe el resultado y devuelve {'escaneados': n, 'con_hits': n}."""
```

**"Sólo los nuevos" sale del store**, no de un fichero de marcas:

```sql
SELECT sha256 FROM payload WHERE yara_hits IS NULL ORDER BY first_seen LIMIT ?;
```

Y al terminar cada uno, `yara_hits` pasa a ser la lista CSV de reglas o `''` (cadena vacía) si no
matcheó nada — **no `NULL`**, para que no se vuelva a escanear en la corrida siguiente. Esa
distinción entre `NULL` (sin escanear) y `''` (escaneado, sin hits) es la que hace idempotente la
fase.

### 3. Reglas en `rules/`

- **Propias**, escritas contra lo que el corpus tenga de verdad: droppers de shell de Cowrie,
  binarios ELF de Mirai/Gafgyt, webshells del catch-all de nginx.
- Más un set público curado y **vendorizado con su licencia** (p.ej. reglas de YARA-Rules o
  Neo23x0/signature-base, ambas permisivas). No se descargan en cada corrida: se commitean, así el
  resultado es reproducible.
- `rules/` **sí se versiona** (a diferencia de `data/`).

### 4. Dónde se invoca

Como paso del **colector**, no del pipeline: es el productor del corpus y ya escribe en el store
(invariante de F-B2). Al final de `consolidate()`, después de la ingesta, y envuelto en el mismo
try/except.

Toggle `YARA_ENABLED` en `config.py`, arrancando en `False`.

### 5. La regla que no se negocia

**Los payloads no se ejecutan nunca.** El corpus es cuarentena: se hashea, se analiza
estáticamente, y nada más. Ni `file`, ni `strings` sobre un fichero montado como ejecutable, ni
sandbox local. Esto no es una preferencia de estilo.

Consecuencia práctica: `scan_payload` abre el fichero en modo lectura binaria y se lo pasa a YARA;
el directorio `payloads/` no necesita permiso de ejecución.

### 6. `tests/test_yara_scan.py`

Con `pytest.importorskip("yara")` para que la suite pase sin la dependencia.

| Test | Qué fija |
|---|---|
| `test_compile_rules_devuelve_none_sin_yara` | Simulando `ImportError` |
| `test_compile_rules_saltea_regla_rota` | Una `.yar` inválida ⇒ warning, las demás compilan |
| `test_scan_payload_detecta_la_regla` | Regla trivial que matchea una cadena fija |
| `test_scan_payload_sin_hits_devuelve_vacio` | |
| `test_solo_escanea_los_nuevos` | Uno con `yara_hits=''` no se vuelve a escanear |
| `test_sin_hits_marca_cadena_vacia_no_null` | La distinción que hace idempotente la fase |
| `test_correr_dos_veces_no_reescanea` | `escaneados == 0` la segunda vez |

## Criterio de hecho

Al menos un payload real del corpus queda clasificado por una regla, el resultado está en
`payload.yara_hits`, y **correr la fase dos veces no reprocesa lo ya analizado**:

```bash
python3 -m separatio.yara_scan            # → escaneados: N, con hits: M
python3 -m separatio.yara_scan            # → escaneados: 0
sqlite3 data/archivo.db "select sha256, family, yara_hits from payload where yara_hits != ''"
```

## As-built

*(vacío hasta el cierre)*

## Pendientes que deja

*(a completar)*
