"""
config.py — La configuración efectiva del pipeline.

Desde F-G/G-2 (2026-08-09) esto es una **fachada**: los valores, sus defaults y
sus comentarios viven en `separatio/settings.py`, dentro del dataclass congelado
`Settings`. Acá sólo se construye la instancia desde el entorno y se exponen sus
campos como constantes de módulo.

Por qué sigue existiendo el módulo, en vez de que todo el mundo importe
`Settings`:

  * Los ~187 accesos del tipo `config.MAX_ARTICLES` que había repartidos por el
    repo siguen funcionando **sin tocarse**, y con ellos el
    `monkeypatch.setattr(config, "STORE_ENABLED", False)` de los tests.
  * `hygiene.build_classifier` y `setup_check` leen la config **por nombre
    dinámico** (`getattr(config, name, default)`); un módulo con los nombres
    planos es exactamente lo que esperan.
  * `tools/pull_honeypot.sh` invoca al colector fuera del venv: cuanto menos
    maquinaria haga falta para leer un valor, mejor.

**Para código nuevo, preferí recibir un `Settings` por parámetro** (así lo hacen
`pipeline.py` y los módulos hoja desde G-2) y usar `config.SETTINGS` sólo como
valor por defecto. Editar un valor fijo se sigue haciendo en `settings.py`.

Nota de orden: `from_env()` corre al importar este módulo, así que el entry
point tiene que hacer `load_dotenv()` **antes** — es lo que hacen `pipeline.py`
y `setup_check.py`, y no cambió con G-2.
"""

from separatio.settings import Settings

#: La configuración efectiva de este proceso.
SETTINGS = Settings.from_env()

# Los campos de `SETTINGS`, como constantes de módulo. Se hace en un loop y no a
# mano para que no puedan divergir: `settings.py` es la única lista de nombres.
# El coste es que estos nombres no son visibles para un lector ni para un linter
# — para saber qué hay, y por qué vale lo que vale, se lee `settings.py`.
# (`PROJECT_ROOT` y `REPO_ROOT` entran por acá también: son campos del dataclass.)
globals().update(SETTINGS.as_dict())
