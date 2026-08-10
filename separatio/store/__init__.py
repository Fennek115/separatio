"""
store — el archivo de inteligencia (F-B1 del rework).

Un fichero SQLite (`data/archivo.db`) con cinco tablas: `ioc` (identidad),
`observation` (cada avistamiento, append-only), `enrichment` (el cache que
ahorra cuota), `payload` (el corpus content-addressed) y `meta` (la versión del
esquema).

`db.py` abre y migra; `models.py` consulta. Nada de esto cambia la conducta del
pipeline por sí solo: F-B2 cablea la escritura desde el colector y F-C la
lectura desde el pipeline.

    from separatio.store import store, models

    with store() as conn:
        if conn is not None:
            models.upsert_ioc(conn, "1.2.3.4", "ip", models.now_iso())
"""

from separatio.store import models, queries
from separatio.store.db import (
    MEMORY,
    SCHEMA_PATH,
    SCHEMA_VERSION,
    default_path,
    migrate,
    open_store,
    schema_version,
    store,
)

__all__ = [
    "MEMORY",
    "SCHEMA_PATH",
    "SCHEMA_VERSION",
    "default_path",
    "migrate",
    "models",
    "open_store",
    "queries",
    "schema_version",
    "store",
]
