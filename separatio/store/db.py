"""
db.py — apertura y migración del store (F-B1 del rework).

El fichero SQLite (`data/archivo.db`) es el archivo de inteligencia: la memoria
que le falta al pipeline para poder decir *"esta IP volvió N días"*. Este módulo
sólo lo abre y lo migra; el acceso vive en `models.py`.

**La regla que este módulo no puede violar:** si el fichero no se puede abrir,
`open_store` **loguea y devuelve `None`**. Nadie aborta, nadie propaga la
excepción. Es el mismo patrón tolerante a fallos que ya usan
`pipeline.stage27_enrich` y `history.load_history`: el informe diario está en
producción y ninguna fase nueva lo puede romper (invariante 1 del rework).

Sólo biblioteca estándar (`sqlite3` lo es), a propósito: el colector que va a
escribir acá en F-B2 corre en el CT 113 con el `python3` del sistema, sin venv.

Uso típico:

    with store() as conn:
        if conn is None:
            return                      # el store no está: seguir sin él
        models.upsert_ioc(conn, "1.2.3.4", "ip", ts)
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

MEMORY = ":memory:"

# PRAGMAs de cada conexión, en orden. WAL primero porque es el que permite que
# el pull (cada 6 h) y el pipeline (07:00) se solapen sin bloquearse.
_PRAGMAS = (
    "PRAGMA journal_mode=WAL",      # lectores y escritor concurrentes
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",     # 5s antes de dar 'database is locked'
    "PRAGMA synchronous=NORMAL",    # suficiente con WAL; menos fsync en el disco del CT
)

# En sólo-lectura no se puede escribir el journal ni el header: WAL y synchronous
# fallarían con 'attempt to write a readonly database'.
_PRAGMAS_RO = (
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
)


def default_path(settings=None) -> str:
    """Ruta del store según el `Settings` dado, el `config` global, o el repo.

    El último fallback existe porque el colector se invoca con el `python3` del
    sistema y `PYTHONPATH` apuntando al repo: importar `separatio.config`
    funciona, pero este módulo no depende de que funcione."""
    if settings is not None:
        return str(settings.STORE_PATH)
    try:
        from separatio import config
        return str(config.STORE_PATH)
    except Exception:                                    # pragma: no cover
        repo_root = Path(__file__).resolve().parents[2]
        return str(repo_root / "data" / "archivo.db")


def _enabled(settings=None) -> bool:
    if settings is not None:
        return bool(settings.STORE_ENABLED)
    try:
        from separatio import config
        return bool(config.STORE_ENABLED)
    except Exception:                                    # pragma: no cover
        return True


def open_store(path: str | Path | None = None,
               *, read_only: bool = False,
               settings=None) -> sqlite3.Connection | None:
    """Abre el store y lo migra. Devuelve None si no se puede — **nunca levanta**.

    `path=None` usa `STORE_PATH` y respeta `STORE_ENABLED` —del `Settings` que se
    pase (F-G/G-2) o del `config` global—; una ruta explícita lo abre igual (los
    tests pasan `":memory:"`).
    `read_only=True` abre con URI `file:…?mode=ro` y **no migra**: es como lo va
    a abrir el pipeline a partir de F-C.
    """
    explicit = path is not None
    if not explicit and not _enabled(settings):
        logger.debug("    store: deshabilitado por STORE_ENABLED")
        return None

    target = str(path) if explicit else default_path(settings)

    try:
        if target != MEMORY:
            p = Path(target)
            if read_only and not p.is_file():
                logger.warning(f"    store: no existe {p} (sólo-lectura), se sigue sin store")
                return None
            if not read_only:
                p.parent.mkdir(parents=True, exist_ok=True)

        if read_only and target != MEMORY:
            conn = sqlite3.connect(f"file:{Path(target).as_posix()}?mode=ro",
                                   uri=True, timeout=5.0)
        else:
            conn = sqlite3.connect(target, timeout=5.0)

        conn.row_factory = sqlite3.Row
        for pragma in (_PRAGMAS_RO if read_only else _PRAGMAS):
            try:
                conn.execute(pragma)
            except sqlite3.Error as e:
                logger.debug(f"    store: {pragma} falló ({e})")

        if not read_only:
            migrate(conn)
        return conn
    except Exception as e:
        logger.warning(f"    store: no se pudo abrir {target} ({e}) — se sigue sin store")
        return None


def schema_version(conn: sqlite3.Connection) -> int:
    """Versión del esquema en el fichero. 0 si nunca se migró."""
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.Error:
        return 0
    try:
        return int(row[0]) if row else 0
    except (TypeError, ValueError):
        return 0


def migrate(conn: sqlite3.Connection) -> int:
    """Aplica el DDL y actualiza `meta.schema_version`. Idempotente.

    Devuelve la versión resultante. Cuando haya una versión 2, acá va el
    `if current < 2: conn.executescript(...)` — el DDL de la 1 no se toca."""
    current = schema_version(conn)
    if current >= SCHEMA_VERSION:
        return current

    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute(
        "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()
    if current == 0:
        logger.info(f"    store: esquema creado (versión {SCHEMA_VERSION})")
    else:
        logger.info(f"    store: migrado {current} → {SCHEMA_VERSION}")
    return SCHEMA_VERSION


@contextmanager
def store(path: str | Path | None = None, *, read_only: bool = False):
    """Context manager: cede la conexión (**o `None`**) y commitea/cierra al salir.

    Que ceda `None` es deliberado: el caller decide qué hacer sin store, y nunca
    tiene que envolver la apertura en su propio try/except."""
    conn = open_store(path, read_only=read_only)
    try:
        yield conn
    except Exception:
        if conn is not None and not read_only:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        raise
    else:
        if conn is not None and not read_only:
            try:
                conn.commit()
            except sqlite3.Error as e:
                logger.warning(f"    store: no se pudo commitear ({e})")
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
