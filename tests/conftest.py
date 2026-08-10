"""conftest.py — guardas que valen para toda la suite.

Hay una sola, y es importante: **ningún test puede escribir en el store real.**

Se descubrió el 2026-08-10 desplegando al CT 113. Desde F-B2,
`honeypot_collector.consolidate()` abría el store con `store.db.store()` sin
ruta, así que caía en el default `REPO_ROOT/data/archivo.db`; los tests le
pasaban un `out` en `tmp_path` pero no redirigían el store, y **cada corrida de
la suite inyectaba sus fixtures en el archivo de producción**. El store del
laptop había acumulado `times_seen` 50/57/42 y 150 observaciones falsas, y una
sesión anterior las tomó por dato real del honeypot (ver
`docs/REWORK-ESTADO.md` §Bugs abiertos).

El arreglo de fondo es el parámetro `db_path` de `consolidate()`, que los tests
ahora pasan explícitamente. Esto es el cinturón además de los tirantes: como
`store.db.default_path()` resuelve por `config.STORE_PATH`, redirigirlo por test
hace que **cualquier** código que caiga al default —incluido uno que se escriba
mañana— termine en `tmp_path` y no en el archivo real.
"""

import pytest

from separatio import config


@pytest.fixture(autouse=True)
def _store_aislado(tmp_path, monkeypatch):
    """Manda el store por default a `tmp_path`, para todos los tests.

    Se pisan **los dos** lados de la fachada de G-2 —la constante de módulo y el
    `Settings` del que sale— porque `db.default_path()` acepta un `settings=` y
    resuelve por ahí cuando se lo pasan. Pisar sólo `config.STORE_PATH` dejaría
    el agujero abierto para ese camino, y además haría divergir la fachada (hay
    un test de G-2 que comprueba que no diverge).
    """
    destino = str(tmp_path / "archivo-test.db")
    monkeypatch.setattr(config, "SETTINGS", config.SETTINGS.derive(STORE_PATH=destino))
    monkeypatch.setattr(config, "STORE_PATH", destino)
