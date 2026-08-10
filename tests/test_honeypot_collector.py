"""Tests del consolidador del honeypot (F-A del rework) — sin red, sin DNS, sobre tmp_path.

Fija el criterio de hecho de F-A: una corrida sobre logs que contienen la IP
propia la excluye, etiqueta a los escáneres de investigación sin meterlos en el
export de IOCs, y deja pasar sólo lo desconocido — que es lo interesante.
"""

import csv
import json
from datetime import datetime, timezone

from separatio.honeypot_collector import consolidate
from separatio.hygiene import IpClassifier
from separatio.store import db

# Fixtures. Tienen que ser IPs GLOBALES: los rangos de documentación
# (198.51.100.0/24, 203.0.113.0/24) no pasan el filtro `public()`, que corre
# antes del clasificador. La IP propia real vive en OWN_IPS del .env — el repo
# es público.
PROPIA = "45.9.148.52"          # hace de laptop del usuario: el caso que motivó F-A
CENSYS = "162.142.125.7"        # dentro de una CIDR publicada por Censys
ATACANTE = "45.9.148.99"        # ninguna de las dos cosas: el subconjunto útil


def _ahora():
    return datetime.now(timezone.utc).isoformat()


def _raw(tmp_path, ips=(PROPIA, CENSYS, ATACANTE)):
    """Un raw/ sintético con una request web por IP."""
    raw = tmp_path / "raw"
    raw.mkdir()
    lineas = []
    for ip in ips:
        lineas.append(json.dumps({
            "ts": _ahora(), "ip": ip, "host": "h", "method": "GET",
            "uri": "/.env", "status": 404, "ua": "curl/8", "body": "",
        }))
    (raw / "web.json").write_text("\n".join(lineas) + "\n")
    return raw


def _clf():
    return IpClassifier(own_ips=[PROPIA], use_ptr=False)


def _run(tmp_path, **kw):
    raw = kw.pop("raw", None) or _raw(tmp_path)
    out = tmp_path / "out"
    # `db_path` explícito: sin él `consolidate()` resuelve al store del repo y la
    # suite escribe sus fixtures en producción — el bug del 2026-08-10.
    return consolidate(raw, out, 24, db_path=db.MEMORY,
                       classifier=kw.pop("classifier", None) or _clf()), out


# ── el criterio de hecho de F-A ─────────────────────────────

def test_la_ip_propia_no_llega_a_atacantes(tmp_path):
    r, out = _run(tmp_path)
    ips = [a["ip"] for a in r["attackers"]]
    assert PROPIA not in ips
    assert r["hygiene"]["self_excluded"] == 1
    assert r["hygiene"]["self_hits"] == 1
    assert r["hygiene"]["self_ips"] == [PROPIA]
    # y tampoco al fichero que lee el enricher
    escrito = json.loads((out / "attackers.json").read_text())
    assert PROPIA not in [a["ip"] for a in escrito["attackers"]]
    assert escrito["hygiene"]["self_excluded"] == 1


def test_la_ip_propia_no_llega_al_timeline_de_tecnicas(tmp_path):
    r, out = _run(tmp_path)
    assert PROPIA not in [e["ip"] for e in r["events"]]
    assert PROPIA not in (out / "events.latest.jsonl").read_text()


# ── escáneres: se etiquetan, no se descartan ────────────────

def test_el_escaner_queda_etiquetado_pero_presente(tmp_path):
    r, _ = _run(tmp_path)
    censys = next(a for a in r["attackers"] if a["ip"] == CENSYS)
    assert censys["class"] == "scanner"
    assert censys["scanner_name"] == "censys"
    assert r["hygiene"]["scanners"] == {"censys": [CENSYS]}


def test_el_escaner_no_entra_al_export_de_iocs(tmp_path):
    _, out = _run(tmp_path)
    with open(out / "iocs.csv") as f:
        valores = [row["value"] for row in csv.DictReader(f)]
    assert valores == [ATACANTE]        # ni la propia ni el escáner


def test_el_escaner_si_entra_al_timeline(tmp_path):
    """Que Censys te escanee es dato: no es un ataque, pero pasó."""
    r, _ = _run(tmp_path)
    assert CENSYS in [e["ip"] for e in r["events"]]


# ── el residuo, que es lo que interesa ──────────────────────

def test_el_desconocido_pasa_entero(tmp_path):
    r, _ = _run(tmp_path)
    a = next(a for a in r["attackers"] if a["ip"] == ATACANTE)
    assert a["class"] == "unknown"
    assert a["scanner_name"] is None
    assert a["hits"] == 1
    assert r["hygiene"]["unknown_ips"] == 1


# ── comportamiento general del consolidador ─────────────────

def test_sin_allowlist_la_ip_propia_sigue_entrando(tmp_path):
    """Prueba de que el test de arriba mide la higiene y no otra cosa."""
    r, _ = _run(tmp_path, classifier=IpClassifier(own_ips=[], use_ptr=False))
    assert PROPIA in [a["ip"] for a in r["attackers"]]
    assert r["hygiene"]["self_excluded"] == 0


def test_reingerir_el_mismo_dia_no_duplica(tmp_path):
    """El pull corre cada 6 h: reconsolidar la misma ventana da lo mismo."""
    raw = _raw(tmp_path)
    out = tmp_path / "out"
    primera = consolidate(raw, out, 24, db_path=db.MEMORY, classifier=_clf())
    segunda = consolidate(raw, out, 24, db_path=db.MEMORY, classifier=_clf())
    assert [a["ip"] for a in primera["attackers"]] == [a["ip"] for a in segunda["attackers"]]
    assert len(primera["events"]) == len(segunda["events"])
    escrito = json.loads((out / "attackers.json").read_text())
    assert len(escrito["attackers"]) == 2


def test_las_ips_privadas_se_ignoran_como_antes(tmp_path):
    """Regresión: el filtro `public()` es anterior a F-A y sigue mandando."""
    raw = _raw(tmp_path, ips=("127.0.0.1", "10.0.0.5", ATACANTE))
    r, _ = _run(tmp_path, raw=raw)
    assert [a["ip"] for a in r["attackers"]] == [ATACANTE]


def test_raw_vacio_no_rompe(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    r, out = _run(tmp_path, raw=raw)
    assert r["attackers"] == []
    assert json.loads((out / "attackers.json").read_text())["attackers"] == []


def test_la_suite_no_toca_el_store_del_repo(tmp_path):
    """Regresión del 2026-08-10: correr la suite escribía en producción.

    `consolidate()` abría el store sin ruta y caía en `REPO_ROOT/data/archivo.db`,
    así que cada corrida de pytest metía a PROPIA/CENSYS/ATACANTE en el archivo
    real. Este test corre **a propósito sin `db_path`** —el camino que fallaba— y
    comprueba que el fichero del repo no se crea ni se modifica; lo garantiza el
    `conftest.py`, que manda el default a `tmp_path`.
    """
    from pathlib import Path

    from separatio import config

    real = Path(config.REPO_ROOT) / "data" / "archivo.db"
    antes = real.stat().st_mtime_ns if real.exists() else None

    consolidate(_raw(tmp_path), tmp_path / "out", 24, classifier=_clf())

    despues = real.stat().st_mtime_ns if real.exists() else None
    assert antes == despues, f"la suite escribió en el store real: {real}"
