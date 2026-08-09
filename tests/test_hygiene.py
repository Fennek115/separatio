"""Tests del clasificador de higiene (F-A del rework) — deterministas, sin red ni DNS."""

import separatio.hygiene as hygiene
from separatio.hygiene import (
    SCANNER, SELF, UNKNOWN,
    IpClassifier, build_classifier, own_ips_from_env, parse_ip_list,
    resolve_public_ip,
)

# IP dentro de una CIDR publicada por Censys (separatio/hygiene.py).
CENSYS_IP = "162.142.125.7"


def _clf(**kw):
    """Clasificador sin PTR: los tests no tocan la red."""
    kw.setdefault("use_ptr", False)
    return IpClassifier(**kw)


# ── parseo de listas ────────────────────────────────────────

def test_parse_ip_list_tolera_ruido():
    assert parse_ip_list("") == []
    assert parse_ip_list("1.2.3.4") == ["1.2.3.4"]
    assert parse_ip_list(" 1.2.3.4 , 10.0.0.0/8 ;\n# comentario\n5.6.7.8") == [
        "1.2.3.4", "10.0.0.0/8", "5.6.7.8"]


def test_own_ips_from_env(monkeypatch):
    monkeypatch.setenv("OWN_IPS", "1.2.3.4,10.0.0.0/8")
    assert own_ips_from_env() == ["1.2.3.4", "10.0.0.0/8"]
    monkeypatch.delenv("OWN_IPS")
    assert own_ips_from_env() == []


# ── clasificación ───────────────────────────────────────────

def test_ip_propia_exacta_es_self():
    clf = _clf(own_ips=["45.9.148.52"])
    assert clf.classify("45.9.148.52") == (SELF, None)


def test_ip_propia_por_cidr_es_self():
    clf = _clf(own_ips=["45.9.148.0/24"])
    assert clf.classify("45.9.148.52")[0] == SELF
    assert clf.classify("45.9.149.52")[0] == UNKNOWN


def test_cidr_publicada_de_censys_es_scanner():
    assert _clf().classify(CENSYS_IP) == (SCANNER, "censys")


def test_ip_cualquiera_es_unknown():
    assert _clf().classify("45.9.148.99") == (UNKNOWN, None)


def test_lo_propio_gana_sobre_escaner():
    """Si una IP está en OWN_IPS, es propia aunque coincida con un escáner."""
    clf = _clf(own_ips=[CENSYS_IP])
    assert clf.classify(CENSYS_IP)[0] == SELF


def test_entrada_basura_no_explota():
    clf = _clf(own_ips=["no-es-una-ip", "", "999.1.1.1"])
    assert clf.own_count == 0
    assert clf.classify("") == (UNKNOWN, None)
    assert clf.classify("no-es-una-ip") == (UNKNOWN, None)


def test_ipv6_no_confunde_al_matcher():
    clf = _clf(own_ips=["2001:db8::/32"])
    assert clf.classify("2001:db8::1")[0] == SELF
    assert clf.classify("2001:dead::1")[0] == UNKNOWN
    assert clf.classify(CENSYS_IP)[0] == SCANNER   # v4 vs redes v6 sin romperse


def test_toggle_apaga_la_clasificacion_de_escaneres():
    assert _clf(classify_scanners=False).classify(CENSYS_IP) == (UNKNOWN, None)


def test_add_own_invalida_el_cache():
    clf = _clf()
    assert clf.classify("45.9.148.99")[0] == UNKNOWN
    clf.add_own("45.9.148.99")
    assert clf.classify("45.9.148.99")[0] == SELF


# ── PTR (rDNS), sin tocar la red ────────────────────────────

def test_ptr_reconoce_al_escaner(monkeypatch):
    monkeypatch.setattr(hygiene, "_reverse_lookup",
                        lambda ip, t: "soda.census.shodan.io")
    assert IpClassifier(use_ptr=True).classify("71.6.135.131") == (SCANNER, "shodan")


def test_ptr_sin_resultado_deja_unknown(monkeypatch):
    monkeypatch.setattr(hygiene, "_reverse_lookup", lambda ip, t: None)
    assert IpClassifier(use_ptr=True).classify("45.9.148.99") == (UNKNOWN, None)


def test_ptr_respeta_el_tope_de_consultas(monkeypatch):
    llamadas = []
    monkeypatch.setattr(hygiene, "_reverse_lookup",
                        lambda ip, t: llamadas.append(ip) or None)
    clf = IpClassifier(use_ptr=True, ptr_max_lookups=2)
    for i in range(5):
        clf.classify(f"45.9.148.{i}")
    assert len(llamadas) == 2


def test_ptr_no_matchea_dominio_que_solo_contiene_el_sufijo(monkeypatch):
    """`noshodan.io.evil.com` no es Shodan."""
    monkeypatch.setattr(hygiene, "_reverse_lookup", lambda ip, t: "shodan.io.evil.com")
    assert IpClassifier(use_ptr=True).classify("45.9.148.99")[0] == UNKNOWN


# ── resolución de la IP pública propia ──────────────────────

def test_resolve_public_ip_cachea(monkeypatch, tmp_path):
    cache = tmp_path / "own_ips.auto"

    class _Resp:
        def read(self, n): return b"198.51.100.7\n"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(hygiene.urllib.request, "urlopen", lambda *a, **k: _Resp())
    assert resolve_public_ip("http://x", 1, cache) == "198.51.100.7"
    assert cache.read_text().strip() == "198.51.100.7"


def test_resolve_public_ip_falla_hacia_el_cache(monkeypatch, tmp_path):
    """Fail-open hacia el último valor conocido: seguir excluyendo la IP vieja es
    mucho menos malo que volver a contar el laptop como atacante."""
    cache = tmp_path / "own_ips.auto"
    cache.write_text("198.51.100.7\n")

    def _boom(*a, **k):
        raise OSError("sin red")

    monkeypatch.setattr(hygiene.urllib.request, "urlopen", _boom)
    assert resolve_public_ip("http://x", 1, cache) == "198.51.100.7"


def test_resolve_public_ip_sin_red_ni_cache_devuelve_none(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise OSError("sin red")

    monkeypatch.setattr(hygiene.urllib.request, "urlopen", _boom)
    assert resolve_public_ip("http://x", 1, tmp_path / "no-existe") is None


def test_resolve_public_ip_rechaza_respuesta_que_no_es_ip(monkeypatch, tmp_path):
    class _Resp:
        def read(self, n): return b"<html>error</html>"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(hygiene.urllib.request, "urlopen", lambda *a, **k: _Resp())
    assert resolve_public_ip("http://x", 1, tmp_path / "c") is None


# ── construcción desde config ───────────────────────────────

class _Cfg:
    OWN_IPS = "203.0.113.9"
    OWN_IP_RESOLVE = False
    SCANNER_PTR_LOOKUP = False


def test_build_classifier_lee_config_y_entorno(monkeypatch):
    monkeypatch.setenv("OWN_IPS", "198.51.100.1")
    clf = build_classifier(_Cfg)
    assert clf.classify("198.51.100.1")[0] == SELF   # del entorno
    assert clf.classify("203.0.113.9")[0] == SELF    # de config
    assert clf.classify(CENSYS_IP)[0] == SCANNER


def test_build_classifier_no_resuelve_si_el_toggle_esta_apagado(monkeypatch):
    monkeypatch.delenv("OWN_IPS", raising=False)
    monkeypatch.setattr(hygiene, "resolve_public_ip",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no debía llamarse")))
    build_classifier(_Cfg)
