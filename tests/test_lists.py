"""Tests de las listas locales (F-E) — fixtures en memoria, sin red real."""

import os
import time

import requests

from separatio import lists


class _FakeResp:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        pass


def _patch_get(monkeypatch, text_or_map):
    """Monkeypatchea net.get_with_retry. Acepta un texto único o {url: texto}."""
    def fake_get(url, **kwargs):
        text = text_or_map[url] if isinstance(text_or_map, dict) else text_or_map
        return _FakeResp(text)
    monkeypatch.setattr(lists.net, "get_with_retry", fake_get)
    return fake_get


def test_lookup_encuentra_ip_en_lista_plana(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "1.2.3.4\n5.6.7.8\n9.9.9.9\n10.10.10.10\n11.11.11.11\n")
    ll = lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path)
    ll.load()
    hits = ll.lookup("5.6.7.8")
    assert len(hits) == 1
    assert hits[0].source == "jamesbrine"


def test_lookup_devuelve_vacio_para_el_residuo(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "1.2.3.4\n5.6.7.8\n")
    ll = lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path)
    ll.load()
    assert ll.lookup("8.8.8.8") == []


def test_lookup_acumula_varias_listas(tmp_path, monkeypatch):
    _patch_get(monkeypatch, {
        "http://a": "1.2.3.4\n",
        "http://b": "1.2.3.4\n9.9.9.9\n",
    })
    ll = lists.LocalLists({"jamesbrine": "http://a", "firehol_tor": "http://b"}, cache_dir=tmp_path)
    ll.load()
    hits = ll.lookup("1.2.3.4")
    assert {h.source for h in hits} == {"jamesbrine", "firehol_tor"}


def test_ipsum_reporta_el_score(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "1.2.3.4\t9\n5.6.7.8\t2\n")
    ll = lists.LocalLists({"ipsum": "http://x"}, cache_dir=tmp_path, ipsum_min_score=3)
    ll.load()
    hits = ll.lookup("1.2.3.4")
    assert hits[0].detail == "reportada en 9 listas"
    # sigue perteneciendo a la lista (bisect) aunque el score no supere el piso
    hits2 = ll.lookup("5.6.7.8")
    assert hits2[0].source == "ipsum"
    assert hits2[0].detail == ""


def test_netset_matchea_por_rango(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "10.0.0.0/8\n192.168.1.0/24\n")
    ll = lists.LocalLists({"firehol_level1": "http://x"}, cache_dir=tmp_path)
    ll.load()
    assert ll.lookup("10.1.2.3")[0].source == "firehol_level1"
    assert ll.lookup("11.0.0.1") == []


def test_frontera_de_rango(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "192.168.1.0/24\n")
    ll = lists.LocalLists({"firehol_level1": "http://x"}, cache_dir=tmp_path)
    ll.load()
    assert ll.lookup("192.168.1.0") != []       # primera IP del rango
    assert ll.lookup("192.168.1.255") != []     # última IP del rango
    assert ll.lookup("192.168.2.0") == []       # la siguiente, fuera


def test_ipv6_no_rompe(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "1.2.3.4\n")
    ll = lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path)
    ll.load()
    assert ll.lookup("2001:db8::1") == []


def test_linea_malformada_se_ignora(tmp_path, monkeypatch):
    _patch_get(monkeypatch, "1.2.3.4\nno-es-una-ip\n999.999.999.999\n\n# comentario\n5.6.7.8\n")
    ll = lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path)
    ll.load()
    assert ll.stats()["jamesbrine"] == 2
    assert ll.lookup("1.2.3.4") != []
    assert ll.lookup("5.6.7.8") != []


def test_cache_vencido_se_redescarga(tmp_path, monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _FakeResp("1.2.3.4\n")

    monkeypatch.setattr(lists.net, "get_with_retry", fake_get)

    lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path, ttl_hours=12).load()
    assert len(calls) == 1

    # cache recién escrita: no vuelve a pedir
    lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path, ttl_hours=12).load()
    assert len(calls) == 1

    # mtime viejo: vuelve a pedir
    cache_file = tmp_path / "jamesbrine.txt"
    old = time.time() - 13 * 3600
    os.utime(cache_file, (old, old))
    lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path, ttl_hours=12).load()
    assert len(calls) == 2


def test_fallo_de_red_usa_cache_vencido(tmp_path, monkeypatch):
    cache_file = tmp_path / "jamesbrine.txt"
    cache_file.write_text("1.2.3.4\n")
    old = time.time() - 100 * 3600
    os.utime(cache_file, (old, old))

    def fake_get(url, **kwargs):
        raise requests.ConnectionError("caído")

    monkeypatch.setattr(lists.net, "get_with_retry", fake_get)
    ll = lists.LocalLists({"jamesbrine": "http://x"}, cache_dir=tmp_path, ttl_hours=12)
    ll.load()
    assert ll.lookup("1.2.3.4") != []


def test_sin_red_ni_cache_la_lista_queda_vacia(tmp_path, monkeypatch):
    # ipsum ya tiene cache fresca; jamesbrine no tiene nada.
    (tmp_path / "ipsum.txt").write_text("1.2.3.4\t9\n")

    def fake_get(url, **kwargs):
        raise requests.ConnectionError("caído")

    monkeypatch.setattr(lists.net, "get_with_retry", fake_get)
    ll = lists.LocalLists({"jamesbrine": "http://a", "ipsum": "http://b"}, cache_dir=tmp_path)
    ll.load()
    assert ll.stats()["jamesbrine"] == 0
    assert ll.lookup("1.2.3.4")[0].source == "ipsum"
