"""Tests de la escritura atómica y lectura tolerante del historial."""

import json

import history


def test_atomic_save_roundtrip(tmp_path):
    p = tmp_path / "history.json"
    data = {"2026-06-22": {"total": 5, "actors": ["LockBit"]}}
    history.save_history(data, str(p))
    assert p.exists()
    assert not (tmp_path / "history.json.tmp").exists()   # tmp limpiado
    assert json.loads(p.read_text(encoding="utf-8")) == data


def test_save_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "dir" / "history.json"
    history.save_history({"x": 1}, str(p))
    assert p.exists()


def test_load_missing_returns_empty(tmp_path):
    assert history.load_history(str(tmp_path / "nope.json")) == {}


def test_load_corrupt_returns_empty(tmp_path):
    p = tmp_path / "history.json"
    p.write_text("{ not valid json", encoding="utf-8")
    assert history.load_history(str(p)) == {}
