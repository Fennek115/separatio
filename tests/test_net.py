"""Tests del helper de reintentos HTTP — sin red real (fake session)."""

import pytest
import requests

from separatio import net


class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeSession:
    """Devuelve códigos de una secuencia; cuenta llamadas."""
    def __init__(self, sequence):
        self.sequence = list(sequence)
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        item = self.sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return _FakeResp(item)


def test_retries_on_503_then_succeeds(monkeypatch):
    monkeypatch.setattr(net.time, "sleep", lambda *_: None)
    sess = _FakeSession([503, 200])
    resp = net.request_with_retry("GET", "http://x", session=sess, retries=3)
    assert resp.status_code == 200
    assert sess.calls == 2


def test_gives_up_after_retries(monkeypatch):
    monkeypatch.setattr(net.time, "sleep", lambda *_: None)
    sess = _FakeSession([503, 503, 503])
    resp = net.request_with_retry("GET", "http://x", session=sess, retries=3)
    assert resp.status_code == 503     # devuelve el último, no lanza
    assert sess.calls == 3


def test_no_retry_on_404(monkeypatch):
    monkeypatch.setattr(net.time, "sleep", lambda *_: None)
    sess = _FakeSession([404, 200])
    resp = net.request_with_retry("GET", "http://x", session=sess, retries=3)
    assert resp.status_code == 404     # 4xx no reintenta
    assert sess.calls == 1


def test_retries_on_connection_error_then_raises(monkeypatch):
    monkeypatch.setattr(net.time, "sleep", lambda *_: None)
    sess = _FakeSession([requests.ConnectionError(), requests.ConnectionError()])
    with pytest.raises(requests.ConnectionError):
        net.request_with_retry("GET", "http://x", session=sess, retries=2)
    assert sess.calls == 2
