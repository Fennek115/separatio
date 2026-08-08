"""
net.py — utilidades de red con reintentos.

Helper sin dependencias (no requiere tenacity) para reintentar peticiones HTTP
ante fallos transitorios: errores de conexión/timeout y códigos 5xx / 429.
Backoff exponencial con tope. Usado por miniflux_client.py y correlator.py
(KEV/EPSS) para que un blip de red no aborte el run completo.
"""

from __future__ import annotations

import logging
import time

import requests

logger = logging.getLogger(__name__)

# Códigos que justifican reintento (transitorios). 429 = rate limit.
_RETRY_STATUS = {429, 500, 502, 503, 504}


def request_with_retry(
    method: str,
    url: str,
    *,
    session: requests.Session | None = None,
    retries: int = 3,
    backoff: float = 1.5,
    max_backoff: float = 20.0,
    **kwargs,
) -> requests.Response:
    """Ejecuta una petición HTTP con reintentos y backoff exponencial.

    Reintenta ante ConnectionError/Timeout y ante status en _RETRY_STATUS.
    Lanza la última excepción (o levanta raise_for_status) si se agotan los
    intentos. No reintenta ante 4xx distintos de 429 (errores del cliente)."""
    do = (session or requests).request
    last_exc: Exception | None = None

    for attempt in range(1, retries + 1):
        try:
            resp = do(method, url, **kwargs)
            if resp.status_code in _RETRY_STATUS and attempt < retries:
                wait = min(backoff ** attempt, max_backoff)
                logger.warning(
                    f"  HTTP {resp.status_code} en {url} — reintento "
                    f"{attempt}/{retries - 1} en {wait:.1f}s"
                )
                time.sleep(wait)
                continue
            return resp
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            if attempt < retries:
                wait = min(backoff ** attempt, max_backoff)
                logger.warning(
                    f"  Fallo de red en {url} ({e.__class__.__name__}) — "
                    f"reintento {attempt}/{retries - 1} en {wait:.1f}s"
                )
                time.sleep(wait)
            else:
                raise

    # Solo se alcanza si la última iteración fue un status reintentable.
    if last_exc:
        raise last_exc
    return resp  # type: ignore[return-value]


def get_with_retry(url: str, **kwargs) -> requests.Response:
    return request_with_retry("GET", url, **kwargs)
