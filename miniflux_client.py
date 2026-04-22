"""
miniflux_client.py — Cliente para la API de Miniflux.
Obtiene artículos no leídos y los marca como leídos tras procesar.
"""

import requests
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Article:
    """Representa un artículo obtenido de Miniflux."""
    id: int
    title: str
    url: str
    feed_title: str
    feed_category: str
    content: str          # HTML/texto que viene en el feed (puede estar vacío)
    published_at: str

    def has_full_content(self, min_length: int = 300) -> bool:
        return len(self.content.strip()) >= min_length


class MinifluxClient:
    """
    Cliente liviano para la API REST de Miniflux.
    Documentación: https://miniflux.app/docs/api.html
    """

    def __init__(self, base_url: str, username: str = None,
                 password: str = None, api_token: str = None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        if api_token:
            # API token es la forma recomendada (Settings > API Keys en Miniflux)
            self.session.headers.update({"X-Auth-Token": api_token})
        elif username and password:
            self.session.auth = (username, password)
        else:
            raise ValueError("Se requiere api_token o username+password")

    def _get(self, endpoint: str, params: dict = None) -> dict:
        url = f"{self.base_url}/v1/{endpoint}"
        resp = self.session.get(url, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def _put(self, endpoint: str, payload: dict) -> None:
        url = f"{self.base_url}/v1/{endpoint}"
        resp = self.session.put(url, json=payload, timeout=10)
        resp.raise_for_status()

    def get_unread_articles(self, limit: int = 200,
                            category_id: Optional[int] = None) -> list[Article]:
        """
        Obtiene artículos no leídos de Miniflux.
        Aplica paginación automática si hay más artículos que el límite de la API.
        """
        params = {
            "status": "unread",
            "limit": min(limit, 200),   # Miniflux max por página = 10000, pero 200 es seguro
            "order": "published_at",
            "direction": "desc",
        }
        if category_id:
            params["category_id"] = category_id

        articles = []
        offset = 0
        total = None

        while True:
            params["offset"] = offset
            data = self._get("entries", params=params)

            if total is None:
                total = data.get("total", 0)
                logger.info(f"Total artículos no leídos: {total}")

            entries = data.get("entries", [])
            if not entries:
                break

            for entry in entries:
                feed = entry.get("feed", {})
                category = feed.get("category", {})
                articles.append(Article(
                    id=entry["id"],
                    title=entry.get("title", "Sin título"),
                    url=entry.get("url", ""),
                    feed_title=feed.get("title", "Desconocido"),
                    feed_category=category.get("title", "Sin categoría"),
                    content=entry.get("content", ""),
                    published_at=entry.get("published_at", ""),
                ))

            offset += len(entries)
            if offset >= min(limit, total):
                break

        logger.info(f"Artículos cargados: {len(articles)}")
        return articles

    def mark_as_read(self, article_ids: list[int]) -> None:
        """Marca una lista de artículos como leídos en Miniflux."""
        if not article_ids:
            return
        # La API acepta hasta 1000 IDs por llamada
        for i in range(0, len(article_ids), 500):
            batch = article_ids[i:i + 500]
            self._put("entries", {"entry_ids": batch, "status": "read"})
        logger.info(f"Marcados como leídos: {len(article_ids)} artículos")

    def get_categories(self) -> list[dict]:
        """Lista todas las categorías disponibles."""
        return self._get("categories")
