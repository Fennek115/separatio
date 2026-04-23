"""
extractor.py — Extracción de contenido limpio de páginas web.
Usa trafilatura como motor principal con fallback a BeautifulSoup.
"""

import logging
import re
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import trafilatura
import requests

logger = logging.getLogger(__name__)


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().removeprefix("www.")
    except Exception:
        return ""


def clean_html_content(html: str) -> str:
    """
    Convierte HTML del feed RSS a texto plano limpio.
    Útil cuando el feed entrega contenido parcial en HTML.
    """
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    # Eliminar scripts, estilos y elementos no textuales
    for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()
    text = soup.get_text(separator="\n")
    # Limpiar líneas vacías excesivas
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines)


def fetch_url_content(url: str, timeout: int = 15,
                      blocked_domains: set | None = None) -> str:
    """
    Descarga una URL y extrae el contenido principal con trafilatura.
    Retorna texto limpio o cadena vacía si falla o el dominio está bloqueado.
    """
    if not url:
        return ""
    if blocked_domains and _domain(url) in blocked_domains:
        logger.debug(f"[skip-blocked] {_domain(url)}")
        return ""
    try:
        # trafilatura puede hacer el fetch internamente
        downloaded = trafilatura.fetch_url(url)
        if downloaded:
            text = trafilatura.extract(
                downloaded,
                include_comments=False,
                include_tables=True,
                no_fallback=False,
                favor_precision=True,
            )
            if text and len(text) > 200:
                return text.strip()

        # Fallback: requests + BeautifulSoup
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        }
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return clean_html_content(resp.text)

    except Exception as e:
        logger.warning(f"No se pudo extraer {url}: {e}")
        return ""


def extract_article_text(article, timeout: int = 15,
                          min_length: int = 200,
                          blocked_domains: set | None = None) -> str:
    """
    Estrategia de extracción en 3 pasos:
      1. Usar contenido del feed si es suficientemente completo
      2. Si no → hacer fetch de la URL (salvo dominio bloqueado)
      3. Si todo falla → usar el título como fallback mínimo
    """
    # Paso 1: contenido del feed
    if article.has_full_content(min_length):
        text = clean_html_content(article.content)
        if len(text) >= min_length:
            logger.debug(f"[feed] {article.title[:60]}")
            return text

    # Paso 2: scraping de la URL
    logger.debug(f"[fetch] {article.url[:80]}")
    time.sleep(0.5)   # pequeña pausa para no sobrecargar servidores
    fetched = fetch_url_content(article.url, timeout=timeout,
                                blocked_domains=blocked_domains)
    if len(fetched) >= min_length:
        return fetched

    # Paso 3: fallback al contenido parcial del feed o solo el título
    partial = clean_html_content(article.content)
    if partial:
        return partial

    logger.warning(f"[fallback] Solo título disponible: {article.title}")
    return article.title


def truncate_text(text: str, max_tokens_approx: int = 800) -> str:
    """
    Trunca el texto para no exceder el contexto del modelo.
    Estimación: 1 token ≈ 4 caracteres en inglés, ~3.5 en español.
    """
    max_chars = max_tokens_approx * 4
    if len(text) <= max_chars:
        return text
    # Cortar en límite de párrafo para no partir oraciones
    truncated = text[:max_chars]
    last_newline = truncated.rfind("\n")
    if last_newline > max_chars * 0.7:
        truncated = truncated[:last_newline]
    return truncated + "\n[... contenido truncado ...]"
