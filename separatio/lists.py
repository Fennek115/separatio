"""
lists.py — pertenencia de IPs en listas locales (F-E del rework).

No es un `Enricher`: los enrichers cruzan los IOCs de las *noticias* (Stage
2.7); esto es un servicio de consulta que el enricher inverso (F-C) usa sobre
las IPs del *honeypot*, para responder gratis "¿esta IP ya la reportó alguien
más?" antes de gastar una consulta de GreyNoise.

Cuatro fuentes agregadas (jamesbrine, IPsum L3, FireHOL tor_exits, FireHOL
level1) suman ~1,08 M indicadores. Guardarlos como `set` de strings cuesta 91 MB
— el 18 % de la RAM del CT 113 (512 MiB) para una sola lista. La estructura que
entra en presupuesto es `array('I')` ordenado + `bisect`: cada IP es un entero
de 4 bytes, medido en 4,3 MB para el lote completo (ver docs/fases/F-E.md).

Fail-open en la descarga, en este orden: si falla se usa la copia en disco
aunque esté vencida; si tampoco hay copia, esa lista queda vacía y se loguea.
Una lista caída degrada (llega más residuo a F-C) — nunca rompe el pipeline.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from array import array
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path

from separatio import net

logger = logging.getLogger(__name__)

# Medido el 2026-08-08: jamesbrine devuelve 403 al STIX con el UA por defecto
# de curl/requests. iplist.txt hoy no lo exige, pero es el mismo servidor.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)


@dataclass
class ListHit:
    source: str            # jamesbrine | ipsum | firehol_tor | firehol_level1
    detail: str = ""       # p.ej. "reportada en 7 listas" (sólo IPsum trae score)


def _ipv4_int(token: str) -> int | None:
    try:
        addr = ipaddress.IPv4Address(token)
    except ValueError:
        return None
    return int(addr)


class _SourceList:
    """Pertenencia para una sola fuente: IPs sueltas + redes CIDR.

    Ambas formas se mezclan porque un mismo feed puede traer líneas de los dos
    tipos (los .ipset/.netset de FireHOL). Cada una con su propio bisect."""

    __slots__ = ("_flat", "_net_start", "_net_end")

    def __init__(self):
        self._flat = array("I")
        self._net_start = array("I")
        self._net_end: list[int] = []

    def build(self, path: Path | None) -> None:
        """Lee `path` línea a línea (no `.read().splitlines()`): con 1 M de IPs,
        materializar la lista completa de strings de una sola vez costó ~90 MB
        transitorios y sacó al proceso del techo de RAM del CT — medido en F-E
        (2026-08-09, `systemd-run -p MemoryMax=120M`: pico real 128,8 MB con la
        versión que hacía `splitlines()`). Iterar el archivo abierto sólo
        mantiene viva una línea a la vez."""
        flat_ints: list[int] = []
        nets: list[tuple[int, int]] = []
        if path is not None:
            with path.open(encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    token = line.split()[0]
                    try:
                        if "/" in token:
                            n = ipaddress.ip_network(token, strict=False)
                            if n.version != 4:
                                continue
                            nets.append((int(n.network_address), int(n.broadcast_address)))
                        else:
                            ip_int = _ipv4_int(token)
                            if ip_int is not None:
                                flat_ints.append(ip_int)
                    except ValueError:
                        continue    # línea malformada: se ignora, no rompe la carga
        # sorted(), no sorted(set(...)): con 1 M de enteros, el set intermedio
        # sumaba ~25 MB transitorios al pico de RAM medido en el CT sin aportar
        # nada — un duplicado en el array sólo desperdicia 4 bytes, `bisect` lo
        # tolera igual (F-E, 2026-08-09).
        self._flat = array("I", sorted(flat_ints))
        nets.sort()
        self._net_start = array("I", (n[0] for n in nets))
        self._net_end = [n[1] for n in nets]

    def contains(self, ip_int: int) -> bool:
        if self._flat:
            i = bisect_left(self._flat, ip_int)
            if i < len(self._flat) and self._flat[i] == ip_int:
                return True
        if self._net_start:
            i = bisect_left(self._net_start, ip_int)
            if i < len(self._net_start) and self._net_start[i] == ip_int:
                return True
            if i > 0 and self._net_start[i - 1] <= ip_int <= self._net_end[i - 1]:
                return True
        return False

    def __len__(self) -> int:
        return len(self._flat) + len(self._net_start)

    def nbytes(self) -> int:
        """RAM aproximada de esta fuente (para `stats()`, no un tracemalloc real)."""
        return (self._flat.itemsize * len(self._flat)
                + self._net_start.itemsize * len(self._net_start)
                + len(self._net_end) * 28)     # int de Python en una lista, aprox


def _parse_ipsum_scores(path: Path | None, min_score: int) -> dict[int, int]:
    """IPsum trae `IP<TAB>score`. Sólo se guardan las que superan el piso —
    son 113 k líneas de texto (~1 MB), nada comparado con jamesbrine: el dict
    no pesa. Streaming igual que `_SourceList.build`, por la misma razón."""
    scores: dict[int, int] = {}
    if path is None:
        return scores
    with path.open(encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            score = int(parts[1])
            if score < min_score:
                continue
            ip_int = _ipv4_int(parts[0])
            if ip_int is not None:
                scores[ip_int] = score
    return scores


def _ensure_cache(name: str, url: str, cache_path: Path, ttl_hours: float,
                   force: bool, timeout: float) -> Path | None:
    """Deja una copia utilizable en `cache_path` y devuelve su ruta, o `None`
    si no hay ninguna (ni fresca, ni vencida, ni descargable). Fail-open: una
    descarga rota usa la copia vieja; sin copia, la fuente queda vacía."""
    if not force and cache_path.exists():
        age_h = (time.time() - cache_path.stat().st_mtime) / 3600
        if age_h < ttl_hours:
            return cache_path

    try:
        resp = net.get_with_retry(url, timeout=timeout, headers={"User-Agent": _USER_AGENT})
        resp.raise_for_status()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(resp.text)
        return cache_path
    except Exception as e:
        if cache_path.exists():
            logger.warning(f"    lists: fallo al descargar {name} ({e}) — usando copia en cache vencida")
            return cache_path
        logger.warning(f"    lists: fallo al descargar {name} ({e}) y sin copia en cache — lista vacía")
        return None


class LocalLists:
    """Pertenencia de IPs en listas locales. array('I') + bisect: 4 bytes por IP."""

    def __init__(self, sources: dict[str, str], cache_dir, ttl_hours: float = 12,
                 ipsum_min_score: int = 3, timeout: float = 20):
        self.sources = dict(sources)
        self.cache_dir = Path(cache_dir)
        self.ttl_hours = ttl_hours
        self.ipsum_min_score = ipsum_min_score
        self.timeout = timeout
        self._lists: dict[str, _SourceList] = {}
        self._ipsum_scores: dict[int, int] = {}

    @classmethod
    def from_config(cls, config=None) -> "LocalLists":
        if config is None:
            from separatio import config
        return cls(
            sources=dict(getattr(config, "LOCAL_LISTS", {})),
            cache_dir=getattr(config, "FEED_CACHE_DIR", "data/feeds"),
            ttl_hours=float(getattr(config, "FEED_TTL_HOURS", 12)),
            ipsum_min_score=int(getattr(config, "IPSUM_MIN_SCORE", 3)),
        )

    def load(self, *, force: bool = False) -> None:
        """Descarga lo vencido y carga todo en memoria. Fail-open (ver módulo)."""
        for name, url in self.sources.items():
            cache_path = self.cache_dir / f"{name}.txt"
            path = _ensure_cache(name, url, cache_path, self.ttl_hours, force, self.timeout)
            src = _SourceList()
            src.build(path)
            self._lists[name] = src
            if name == "ipsum":
                self._ipsum_scores = _parse_ipsum_scores(path, self.ipsum_min_score)
        logger.info(f"    lists: cargadas {self.stats()}")

    def lookup(self, ip: str) -> list[ListHit]:
        """Todas las listas en las que aparece la IP. Lista vacía = el residuo interesante."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        if addr.version != 4:
            return []       # hoy los sensores no ven IPv6; no rompe, no matchea

        ip_int = int(addr)
        hits: list[ListHit] = []
        for name, src in self._lists.items():
            if not src.contains(ip_int):
                continue
            detail = ""
            if name == "ipsum":
                score = self._ipsum_scores.get(ip_int)
                if score is not None:
                    detail = f"reportada en {score} listas"
            hits.append(ListHit(source=name, detail=detail))
        return hits

    def stats(self) -> dict:
        """{'jamesbrine': 1063843, ...} + RAM aproximada. Va al log."""
        out = {name: len(src) for name, src in self._lists.items()}
        ram_bytes = sum(src.nbytes() for src in self._lists.values())
        out["_ram_mb"] = round(ram_bytes / 1e6, 2)
        return out
