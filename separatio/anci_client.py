"""
anci_client.py — Cliente de la API pública de ciberseguridad de ANCI (Chile).

`https://csirt.gob.cl/api/v1/` es la API de la Agencia Nacional de Ciberseguridad:
**sin API key y sin registro**. Cubre los cinco endpoints que publica —`alerts`,
`news`, `documents`, `events`, `galleries`— aunque el enricher de Stage 2.7 use
tres: tener el cliente completo es lo que permite investigar a mano por CLI sin
arrancar el pipeline.

**Licencia CC BY-SA 4.0: la atribución es obligatoria.** El nombre visible de la
fuente ("CSIRT Chile (ANCI)") lo pone `enrichers/anci.py`, que es quien la mete
en el informe.

Módulo hoja al estilo de `miniflux_client.py`: **no importa `config` ni
`pipeline`**, así que se testea suelto y sin montar el entorno.

Cinco cosas medidas contra la API el 2026-08-19 que condicionan este diseño
(regla del proyecto: gana la máquina, no el documento):

  1. **`/alerts/` NO viene en orden de publicación**, aunque su `description` lo
     afirme. Viene por `latest_revision_created_at` desc: en la página 1 real hay
     1049 pares invertidos respecto de `date` y 0 respecto de la revisión. Por eso
     `alerts()` **corta el paginado por revisión** (el orden real) y deja el filtro
     por fecha de publicación al llamador. Es correcto y termina: publicar crea
     revisión, así que `revisión >= date` siempre y toda alerta publicada dentro
     de la ventana aparece antes del primer ítem con revisión anterior al corte.
  2. Por lo mismo **no se usan `from_date`/`to_date`**: filtran por fecha de
     revisión, así que devuelven alertas viejas revisadas ayer y omiten alertas
     publicadas dentro del rango que nadie tocó.
  3. **`/news/` no tiene orden alguno**: la noticia más nueva (2026-08-17) estaba
     en la página 3 de 3. Hay que paginar entero y ordenar en local.
  4. **`/documents/` no trae fecha.** "Qué es nuevo" se resuelve por diff contra
     el snapshot de la corrida anterior (lo hace el enricher).
  5. **Hay rate limit no documentado, detrás de Cloudflare**: se dispara con una
     decena de peticiones seguidas y responde `429` o un cuerpo de texto plano
     `error code: 1015` que **no es JSON**. De ahí la caché en disco con TTL, la
     pausa entre páginas y que un cuerpo no-JSON levante `AnciError` con el
     fragmento en vez de un traceback de `json.decoder`.

`page_size` topea en **100 en silencio** (pedir 200 devuelve 100, sin error).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from separatio import net

logger = logging.getLogger(__name__)

BASE_URL = "https://csirt.gob.cl/api/v1/"
USER_AGENT = "separatio-pipeline (homelab CTI)"

# Tope real del backend: pedir más devuelve 100 igual, sin error.
MAX_PAGE_SIZE = 100

# TTL por endpoint, en segundos. Las alertas son lo único que cambia a diario;
# el catálogo de documentos se mueve una vez al mes.
DEFAULT_TTL = {
    "alerts":    6 * 3600,
    "news":      24 * 3600,
    "documents": 7 * 24 * 3600,
    "events":    24 * 3600,
    "galleries": 7 * 24 * 3600,
}

# Tipos de IOC del vocabulario de ANCI que se pueden cruzar contra los IOCs de
# los artículos, mapeados al `kind` de `enrichment.IocVerdict`. Los que quedan
# fuera —mitre-attck, asunto-email, comando, ruta-de-archivo, clave-de-registro,
# botnet— no son indicadores de red ni de fichero: cruzarlos sería ruido.
CROSSABLE_IOCS = {
    "url":     "url",
    "ipv4":    "ip",
    "ipv6":    "ip",
    "dominio": "domain",
    "sha256":  "hash",
    "sha1":    "hash",
    "md5":     "hash",
}


class AnciError(RuntimeError):
    """Fallo hablando con la API de ANCI (cuerpo no-JSON, forma inesperada…)."""


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _s(value) -> str:
    """Cualquier cosa -> str limpio. La API manda `null` en campos opcionales."""
    return "" if value is None else str(value).strip()


def _list(value) -> list:
    return value if isinstance(value, list) else []


def parse_ts(value) -> datetime | None:
    """ISO-8601 de la API -> datetime con tz. `None` si no se puede."""
    text = _s(value)
    if not text:
        return None
    try:
        ts = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def parse_epss(value) -> float | None:
    """"87.4480%" -> 87.448. La API lo manda como texto con signo de porcentaje."""
    text = _s(value).rstrip("%")
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────
# MODELOS
# ─────────────────────────────────────────────────────────
# Todos los `from_api` son tolerantes a propósito: campo que falta -> default,
# campo nuevo -> ignorado. Es la API de un tercero y va a cambiar sin avisar.

@dataclass(frozen=True)
class Ioc:
    ioc_type: str
    value: str
    comment: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Ioc":
        return cls(ioc_type=_s(d.get("ioc_type")).lower(),
                   value=_s(d.get("value")),
                   comment=_s(d.get("comment")))

    @property
    def kind(self) -> str:
        """El `kind` de `IocVerdict`, o "" si no es un IOC cruzable."""
        return CROSSABLE_IOCS.get(self.ioc_type, "")


@dataclass(frozen=True)
class Vulnerability:
    code: str
    source: str = ""
    url: str = ""
    cvss: str = ""
    epss: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Vulnerability":
        return cls(code=_s(d.get("code")).upper(), source=_s(d.get("source")),
                   url=_s(d.get("url")), cvss=_s(d.get("cvss")),
                   epss=_s(d.get("epss")))

    @property
    def epss_pct(self) -> float | None:
        return parse_epss(self.epss)


@dataclass(frozen=True)
class Product:
    name: str
    versions: tuple[str, ...] = ()

    @classmethod
    def from_api(cls, d: dict) -> "Product":
        return cls(name=_s(d.get("name")),
                   versions=tuple(_s(v) for v in _list(d.get("versions"))))


@dataclass(frozen=True)
class Update:
    date: str = ""
    description: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Update":
        return cls(date=_s(d.get("date")), description=_s(d.get("description")))


@dataclass(frozen=True)
class Evidence:
    image: str = ""
    caption: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Evidence":
        return cls(image=_s(d.get("image")), caption=_s(d.get("caption")))


@dataclass(frozen=True)
class Alert:
    code: str
    title: str = ""
    incident_type: str = ""
    tlp: str = ""
    category: str = ""
    date: str = ""                 # fecha de PUBLICACIÓN (la que importa)
    revised: str = ""              # latest_revision_created_at (el orden real)
    general_description: str = ""
    specific_description: str = ""
    mitigation: str = ""
    tags: tuple[str, ...] = ()
    affected_entities: tuple[str, ...] = ()
    iocs: tuple[Ioc, ...] = ()
    vulnerabilities: tuple[Vulnerability, ...] = ()
    vulnerable_products: tuple[Product, ...] = ()
    updates: tuple[Update, ...] = ()
    evidences: tuple[Evidence, ...] = ()

    @classmethod
    def from_api(cls, d: dict) -> "Alert":
        return cls(
            code=_s(d.get("code")),
            title=_s(d.get("title")),
            incident_type=_s(d.get("incident_type")),
            tlp=_s(d.get("tlp")),
            category=_s(d.get("category")),
            date=_s(d.get("date")),
            revised=_s(d.get("latest_revision_created_at")),
            general_description=_s(d.get("general_description")),
            specific_description=_s(d.get("specific_description")),
            mitigation=_s(d.get("mitigation")),
            tags=tuple(_s(t) for t in _list(d.get("tags"))),
            affected_entities=tuple(_s(e) for e in _list(d.get("affected_entities"))),
            iocs=tuple(Ioc.from_api(i) for i in _list(d.get("iocs")) if isinstance(i, dict)),
            vulnerabilities=tuple(Vulnerability.from_api(v)
                                  for v in _list(d.get("vulnerabilities"))
                                  if isinstance(v, dict) and _s(v.get("code"))),
            vulnerable_products=tuple(Product.from_api(p)
                                      for p in _list(d.get("vulnerable_products"))
                                      if isinstance(p, dict)),
            updates=tuple(Update.from_api(u) for u in _list(d.get("updates"))
                          if isinstance(u, dict)),
            evidences=tuple(Evidence.from_api(e) for e in _list(d.get("evidences"))
                            if isinstance(e, dict)),
        )

    @property
    def published_at(self) -> datetime | None:
        return parse_ts(self.date)

    @property
    def revised_at(self) -> datetime | None:
        return parse_ts(self.revised)

    @property
    def day(self) -> str:
        return self.date[:10]

    def crossable_iocs(self) -> list[Ioc]:
        """Los IOCs que tiene sentido cruzar contra los de los artículos."""
        return [i for i in self.iocs if i.kind and i.value]

    def cve_map(self) -> dict[str, Vulnerability]:
        """CVE en mayúsculas -> su vulnerabilidad (con CVSS y EPSS)."""
        return {v.code: v for v in self.vulnerabilities if v.code}


@dataclass(frozen=True)
class NewsArticle:
    title: str = ""
    url: str = ""
    date: str = ""
    body: str = ""
    category: str = ""
    tags: tuple[str, ...] = ()

    @classmethod
    def from_api(cls, d: dict) -> "NewsArticle":
        return cls(title=_s(d.get("title")), url=_s(d.get("url")),
                   date=_s(d.get("date")), body=_s(d.get("body")),
                   category=_s(d.get("category")),
                   tags=tuple(_s(t) for t in _list(d.get("tags"))))

    @property
    def published_at(self) -> datetime | None:
        return parse_ts(self.date)


@dataclass(frozen=True)
class Document:
    title: str = ""
    file: str = ""
    description: str = ""
    category: str = ""
    tags: tuple[str, ...] = ()

    @classmethod
    def from_api(cls, d: dict) -> "Document":
        return cls(title=_s(d.get("title")), file=_s(d.get("file")),
                   description=_s(d.get("description")),
                   category=_s(d.get("category")),
                   tags=tuple(_s(t) for t in _list(d.get("tags"))))

    @property
    def root_category(self) -> str:
        """`boletines/ediciones-anteriores` -> `boletines`."""
        return self.category.split("/")[0]

    @property
    def key(self) -> str:
        """Identidad estable para el diff entre corridas (no hay fecha)."""
        return self.file or self.title


@dataclass(frozen=True)
class Event:
    title: str = ""
    starts: str = ""
    ends: str = ""
    location: str = ""
    location_detail: str = ""
    registration_link: str = ""
    more_info_link: str = ""
    category: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Event":
        return cls(title=_s(d.get("title")), starts=_s(d.get("starts")),
                   ends=_s(d.get("ends")), location=_s(d.get("location")),
                   location_detail=_s(d.get("location_detail")),
                   registration_link=_s(d.get("registration_link")),
                   more_info_link=_s(d.get("more_info_link")),
                   category=_s(d.get("category")))

    @property
    def starts_at(self) -> datetime | None:
        return parse_ts(self.starts)


@dataclass(frozen=True)
class Gallery:
    title: str = ""
    images: tuple[tuple[str, str], ...] = ()   # (image, caption)

    @classmethod
    def from_api(cls, d: dict) -> "Gallery":
        return cls(title=_s(d.get("title")),
                   images=tuple((_s(i.get("image")), _s(i.get("caption")))
                                for i in _list(d.get("gallery_images"))
                                if isinstance(i, dict)))


# ─────────────────────────────────────────────────────────
# CLIENTE
# ─────────────────────────────────────────────────────────

@dataclass
class AnciClient:
    """Cliente HTTP + caché en disco de la API pública de ANCI.

    `cache_dir=None` desactiva la caché (útil en tests y en el CLI con
    `--no-cache`). `force_refresh` ignora la copia fresca pero sigue
    escribiéndola, y sigue valiendo como red de seguridad si la API falla."""

    base_url: str = BASE_URL
    timeout: int = 20
    page_size: int = MAX_PAGE_SIZE
    max_pages: int = 10
    pause: float = 2.0
    cache_dir: str | os.PathLike | None = None
    ttl: dict = field(default_factory=lambda: dict(DEFAULT_TTL))
    force_refresh: bool = False
    user_agent: str = USER_AGENT
    requests_made: int = field(default=0, init=False)
    _last_request: float = field(default=0.0, init=False, repr=False)

    # ── HTTP ──────────────────────────────────────────────

    def _throttle(self) -> None:
        """Deja pasar como mucho una petición cada `pause` segundos.

        Va acá y no en `_paged` porque el rate limit de Cloudflare cuenta
        peticiones, no páginas: una corrida que pide alertas + noticias +
        documentos encadena tres paginados y era ahí donde saltaba el 429
        (visto en la verificación del 2026-08-19). Como mide contra la última
        petición real, no cobra nada cuando las llamadas ya vienen espaciadas."""
        if not self.pause:
            return
        espera = self.pause - (time.monotonic() - self._last_request)
        if espera > 0:
            time.sleep(espera)

    def _get(self, endpoint: str, params: dict) -> dict:
        url = self.base_url.rstrip("/") + "/" + endpoint.strip("/") + "/"
        self._throttle()
        resp = net.request_with_retry(
            "GET", url, params=params,
            headers={"User-Agent": self.user_agent}, timeout=self.timeout,
        )
        self._last_request = time.monotonic()
        self.requests_made += 1
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError as e:
            # Cloudflare responde `error code: 1015` en texto plano cuando se
            # dispara el rate limit no documentado (hallazgo 5).
            snippet = _s(getattr(resp, "text", ""))[:80].replace("\n", " ")
            raise AnciError(f"{url}: respuesta no-JSON "
                            f"(HTTP {resp.status_code}): {snippet!r}") from e
        if not isinstance(data, dict):
            raise AnciError(f"{url}: se esperaba un objeto, "
                            f"vino {type(data).__name__}")
        return data

    def _paged(self, endpoint: str,
               stop: Callable[[list[dict]], bool] | None = None) -> list[dict]:
        """Pagina `endpoint` hasta agotarlo o hasta que `stop(pagina)` diga basta.

        `stop` recibe los ítems crudos de la página **ya acumulados** y decide si
        vale la pena pedir la siguiente; se usa para cortar por revisión en
        `/alerts/` (hallazgo 1)."""
        items: list[dict] = []
        size = min(self.page_size, MAX_PAGE_SIZE)
        for page in range(1, self.max_pages + 1):
            data = self._get(endpoint, {"page": page, "page_size": size})
            batch = [i for i in (data.get("items") or []) if isinstance(i, dict)]
            if not batch:
                break
            items += batch
            total = int(data.get("count") or 0)
            if stop is not None and stop(batch):
                break
            if len(batch) < size or (total and len(items) >= total):
                break
        else:
            logger.warning(f"    ANCI: {endpoint} cortado por el tope de "
                           f"{self.max_pages} páginas ({len(items)} ítems)")
        return items

    # ── CACHÉ ─────────────────────────────────────────────

    def _cache_file(self, endpoint: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return Path(self.cache_dir) / f"{endpoint}.json"

    @staticmethod
    def _read_cache(path: Path) -> dict | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) and isinstance(data.get("items"), list) else None

    @staticmethod
    def _write_cache(path: Path, items: list[dict]) -> None:
        """Escritura atómica (mismo criterio que `history.save_history`)."""
        payload = {
            "fetched": datetime.now(timezone.utc).isoformat(),
            "count": len(items),
            "items": items,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except OSError as e:
            logger.warning(f"    ANCI: no se pudo escribir la caché {path}: {e}")

    def _cached(self, endpoint: str, fetch: Callable[[], list[dict]]) -> list[dict]:
        """Caché con TTL y **fail-open a copia vencida**, igual que `LocalLists`:
        si la API falla y hay copia vieja, se usa esa antes que quedarse sin dato."""
        path = self._cache_file(endpoint)
        cached = self._read_cache(path) if path is not None else None
        if cached is not None and not self.force_refresh:
            age = self._age_seconds(cached)
            if age is not None and age < self.ttl.get(endpoint, 0):
                logger.debug(f"    ANCI: {endpoint} desde caché "
                             f"({len(cached['items'])} ítems, {age / 3600:.1f} h)")
                return cached["items"]
        try:
            items = fetch()
        except Exception as e:
            if cached is not None:
                logger.warning(f"    ANCI: {endpoint} falló ({e}); se usa la "
                               f"copia vencida de la caché")
                return cached["items"]
            raise
        if path is not None:
            self._write_cache(path, items)
        return items

    @staticmethod
    def _age_seconds(cached: dict) -> float | None:
        ts = parse_ts(cached.get("fetched"))
        if ts is None:
            return None
        return (datetime.now(timezone.utc) - ts).total_seconds()

    # ── ENDPOINTS ─────────────────────────────────────────

    def alerts(self, since: datetime | None = None) -> list[Alert]:
        """Alertas, más recientes primero **por fecha de publicación**.

        `since` acota el paginado: se dejan de pedir páginas cuando la revisión
        más vieja de la última página queda antes del corte. Ojo, el corte va por
        revisión porque **ése** es el orden real del listado (hallazgo 1); el
        filtro por publicación se aplica después, ya en memoria."""
        def stop(batch: list[dict]) -> bool:
            if since is None:
                return False
            revisions = [ts for i in batch
                         if (ts := parse_ts(i.get("latest_revision_created_at")))]
            return bool(revisions) and min(revisions) < since

        raw = self._cached("alerts", lambda: self._paged("alerts", stop=stop))
        alerts = [Alert.from_api(a) for a in raw]
        if since is not None:
            alerts = [a for a in alerts
                      if (ts := a.published_at) is not None and ts >= since]
        alerts.sort(key=lambda a: a.date, reverse=True)
        return alerts

    def news(self, since: datetime | None = None) -> list[NewsArticle]:
        """Noticias, más recientes primero.

        Se pagina **entero** a propósito: el endpoint no devuelve orden alguno y
        la noticia más nueva puede estar en la última página (hallazgo 3)."""
        raw = self._cached("news", lambda: self._paged("news"))
        items = [NewsArticle.from_api(n) for n in raw]
        if since is not None:
            items = [n for n in items
                     if (ts := n.published_at) is not None and ts >= since]
        items.sort(key=lambda n: n.date, reverse=True)
        return items

    def documents(self, categories: Iterable[str] | None = None) -> list[Document]:
        """Documentos (boletines, informes). Sin fecha en el esquema: el "qué es
        nuevo" se resuelve por diff contra la corrida anterior (hallazgo 4)."""
        raw = self._cached("documents", lambda: self._paged("documents"))
        docs = [Document.from_api(d) for d in raw]
        if categories is not None:
            allowed = {c.strip().lower() for c in categories if _s(c)}
            docs = [d for d in docs if d.root_category.lower() in allowed]
        return docs

    def events(self, upcoming_only: bool = False) -> list[Event]:
        raw = self._cached("events", lambda: self._paged("events"))
        items = [Event.from_api(e) for e in raw]
        if upcoming_only:
            now = datetime.now(timezone.utc)
            items = [e for e in items
                     if (ts := e.starts_at) is not None and ts >= now]
        items.sort(key=lambda e: e.starts)
        return items

    def galleries(self) -> list[Gallery]:
        raw = self._cached("galleries", lambda: self._paged("galleries"))
        return [Gallery.from_api(g) for g in raw]


# ─────────────────────────────────────────────────────────
# VOLCADO LOCAL DE IOCs
# ─────────────────────────────────────────────────────────

EXPORT_FIELDS = ["code", "date", "tlp", "incident_type", "title",
                 "ioc_type", "value", "comment"]

# Listas planas por tipo, listas para consumir desde un proxy o un firewall.
_LIST_FILES = {
    "ips":     ("ipv4", "ipv6"),
    "domains": ("dominio",),
    "urls":    ("url",),
    "hashes":  ("sha256", "sha1", "md5"),
}


def export_iocs(alerts: list[Alert], out_dir: str | os.PathLike,
                prefix: str = "anci") -> dict[str, str]:
    """Vuelca los IOCs de `alerts` a CSV + listas por tipo. Devuelve las rutas.

    Deduplica por `(code, value)`: la misma URL puede aparecer en dos alertas
    distintas y las dos son información, pero repetida dentro de una alerta no."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for a in alerts:
        for ioc in a.iocs:
            key = (a.code, ioc.value)
            if not ioc.value or key in seen:
                continue
            seen.add(key)
            rows.append({
                "code": a.code, "date": a.day, "tlp": a.tlp,
                "incident_type": a.incident_type, "title": a.title,
                "ioc_type": ioc.ioc_type, "value": ioc.value,
                "comment": ioc.comment,
            })

    paths: dict[str, str] = {}
    csv_path = out / f"{prefix}-iocs.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    paths["csv"] = str(csv_path)

    for name, types in _LIST_FILES.items():
        values = sorted({r["value"] for r in rows if r["ioc_type"] in types})
        path = out / f"{prefix}-{name}.txt"
        path.write_text("".join(f"{v}\n" for v in values), encoding="utf-8")
        paths[name] = str(path)

    logger.info(f"ANCI: {len(rows)} IOCs exportados → {csv_path}")
    return paths


# ─────────────────────────────────────────────────────────
# CLI — investigación manual, sin arrancar el pipeline
# ─────────────────────────────────────────────────────────

def _build_client(args) -> AnciClient:
    return AnciClient(
        base_url=args.base_url,
        cache_dir=None if args.no_cache else args.cache_dir,
        force_refresh=args.refresh,
        timeout=args.timeout,
    )


def _since(args) -> datetime | None:
    if not args.since:
        return None
    return datetime.fromisoformat(args.since).replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m separatio.anci_client",
        description="Cliente de la API pública de ANCI/CSIRT Chile "
                    "(datos CC BY-SA 4.0).")
    parser.add_argument("--stats", action="store_true",
                        help="resumen del corpus (alertas, IOCs, CVEs)")
    parser.add_argument("--export", action="store_true",
                        help="volcar los IOCs a CSV + listas por tipo")
    parser.add_argument("--endpoint", choices=["alerts", "news", "documents",
                                               "events", "galleries"],
                        help="volcar un endpoint crudo a stdout (JSON)")
    parser.add_argument("--since", metavar="AAAA-MM-DD",
                        help="acotar por fecha de publicación")
    parser.add_argument("--days", type=int, default=90,
                        help="ventana por defecto en días (default: 90)")
    parser.add_argument("--limit", type=int, default=20,
                        help="ítems a mostrar con --endpoint (default: 20)")
    parser.add_argument("--out", default="data/feeds",
                        help="destino de --export (default: data/feeds)")
    parser.add_argument("--cache-dir", default="data/feeds/anci")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--refresh", action="store_true",
                        help="ignorar la caché fresca y volver a pedir")
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    client = _build_client(args)
    since = _since(args) or (datetime.now(timezone.utc) - timedelta(days=args.days))

    if not (args.stats or args.export or args.endpoint):
        args.stats = True

    if args.endpoint:
        getter = {
            "alerts":    lambda: [a.__dict__ for a in client.alerts(since)],
            "news":      lambda: [n.__dict__ for n in client.news(since)],
            "documents": lambda: [d.__dict__ for d in client.documents()],
            "events":    lambda: [e.__dict__ for e in client.events()],
            "galleries": lambda: [g.__dict__ for g in client.galleries()],
        }[args.endpoint]
        print(json.dumps(getter()[:args.limit], ensure_ascii=False,
                         indent=2, default=str))

    if args.stats:
        alerts = client.alerts(since)
        iocs = [i for a in alerts for i in a.iocs]
        cves = {v.code for a in alerts for v in a.vulnerabilities}
        by_type: dict[str, int] = {}
        for i in iocs:
            by_type[i.ioc_type] = by_type.get(i.ioc_type, 0) + 1
        by_incident: dict[str, int] = {}
        for a in alerts:
            by_incident[a.incident_type] = by_incident.get(a.incident_type, 0) + 1
        print(f"\nDesde {since.date()} — {len(alerts)} alertas, "
              f"{len(iocs)} IOCs, {len(cves)} CVEs")
        print("\n  Por tipo de alerta:")
        for k, n in sorted(by_incident.items(), key=lambda kv: -kv[1]):
            print(f"    {n:5}  {k}")
        print("\n  Por tipo de IOC:")
        for k, n in sorted(by_type.items(), key=lambda kv: -kv[1]):
            print(f"    {n:5}  {k}")

    if args.export:
        alerts = client.alerts(since)
        paths = export_iocs(alerts, args.out)
        for name, path in paths.items():
            print(f"  {name:8} → {path}")

    print(f"\n  peticiones HTTP gastadas: {client.requests_made}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
