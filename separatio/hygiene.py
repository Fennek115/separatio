"""
hygiene.py — higiene de la entrada del dato propio (F-A del rework).

Clasifica cada IP que aparece en los logs del honeypot en tres categorías que
significan cosas distintas y por eso se tratan distinto:

  self     — infraestructura propia (el laptop, la IP pública de casa, el CT).
             NO es dato: se descarta y sólo se cuenta.
  scanner  — escáner de investigación conocido (Censys, Shodan, Shadowserver…).
             SÍ es dato, pero no es un ataque: se **etiqueta**, no se descarta.
             Saber que Shadowserver te escanea es información válida; meterlo en
             `iocs.csv` como indicador de compromiso, no.
  unknown  — todo lo demás. El subconjunto interesante, el que merece gastar
             cuota de API en las fases siguientes.

Sin esto, todas las fases del rework destilan ruido con cariño: la primera
corrida del colector reportó como atacante al laptop del propio usuario — el
100 % del dataset. (La IP concreta vive en `OWN_IPS`, en el entorno: el repo es
público.)

Dos clasificadores, en orden de coste:

  1. CIDR publicadas por el proveedor. Instantáneo, pero **sólo Censys publica
     una lista consultable**; el resto no la publica o rota IPs de nube (Rapid7
     Sonar corre en EC2 con IPs no estáticas). Verificado el 2026-08-09.
  2. PTR (rDNS). Es el clasificador que **no se pudre**: estos escáneres ponen
     un PTR que dice literalmente quiénes son (`…censys-scanner.com`,
     `soda.census.shodan.io`, `recyber.net` — resueltos en vivo el 2026-08-09).
     Cuesta una consulta DNS por IP nueva, sin cuota y cacheada en memoria.

Sólo biblioteca estándar, a propósito: este módulo lo usa el colector, que corre
en el CT 113 con el `python3` del sistema, sin venv y sin dependencias.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# ESCÁNERES DE INVESTIGACIÓN CONOCIDOS
# ─────────────────────────────────────────────
# Estas listas etiquetan, no filtran: una entrada de más se ve en el dato (el
# nombre del escáner queda escrito en attackers.json), no desaparece en silencio.

# CIDR publicadas oficialmente por el proveedor.
# Censys: https://support.censys.io/hc/en-us/articles/360043177092-Opt-Out-of-Data-Collection
#         traído por HTTP el 2026-08-09; es el único proveedor del lote con una
#         lista completa y consultable en su web.
SCANNER_CIDRS: dict[str, tuple[str, ...]] = {
    "censys": (
        "66.132.148.0/24", "66.132.153.0/24", "66.132.159.0/24",
        "66.132.172.0/24", "66.132.186.0/24", "66.132.195.0/24",
        "66.132.224.0/24", "162.142.125.0/24", "167.94.138.0/24",
        "167.94.145.0/24", "167.94.146.0/24", "167.248.133.0/24",
        "199.45.154.0/24", "199.45.155.0/24", "206.168.34.0/24",
        "206.168.35.0/24",
    ),
}

# Sufijos de PTR (rDNS). Convención estable de cada proyecto de escaneo.
# Verificados en vivo el 2026-08-09 (censys-scanner.com, census.shodan.io,
# recyber.net); el resto son las convenciones publicadas por cada proyecto.
SCANNER_PTR_SUFFIXES: dict[str, tuple[str, ...]] = {
    "censys":           ("censys-scanner.com", "censys.io"),
    "shodan":           ("shodan.io",),
    "shadowserver":     ("shadowserver.org",),
    "onyphe":           ("onyphe.net", "onyphe.io"),
    "binaryedge":       ("binaryedge.ninja", "binaryedge.io"),
    "rapid7":           ("rapid7.com",),
    "stretchoid":       ("stretchoid.com",),
    "driftnet":         ("internet-measurement.com", "driftnet.io"),
    "leakix":           ("leakix.net", "leakix.org"),
    "projectdiscovery": ("projectdiscovery.io",),
    "netsystems":       ("netsystemsresearch.com",),
    "recyber":          ("recyber.net",),
    "alphastrike":      ("alphastrike.io",),
    "criminalip":       ("criminalip.com",),
    "ipip":             ("security.ipip.net",),
    "bitsight":         ("bitsight.com",),
    "xpanse":           ("expanseinc.com",),
    "academic":         ("internet-census.org", "rwth-aachen.de",
                         "bufferover.run", "sfj.corp.censys.io"),
}


# ─────────────────────────────────────────────
# IPs PROPIAS
# ─────────────────────────────────────────────

def parse_ip_list(raw: str) -> list[str]:
    """Parsea 'a.b.c.d, x.y.z.w/24' → lista de literales. Tolera vacío y basura."""
    if not raw:
        return []
    out = []
    for tok in raw.replace(";", ",").replace("\n", ",").split(","):
        tok = tok.strip()
        if tok and not tok.startswith("#"):
            out.append(tok)
    return out


def own_ips_from_env(env_var: str = "OWN_IPS") -> list[str]:
    """IPs/CIDR propias declaradas en el entorno (el .env, o intel.env en el CT).

    Van al entorno y no al repo porque el repo es público y son la dirección de
    casa."""
    return parse_ip_list(os.getenv(env_var, ""))


def resolve_public_ip(url: str, timeout: float = 5.0,
                      cache_path: str | Path | None = None) -> str | None:
    """Resuelve la IP pública actual contra un servicio externo.

    Las IPs propias son dinámicas (la de casa cambia sola); una allowlist
    estática se pudre en silencio y el dataset se vuelve a contaminar. Esto la
    mantiene sola, con una petición por corrida.

    **Fail-open hacia el último valor conocido**: si la consulta falla se
    devuelve lo cacheado en disco. Excluir de más una IP que ya era nuestra es
    mucho menos malo que volver a contar el laptop como atacante.
    """
    ip = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "separatio-hygiene"})
        with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310
            ip = r.read(64).decode("utf-8", "ignore").strip()
        ipaddress.ip_address(ip)          # valida; si no es una IP, salta al except
    except Exception as e:
        logger.debug(f"    hygiene: no se pudo resolver la IP pública ({e})")
        ip = None

    if cache_path:
        cache = Path(cache_path)
        if ip:
            try:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(ip + "\n")
            except OSError as e:
                logger.debug(f"    hygiene: no se pudo cachear la IP propia ({e})")
        else:
            try:
                cached = cache.read_text().strip()
                ipaddress.ip_address(cached)
                logger.debug(f"    hygiene: usando IP propia cacheada {cached}")
                return cached
            except (OSError, ValueError):
                return None
    return ip


# ─────────────────────────────────────────────
# EL CLASIFICADOR
# ─────────────────────────────────────────────

SELF = "self"
SCANNER = "scanner"
UNKNOWN = "unknown"


def _reverse_lookup(ip: str, timeout: float) -> str | None:
    """PTR con tope de reloj real.

    `socket.gethostbyaddr` no acepta timeout (resuelve por libc) y puede quedarse
    colgado: el proyecto ya se quemó con un fetch sin tope duro (37 min dormido,
    2026-08-08). Se corre en un thread daemon que se abandona al vencer."""
    box: list[str] = []

    def _work():
        try:
            box.append(socket.gethostbyaddr(ip)[0])
        except Exception:
            pass

    t = threading.Thread(target=_work, daemon=True)
    t.start()
    t.join(timeout)
    return box[0].lower() if box else None


class IpClassifier:
    """Clasifica IPs en self / scanner / unknown. Reusable y cacheado por instancia."""

    def __init__(self, own_ips=(), classify_scanners: bool = True,
                 use_ptr: bool = True, ptr_timeout: float = 3.0,
                 ptr_max_lookups: int = 500):
        self._own_exact: set[str] = set()
        self._own_nets: list = []
        for entry in own_ips:
            self._add_own(entry)

        self.classify_scanners = classify_scanners
        self.use_ptr = use_ptr
        self.ptr_timeout = ptr_timeout
        self.ptr_max_lookups = ptr_max_lookups
        self._ptr_done = 0

        self._scanner_nets: list[tuple] = []
        if classify_scanners:
            for name, cidrs in SCANNER_CIDRS.items():
                for c in cidrs:
                    try:
                        self._scanner_nets.append((ipaddress.ip_network(c), name))
                    except ValueError:
                        logger.warning(f"    hygiene: CIDR de escáner inválida ignorada: {c}")

        self._cache: dict[str, tuple[str, str | None]] = {}

    def _add_own(self, entry: str) -> None:
        entry = (entry or "").strip()
        if not entry:
            return
        try:
            if "/" in entry:
                self._own_nets.append(ipaddress.ip_network(entry, strict=False))
            else:
                self._own_exact.add(str(ipaddress.ip_address(entry)))
        except ValueError:
            logger.warning(f"    hygiene: entrada de OWN_IPS inválida ignorada: {entry!r}")

    def add_own(self, entry: str) -> None:
        """Suma una IP propia después de construir el clasificador (p.ej. la resuelta)."""
        before = (len(self._own_exact), len(self._own_nets))
        self._add_own(entry)
        if (len(self._own_exact), len(self._own_nets)) != before:
            self._cache.clear()

    @property
    def own_count(self) -> int:
        return len(self._own_exact) + len(self._own_nets)

    def classify(self, ip: str) -> tuple[str, str | None]:
        """Devuelve (clase, nombre). `nombre` sólo viene informado para escáneres."""
        if not ip:
            return (UNKNOWN, None)
        hit = self._cache.get(ip)
        if hit:
            return hit
        result = self._classify_uncached(ip)
        self._cache[ip] = result
        return result

    def _classify_uncached(self, ip: str) -> tuple[str, str | None]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return (UNKNOWN, None)

        if str(addr) in self._own_exact:
            return (SELF, None)
        for net in self._own_nets:
            if addr.version == net.version and addr in net:
                return (SELF, None)

        if not self.classify_scanners:
            return (UNKNOWN, None)

        for net, name in self._scanner_nets:
            if addr.version == net.version and addr in net:
                return (SCANNER, name)

        if self.use_ptr and self._ptr_done < self.ptr_max_lookups:
            self._ptr_done += 1
            ptr = _reverse_lookup(ip, self.ptr_timeout)
            if ptr:
                host = ptr.rstrip(".")
                for name, suffixes in SCANNER_PTR_SUFFIXES.items():
                    for suf in suffixes:
                        if host == suf or host.endswith("." + suf):
                            return (SCANNER, name)

        return (UNKNOWN, None)


def build_classifier(settings=None) -> IpClassifier:
    """Construye el clasificador desde un `Settings` (o el módulo `config`).

    Acepta cualquier objeto que responda a los nombres por `getattr` — desde
    F-G/G-2 lo natural es un `separatio.settings.Settings`, pero el módulo
    `config` sigue sirviendo. Sin nada, cae al entorno, para que el colector
    funcione aunque se lo invoque fuera del paquete.""" 
    def cfg(name, default):
        return getattr(settings, name, default) if settings is not None else default

    own = own_ips_from_env()
    own += parse_ip_list(str(cfg("OWN_IPS", "")))

    clf = IpClassifier(
        own_ips=own,
        classify_scanners=bool(cfg("SCANNER_CLASSIFY", True)),
        use_ptr=bool(cfg("SCANNER_PTR_LOOKUP", True)),
        ptr_timeout=float(cfg("SCANNER_PTR_TIMEOUT", 3.0)),
        ptr_max_lookups=int(cfg("SCANNER_PTR_MAX", 500)),
    )

    if bool(cfg("OWN_IP_RESOLVE", True)):
        resolved = resolve_public_ip(
            str(cfg("OWN_IP_RESOLVE_URL", "https://api.ipify.org")),
            float(cfg("OWN_IP_RESOLVE_TIMEOUT", 5.0)),
            cfg("OWN_IP_CACHE", None),
        )
        if resolved:
            clf.add_own(resolved)

    return clf
