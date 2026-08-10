"""
honeypot_collector.py — consolidación de los logs crudos del honeypot (capa 4).

Toma lo que `tools/pull_honeypot.sh` bajó por SSH a `raw/` y produce los
artefactos que consume el resto del proyecto:

  attackers.json      rolling — lo que lee `enrichers/honeypot.py`
  iocs.csv            export importable por MISP (una fila por IOC)
  events.jsonl        línea de tiempo de técnicas, ordenada por fecha
  payloads/<sha>.bin  corpus content-addressed, deduplicado
  hashes.log          índice del corpus (sha, fecha, sensor, servicio, tamaño, ip)
  by-date/<fecha>/    snapshot inmutable del día, autocontenido

Vivía como heredoc dentro del script de bash; se extrajo a módulo para poder
testearlo (F-A del rework, `docs/fases/F-A.md`). Sólo usa la biblioteca estándar
a propósito: el colector corre en el CT 113 con el `python3` del sistema, sin
venv y sin dependencias.

Uso:  python3 -m separatio.honeypot_collector <RAW_DIR> <OUT_DIR> <WINDOW_HOURS>
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import logging
import re
import sys
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from separatio.hygiene import SCANNER, SELF, build_classifier

logger = logging.getLogger(__name__)

# TCP triviales que NO valen como "payload" archivable (sí como técnica).
TRIVIAL_TCP = re.compile(r'^(PING|INFO|QUIT|COMMAND(\s+DOCS)?|AUTH\b.*|SELECT\s+\d+|'
                         r'CLIENT\s+\S+|ECHO\b.*|HELLO\b.*)\s*$', re.I | re.S)

# Servicios "golosos" de Beelzebub, mapeados desde su Description.
_KINDS = (("docker", "docker"), ("elasticsearch", "elastic"), ("redis", "redis"),
          ("mysql", "mysql"), ("postgres", "postgres"), ("vnc", "vnc"))


def ts(v):
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_cowrie(lines, cutoff, bump, record, att, dl_meta):
    """VM1 Cowrie: eventos con src_ip, HASSH del cliente SSH y descargas en sesión."""
    for line in lines:
        try:
            e = json.loads(line)
        except Exception:
            continue
        when = ts(e.get("timestamp"))
        if when and when < cutoff:
            continue
        ip = e.get("src_ip")
        bump(ip, "cowrie", when, sensor="vm1-cowrie")
        # HASSH: fingerprint del cliente/tooling SSH (el "JA3" del SSH), robusto al
        # cambio de IP. Cowrie lo emite en los eventos de kex.
        h = e.get("hassh")
        if h and ip and public(ip) and ip in att:
            att[ip].setdefault("hassh", set()).add(h)
        eid = e.get("eventid", "")
        if eid == "cowrie.command.input":
            inp = e.get("input") or ""
            record(when, ip, "vm1-cowrie", "ssh", inp,
                   inp.encode(errors="ignore") if len(inp) >= 24 else None)
        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            record(when, ip, "vm1-cowrie", "ssh",
                   f"login {e.get('username')}:{e.get('password')} ({eid.split('.')[-1]})")
        elif eid == "cowrie.session.file_download":
            sh = e.get("shasum")
            if sh:
                dl_meta.setdefault(sh, (ip, when))
            record(when, ip, "vm1-cowrie", "ssh",
                   f"download {e.get('url') or sh}")


def parse_web(lines, cutoff, bump, record):
    """VM1 Web (nginx honey): una línea JSON por request."""
    for line in lines:
        try:
            e = json.loads(line)
        except Exception:
            continue
        when = ts(e.get("ts"))
        if when and when < cutoff:
            continue
        bump(e.get("ip"), "web", when, e.get("uri"), sensor="vm1-web")
        body = e.get("body") or ""
        pb = body.encode(errors="ignore") if body not in ("", "-") else None
        record(when, e.get("ip"), "vm1-web", "web",
               f"{e.get('method','')} {e.get('uri','')}", pb)


def parse_beelzebub(lines, cutoff, bump, record):
    """VM2 Beelzebub: servicios golosos. Cada evento trae event.SourceIp +
    (RequestURI HTTP | Command TCP) + Description."""
    for line in lines:
        try:
            obj = json.loads(line)
        except Exception:
            continue
        ev = obj.get("event")
        if not isinstance(ev, dict):
            continue                         # líneas de arranque ("Init service...") sin evento
        ip = ev.get("SourceIp")
        if not ip:
            continue                         # "End TCP Session" viene sin IP
        when = ts(ev.get("DateTime"))
        if when and when < cutoff:
            continue
        desc = (ev.get("Description") or "").lower()
        kind = next((k for sub, k in _KINDS if sub in desc), "services")
        if ev.get("Protocol") == "HTTP" or ev.get("HTTPMethod"):
            body = ev.get("Body") or ""
            action = f"{ev.get('HTTPMethod','')} {ev.get('RequestURI','')}"
            pb = body.encode(errors="ignore") if body else None
        else:                                # TCP
            cmd = (ev.get("Command") or "").strip()
            action = cmd
            pb = cmd.encode(errors="ignore") if cmd and len(cmd) >= 8 and not TRIVIAL_TCP.match(cmd) else None
        bump(ip, kind, when, action, sensor="vm2-services")
        record(when, ip, "vm2-services", kind, action, pb)


def parse_cowrie_downloads(tarp, dl_meta, klass, payloads, events):
    """VM1 Cowrie: binarios descargados en sesión (2º stage real) al corpus.

    Cowrie los nombra por SHA-256; se hashea de nuevo por las dudas y se atribuye
    a la IP/hora del evento file_download correspondiente."""
    if not tarp.exists() or not tarp.stat().st_size:
        return
    try:
        with tarfile.open(tarp) as tf:
            for m in tf.getmembers():
                if not m.isfile() or not m.size:
                    continue
                f = tf.extractfile(m)
                data = f.read() if f else b""
                if not data:
                    continue
                sha = hashlib.sha256(data).hexdigest()
                payloads.setdefault(sha, data)
                meta = dl_meta.get(sha) or dl_meta.get(Path(m.name).name)
                ip_dl, when_dl = (meta if meta else (None, None))
                if ip_dl and klass(ip_dl)[0] == SELF:
                    continue
                events.append({"ts": when_dl.isoformat() if when_dl else None,
                               "ip": ip_dl or "?", "sensor": "vm1-cowrie",
                               "service": "ssh-download",
                               "action": f"malware sample {sha[:12]}",
                               "sha256": sha, "size": len(data)})
    except Exception:
        pass


def write_artifacts(raw, out, daydir, payload, events, payloads):
    """Escribe attackers.json/iocs.csv (rolling en out/ + snapshot en daydir/),
    la línea de tiempo de eventos y el corpus de payloads content-addressed.
    Devuelve la cantidad de payloads nuevos que entraron al corpus."""
    day = daydir.name
    attackers = payload["attackers"]
    # Los escáneres de investigación NO son indicadores de compromiso: quedan en
    # attackers.json (etiquetados, son dato) pero fuera del export de IOCs.
    ioc_rows = [a for a in attackers if a.get("class") != SCANNER]

    def write_csv(path):
        # CSV listo para importar en MISP (u otras plataformas). El módulo CSVImport
        # de MISP mapea estas columnas; type=ip-src, to_ids=1 = usar para detección.
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["value", "type", "category", "to_ids",
                        "comment", "first_seen", "last_seen"])
            for a in ioc_rows:
                comment = (f"honeypot propio | {a['hits']} hits | "
                           f"servicios: {'+'.join(a['kinds']) or '?'} | "
                           f"sensores: {'+'.join(a['sensors']) or '?'}"
                           + (" | crowdsec" if a["crowdsec"] else ""))
                w.writerow([a["ip"], "ip-src", "Network activity", 1,
                            comment, a.get("first_seen") or "", a.get("last_seen") or ""])
            # HASSH (fingerprint del cliente SSH) como IOC propio, tipo MISP hassh-md5.
            hassh_ips = {}
            for a in ioc_rows:
                for h in a.get("hassh", []):
                    hassh_ips.setdefault(h, []).append(a["ip"])
            for h, ips in hassh_ips.items():
                w.writerow([h, "hassh-md5", "Network activity", 1,
                            f"honeypot propio | cliente SSH visto desde: {', '.join(ips[:8])}",
                            "", ""])

    out.mkdir(parents=True, exist_ok=True)

    # (1) Rolling: lo que lee el enricher de Separatio + CSV "última corrida".
    (out / "attackers.json").write_text(json.dumps(payload, indent=1))
    write_csv(out / "iocs.csv")

    # (2) Snapshot inmutable por fecha (carpeta ordenada, para archivo/forense/MISP).
    (daydir / "raw").mkdir(parents=True, exist_ok=True)
    (daydir / "attackers.json").write_text(json.dumps(payload, indent=1))
    write_csv(daydir / "iocs.csv")
    for name in ("cowrie.json", "web.json", "decisions.json", "beelzebub.json"):
        src = raw / name
        if src.exists() and src.stat().st_size:
            (daydir / "raw" / name).write_text(src.read_text(errors="ignore"))

    # (3) Línea de tiempo de TÉCNICAS (ordenada, por fecha) + rolling.
    if events:
        events.sort(key=lambda x: x["ts"] or "")
        ev_txt = "\n".join(json.dumps(x, ensure_ascii=False) for x in events) + "\n"
        (daydir / "events.jsonl").write_text(ev_txt)
        (out / "events.latest.jsonl").write_text(ev_txt)

    # (4) PAYLOADS crudos, content-addressed por SHA-256:
    #     - corpus deduplicado en payloads/<sha>.bin (para VT/YARA/MalwareBazaar)
    #     - copia del día en by-date/<fecha>/payloads/ (carpeta autocontenida)
    #     - índice hashes.log (sha, fecha, sensor, servicio, tamaño, ip)
    new_payloads = 0
    if payloads:
        pdir_day = daydir / "payloads"; pdir_day.mkdir(parents=True, exist_ok=True)
        pdir_master = out / "payloads"; pdir_master.mkdir(parents=True, exist_ok=True)
        hashlog = out / "hashes.log"
        known = set()
        if hashlog.exists():
            known = {l.split("\t", 1)[0] for l in hashlog.read_text(errors="ignore").splitlines() if l.strip()}
        first_ev = {}
        for x in events:
            if x["sha256"] and x["sha256"] not in first_ev:
                first_ev[x["sha256"]] = x
        with hashlog.open("a") as hl:
            for sha, data in payloads.items():
                (pdir_day / f"{sha}.bin").write_bytes(data)
                master = pdir_master / f"{sha}.bin"
                if not master.exists():
                    master.write_bytes(data)
                if sha not in known:
                    x = first_ev.get(sha, {})
                    hl.write(f"{sha}\t{day}\t{x.get('sensor','?')}\t"
                             f"{x.get('service','?')}\t{len(data)}\t{x.get('ip','?')}\n")
                    new_payloads += 1

    return new_payloads


def consolidate(raw: Path, out: Path, window: int, classifier=None) -> dict:
    """Lee raw/, escribe los artefactos en out/ y devuelve un resumen de la corrida.

    `classifier` es un `hygiene.IpClassifier`; si no se pasa se construye desde
    `separatio.config`. Las IPs propias se descartan (sólo se cuentan) y los
    escáneres de investigación se etiquetan pero no llegan a `iocs.csv` — ver
    `docs/fases/F-A.md`."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window)

    if classifier is None:
        try:
            from separatio import config as _config
        except Exception:
            _config = None
        classifier = build_classifier(_config)

    att = {}
    hyg = {"self_ips": set(), "self_hits": 0, "scanners": {}}

    def klass(ip):
        """(clase, nombre) para una IP ya validada como pública."""
        return classifier.classify(ip)

    def bump(ip, kind, when, uri=None, sensor=None):
        if not ip or not public(ip):
            return
        cls, name = klass(ip)
        if cls == SELF:
            hyg["self_ips"].add(ip)
            hyg["self_hits"] += 1
            return
        a = att.setdefault(ip, {"ip": ip, "hits": 0, "kinds": set(), "sensors": set(),
                                "first_seen": None, "last_seen": None,
                                "sample_uris": set(), "crowdsec": False,
                                "class": cls, "scanner_name": name})
        if cls == SCANNER:
            hyg["scanners"].setdefault(name, set()).add(ip)
        a["hits"] += 1
        a["kinds"].add(kind)
        if sensor:
            a["sensors"].add(sensor)
        if uri:
            a["sample_uris"].add(uri)
        if when:
            w = when.isoformat()
            if not a["first_seen"] or w < a["first_seen"]:
                a["first_seen"] = w
            if not a["last_seen"] or w > a["last_seen"]:
                a["last_seen"] = w

    # --- Payloads + línea de tiempo de técnicas ---
    # events: cada interacción maliciosa (para estudiar TTPs en orden por fecha).
    # payloads: bytes crudos deduplicados por SHA-256 (cuarentena, VT/YARA/MalwareBazaar).
    events = []
    payloads = {}          # sha256 -> bytes (dedup en esta corrida)
    dl_meta = {}           # shasum de descarga Cowrie -> (ip, when) para atribuir el binario

    def record(when, ip, sensor, service, action, payload=None):
        """Registra la técnica (siempre) y, si es sustancial, el payload crudo."""
        if not ip or not public(ip):
            return
        if klass(ip)[0] == SELF:
            return                       # tráfico propio: no es dato, no entra al timeline
        sha = None
        if payload:
            sha = hashlib.sha256(payload).hexdigest()
            payloads.setdefault(sha, payload)
        events.append({"ts": when.isoformat() if when else None, "ip": ip,
                       "sensor": sensor, "service": service,
                       "action": (action or "")[:500],
                       "sha256": sha, "size": len(payload) if payload else 0})

    def lines(name):
        p = raw / name
        return p.read_text(errors="ignore").splitlines() if p.exists() else []

    parse_cowrie(lines("cowrie.json"), cutoff, bump, record, att, dl_meta)
    parse_web(lines("web.json"), cutoff, bump, record)
    parse_beelzebub(lines("beelzebub.json"), cutoff, bump, record)
    parse_cowrie_downloads(raw / "cowrie_downloads.tar", dl_meta, klass, payloads, events)

    # --- CrowdSec (VM1): marcar IPs con decisión ---
    try:
        for d in json.loads((raw / "decisions.json").read_text() or "[]"):
            for dec in d.get("decisions", []) or []:
                ip = dec.get("value")
                if ip in att:
                    att[ip]["crowdsec"] = True
    except Exception:
        pass

    attackers = []
    for a in att.values():
        a["kinds"] = sorted(a["kinds"])
        a["sensors"] = sorted(a["sensors"])
        a["sample_uris"] = sorted(a["sample_uris"])[:5]
        a["hassh"] = sorted(a.get("hassh", []))
        attackers.append(a)
    attackers.sort(key=lambda a: a["hits"], reverse=True)

    generated = datetime.now(timezone.utc)
    hygiene = {
        "self_excluded": len(hyg["self_ips"]),
        "self_hits": hyg["self_hits"],
        "self_ips": sorted(hyg["self_ips"]),
        "scanners": {name: sorted(ips) for name, ips in sorted(hyg["scanners"].items())},
        "unknown_ips": sum(1 for a in attackers if a.get("class") != SCANNER),
    }
    payload = {"generated": generated.isoformat(), "window_hours": window,
               "hygiene": hygiene, "attackers": attackers}

    daydir = out / "by-date" / generated.strftime("%Y-%m-%d")
    new_payloads = write_artifacts(raw, out, daydir, payload, events, payloads)

    # El store es una VISTA de lo que ya está en disco: si falla, se loguea y se
    # sigue. Los artefactos son la fuente de verdad y el backfill puede rehacerlo.
    store_stats = None
    try:
        from separatio.store.db import store as _store
        from separatio.store.ingest import ingest_run
        with _store() as conn:
            if conn is not None:
                store_stats = ingest_run(conn, attackers=payload, events=events,
                                         hashes=None)
    except Exception as e:                       # noqa: BLE001 — nunca romper el pull
        logger.warning(f"[pull] store: no se pudo ingerir ({e})")

    return {"attackers": attackers, "events": events, "payloads": payloads,
            "new_payloads": new_payloads, "daydir": daydir, "out": out,
            "hygiene": hygiene, "store": store_stats}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    raw, out, window = Path(argv[0]), Path(argv[1]), int(argv[2])
    r = consolidate(raw, out, window)

    attackers, events, payloads = r["attackers"], r["events"], r["payloads"]
    h = r["hygiene"]
    cross = sum(1 for a in attackers if len(a["sensors"]) > 1)
    scanner_ips = sum(len(v) for v in h["scanners"].values())
    print(f"[pull] higiene: {h['self_excluded']} IP(s) propia(s) descartada(s) "
          f"({h['self_hits']} hits) · {scanner_ips} escáner(es) etiquetado(s)"
          + (f" [{', '.join(h['scanners'])}]" if h["scanners"] else ""))
    print(f"[pull] {len(attackers)} IPs atacantes públicas "
          f"({cross} vistas por >1 sensor, {h['unknown_ips']} sin clasificar)")
    print(f"[pull]   IOCs:     {out/'attackers.json'} + {out/'iocs.csv'}")
    print(f"[pull]   técnicas: {len(events)} eventos -> {r['daydir']/'events.jsonl'}")
    print(f"[pull]   payloads: {len(payloads)} únicos ({r['new_payloads']} nuevos al corpus) "
          f"-> {out/'payloads'}/ · índice {out/'hashes.log'}")
    print(f"[pull]   por fecha: {r['daydir']}/")
    s = r.get("store")
    if s:
        print(f"[pull]   store: {s['iocs_nuevos']} IOCs nuevos, "
              f"{s['observaciones_nuevas']} observaciones nuevas, "
              f"{s['payloads_nuevos']} payload(s) nuevo(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
