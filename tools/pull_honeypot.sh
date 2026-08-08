#!/usr/bin/env bash
# pull_honeypot.sh — Colector PULL de los honeypots (capa 4 de Separatio).
#
# Corre EN CASA (CT 113 intel o motherbase), se conecta a los honeypots de Oracle
# a buscar los logs y produce data/honeypot/attackers.json para el enricher.
# Los honeypots NO tienen credenciales ni saben de esta máquina: casa inicia todo.
#
# Dos sensores (poblaciones distintas, ver honeypot/PLAN.md):
#   - VM1 (synapse, 161.153.193.0): Cowrie SSH + Nginx web catch-all + CrowdSec.
#   - VM2 (ivory,   146.181.45.153): Beelzebub, servicios "golosos" (Redis,
#     Docker API, Elasticsearch, MySQL, Postgres, VNC). Ver honeypot/VM2-PLAN.md.
#
# Requisitos (una vez):
#   - Claves SSH de solo-lectura: id_oracle_synapse (VM1) e id_oracle_ivory (VM2).
#   - La Security List de OCI debe permitir SSH (22) desde la IP pública de casa
#     (hoy 200.120.126.170; es dinámica). Ver honeypot/DEPLOY.md §OCI.
#
# Uso:  ./tools/pull_honeypot.sh [WINDOW_HOURS]
#   Hosts/claves override por env: VM1_HOST VM1_KEY VM2_HOST VM2_KEY
set -euo pipefail

WINDOW="${1:-24}"
VM1_HOST="${VM1_HOST:-ubuntu@161.153.193.0}"
VM1_KEY="${VM1_KEY:-$HOME/.ssh/id_oracle_synapse}"
VM2_HOST="${VM2_HOST:-ubuntu@146.181.45.153}"
VM2_KEY="${VM2_KEY:-$HOME/.ssh/id_oracle_ivory}"
OUT_DIR="${OUT_DIR:-$(cd "$(dirname "$0")/.." && pwd)/data/honeypot}"
RAW_DIR="${RAW_DIR:-$OUT_DIR/raw}"
mkdir -p "$RAW_DIR"

# NO_PULL=1 salta el SSH y solo re-consolida los raw/ que ya están (para tests).
if [ -z "${NO_PULL:-}" ]; then
  SSH1="ssh -o BatchMode=yes -o ConnectTimeout=15 -i $VM1_KEY $VM1_HOST"
  SSH2="ssh -o BatchMode=yes -o ConnectTimeout=15 -i $VM2_KEY $VM2_HOST"

  echo "[pull] VM1 (Cowrie/Nginx/CrowdSec) desde $VM1_HOST (ventana ${WINDOW}h)..."
  $SSH1 'sudo cat /home/cowrie/cowrie/var/log/cowrie/cowrie.json 2>/dev/null' > "$RAW_DIR/cowrie.json"    || true
  $SSH1 'sudo cat /var/log/nginx/honey.json 2>/dev/null'                       > "$RAW_DIR/web.json"       || true
  $SSH1 'sudo cscli decisions list -o json 2>/dev/null'                        > "$RAW_DIR/decisions.json" || echo "[]" > "$RAW_DIR/decisions.json"
  # Binarios que Cowrie descargó en sesión (2º stage real, nombrados por SHA-256).
  $SSH1 'sudo tar -C /home/cowrie/cowrie/var/lib/cowrie -cf - downloads 2>/dev/null' > "$RAW_DIR/cowrie_downloads.tar" || true

  echo "[pull] VM2 (Beelzebub, servicios golosos) desde $VM2_HOST..."
  $SSH2 'sudo cat /var/lib/beelzebub/logs/beelzebub.json 2>/dev/null'          > "$RAW_DIR/beelzebub.json" || true
fi

# Consolidar a attackers.json (IP -> hits, tipos, sensores, señuelos, crowdsec).
python3 - "$RAW_DIR" "$OUT_DIR" "$WINDOW" <<'PY'
import json, sys, ipaddress, csv, hashlib, re, tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

raw, out, window = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
cutoff = datetime.now(timezone.utc) - timedelta(hours=window)

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

att = {}
def bump(ip, kind, when, uri=None, sensor=None):
    if not ip or not public(ip):
        return
    a = att.setdefault(ip, {"ip": ip, "hits": 0, "kinds": set(), "sensors": set(),
                            "first_seen": None, "last_seen": None,
                            "sample_uris": set(), "crowdsec": False})
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
# TCP triviales que NO valen como "payload" archivable (sí como técnica).
TRIVIAL_TCP = re.compile(r'^(PING|INFO|QUIT|COMMAND(\s+DOCS)?|AUTH\b.*|SELECT\s+\d+|'
                         r'CLIENT\s+\S+|ECHO\b.*|HELLO\b.*)\s*$', re.I | re.S)

def record(when, ip, sensor, service, action, payload=None):
    """Registra la técnica (siempre) y, si es sustancial, el payload crudo."""
    if not ip or not public(ip):
        return
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

# --- VM1 Cowrie: eventos con src_ip ---
for line in lines("cowrie.json"):
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

# --- VM1 Web (nginx honey): una línea JSON por request ---
for line in lines("web.json"):
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

# --- VM2 Beelzebub: servicios golosos ---
# Cada evento trae event.SourceIp + (RequestURI HTTP | Command TCP) + Description.
_KINDS = (("docker", "docker"), ("elasticsearch", "elastic"), ("redis", "redis"),
          ("mysql", "mysql"), ("postgres", "postgres"), ("vnc", "vnc"))
for line in lines("beelzebub.json"):
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

# --- VM1 Cowrie: binarios descargados en sesión (2º stage real) al corpus ---
# Cowrie los nombra por SHA-256; se hashea de nuevo por las dudas y se atribuye
# a la IP/hora del evento file_download correspondiente.
tarp = raw / "cowrie_downloads.tar"
if tarp.exists() and tarp.stat().st_size:
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
                events.append({"ts": when_dl.isoformat() if when_dl else None,
                               "ip": ip_dl or "?", "sensor": "vm1-cowrie",
                               "service": "ssh-download",
                               "action": f"malware sample {sha[:12]}",
                               "sha256": sha, "size": len(data)})
    except Exception:
        pass

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
payload = {"generated": generated.isoformat(), "window_hours": window, "attackers": attackers}

def write_csv(path):
    # CSV listo para importar en MISP (u otras plataformas). El módulo CSVImport
    # de MISP mapea estas columnas; type=ip-src, to_ids=1 = usar para detección.
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["value", "type", "category", "to_ids",
                    "comment", "first_seen", "last_seen"])
        for a in attackers:
            comment = (f"honeypot propio | {a['hits']} hits | "
                       f"servicios: {'+'.join(a['kinds']) or '?'} | "
                       f"sensores: {'+'.join(a['sensors']) or '?'}"
                       + (" | crowdsec" if a["crowdsec"] else ""))
            w.writerow([a["ip"], "ip-src", "Network activity", 1,
                        comment, a.get("first_seen") or "", a.get("last_seen") or ""])
        # HASSH (fingerprint del cliente SSH) como IOC propio, tipo MISP hassh-md5.
        hassh_ips = {}
        for a in attackers:
            for h in a.get("hassh", []):
                hassh_ips.setdefault(h, []).append(a["ip"])
        for h, ips in hassh_ips.items():
            w.writerow([h, "hassh-md5", "Network activity", 1,
                        f"honeypot propio | cliente SSH visto desde: {', '.join(ips[:8])}",
                        "", ""])

# (1) Rolling: lo que lee el enricher de Separatio + CSV "última corrida".
(out / "attackers.json").write_text(json.dumps(payload, indent=1))
write_csv(out / "iocs.csv")

# (2) Snapshot inmutable por fecha (carpeta ordenada, para archivo/forense/MISP).
day = generated.strftime("%Y-%m-%d")
daydir = out / "by-date" / day
(daydir / "raw").mkdir(parents=True, exist_ok=True)
(daydir / "attackers.json").write_text(json.dumps(payload, indent=1))
write_csv(daydir / "iocs.csv")
for name in ("cowrie.json", "web.json", "decisions.json", "beelzebub.json"):
    src = raw / name
    if src.exists() and src.stat().st_size:
        (daydir / "raw" / name).write_text(src.read_text(errors="ignore"))

# (3) Línea de tiempo de TÉCNICAS (ordenada, por fecha) + rolling.
new_payloads = 0
if events:
    events.sort(key=lambda x: x["ts"] or "")
    ev_txt = "\n".join(json.dumps(x, ensure_ascii=False) for x in events) + "\n"
    (daydir / "events.jsonl").write_text(ev_txt)
    (out / "events.latest.jsonl").write_text(ev_txt)

# (4) PAYLOADS crudos, content-addressed por SHA-256:
#     - corpus deduplicado en payloads/<sha>.bin (para VT/YARA/MalwareBazaar)
#     - copia del día en by-date/<fecha>/payloads/ (carpeta autocontenida)
#     - índice hashes.log (sha, fecha, sensor, servicio, tamaño, ip)
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

cross = sum(1 for a in attackers if len(a["sensors"]) > 1)
print(f"[pull] {len(attackers)} IPs atacantes públicas "
      f"({cross} vistas por >1 sensor)")
print(f"[pull]   IOCs:     {out/'attackers.json'} + {out/'iocs.csv'}")
print(f"[pull]   técnicas: {len(events)} eventos -> {daydir/'events.jsonl'}")
print(f"[pull]   payloads: {len(payloads)} únicos ({new_payloads} nuevos al corpus) "
      f"-> {out/'payloads'}/ · índice {out/'hashes.log'}")
print(f"[pull]   por fecha: {daydir}/")
PY
