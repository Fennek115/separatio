#!/usr/bin/env bash
# pull_honeypot.sh — Colector PULL del honeypot (capa 4 de Separatio).
#
# Corre EN CASA (CT 113 intel o motherbase), se conecta al honeypot de Oracle
# a buscar los logs y produce data/honeypot/attackers.json para el enricher.
# El honeypot NO tiene credenciales ni sabe de esta máquina: casa inicia todo.
#
# Requisitos (una vez):
#   - Clave SSH de solo-lectura a la VM1 honeypot (id_oracle_synapse).
#   - OCI Security List del honeypot debe permitir SSH (22) desde la IP pública
#     de casa (200.120.126.170). Ver honeypot/DEPLOY.md §OCI.
#
# Uso:  ./tools/pull_honeypot.sh [HOST] [WINDOW_HOURS]
set -euo pipefail

HOST="${1:-ubuntu@161.153.193.0}"
WINDOW="${2:-24}"
KEY="${HONEYPOT_SSH_KEY:-$HOME/.ssh/id_oracle_synapse}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/data/honeypot"
RAW_DIR="$OUT_DIR/raw"
mkdir -p "$RAW_DIR"

SSH="ssh -o BatchMode=yes -o ConnectTimeout=15 -i $KEY $HOST"

echo "[pull] trayendo logs de $HOST (ventana ${WINDOW}h)..."

# Logs crudos (para archivo/forense) + decisiones de crowdsec.
$SSH 'sudo cat /home/cowrie/cowrie/var/log/cowrie/cowrie.json 2>/dev/null' > "$RAW_DIR/cowrie.json"  || true
$SSH 'sudo cat /var/log/nginx/honey.json 2>/dev/null'                       > "$RAW_DIR/web.json"     || true
$SSH 'sudo cscli decisions list -o json 2>/dev/null'                        > "$RAW_DIR/decisions.json" || echo "[]" > "$RAW_DIR/decisions.json"

# Consolidar a attackers.json (IP -> hits, tipos, URIs señuelo, crowdsec).
python3 - "$RAW_DIR" "$OUT_DIR" "$WINDOW" <<'PY'
import json, sys, ipaddress
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
def bump(ip, kind, when, uri=None):
    if not ip or not public(ip):
        return
    a = att.setdefault(ip, {"ip": ip, "hits": 0, "kinds": set(),
                            "first_seen": None, "last_seen": None,
                            "sample_uris": set(), "crowdsec": False})
    a["hits"] += 1
    a["kinds"].add(kind)
    if uri:
        a["sample_uris"].add(uri)
    if when:
        w = when.isoformat()
        if not a["first_seen"] or w < a["first_seen"]:
            a["first_seen"] = w
        if not a["last_seen"] or w > a["last_seen"]:
            a["last_seen"] = w

# Cowrie: eventos con src_ip
for line in (raw / "cowrie.json").read_text(errors="ignore").splitlines() if (raw/"cowrie.json").exists() else []:
    try:
        e = json.loads(line)
    except Exception:
        continue
    when = ts(e.get("timestamp"))
    if when and when < cutoff:
        continue
    bump(e.get("src_ip"), "cowrie", when)

# Web (nginx honey): una línea JSON por request
for line in (raw / "web.json").read_text(errors="ignore").splitlines() if (raw/"web.json").exists() else []:
    try:
        e = json.loads(line)
    except Exception:
        continue
    when = ts(e.get("ts"))
    if when and when < cutoff:
        continue
    bump(e.get("ip"), "web", when, e.get("uri"))

# CrowdSec: marcar IPs con decisión
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
    a["sample_uris"] = sorted(a["sample_uris"])[:5]
    attackers.append(a)
attackers.sort(key=lambda a: a["hits"], reverse=True)

(out / "attackers.json").write_text(json.dumps({
    "generated": datetime.now(timezone.utc).isoformat(),
    "window_hours": window,
    "attackers": attackers,
}, indent=1))
print(f"[pull] {len(attackers)} IPs atacantes públicas -> {out/'attackers.json'}")
PY
