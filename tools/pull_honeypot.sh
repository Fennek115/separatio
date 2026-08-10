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
#     Docker API, Elasticsearch, MySQL, Postgres, VNC) + CrowdSec sobre su sshd
#     REAL, que sigue en el 22. Ver honeypot/VM2-PLAN.md.
#
# Requisitos (una vez):
#   - Claves SSH de solo-lectura: id_oracle_synapse (VM1) e id_oracle_ivory (VM2).
#   - La Security List de OCI debe permitir SSH (22) desde la IP pública de casa
#     (es dinámica; el valor actual está en OWN_IPS del .env / intel.env).
#     Ver honeypot/DEPLOY.md §OCI.
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

  echo "[pull] VM2 (Beelzebub + CrowdSec) desde $VM2_HOST..."
  $SSH2 'sudo cat /var/lib/beelzebub/logs/beelzebub.json 2>/dev/null'          > "$RAW_DIR/beelzebub.json" || true
  # CrowdSec de VM2 (instalado el 2026-08-10): en VM1 el 22 pasó a Cowrie y su
  # CrowdSec se quedó sin entrada útil, así que el sshd REAL de ivory es hoy la
  # única fuente con fuerza bruta sostenida. Ver honeypot/EXPONER.md §CrowdSec.
  $SSH2 'sudo cscli decisions list -o json 2>/dev/null'                        > "$RAW_DIR/decisions_vm2.json" || echo "[]" > "$RAW_DIR/decisions_vm2.json"
fi

# Consolidar a attackers.json (IP -> hits, tipos, sensores, señuelos, crowdsec).
# La lógica vive en separatio/honeypot_collector.py (módulo testeable, sólo stdlib:
# el python3 del sistema alcanza, no hace falta el venv del CT).
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
  "${PYTHON:-python3}" -m separatio.honeypot_collector "$RAW_DIR" "$OUT_DIR" "$WINDOW"
