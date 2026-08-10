"""
ioc_processor.py — Clasificación y export de los IOCs del día.

Salió de `pipeline.py` en F-G/G-3 (`_detect_ioc_type` + `export_iocs`). No tiene
estado ni depende de `config`: el destino se le pasa por parámetro, así que se
puede ejercitar en un `tmp_path` sin montar el pipeline entero.

**Por qué no reusa `enrichment.ioc_kind`** (el plan de G-3 lo proponía): las dos
funciones tienen contratos distintos y cambiarlas por una habría cambiado la
columna `type` de `iocs.csv`, cosa que la regla de F-G prohíbe.

  | | `detect_ioc_type` (acá) | `enrichment.ioc_kind` |
  |---|---|---|
  | hashes | `md5` / `sha1` / `sha256` | `hash` (los tres juntos) |
  | entrada | el IOC crudo del resumen | el IOC ya normalizado (minúsculas) |
  | hex en mayúsculas | lo reconoce | cae a `other` |
  | `1.2.3.4:puerto` | sólo con puerto numérico | cualquier cosa tras `:` |

`ioc_kind` sirve para decidir a qué enricher mandar un IOC; ésta para etiquetar
una fila de un CSV que consume un humano. Se dejaron separadas a propósito.
"""

from __future__ import annotations

import csv
import json
import logging
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from separatio.analyzer import ArticleSummary

logger = logging.getLogger(__name__)

CSV_FIELDS = ["date", "ioc", "type", "severity", "title", "feed", "cves", "reputation"]


def detect_ioc_type(ioc: str) -> str:
    """ip | sha256 | sha1 | md5 | url | domain | other."""
    ioc = ioc.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", ioc):
        return "ip"
    if re.match(r"^[0-9a-fA-F]{64}$", ioc):
        return "sha256"
    if re.match(r"^[0-9a-fA-F]{40}$", ioc):
        return "sha1"
    if re.match(r"^[0-9a-fA-F]{32}$", ioc):
        return "md5"
    if ioc.startswith(("http://", "https://")):
        return "url"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", ioc):
        return "domain"
    return "other"


def export_iocs(
    summaries: list["ArticleSummary"], date_str: str, output_dir: str,
    enrichment=None,
) -> dict[str, str]:
    """Exporta todos los IOCs únicos de los resúmenes a CSV y JSON.

    Si se pasa el `EnrichmentContext` de Stage 2.7 (ya corrida), cada fila lleva
    además el veredicto de reputación externa de ese IOC — antes el export corría
    *antes* de Stage 2.7 y el CSV/JSON salía sin esa información (F-G/G-4)."""
    rows = []
    for s in summaries:
        for ioc in s.iocs:
            rows.append({
                "date":     date_str,
                "ioc":      ioc.strip(),
                "type":     detect_ioc_type(ioc),
                "severity": s.severity,
                "title":    s.title,
                "feed":     s.feed_title,
                "cves":     "|".join(s.cves),
            })

    if not rows:
        return {}

    seen: set[str] = set()
    unique = [r for r in rows if r["ioc"] not in seen and not seen.add(r["ioc"])]  # type: ignore[func-returns-value]

    verdicts_by_ioc: dict[str, list[dict]] = defaultdict(list)
    if enrichment is not None:
        for v in enrichment.export_rows():
            verdicts_by_ioc[v["ioc"]].append(v)
    for row in unique:
        row["reputation"] = "|".join(
            f"{v['source']}:{v['label']}" for v in verdicts_by_ioc.get(row["ioc"], [])
        )

    safe_date = date_str.replace(" ", "_").replace("/", "-")
    paths: dict[str, str] = {}

    iocs_dir = os.path.join(output_dir, "iocs")
    Path(iocs_dir).mkdir(parents=True, exist_ok=True)

    csv_path = os.path.join(iocs_dir, f"iocs-{safe_date}.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(unique)
    paths["iocs_csv"] = csv_path

    by_type: dict[str, list] = defaultdict(list)
    for row in unique:
        by_type[row["type"]].append(row)

    json_path = os.path.join(iocs_dir, f"iocs-{safe_date}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dict(by_type), f, ensure_ascii=False, indent=2)
    paths["iocs_json"] = json_path

    logger.info(f"IOCs exportados: {len(unique)} unicos → {csv_path}")
    return paths
