"""
runlog.py — F-H: el manifiesto de la corrida.

Responde, después de cada corrida y sin leer 190 KB de log: **qué corrió, qué se
usó, qué falló y por qué, y qué datos NO llegaron al LLM.**

El pipeline recorta en ocho lugares distintos (topes por fuente, por artículo,
por fase, truncados de texto, fetches abandonados) y hasta F-H todos esos
recortes eran silenciosos: el informe se generaba igual y nadie sabía con qué
mitad de los datos. Acá se registran con números —`shown`/`total`— y se
declaran al cierre.

Diseño: **singleton de módulo, como el `logger`.** El manifiesto es transversal
—lo tocan `extractor`, `enrichment`, `history`, `analyzer` y `pipeline`, que no
comparten firma— y pasarlo por parámetro obligaría a cambiar ocho funciones.

**El no-op es la pieza que lo hace seguro**: si nadie llamó a `start_run` (los
tests, un import suelto, `ipcheck` como CLI), cada `record_*` no hace nada y no
falla. Instrumentar nunca puede romper el pipeline.

Uso típico:

    runlog.start_run("2026-08-09", "full")
    with runlog.stage("stage1"):
        ...
    runlog.record_drop("enrichment.format_for_prompt", 25, 63, detail="IPsum")
    manifest = runlog.finish_run(Path(out) / "run-manifest.json")
    sys.exit(manifest.exit_code())
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_NAME = "run-manifest.json"

# Señales de truncado por proveedor (espejo de analyzer._TRUNCATED).
TRUNCATED_FINISH = {"length", "max_tokens", "MAX_TOKENS", "RECITATION"}

# Etapas cuyo fallo significa "no hay informe" → status failed, exit 1.
CRITICAL_STAGES = {"stage3", "stage3_phases", "stage4"}

# Etiqueta legible por punto de recorte, para el bloque de resumen.
DROP_LABELS: dict[str, str] = {
    "enrichment.format_for_prompt":        "veredictos de enrichment recortados",
    "analyzer._format_phase_items":        "artículos no enviados al prompt de fase",
    "analyzer._format_phase_items.iocs":   "IOCs recortados por el tope por artículo",
    "analyzer.build_report_prompt.iocs":   "IOCs recortados en el informe consolidado",
    "history.format_for_prompt":           "líneas de contexto histórico recortadas",
    "extractor.truncate_text":             "artículos truncados por ARTICLE_MAX_TOKENS",
    "extractor.extract_article_text":      "artículos entraron sólo con el título, sin cuerpo",
    "pipeline.stage1_fetch.per_feed":      "artículos descartados por el tope por feed",
    "pipeline.stage1_fetch.global":        "artículos descartados por MAX_ARTICLES",
    "pipeline.stage2_summarize":           "artículos sin resumen utilizable",
    "pipeline.stage3_phases.enrichment":   "fases que NO reciben enrichment, por diseño actual",
    "enrichers.honeypot.notes":            "atacantes del honeypot no listados en el prompt",
    "enrichers.honeypot.uris":             "URIs señuelo recortadas",
}


# ─────────────────────────────────────────────────────────
# TIPOS
# ─────────────────────────────────────────────────────────

@dataclass
class Drop:
    """Un recorte concreto: qué se mostró de cuánto había, y dónde."""
    where: str          # "enrichment.format_for_prompt"
    kind: str           # cap | truncate | filter | failure
    shown: int
    total: int
    detail: str = ""    # "IPsum" / "articulo 42" / …

    @property
    def omitted(self) -> int:
        return max(0, self.total - self.shown)


@dataclass
class LlmCall:
    stage: str
    model: str
    in_tokens: int
    out_tokens: int
    finish_reason: str
    truncated: bool
    duration_s: float


@dataclass
class Failure:
    component: str      # "enricher:OpenPhish" / "stage:3"
    error_type: str
    message: str


@dataclass
class RunManifest:
    date: str
    mode: str                     # full | dry-run | report-only | weekly
    started_at: str
    finished_at: str | None = None
    duration_s: float = 0.0
    status: str = "ok"            # ok | degraded | failed
    stages: dict = field(default_factory=dict)   # nombre -> {ok, duration_s, error}
    counts: dict = field(default_factory=dict)   # articulos_disponibles, tomados, …
    drops: list[Drop] = field(default_factory=list)
    llm_calls: list[LlmCall] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)
    sources: dict = field(default_factory=dict)  # enricher -> "ok" | "failed: <motivo>"
    report_paths: dict = field(default_factory=dict)
    # Una corrida que por diseño no genera informe (weekly sin caché, "no hay
    # artículos") no es un fallo: se declara acá para que el status no mienta.
    expect_report: bool = True

    # ── agregados ────────────────────────────────────────

    def totals(self) -> dict:
        return {
            "in_tokens":      sum(c.in_tokens for c in self.llm_calls),
            "out_tokens":     sum(c.out_tokens for c in self.llm_calls),
            "llamadas":       len(self.llm_calls),
            "truncadas":      sum(1 for c in self.llm_calls if c.truncated),
            "datos_omitidos": sum(d.omitted for d in self.drops),
        }

    def compute_status(self) -> str:
        """ok | degraded | failed — ver la tabla de docs/fases/F-H.md §5."""
        critical_failed = any(
            not s.get("ok", True)
            for name, s in self.stages.items()
            if name in CRITICAL_STAGES
        )
        no_report = self.expect_report and bool(self.stages) and not self.report_paths
        if critical_failed or no_report:
            return "failed"

        degraded = (
            bool(self.failures)
            or any(not s.get("ok", True) for s in self.stages.values())
            or any(v != "ok" for v in self.sources.values())
            or self.totals()["truncadas"] > 0
        )
        return "degraded" if degraded else "ok"

    def exit_code(self) -> int:
        """`degraded` sale con 0 a propósito: si saliera con 1 el timer marcaría
        la unidad como fallida cada día que un feed esté caído, y el usuario
        dejaría de mirarla. El estado se consulta con `--last-run`."""
        return 1 if self.status == "failed" else 0

    # ── serialización ────────────────────────────────────

    def to_dict(self) -> dict:
        d = asdict(self)
        d["totals"] = self.totals()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "RunManifest":
        known = cls.__dataclass_fields__
        kw = {k: v for k, v in data.items() if k in known}
        kw["drops"] = [Drop(**d) for d in data.get("drops", [])]
        kw["llm_calls"] = [LlmCall(**c) for c in data.get("llm_calls", [])]
        kw["failures"] = [Failure(**f) for f in data.get("failures", [])]
        return cls(**kw)

    def summary_text(self) -> str:
        return _summary_text(self)


class _NoOp:
    """El manifiesto ausente. Acepta todo, no guarda nada, nunca falla."""

    date = ""
    mode = ""
    started_at = ""
    finished_at = None
    duration_s = 0.0
    status = "ok"
    expect_report = True

    def __init__(self) -> None:
        self.stages: dict = {}
        self.counts: dict = {}
        self.sources: dict = {}
        self.report_paths: dict = {}
        self.drops: list = []
        self.llm_calls: list = []
        self.failures: list = []

    def totals(self) -> dict:
        return {"in_tokens": 0, "out_tokens": 0, "llamadas": 0,
                "truncadas": 0, "datos_omitidos": 0}

    def compute_status(self) -> str:
        return "ok"

    def exit_code(self) -> int:
        return 0

    def summary_text(self) -> str:
        return ""

    def __bool__(self) -> bool:
        return False


_NOOP = _NoOp()
_current: RunManifest | None = None


# ─────────────────────────────────────────────────────────
# API DE INSTRUMENTACIÓN
# ─────────────────────────────────────────────────────────

def start_run(date: str, mode: str) -> RunManifest:
    global _current
    _current = RunManifest(date=date, mode=mode, started_at=_now())
    return _current


def current() -> RunManifest | _NoOp:
    """El manifiesto activo, o un no-op si no hay corrida iniciada."""
    return _current if _current is not None else _NOOP


def reset() -> None:
    """Descarta el manifiesto activo (tests, y cierre de `finish_run`)."""
    global _current
    _current = None


def record_drop(where: str, shown: int, total: int,
                detail: str = "", kind: str = "cap") -> None:
    """Registra que se mostraron `shown` de `total`. Si no hubo recorte, no
    registra nada: los call sites pueden llamar sin condicionar."""
    if _current is None or total <= shown:
        return
    _current.drops.append(Drop(where=where, kind=kind, shown=shown,
                               total=total, detail=detail))


def record_llm(stage: str, model: str, in_tok: int, out_tok: int,
               finish: str, max_tokens: int, duration_s: float = 0.0) -> None:
    if _current is None:
        return
    _current.llm_calls.append(LlmCall(
        stage=stage, model=model,
        in_tokens=int(in_tok or 0), out_tokens=int(out_tok or 0),
        finish_reason=str(finish), truncated=str(finish) in TRUNCATED_FINISH,
        duration_s=round(duration_s, 2),
    ))


def record_failure(component: str, exc: BaseException | str) -> None:
    if _current is None:
        return
    if isinstance(exc, BaseException):
        error_type, message = type(exc).__name__, str(exc)
    else:
        error_type, message = "Error", str(exc)
    _current.failures.append(Failure(component=component,
                                     error_type=error_type, message=message))


def record_stage(name: str, ok: bool, duration_s: float, error: str | None = None) -> None:
    if _current is None:
        return
    _current.stages[name] = {"ok": ok, "duration_s": round(duration_s, 2), "error": error}


def record_count(name: str, value: int) -> None:
    if _current is None:
        return
    _current.counts[name] = value


def record_source(name: str, status: str) -> None:
    """enricher -> 'ok' | 'failed: <motivo>' | 'skipped: <motivo>'.

    Un `skipped` que declaró el propio enricher (p.ej. MalwareBazaar sin
    Auth-Key) NO se pisa con el 'ok' que `run_enrichment` pone al ver que no
    hubo excepción: no lanzar no es lo mismo que haber consultado la fuente.
    Ése era el peor caso de dato perdido en silencio — una fuente habilitada
    que no aportaba nada y el informe salía igual, sin decirlo."""
    if _current is None:
        return
    if status == "ok" and str(_current.sources.get(name, "")).startswith("skipped"):
        return
    _current.sources[name] = status


def record_report(paths: dict) -> None:
    if _current is None:
        return
    _current.report_paths.update({k: str(v) for k, v in (paths or {}).items()})


def expect_no_report(reason: str) -> None:
    """La corrida termina sin informe por diseño (weekly sin caché, sin
    artículos nuevos): eso es `degraded`, no `failed`."""
    if _current is None:
        return
    _current.expect_report = False
    record_failure("pipeline", reason)


@contextmanager
def stage(name: str):
    """Cronometra una etapa y registra su resultado. Reraise: la política de
    fallos sigue siendo del pipeline, acá sólo se anota."""
    t0 = time.monotonic()
    try:
        yield
    except Exception as e:
        record_stage(name, False, time.monotonic() - t0, f"{type(e).__name__}: {e}")
        record_failure(f"stage:{name}", e)
        raise
    else:
        record_stage(name, True, time.monotonic() - t0)


def finish_run(path: str | Path) -> RunManifest:
    """Cierra el manifiesto, calcula el status y lo escribe atómicamente."""
    manifest = _current
    if manifest is None:
        return _NOOP  # type: ignore[return-value]
    manifest.finished_at = _now()
    manifest.duration_s = _elapsed(manifest.started_at, manifest.finished_at)
    manifest.status = manifest.compute_status()
    try:
        write_manifest(manifest, path)
    except Exception as e:                       # nunca romper la corrida por el log
        logger.warning(f"No se pudo escribir el manifiesto en {path}: {e}")
    reset()
    return manifest


# ─────────────────────────────────────────────────────────
# PERSISTENCIA
# ─────────────────────────────────────────────────────────

def write_manifest(manifest: RunManifest, path: str | Path) -> Path:
    """Escritura atómica: tmp + fsync + os.replace, igual que history.save_history."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    return p


def load_manifest(path: str | Path) -> RunManifest:
    with open(path, encoding="utf-8") as f:
        return RunManifest.from_dict(json.load(f))


def find_latest_manifest(output_dir: str | Path) -> Path | None:
    """El `run-manifest.json` más reciente bajo OUTPUT_DIR/<fecha>/."""
    root = Path(output_dir)
    candidates = sorted(root.glob(f"*/{MANIFEST_NAME}"))
    if not candidates:
        return None

    def key(p: Path):
        try:
            with open(p, encoding="utf-8") as f:
                started = json.load(f).get("started_at") or ""
        except Exception:
            started = ""
        return (started, p.stat().st_mtime)

    return max(candidates, key=key)


# ─────────────────────────────────────────────────────────
# BLOQUE DE RESUMEN
# ─────────────────────────────────────────────────────────

_RULE = "═" * 50


def _summary_text(m: RunManifest) -> str:
    t = m.totals()
    lines = [
        _RULE,
        f"  RESUMEN DE LA CORRIDA — {m.date}  [{m.status}]",
        _RULE,
        f"  Modo:         {m.mode}",
        f"  Duración:     {_human_duration(m.duration_s)}",
    ]

    c = m.counts
    if c:
        # Se arma con lo que haya: --report-only no pasa por stage 1-2 y no
        # tiene pool ni fallidos, y ponerle "?" sería mentir por omisión.
        etapas = [(f"{c[k]} {texto}") for k, texto in (
            ("articulos_pool", "en el pool"),
            ("articulos_cache", "desde caché"),
            ("articulos_tomados", "tomados"),
            ("articulos_resumidos", "resumidos"),
        ) if k in c]
        if etapas:
            cola = (f", {c['articulos_fallidos']} fallidos"
                    if "articulos_fallidos" in c else "")
            lines.append(f"  Artículos:    {' → '.join(etapas)}{cola}")
        for k, v in c.items():
            if not k.startswith("articulos_"):
                lines.append(f"  {k + ':':<13} {v}")

    if m.llm_calls:
        truncadas = [call for call in m.llm_calls if call.truncated]
        trunc_txt = ""
        if truncadas:
            quienes = ", ".join(sorted({call.stage for call in truncadas}))
            trunc_txt = f" · {len(truncadas)} truncada(s) ({quienes})"
        lines.append(
            f"  LLM:          {t['llamadas']} llamadas · "
            f"{_num(t['in_tokens'])} in / {_num(t['out_tokens'])} out{trunc_txt}"
        )

    if m.sources:
        ok = [n for n, v in m.sources.items() if v == "ok"]
        bad = [(n, str(v)) for n, v in m.sources.items() if v != "ok"]
        lines.append(f"  Enrichers:    {len(ok)} ok ({', '.join(ok) or '—'})")
        for name, motivo in bad:
            # OMITIDA = habilitada pero no consultó (falta la key); FALLIDA =
            # se intentó y reventó. Son problemas distintos.
            etiqueta = "OMITIDA" if motivo.startswith("skipped") else "FALLIDA"
            lines.append(f"                {etiqueta}: {name} — "
                         f"{motivo.removeprefix('failed: ').removeprefix('skipped: ')}")

    otras = [f for f in m.failures if not f.component.startswith("enricher:")]
    if otras:
        lines.append("  Fallos:")
        for f in otras:
            lines.append(f"    · {f.component} — {f.error_type}: {f.message[:110]}")

    if m.drops:
        lines.append("  Datos NO enviados al LLM:")
        lines.extend(_drop_lines(m.drops))

    if m.stages:
        malas = [n for n, s in m.stages.items() if not s.get("ok", True)]
        if malas:
            lines.append(f"  Etapas fallidas: {', '.join(malas)}")

    lines.append(_RULE)
    return "\n".join(lines)


def _drop_lines(drops: list[Drop]) -> list[str]:
    """Una línea por punto de recorte, con los números reales."""
    by_where: dict[str, list[Drop]] = {}
    for d in drops:
        by_where.setdefault(d.where, []).append(d)

    out: list[str] = []
    for where, items in sorted(by_where.items(),
                               key=lambda kv: -sum(d.omitted for d in kv[1])):
        omitted = sum(d.omitted for d in items)
        label = DROP_LABELS.get(where, where)
        detalles = [d for d in sorted(items, key=lambda d: -d.omitted) if d.detail]
        extra = ""
        if detalles:
            muestra = ", ".join(f"{d.detail} {d.shown}/{d.total}" for d in detalles[:3])
            if len(detalles) > 3:
                muestra += f", +{len(detalles) - 3} más"
            extra = f" ({muestra})"
        elif len(items) == 1:
            extra = f" ({items[0].shown}/{items[0].total})"
        out.append(f"    · {omitted} {label}{extra}")
    return out


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _elapsed(started_at: str, finished_at: str) -> float:
    try:
        delta = datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)
        return round(delta.total_seconds(), 2)
    except Exception:
        return 0.0


def _human_duration(seconds: float) -> str:
    seconds = int(seconds or 0)
    if seconds < 60:
        return f"{seconds}s"
    return f"{seconds // 60}m {seconds % 60:02d}s"


def _num(n: int) -> str:
    return f"{n:,}".replace(",", ".")
