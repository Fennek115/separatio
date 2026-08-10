"""
enrichers/honeypot_recon.py — el enricher inverso (F-C del rework).

`enrichers/honeypot.py` responde "¿un IOC de las noticias me pegó?" (noticia →
honeypot). Este es el sentido contrario: "¿las IPs que me pegaron son actor
conocido o ruido de internet?" (honeypot → mundo). Su universo son las IPs del
store en la ventana reciente, no los IOCs de los artículos del día —
`enrich(iocs, ctx)` recibe `iocs` sólo para cumplir el contrato de `Enricher` y
lo ignora a propósito.

El triage, en orden (cada etapa resuelve un subconjunto a coste 0 antes de
gastar la próxima):

    0. HIGIENE   klass == "scanner"            → descartar, coste 0
    1. CACHE     enrichment fresca (greynoise) → reutilizar, coste 0
    2. LISTAS    LocalLists.lookup(ip)         → nota + terminar, coste 0
    3. RESIDUO   el resto: la única franja que gasta cuota de GreyNoise

Sólo el resultado NEGATIVO de GreyNoise (`noise=False` — no lo ve escanear
internet) es señal fuerte: es lo único disponible que se parece a "esto podría
venir dirigido a mí". Escala a la cascada completa de `ipcheck` hasta
`max_escalate` por corrida; lo que exceda ese tope igual emite el veredicto
(con menos detalle, sin cascada) — nada se pierde en silencio. El presupuesto
de GreyNoise se cuenta contra el store (`quota_used`), no en una variable en
memoria, para que sobreviva a reinicios y a que el pipeline y el colector sean
procesos distintos.
"""

from __future__ import annotations

import logging
import time

from separatio import runlog
from separatio.enrichment import Enricher, EnrichmentContext, IocVerdict
from separatio.store import db, models, queries

logger = logging.getLogger(__name__)

_DEFAULT_QUOTAS = {"greynoise": {"limit": 20, "window": "week"}}
_DEFAULT_TTL_DAYS = {"greynoise": 7, "abuseipdb": 30, "virustotal": 30, "otx": 30}
# Fuentes de la cascada de ipcheck cuyo resultado tiene sentido cachear en el
# store (mismo TTL que su fila en _DEFAULT_TTL_DAYS). shodan/ipapi/urlhaus/
# threatfox no están: no hay presupuesto que proteger en ellas acá.
_CASCADE_CACHE_SOURCES = ("abuseipdb", "virustotal", "otx")

_LABEL_SIGNAL = "posible actividad dirigida"


class HoneypotReconEnricher(Enricher):
    name = "honeypot-recon"

    def __init__(self, window_hours: int = 26, max_escalate: int = 5,
                 quotas: dict | None = None, ttl_days: dict | None = None,
                 vt_sleep: int = 15, lists=None, *,
                 recurrence_window_days: int = 14, hassh_min_ips: int = 3,
                 hassh_window_days: int = 30):
        self.window_hours = window_hours
        self.max_escalate = max_escalate
        self.quotas = quotas or _DEFAULT_QUOTAS
        self.ttl_days = ttl_days or _DEFAULT_TTL_DAYS
        self.vt_sleep = vt_sleep
        self.recurrence_window_days = recurrence_window_days
        self.hassh_min_ips = hassh_min_ips
        self.hassh_window_days = hassh_window_days
        # Inyectable para tests (evita red): objeto con `.lookup(ip) -> list[ListHit]`.
        # Si no se pasa, se carga (y descarga, si hace falta) `LocalLists` real.
        self._lists = lists

    # ── dependencias con import diferido: el enricher se puede construir
    # (y testear con dobles) sin arrastrar ipcheck/lists en el import ──

    def _get_lists(self):
        if self._lists is None:
            from separatio.lists import LocalLists
            ll = LocalLists.from_config()
            ll.load()
            self._lists = ll
        return self._lists

    @staticmethod
    def _check_greynoise(ip: str):
        from ipcheck.ip_enricher import check_greynoise
        return check_greynoise(ip, True, timeout=10)

    @staticmethod
    def _cascade(ip: str):
        from ipcheck.ip_enricher import ApiKeys, IpEnricher
        session = IpEnricher(ApiKeys.from_env(), disabled={"greynoise"})
        return session, session.enrich(ip)

    # ── el triage ──

    def enrich(self, iocs: dict[str, list[str]], ctx: EnrichmentContext) -> None:
        conn = db.open_store()
        if conn is None:
            logger.debug("    honeypot-recon: sin store, se omite")
            return
        try:
            self._run(conn, ctx)
        finally:
            conn.close()

    def _run(self, conn, ctx: EnrichmentContext) -> None:
        now = models.now_iso()
        rows = models.recent_ips(conn, self.window_hours, origin="honeypot", now=now)

        scanners = [r for r in rows if r.get("klass") == "scanner"]
        candidates = [r for r in rows if r.get("klass") != "scanner"]

        # 1. CACHE
        cached_noise: list[dict] = []
        cached_signal: list[dict] = []
        after_cache: list[dict] = []
        for r in candidates:
            cached = models.get_cached(conn, r["value"], "greynoise", now=now)
            if cached is None:
                after_cache.append(r)
            elif cached["verdict"] == "signal":
                cached_signal.append(r)
            else:
                cached_noise.append(r)   # "noise" o "error": no vale la pena reintentar hoy

        # 2. LISTAS
        lists = self._get_lists()
        list_hits: list[tuple[dict, list]] = []
        residuo: list[dict] = []
        for r in after_cache:
            hits = lists.lookup(r["value"])
            if hits:
                list_hits.append((r, hits))
            else:
                residuo.append(r)

        # Orden de interés (F-C §1, afinado en F-D): días distintos *dentro de
        # la ventana de reincidencia* > payload > multi-sensor > times_seen.
        # `ip_recurrence()` reemplaza el `days_seen` plano de F-C —que es de la
        # vida entera del indicador— por el conteo acotado a la ventana.
        recurrence_by_ip = {r["value"]: queries.ip_recurrence(
            conn, r["value"], window_days=self.recurrence_window_days, now=now)
            for r in residuo}
        residuo.sort(key=lambda r: (
            -int((recurrence_by_ip[r["value"]] or {}).get("days_seen") or 0),
            -int(r.get("has_payload") or 0),
            -int(r.get("sensors") or 0),
            -int(r.get("times_seen") or 0),
        ))

        # 3. RESIDUO, acotado al presupuesto real (contado contra el store)
        gn_quota = self.quotas.get("greynoise", _DEFAULT_QUOTAS["greynoise"])
        limit = int(gn_quota.get("limit", 20))
        window = gn_quota.get("window", "week")
        used = models.quota_used(conn, "greynoise", window=window, now=now)
        budget = max(0, limit - used)
        to_query = residuo[:budget]
        runlog.record_drop("enrichers.honeypot_recon.residuo",
                           shown=len(to_query), total=len(residuo))

        for r in cached_noise:
            ctx.add_note(self.name, f"{r['value']}: escáner masivo conocido (cache)")
        for r, hits in list_hits:
            fuentes = ", ".join(h.source for h in hits)
            ctx.add_note(self.name,
                         f"{r['value']}: ruido conocido, {len(hits)} listas ({fuentes})")
        for r in cached_signal:
            self._emit_signal(conn, now, ctx, r["value"],
                             "GreyNoise no la ve escanear internet (cache)")

        # Consulta viva: sólo el residuo que entra en presupuesto
        consultadas = 0
        noise_true = 0
        noise_false_ips: list[str] = []
        for r in to_query:
            ip = r["value"]
            gn = self._check_greynoise(ip)
            consultadas += 1
            verdict, detail = self._store_greynoise(conn, now, ip, gn)
            if verdict == "signal":
                noise_false_ips.append(ip)
            elif verdict == "noise":
                noise_true += 1
                ctx.add_note(self.name, f"{ip}: escáner masivo conocido ({detail})")
            else:
                logger.debug(f"    honeypot-recon: GreyNoise sin resultado para {ip} ({detail})")

        escalate = noise_false_ips[: self.max_escalate]
        sin_cascada = noise_false_ips[self.max_escalate:]
        for ip in escalate:
            self._escalate(conn, now, ip, ctx)
        for ip in sin_cascada:
            self._emit_signal(conn, now, ctx, ip,
                             "no figura en jamesbrine/IPsum/FireHOL; GreyNoise no la ve "
                             "escanear internet (cascada pospuesta: tope de la corrida)")
        if sin_cascada:
            runlog.record_drop("enrichers.honeypot_recon.cascada",
                               shown=len(escalate), total=len(noise_false_ips))

        self._recurrence_notes(conn, now, ctx, candidates, rows)

        if rows:
            detalle_escaner = (f" ({', '.join(sorted({r.get('scanner_name') or '?' for r in scanners}))})"
                               if scanners else "")
            ctx.add_note(self.name,
                         f"{len(rows)} IPs atacaron el honeypot en las últimas "
                         f"{self.window_hours} h: {len(scanners)} escáneres de investigación"
                         f"{detalle_escaner}, {len(list_hits) + len(cached_noise)} en listas públicas, "
                         f"{len(residuo)} sin antecedentes.")

        signal_count = len(cached_signal) + len(noise_false_ips)
        logger.info(f"    [honeypot-recon] ventana {self.window_hours}h: {len(rows)} IPs del store")
        logger.info(f"    [honeypot-recon]   escáneres descartados: {len(scanners)}")
        logger.info(f"    [honeypot-recon]   resueltas por cache: "
                   f"{len(cached_noise) + len(cached_signal)} (0 consultas)")
        logger.info(f"    [honeypot-recon]   en listas locales: {len(list_hits)}")
        logger.info(f"    [honeypot-recon]   residuo: {len(residuo)} → "
                   f"presupuesto {window} {limit}, usadas {used}")
        logger.info(f"    [honeypot-recon]   consultadas: {consultadas} → "
                   f"{noise_true} noise=true, {len(noise_false_ips)} noise=FALSE")
        logger.info(f"    [honeypot-recon]   escaladas a cascada: {len(escalate)}")
        logger.info(f"    [honeypot-recon]   señal fuerte: {signal_count}")

    # ── helpers ──

    def _store_greynoise(self, conn, now: str, ip: str, gn: dict | None) -> tuple[str, str]:
        """Interpreta la respuesta y la cachea — todo lo consultado se cachea,
        sea cual sea el resultado. Devuelve `(verdict, detail)`."""
        ttl = self.ttl_days.get("greynoise", 7)
        if gn and gn.get("status") == "ok":
            if gn.get("noise"):
                verdict, detail = "noise", f"GreyNoise: {gn.get('classification', 'noise')}"
            else:
                verdict, detail = "signal", "GreyNoise no la ve escanear internet"
            models.put_cached(conn, ip, "greynoise", verdict, detail, ttl_days=ttl, now=now)
        else:
            verdict, detail = "error", str((gn or {}).get("detail", "sin respuesta"))
            # Un error no es un resultado real: TTL corto para poder reintentar pronto.
            models.put_cached(conn, ip, "greynoise", verdict, detail, ttl_days=1, now=now)
        return verdict, detail

    def _emit_signal(self, conn, now: str, ctx: EnrichmentContext, ip: str,
                     detail: str) -> None:
        """Señal fuerte: le suma la reincidencia al `detail` (F-D) — es,
        literalmente, el criterio de cierre del rework: 'volvió N de los
        últimos M días; no está en ninguna blocklist; GreyNoise no la ve
        escanear internet'."""
        rec = queries.ip_recurrence(conn, ip, window_days=self.recurrence_window_days,
                                    now=now)
        if rec:
            detail = f"volvió {rec['days_seen']} de los últimos {rec['window_days']} días; {detail}"
        ctx.add(IocVerdict(ioc=ip, kind="ip", source=self.name,
                           label=_LABEL_SIGNAL, detail=detail))

    def _recurrence_notes(self, conn, now: str, ctx: EnrichmentContext,
                          candidates: list[dict], rows: list[dict]) -> None:
        """Las tres notas de reincidencia de F-D, una por tipo:

        1. IPs (no escáner) que volvieron ≥2 días distintos en la ventana.
        2. Payloads ya vistos antes en algún avistamiento de la ventana.
        3. HASSH visto desde muchas IPs — huella de botnet robusta al rotado
           de IP, que ninguna blocklist puede dar porque son listas de IPs."""
        candidate_ips = {r["value"] for r in candidates}
        for r in queries.top_recurrent(conn, limit=5, window_days=self.recurrence_window_days,
                                       now=now):
            if r["value"] not in candidate_ips or r["days_seen"] < 2:
                continue
            ctx.add_note(self.name,
                         f"IP reincidente: {r['value']} volvió {r['days_seen']} de los "
                         f"últimos {r['window_days']} días ({r['times_seen']} hits)")

        seen_sha: set[str] = set()
        for r in rows:
            if not r.get("has_payload"):
                continue
            shas = conn.execute(
                "SELECT DISTINCT payload_sha256 FROM observation "
                "WHERE ioc = ? AND payload_sha256 IS NOT NULL",
                (r["value"],),
            ).fetchall()
            for (sha,) in shas:
                if sha in seen_sha:
                    continue
                seen_sha.add(sha)
                info = queries.payload_history(conn, sha)
                if info and info["times_seen"] > 1:
                    ctx.add_note(self.name,
                                 f"payload ya conocido: {sha[:8]}… desde "
                                 f"{info['first_seen'][:10]}, visto {info['times_seen']} veces")

        for h in queries.hassh_fanout(conn, min_ips=self.hassh_min_ips,
                                      window_days=self.hassh_window_days, now=now):
            ctx.add_note(self.name,
                         f"HASSH {h['hassh'][:8]}… visto desde {h['n_ips']} IPs distintas en "
                         f"{self.hassh_window_days} días — mismo cliente SSH, huella de botnet")

    def _escalate(self, conn, now: str, ip: str, ctx: EnrichmentContext) -> None:
        session, full = self._cascade(ip)
        bits = []
        ab = full.get("abuseipdb") or {}
        if ab.get("status") == "ok" and ab.get("abuse_score"):
            bits.append(f"AbuseIPDB {ab['abuse_score']}%")
        for source in _CASCADE_CACHE_SOURCES:
            data = full.get(source) or {}
            if data.get("status") == "ok":
                hit = bool(data.get("abuse_score") or data.get("malicious") or data.get("pulse_count"))
                models.put_cached(conn, ip, source, "hit" if hit else "clean", "",
                                  ttl_days=self.ttl_days.get(source, 30), now=now)
        detail = "no figura en jamesbrine/IPsum/FireHOL; GreyNoise no la ve escanear internet"
        if bits:
            detail += "; " + " | ".join(bits)
        self._emit_signal(conn, now, ctx, ip, detail)
        if full.get("level_reached") == 3 and not session.vt_quota_exhausted:
            time.sleep(self.vt_sleep)
