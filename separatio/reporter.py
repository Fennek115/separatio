"""
reporter.py — Renderiza el informe de threat intelligence a Markdown, HTML y PDF.

Desde F-G/G-6 (2026-08-09) las plantillas viven fuera del código, en
`separatio/templates/*.html.j2` (Jinja2), y el Markdown lo parsea la librería
`markdown` (Python-Markdown) en vez de la batería de regex que había acá.

Nota de diseño sobre el índice del PDF: la plantilla de PDF numera las páginas
del índice con `target-counter(attr(href), page)`, así que los `href` del TOC y
los `id` de los encabezados **tienen que salir del mismo motor** o las anclas no
resuelven. Por eso el TOC se construye desde `md.toc_tokens` (la extensión `toc`,
con nuestro `_slugify` inyectado) y no re-parseando el Markdown por separado.
"""

import hashlib
import html
import os
import re
import logging
import secrets
from datetime import datetime
from pathlib import Path

import markdown
from markdown.extensions import Extension
from markdown.extensions.toc import TocExtension
from markdown.preprocessors import Preprocessor
from markdown.treeprocessors import Treeprocessor
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# ── Plantillas ───────────────────────────────────────────────────────────────

TEMPLATE_DIR = Path(__file__).parent / "templates"
PDF_TEMPLATE = "pdf.html.j2"
WEB_TEMPLATE = "web.html.j2"

#: Columnas a partir de las cuales una tabla se marca `.table-wide` (el CSS le
#: baja la tipografía para que entre en el A4). Era un `> 6` suelto en el parser.
WIDE_TABLE_MIN_COLS = 6

#: Profundidad del índice: sólo h1/h2, como el TOC original.
TOC_MAX_LEVEL = 2

_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "j2"]),
)


_EMOJI_RE = re.compile(
    u"[\U00002600-\U000027BF"
    u"\U0001F300-\U0001F9FF"
    u"\U0001FA00-\U0001FAFF"
    u"♀-♂"
    u"️‍]+",
    flags=re.UNICODE,
)

def _strip_emoji(text: str) -> str:
    return _EMOJI_RE.sub("", text)


# ── Report identity ──────────────────────────────────────────────────────────

def _make_report_id(date_str: str) -> str:
    """TIR-YYYYMMDD-XXXX — unique per run, printed on every page."""
    suffix = secrets.token_hex(2).upper()
    return f"TIR-{date_str.replace('-', '')}-{suffix}"


def _content_hash(content: str) -> str:
    """Full SHA-256 hex of the markdown content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# ── Slugs y tabla de contenidos ──────────────────────────────────────────────

def _slugify(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = text.lower()
    for src, dst in [("á","a"),("à","a"),("ä","a"),("â","a"),("é","e"),("è","e"),
                     ("ê","e"),("ë","e"),("í","i"),("ì","i"),("î","i"),("ï","i"),
                     ("ó","o"),("ò","o"),("ô","o"),("ö","o"),("ú","u"),("ù","u"),
                     ("û","u"),("ü","u"),("ñ","n"),("ç","c")]:
        text = text.replace(src, dst)
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text.strip("-")


def _slugify_md(value: str, separator: str = "-") -> str:
    """Adaptador de `_slugify` a la firma que espera la extensión `toc`.

    Se inyecta a propósito en vez de usar el slugify por defecto de
    Python-Markdown: el nuestro translitera acentos (`ó`→`o`), y sobre todo
    garantiza que `id` y `href` los genere la misma función.
    """
    return _slugify(value)


def _is_table_separator(line: str) -> bool:
    """¿Es la fila `|---|---|` que separa cabecera de cuerpo en una tabla?"""
    s = line.strip()
    if not s.startswith("|"):
        return False
    inner = s.strip("|")
    return "-" in inner and set(inner) <= set("-:| \t")


class _TableBlankLinePreprocessor(Preprocessor):
    """Despega del párrafo anterior una tabla que quedó sin línea en blanco.

    El LLM escribe seguido bastante seguido:

        **IPs maliciosas:**
        | IP | Veredicto |
        |---|---|

    Python-Markdown exige que la tabla sea su propio bloque, así que sin este
    preprocessor se traga la tabla entera dentro del párrafo. El parser de
    regex anterior sí la reconocía, y perderla sería una regresión — se
    detectó comparando contra el informe real del 2026-08-08.

    Corre después de `fenced_code` (prioridad 25), así que los bloques de
    código ya están fuera del texto y nunca se tocan.
    """

    def run(self, lines: list[str]) -> list[str]:
        out: list[str] = []
        for i, line in enumerate(lines):
            starts_table = (
                line.lstrip().startswith("|")
                and i + 1 < len(lines)
                and _is_table_separator(lines[i + 1])
            )
            # `out[-1]` sin `|` evita partir en dos una tabla ya empezada.
            glued = out and out[-1].strip() and not out[-1].lstrip().startswith("|")
            if starts_table and glued:
                out.append("")
            out.append(line)
        return out


class _WideTableTreeprocessor(Treeprocessor):
    """Marca las tablas de muchas columnas con `class="table-wide"`.

    Python-Markdown no sabe nada de esto; es una regla de presentación nuestra
    que el parser anterior aplicaba al construir el `<table>` a mano.
    """

    def run(self, root):
        for table in root.iter("table"):
            header = table.find("thead/tr")
            if header is None:
                continue
            if len(header.findall("th")) > WIDE_TABLE_MIN_COLS:
                table.set("class", "table-wide")


class _LlmQuirksExtension(Extension):
    """Las dos concesiones al Markdown que realmente escribe el LLM."""

    def extendMarkdown(self, md):
        md.preprocessors.register(_TableBlankLinePreprocessor(md), "table_blank_line", 20)
        md.treeprocessors.register(_WideTableTreeprocessor(md), "wide_table", 4)


def _new_markdown() -> markdown.Markdown:
    """Una instancia nueva por render.

    `markdown.Markdown` acumula estado entre conversiones (los `id` ya usados,
    los `toc_tokens`) y no es thread-safe. Los informes son pocos y cortos, así
    que construir una por render sale más barato que razonar sobre `reset()`.
    """
    return markdown.Markdown(
        extensions=[
            "tables",
            "fenced_code",
            TocExtension(slugify=_slugify_md),
            _LlmQuirksExtension(),
        ],
        output_format="html",
    )


def _flatten_toc(tokens: list[dict]) -> list[tuple[int, str, str]]:
    """`md.toc_tokens` (anidado) → [(level, texto, slug)] en orden de documento."""
    entries: list[tuple[int, str, str]] = []

    def walk(items: list[dict]) -> None:
        for item in items:
            if item["level"] <= TOC_MAX_LEVEL:
                entries.append((item["level"], item["name"], item["id"]))
            walk(item.get("children") or [])

    walk(tokens)
    return entries


def _render_markdown(markdown_text: str) -> tuple[str, list[tuple[int, str, str]]]:
    """Convierte Markdown a HTML y devuelve también las entradas del índice.

    Las dos cosas salen del mismo parseo a propósito (ver la nota del módulo).
    """
    md = _new_markdown()
    body = md.convert(markdown_text)
    return body, _flatten_toc(md.toc_tokens)


def markdown_to_html_body(markdown_text: str) -> str:
    """Markdown → HTML (sólo el cuerpo, sin `<html>` ni `<head>`)."""
    return _render_markdown(markdown_text)[0]


def _extract_toc_entries(markdown_text: str) -> list[tuple[int, str, str]]:
    """Return [(level, display_text, slug_id)] for h1/h2 headings only."""
    return _render_markdown(markdown_text)[1]


def _build_toc_html(entries: list[tuple[int, str, str]]) -> str:
    if not entries:
        return ""
    lines = ['<div class="toc">', '<p class="toc-title">Índice</p>', '<ul class="toc-list">']
    for level, text, slug in entries:
        lines.append(
            f'<li class="toc-h{level}">'
            f'<a class="toc-link" href="#{html.escape(slug, quote=True)}">{html.escape(text)}</a>'
            f'</li>'
        )
    lines += ["</ul>", "</div>"]
    return "\n".join(lines)


def split_report_sections(markdown_text: str) -> dict[str, str]:
    """
    Divide el output del LLM en secciones usando los marcadores de Stage 3.
    Retorna {"vulnerability": <md>, "threat_intel": <md>} si se encuentran marcadores,
    o {"full": <md>} como fallback para compatibilidad con el formato antiguo.

    (El parámetro se llamaba `markdown` hasta G-6; se renombró porque ahora
    sombrearía al módulo `markdown` importado arriba.)
    """
    vuln = re.search(
        r"===VULNERABILITY_BRIEFING===\s*\n(.*?)(?===THREAT_INTEL_DIGEST===|===END===)",
        markdown_text, re.DOTALL,
    )
    intel = re.search(
        r"===THREAT_INTEL_DIGEST===\s*\n(.*?)(?===END===|$)",
        markdown_text, re.DOTALL,
    )
    if vuln and intel:
        return {
            "vulnerability": vuln.group(1).strip(),
            "threat_intel":  intel.group(1).strip(),
        }
    # El modelo no siguió el formato — guardar como informe único
    logger.warning("Marcadores de sección no encontrados; guardando informe único.")
    return {"full": markdown_text}


def _render_html(content: str, template_name: str, date_str: str,
                 generated_at: str, total_articles: int,
                 total_feeds: int, provider: str,
                 report_id: str = "", content_hash: str = "") -> str:
    body, toc_entries = _render_markdown(content)
    toc = _build_toc_html(toc_entries) if template_name == PDF_TEMPLATE else ""
    return _ENV.get_template(template_name).render(
        date=date_str,
        generated_at=generated_at,
        body=body,
        toc=toc,
        total_articles=total_articles,
        total_feeds=total_feeds,
        provider=provider or "pipeline",
        report_id=report_id,
        content_hash=content_hash,
        content_hash_short=content_hash[:16] if content_hash else "",
    )


def _write_pdf(html_string: str, path: str) -> bool:
    """Convierte HTML a PDF con weasyprint. Retorna False si no está instalado."""
    try:
        import weasyprint  # type: ignore
        weasyprint.HTML(string=html_string).write_pdf(path)
        return True
    except ImportError:
        logger.warning(
            "weasyprint no está instalado — PDF omitido. "
            "Instalar con: pip install weasyprint"
        )
        return False
    except Exception as e:
        logger.error(f"Error generando PDF: {e}")
        return False


def _write_report_file(content: str, path: str, fmt: str,
                       date_str: str, generated_at: str,
                       total_articles: int, total_feeds: int,
                       provider: str = "",
                       report_id: str = "", content_hash: str = "") -> None:
    content = _strip_emoji(content)
    if fmt == "md":
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    elif fmt == "pdf":
        html_out = _render_html(content, PDF_TEMPLATE, date_str,
                                generated_at, total_articles, total_feeds, provider,
                                report_id, content_hash)
        _write_pdf(html_out, path)
    else:
        html_out = _render_html(content, WEB_TEMPLATE, date_str,
                                generated_at, total_articles, total_feeds, provider,
                                report_id, content_hash)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_out)


def save_report(markdown_content: str, output_dir: str,
                date_str: str, total_articles: int,
                total_feeds: int, fmt: str = "both",
                split: bool = True, provider: str = "",
                filename_prefix: str | None = None) -> dict[str, str]:
    """
    Guarda el informe bajo output_dir (carpeta fechada).
    - PDF  → output_dir/               (entregable final)
    - MD/HTML → output_dir/reports/    (fuentes)
    filename_prefix sobreescribe el prefijo del archivo "full" (usado para weekly).
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    safe_date    = date_str.replace(" ", "_").replace("/", "-")
    report_id    = _make_report_id(date_str)
    chash        = _content_hash(markdown_content)
    paths: dict[str, str] = {}

    def _write(content: str, path: str, fmt: str) -> None:
        _write_report_file(content, path, fmt, date_str, generated_at,
                           total_articles, total_feeds, provider,
                           report_id=report_id, content_hash=chash)

    sections = split_report_sections(markdown_content) if split else {"full": markdown_content}

    file_prefixes = {
        "vulnerability": "vuln-briefing",
        "threat_intel":  "threat-digest",
        "full":          filename_prefix or "threat-briefing",
    }

    # Un valor con typo dejaría los tres flags en False y el informe no se
    # escribiría **en silencio** — el modo de fallo que este proyecto ya se comió
    # dos veces (la fuente sin key de F-H, el PDF que nunca se generó). Desde que
    # `OUTPUT_FORMAT` se puede poner por entorno (2026-08-10) el typo es fácil,
    # así que se valida y se cae al default avisando.
    FORMATOS = ("markdown", "html", "both", "pdf", "all")
    if fmt not in FORMATOS:
        logger.warning(
            f"OUTPUT_FORMAT='{fmt}' no es válido (esperaba uno de {FORMATOS}) — "
            f"se usa 'both'. Nada se habría escrito con ese valor."
        )
        fmt = "both"

    write_md   = fmt in ("markdown", "both", "all")
    write_html = fmt in ("html", "both", "all")
    write_pdf  = fmt in ("pdf", "all")

    reports_dir = os.path.join(output_dir, "reports")
    if write_md or write_html:
        Path(reports_dir).mkdir(parents=True, exist_ok=True)

    for key, content in sections.items():
        prefix = file_prefixes[key]

        if write_md:
            path = os.path.join(reports_dir, f"{prefix}-{safe_date}.md")
            _write(content, path, "md")
            paths[f"{key}_markdown"] = path
            logger.info(f"Informe Markdown ({key}): {path}")

        if write_html:
            path = os.path.join(reports_dir, f"{prefix}-{safe_date}.html")
            _write(content, path, "html")
            paths[f"{key}_html"] = path
            logger.info(f"Informe HTML ({key}): {path}")

        if write_pdf:
            path = os.path.join(output_dir, f"{prefix}-{safe_date}.pdf")
            _write(content, path, "pdf")
            paths[f"{key}_pdf"] = path
            logger.info(f"Informe PDF ({key}): {path}")

    # Informe completo combinado cuando se generaron secciones separadas
    if "vulnerability" in sections:
        combined = sections["vulnerability"] + "\n\n---\n\n" + sections["threat_intel"]
        if write_md:
            path = os.path.join(reports_dir, f"threat-briefing-{safe_date}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(combined)
            paths["full_markdown"] = path
        if write_html:
            path = os.path.join(reports_dir, f"threat-briefing-{safe_date}.html")
            _write(combined, path, "html")
            paths["full_html"] = path
        if write_pdf:
            path = os.path.join(output_dir, f"threat-briefing-{safe_date}.pdf")
            _write(combined, path, "pdf")
            paths["full_pdf"] = path
            logger.info(f"Informe PDF (completo): {path}")

    return paths
