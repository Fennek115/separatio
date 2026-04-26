"""
reporter.py — Renderiza el informe de threat intelligence a Markdown, HTML y PDF.
"""

import os
import re
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

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


PDF_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Threat Intelligence Briefing — {date}</title>
    <style>
        /*
         * Fuentes recomendadas en el servidor (LXC 112):
         *   apt install fonts-ibm-plex
         * Sin ellas usa Liberation Sans / DejaVu como fallback.
         */
        @page {{
            size: A4;
            margin: 2.2cm 2.5cm 2cm 2.5cm;
            @bottom-right {{
                content: counter(page) " / " counter(pages);
                font-size: 7.5pt;
                color: #9ca3af;
                font-family: "IBM Plex Sans", "Liberation Sans", "DejaVu Sans", sans-serif;
            }}
            @bottom-left {{
                content: "Threat Intelligence  ·  {date}  ·  TLP:WHITE";
                font-size: 7.5pt;
                color: #9ca3af;
                font-family: "IBM Plex Sans", "Liberation Sans", "DejaVu Sans", sans-serif;
            }}
        }}
        @page:first {{
            @bottom-right {{ content: none; }}
            @bottom-left  {{ content: none; }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: "IBM Plex Sans", "Liberation Sans", "DejaVu Sans", sans-serif;
            font-size: 10pt;
            color: #111827;
            line-height: 1.65;
        }}

        /* ── Portada ── */
        .cover {{
            padding-top: 7cm;
            padding-bottom: 4cm;
            page-break-after: always;
        }}
        .cover-rule {{
            width: 2.8cm;
            height: 4px;
            background: #7c3aed;
            margin-bottom: 1.4rem;
        }}
        .cover-label {{
            font-size: 7pt;
            font-weight: 700;
            letter-spacing: 0.22em;
            color: #7c3aed;
            text-transform: uppercase;
            margin-bottom: 0.7rem;
        }}
        .cover h1 {{
            font-size: 27pt;
            font-weight: 700;
            color: #1e1b4b;
            line-height: 1.12;
            margin-bottom: 0.35rem;
        }}
        .cover-date {{
            font-size: 13pt;
            color: #4b5563;
            margin-bottom: 3rem;
        }}
        .cover-meta {{
            font-size: 8.5pt;
            color: #6b7280;
            border-top: 1px solid #e5e7eb;
            padding-top: 0.9rem;
            line-height: 2;
        }}
        .cover-quote {{
            font-size: 8.5pt;
            font-style: italic;
            color: #5b21b6;
            margin: 1.8rem 0 0.6rem;
            padding-left: 0.9rem;
            border-left: 2px solid #c4b5fd;
            line-height: 1.55;
        }}
        .cover-quote cite {{
            font-style: normal;
            font-size: 7pt;
            color: #9ca3af;
            display: block;
            margin-top: 0.3rem;
            letter-spacing: 0.02em;
        }}
        .cover-tlp {{
            display: inline-block;
            border: 1px solid #c4b5fd;
            color: #6d28d9;
            font-size: 7pt;
            font-weight: 700;
            letter-spacing: 0.12em;
            padding: 0.2em 0.65em;
            border-radius: 2px;
            margin-top: 1.6rem;
        }}

        /* ── Encabezados ── */
        h1 {{
            font-size: 15pt;
            font-weight: 700;
            color: #1e1b4b;
            margin: 2rem 0 0.5rem;
            padding-bottom: 0.4rem;
            border-bottom: 2px solid #7c3aed;
            page-break-after: avoid;
        }}
        h2 {{
            font-size: 11pt;
            font-weight: 600;
            color: #1e1b4b;
            margin: 1.4rem 0 0.4rem;
            padding-left: 0.65rem;
            border-left: 3px solid #7c3aed;
            page-break-after: avoid;
        }}
        h3 {{
            font-size: 10pt;
            font-weight: 600;
            color: #374151;
            margin: 1rem 0 0.3rem;
            page-break-after: avoid;
        }}
        h4 {{
            font-size: 9.5pt;
            font-weight: 600;
            color: #4b5563;
            margin: 0.7rem 0 0.2rem;
        }}

        /* ── Cuerpo ── */
        p  {{ margin-bottom: 0.55rem; }}
        ul, ol {{ padding-left: 1.3rem; margin-bottom: 0.6rem; }}
        li {{ margin-bottom: 0.25rem; }}
        strong {{ color: #111827; font-weight: 600; }}
        a  {{ color: #6d28d9; text-decoration: none; }}
        hr {{ border: none; border-top: 1px solid #e5e7eb; margin: 1.3rem 0; }}

        /* ── Código ── */
        code {{
            font-family: "IBM Plex Mono", "Liberation Mono", "DejaVu Sans Mono", monospace;
            font-size: 8.5pt;
            background: #f5f3ff;
            border: 1px solid #ddd6fe;
            border-radius: 3px;
            padding: 0.05em 0.3em;
            color: #4c1d95;
        }}
        pre {{
            font-family: "IBM Plex Mono", "Liberation Mono", "DejaVu Sans Mono", monospace;
            font-size: 8.5pt;
            background: #faf5ff;
            border: 1px solid #ddd6fe;
            border-left: 3px solid #7c3aed;
            border-radius: 3px;
            padding: 0.8rem 1rem;
            margin-bottom: 0.8rem;
            page-break-inside: avoid;
        }}

        /* ── Tablas ── */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 0.9rem;
            font-size: 8.5pt;
        }}
        thead {{
            display: table-header-group;
        }}
        tr {{
            page-break-inside: avoid;
            page-break-after: auto;
        }}
        th {{
            background: #1e1b4b;
            color: #f5f3ff;
            border: 1px solid #312e81;
            padding: 0.45rem 0.65rem;
            text-align: left;
            font-weight: 600;
            font-size: 7.5pt;
            letter-spacing: 0.05em;
        }}
        td {{
            border: 1px solid #e5e7eb;
            padding: 0.4rem 0.65rem;
            vertical-align: top;
        }}
        tr:nth-child(even) td {{ background: #faf5ff; }}

        /* ── Cita ── */
        blockquote {{
            border-left: 3px solid #c4b5fd;
            padding-left: 0.8rem;
            color: #6b7280;
            font-style: italic;
            margin-bottom: 0.6rem;
        }}
        .section-break {{ page-break-before: always; }}
        .colophon {{
            margin-top: 3.5rem;
            padding-top: 1rem;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            font-size: 7.5pt;
            font-style: italic;
            color: #9ca3af;
            letter-spacing: 0.04em;
        }}
    </style>
</head>
<body>
    <div class="cover">
        <div class="cover-rule"></div>
        <div class="cover-label">Daily Briefing</div>
        <h1>Threat Intelligence<br>Report</h1>
        <div class="cover-date">{date}</div>
        <div class="cover-quote">
            "Separa la Tierra del Fuego, lo sutil de lo burdo,<br>pero s&eacute; prudente y circunspecto cuando lo hagas."
            <cite>— Tabula Smaragdina, Hermes Trismegistus</cite>
        </div>
        <div class="cover-meta">
            Generado: {generated_at}<br>
            Art&iacute;culos analizados: {total_articles} &nbsp;&middot;&nbsp; Fuentes: {total_feeds}<br>
            An&aacute;lisis automatizado &nbsp;&middot;&nbsp; Threat Intelligence Pipeline
        </div>
        <div class="cover-tlp">TLP:WHITE</div>
    </div>
    {body}
    <div class="colophon">
        "Lo que tuve que decir sobre el funcionamiento del Sol ha concluido."
        &nbsp;&mdash;&nbsp; Tabula Smaragdina
    </div>
</body>
</html>"""


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Briefing — {date}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #e6edf3;
            --muted: #8b949e;
            --critical: #f85149;
            --high: #ff7b72;
            --medium: #d29922;
            --low: #3fb950;
            --accent: #58a6ff;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.7;
            padding: 2rem;
            max-width: 960px;
            margin: 0 auto;
        }}
        h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 0.5rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
        h2 {{ font-size: 1.25rem; color: var(--text); margin: 2rem 0 0.75rem; border-left: 3px solid var(--accent); padding-left: 0.75rem; }}
        h3 {{ font-size: 1rem; color: var(--muted); margin: 1rem 0 0.5rem; }}
        p  {{ margin-bottom: 0.75rem; color: var(--text); }}
        ul, ol {{ padding-left: 1.5rem; margin-bottom: 0.75rem; }}
        li {{ margin-bottom: 0.3rem; }}
        code {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 0.1em 0.4em;
            font-family: "JetBrains Mono", "Fira Code", monospace;
            font-size: 0.85em;
            color: var(--medium);
        }}
        pre {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem;
            overflow-x: auto;
            margin-bottom: 1rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 1rem;
        }}
        th {{
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 0.5rem 0.75rem;
            text-align: left;
            color: var(--muted);
            font-weight: 600;
        }}
        td {{
            border: 1px solid var(--border);
            padding: 0.5rem 0.75rem;
        }}
        blockquote {{
            border-left: 3px solid var(--border);
            padding-left: 1rem;
            color: var(--muted);
            margin-bottom: 0.75rem;
        }}
        .meta {{
            color: var(--muted);
            font-size: 0.85rem;
            margin-bottom: 2rem;
        }}
        .badge {{
            display: inline-block;
            padding: 0.2em 0.6em;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-right: 0.3rem;
        }}
        .critical {{ background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }}
        .high     {{ background: rgba(255,123,114,0.15); color: var(--high); border: 1px solid var(--high); }}
        .medium   {{ background: rgba(210,153,34,0.15); color: var(--medium); border: 1px solid var(--medium); }}
        hr {{ border: none; border-top: 1px solid var(--border); margin: 2rem 0; }}
        a {{ color: var(--accent); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 3rem; color: var(--muted); font-size: 0.8rem; text-align: center; }}
    </style>
</head>
<body>
    <div class="meta">Generado el {generated_at} · Pipeline de Threat Intelligence</div>
    {body}
    <div class="footer">
        Informe generado automáticamente · {provider} · {total_articles} artículos de {total_feeds} fuentes
    </div>
</body>
</html>"""


def markdown_to_html_body(markdown_text: str) -> str:
    """
    Convierte Markdown básico a HTML sin dependencias externas.
    Soporta: encabezados, listas, código, negrita, cursiva, hr, tablas.
    """
    lines = markdown_text.split("\n")
    html_lines = []
    list_tag: str | None = None   # "ul" | "ol" | None
    in_code_block = False
    in_table = False
    in_thead = False   # True mientras no se haya visto la fila separadora ---

    def close_list() -> None:
        nonlocal list_tag
        if list_tag:
            html_lines.append(f"</{list_tag}>")
            list_tag = None

    def close_table() -> None:
        nonlocal in_table, in_thead
        if in_table:
            html_lines.append("</thead>" if in_thead else "</tbody>")
            html_lines.append("</table>")
            in_table = False
            in_thead = False

    for line in lines:
        # Bloques de código
        if line.strip().startswith("```"):
            if in_code_block:
                html_lines.append("</code></pre>")
                in_code_block = False
            else:
                close_list()
                html_lines.append("<pre><code>")
                in_code_block = True
            continue

        if in_code_block:
            html_lines.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            continue

        # Tablas
        if "|" in line and line.strip().startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not in_table:
                close_list()
                html_lines.append("<table><thead>")
                in_table = True
                in_thead = True
                html_lines.append(
                    "<tr>" + "".join(f"<th>{_inline(c)}</th>" for c in cells) + "</tr>"
                )
            elif in_thead and all(re.match(r"[-:]+", c) for c in cells):
                # fila separadora de Markdown (|---|---|): cierra thead, abre tbody
                html_lines.append("</thead><tbody>")
                in_thead = False
            elif in_thead:
                # fila de datos antes de ver el separador (tabla sin separador)
                html_lines.append("</thead><tbody>")
                in_thead = False
                html_lines.append(
                    "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>"
                )
            else:
                html_lines.append(
                    "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>"
                )
            continue
        elif in_table:
            close_table()

        # Separadores
        if re.match(r"^---+$", line.strip()):
            close_list()
            html_lines.append("<hr>")
            continue

        # Encabezados
        hm = re.match(r"^(#{1,4})\s+(.*)", line)
        if hm:
            close_list()
            level = len(hm.group(1))
            html_lines.append(f"<h{level}>{_inline(hm.group(2))}</h{level}>")
            continue

        # Listas no ordenadas
        if re.match(r"^[\*\-]\s+", line):
            if list_tag != "ul":
                close_list()
                html_lines.append("<ul>")
                list_tag = "ul"
            html_lines.append(f"<li>{_inline(re.sub(r'^[*-]\\s+', '', line))}</li>")
            continue

        # Listas ordenadas
        if re.match(r"^\d+\.\s+", line):
            if list_tag != "ol":
                close_list()
                html_lines.append("<ol>")
                list_tag = "ol"
            html_lines.append(f"<li>{_inline(re.sub(r'^\\d+\\.\\s+', '', line))}</li>")
            continue

        # Línea vacía cierra lista abierta
        if not line.strip():
            close_list()
            html_lines.append("")
            continue

        # Blockquote
        if line.startswith(">"):
            html_lines.append(f"<blockquote><p>{_inline(line.lstrip('> '))}</p></blockquote>")
            continue

        # Párrafo normal
        html_lines.append(f"<p>{_inline(line)}</p>")

    close_list()
    close_table()

    return "\n".join(html_lines)


def _inline(text: str) -> str:
    """Procesa formato inline: negrita, cursiva, código, links."""
    # Código inline
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # Negrita
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"__(.+?)__", r"<strong>\1</strong>", text)
    # Cursiva
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # Links
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def split_report_sections(markdown: str) -> dict[str, str]:
    """
    Divide el output del LLM en secciones usando los marcadores de Stage 3.
    Retorna {"vulnerability": <md>, "threat_intel": <md>} si se encuentran marcadores,
    o {"full": <md>} como fallback para compatibilidad con el formato antiguo.
    """
    vuln = re.search(
        r"===VULNERABILITY_BRIEFING===\s*\n(.*?)(?===THREAT_INTEL_DIGEST===|===END===)",
        markdown, re.DOTALL,
    )
    intel = re.search(
        r"===THREAT_INTEL_DIGEST===\s*\n(.*?)(?===END===|$)",
        markdown, re.DOTALL,
    )
    if vuln and intel:
        return {
            "vulnerability": vuln.group(1).strip(),
            "threat_intel":  intel.group(1).strip(),
        }
    # El modelo no siguió el formato — guardar como informe único
    logger.warning("Marcadores de sección no encontrados; guardando informe único.")
    return {"full": markdown}


def _render_html(content: str, template: str, date_str: str,
                 generated_at: str, total_articles: int,
                 total_feeds: int, provider: str) -> str:
    body = markdown_to_html_body(content)
    return template.format(
        date=date_str,
        generated_at=generated_at,
        body=body,
        total_articles=total_articles,
        total_feeds=total_feeds,
        provider=provider or "pipeline",
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
                       provider: str = "") -> None:
    content = _strip_emoji(content)
    if fmt == "md":
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    elif fmt == "pdf":
        html = _render_html(content, PDF_HTML_TEMPLATE, date_str,
                            generated_at, total_articles, total_feeds, provider)
        _write_pdf(html, path)
    else:
        html = _render_html(content, HTML_TEMPLATE, date_str,
                            generated_at, total_articles, total_feeds, provider)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)


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
    paths: dict[str, str] = {}

    sections = split_report_sections(markdown_content) if split else {"full": markdown_content}

    file_prefixes = {
        "vulnerability": "vuln-briefing",
        "threat_intel":  "threat-digest",
        "full":          filename_prefix or "threat-briefing",
    }

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
            _write_report_file(content, path, "md", date_str, generated_at,
                               total_articles, total_feeds, provider)
            paths[f"{key}_markdown"] = path
            logger.info(f"Informe Markdown ({key}): {path}")

        if write_html:
            path = os.path.join(reports_dir, f"{prefix}-{safe_date}.html")
            _write_report_file(content, path, "html", date_str, generated_at,
                               total_articles, total_feeds, provider)
            paths[f"{key}_html"] = path
            logger.info(f"Informe HTML ({key}): {path}")

        if write_pdf:
            path = os.path.join(output_dir, f"{prefix}-{safe_date}.pdf")
            _write_report_file(content, path, "pdf", date_str, generated_at,
                               total_articles, total_feeds, provider)
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
            _write_report_file(combined, path, "html", date_str, generated_at,
                               total_articles, total_feeds, provider)
            paths["full_html"] = path
        if write_pdf:
            path = os.path.join(output_dir, f"threat-briefing-{safe_date}.pdf")
            _write_report_file(combined, path, "pdf", date_str, generated_at,
                               total_articles, total_feeds, provider)
            paths["full_pdf"] = path
            logger.info(f"Informe PDF (completo): {path}")

    return paths
