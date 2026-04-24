"""
reporter.py — Renderiza el informe de threat intelligence a Markdown, HTML y PDF.
"""

import os
import re
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


PDF_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Threat Intelligence Briefing — {date}</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm 2.5cm;
            @bottom-right {{ content: "Pág. " counter(page) " / " counter(pages); font-size: 8pt; color: #666; }}
            @bottom-left  {{ content: "Threat Intelligence · {date}"; font-size: 8pt; color: #666; }}
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 10pt;
            color: #1a1a1a;
            line-height: 1.6;
        }}
        .cover {{
            text-align: center;
            padding-top: 4cm;
            page-break-after: always;
        }}
        .cover h1 {{ font-size: 22pt; color: #1a56db; margin-bottom: 0.5rem; }}
        .cover .subtitle {{ font-size: 12pt; color: #555; margin-bottom: 2rem; }}
        .cover .meta {{ font-size: 9pt; color: #888; border-top: 1px solid #ddd; padding-top: 1rem; }}
        h1 {{ font-size: 16pt; color: #1a56db; margin: 1.5rem 0 0.5rem;
               border-bottom: 2px solid #1a56db; padding-bottom: 0.3rem; page-break-after: avoid; }}
        h2 {{ font-size: 12pt; color: #1e293b; margin: 1.2rem 0 0.4rem;
               border-left: 3px solid #1a56db; padding-left: 0.5rem; page-break-after: avoid; }}
        h3 {{ font-size: 10pt; color: #334155; margin: 0.8rem 0 0.3rem; page-break-after: avoid; }}
        p  {{ margin-bottom: 0.5rem; }}
        ul, ol {{ padding-left: 1.2rem; margin-bottom: 0.5rem; }}
        li {{ margin-bottom: 0.2rem; }}
        code {{
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            border-radius: 3px;
            padding: 0.05em 0.3em;
            font-family: "Courier New", monospace;
            font-size: 8.5pt;
            color: #0f172a;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 0.8rem;
            font-size: 9pt;
            page-break-inside: avoid;
        }}
        th {{
            background: #1e293b;
            color: #f8fafc;
            border: 1px solid #334155;
            padding: 0.4rem 0.6rem;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            border: 1px solid #cbd5e1;
            padding: 0.35rem 0.6rem;
        }}
        tr:nth-child(even) td {{ background: #f8fafc; }}
        blockquote {{
            border-left: 3px solid #94a3b8;
            padding-left: 0.8rem;
            color: #64748b;
            margin-bottom: 0.5rem;
        }}
        hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 1.2rem 0; }}
        a {{ color: #1a56db; text-decoration: none; }}
        strong {{ color: #0f172a; }}
        .section-break {{ page-break-before: always; }}
        .footer-note {{ margin-top: 1.5rem; font-size: 8pt; color: #94a3b8; text-align: center; }}
    </style>
</head>
<body>
    <div class="cover">
        <div class="subtitle">THREAT INTELLIGENCE REPORT</div>
        <h1>{date}</h1>
        <div class="meta">
            Generado el {generated_at}<br>
            {total_articles} artículos · {total_feeds} fuentes · {provider}
        </div>
    </div>
    {body}
    <div class="footer-note">Informe generado automáticamente — uso interno</div>
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

    def close_list() -> None:
        nonlocal list_tag
        if list_tag:
            html_lines.append(f"</{list_tag}>")
            list_tag = None

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
                html_lines.append("<table>")
                in_table = True
                html_lines.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
            elif all(re.match(r"[-:]+", c) for c in cells):
                pass
            else:
                html_lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            continue
        elif in_table:
            html_lines.append("</table>")
            in_table = False

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
    if in_table:
        html_lines.append("</table>")

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
                split: bool = True, provider: str = "") -> dict[str, str]:
    """
    Guarda el informe en Markdown y/o HTML.
    Si split=True y el contenido contiene marcadores de sección, genera archivos
    separados para el Vulnerability Briefing y el Threat Intel Digest.
    Siempre genera también el informe completo (threat-briefing-*) como fallback.
    Retorna dict con todas las rutas generadas.
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    safe_date    = date_str.replace(" ", "_").replace("/", "-")
    paths: dict[str, str] = {}

    sections = split_report_sections(markdown_content) if split else {"full": markdown_content}

    # Mapeo de clave de sección → prefijo de archivo
    file_prefixes = {
        "vulnerability": "vuln-briefing",
        "threat_intel":  "threat-digest",
        "full":          "threat-briefing",
    }

    write_md   = fmt in ("markdown", "both", "all")
    write_html = fmt in ("html", "both", "all")
    write_pdf  = fmt in ("pdf", "all")

    for key, content in sections.items():
        prefix = file_prefixes[key]

        if write_md:
            path = os.path.join(output_dir, f"{prefix}-{safe_date}.md")
            _write_report_file(content, path, "md", date_str, generated_at,
                               total_articles, total_feeds, provider)
            paths[f"{key}_markdown"] = path
            logger.info(f"Informe Markdown ({key}): {path}")

        if write_html:
            path = os.path.join(output_dir, f"{prefix}-{safe_date}.html")
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

    # Si se generaron secciones separadas, guardar también el informe completo
    # (sin marcadores) para compatibilidad con scripts externos
    if "vulnerability" in sections:
        combined = sections["vulnerability"] + "\n\n---\n\n" + sections["threat_intel"]
        if write_md:
            path = os.path.join(output_dir, f"threat-briefing-{safe_date}.md")
            with open(path, "w", encoding="utf-8") as f:
                f.write(combined)
            paths["full_markdown"] = path
        if write_html:
            path = os.path.join(output_dir, f"threat-briefing-{safe_date}.html")
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
