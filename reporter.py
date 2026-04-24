"""
reporter.py — Renderiza el informe de threat intelligence a Markdown y HTML.
"""

import os
import re
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


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


def _write_report_file(content: str, path: str, fmt: str,
                       date_str: str, generated_at: str,
                       total_articles: int, total_feeds: int,
                       provider: str = "") -> None:
    if fmt == "md":
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        body = markdown_to_html_body(content)
        html = HTML_TEMPLATE.format(
            date=date_str,
            generated_at=generated_at,
            body=body,
            total_articles=total_articles,
            total_feeds=total_feeds,
            provider=provider or "pipeline",
        )
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

    write_md   = fmt in ("markdown", "both")
    write_html = fmt in ("html", "both")

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

    return paths
