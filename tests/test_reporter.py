"""Tests del reporter (F-G/G-6) — sin red, sobre tmp_path.

Antes de G-6 `reporter.py` no tenía un solo test: ningún test del repo lo
importaba, igual que le pasaba a `pipeline.py` antes de G-3. Estos fijan el
contrato de las dos piezas que el ítem cambió —las plantillas Jinja2 y el
parser de Markdown— más lo que ya existía y nadie cubría (`save_report`,
`split_report_sections`).

El invariante que más importa está en `test_toc_*`: la plantilla de PDF numera
las páginas del índice con `target-counter(attr(href), page)`, así que si los
`href` del TOC y los `id` de los encabezados se desincronizan, el índice del
PDF se rompe **en silencio** (sale sin números de página, no falla el render).
"""

from bs4 import BeautifulSoup

import pytest

from separatio.reporter import (
    PDF_TEMPLATE, WEB_TEMPLATE, WIDE_TABLE_MIN_COLS,
    _build_toc_html, _content_hash, _extract_toc_entries, _is_table_separator,
    _make_report_id, _render_html, _render_markdown, _slugify, _strip_emoji,
    markdown_to_html_body, save_report, split_report_sections,
)


def soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


def render(md: str) -> BeautifulSoup:
    return soup(markdown_to_html_body(md))


# ── higiene de texto ────────────────────────────────────────

def test_strip_emoji_saca_emoji_y_deja_acentos():
    assert _strip_emoji("Análisis 🔥 crítico ⚠️") .replace("  ", " ").strip() == \
        "Análisis crítico"


def test_slugify_translitera_acentos_y_enes():
    assert _slugify("Análisis Técnico de Vulnerabilidades") == \
        "analisis-tecnico-de-vulnerabilidades"
    assert _slugify("Año 2026: ¿Qué pasó?") == "ano-2026-que-paso"


def test_slugify_ignora_html_embebido():
    assert _slugify("<strong>Panorama</strong> del Día") == "panorama-del-dia"


def test_report_id_tiene_el_formato_documentado():
    rid = _make_report_id("2026-08-09")
    assert rid.startswith("TIR-20260809-") and len(rid) == len("TIR-20260809-ABCD")


def test_content_hash_es_sha256_hex():
    h = _content_hash("hola")
    assert len(h) == 64 and int(h, 16) >= 0


# ── Markdown: lo básico ─────────────────────────────────────

def test_encabezados_llevan_id_slugificado():
    h = render("# Panorama del Día").find("h1")
    assert h["id"] == "panorama-del-dia"


def test_encabezados_de_los_cuatro_niveles():
    s = render("# a\n\n## b\n\n### c\n\n#### d")
    assert [t.name for t in s.find_all(["h1", "h2", "h3", "h4"])] == ["h1", "h2", "h3", "h4"]


def test_listas_no_ordenadas_y_ordenadas():
    s = render("- uno\n- dos\n")
    assert len(s.find_all("ul")) == 1 and len(s.find_all("li")) == 2
    s = render("1. uno\n2. dos\n")
    assert len(s.find_all("ol")) == 1 and len(s.find_all("li")) == 2


def test_sublistas_indentadas_se_anidan():
    """El parser de regex anterior sólo matcheaba `^[*-]` y dejaba las
    indentadas como párrafo, con el guion visible como texto."""
    s = render("- padre\n    - hijo\n")
    assert s.select_one("ul li ul li").get_text().strip() == "hijo"
    assert "- hijo" not in s.get_text()


def test_inline_negrita_cursiva_codigo_y_link():
    s = render("**b** *i* `c` [t](http://x)")
    assert s.find("strong").text == "b"
    assert s.find("em").text == "i"
    assert s.find("code").text == "c"
    assert s.find("a")["href"] == "http://x"


def test_bloque_de_codigo_con_fences():
    s = render("```\nls -la\n```")
    assert s.find("pre").find("code").text.strip() == "ls -la"


def test_hr_y_blockquote():
    assert render("---").find("hr") is not None
    assert render("> citado").find("blockquote").get_text().strip() == "citado"


def test_hard_break_de_dos_espacios_se_respeta():
    """El LLM usa el hard break estándar (dos espacios al final de línea);
    el parser anterior lo ignoraba y abría un párrafo nuevo por cada línea."""
    s = render("uno  \ndos")
    assert len(s.find_all("p")) == 1 and s.find("br") is not None


# ── Markdown: tablas ────────────────────────────────────────

TABLA = "| A | B |\n|---|---|\n| 1 | 2 |"


def test_tabla_basica():
    s = render(TABLA)
    assert [t.text for t in s.find_all("th")] == ["A", "B"]
    assert [t.text for t in s.find_all("td")] == ["1", "2"]


def test_tabla_pegada_al_parrafo_anterior_igual_se_reconoce():
    """Regresión encontrada contra el informe real del 2026-08-08: el LLM
    escribe la tabla sin línea en blanco después del párrafo, y
    Python-Markdown a secas se la traga entera dentro del `<p>`."""
    s = render("**IPs maliciosas:**\n" + TABLA)
    assert s.find("table") is not None
    assert [t.text for t in s.find_all("th")] == ["A", "B"]


def test_el_arreglo_no_parte_una_tabla_ya_empezada():
    s = render("| A | B |\n|---|---|\n| 1 | 2 |\n|---|---|\n| 3 | 4 |")
    assert len(s.find_all("table")) == 1


def test_el_arreglo_no_toca_lo_que_hay_dentro_de_un_fence():
    s = render("texto\n```\n| A | B |\n|---|---|\n```")
    assert s.find("table") is None
    assert "| A | B |" in s.find("pre").get_text()


@pytest.mark.parametrize("sep,esperado", [
    ("|---|---|", True),
    ("|-----|------|---------|", True),
    ("| :--- | ---: | :---: |", True),
    ("| A | B |", False),
    ("texto suelto", False),
])
def test_is_table_separator(sep, esperado):
    assert _is_table_separator(sep) is esperado


def test_tabla_ancha_lleva_la_clase_table_wide():
    cols = WIDE_TABLE_MIN_COLS + 1
    md = ("|" + "|".join(f"c{i}" for i in range(cols)) + "|\n"
          + "|" + "|".join("---" for _ in range(cols)) + "|\n"
          + "|" + "|".join("v" for _ in range(cols)) + "|")
    assert render(md).find("table").get("class") == ["table-wide"]


def test_tabla_angosta_no_lleva_la_clase():
    assert render(TABLA).find("table").get("class") is None


# ── índice (TOC) ────────────────────────────────────────────

DOC = "# Uno\n\ntexto\n\n## Dos\n\n### Tres\n\n# Cuatro\n"


def test_toc_solo_toma_h1_y_h2():
    assert [(lvl, txt) for lvl, txt, _ in _extract_toc_entries(DOC)] == [
        (1, "Uno"), (2, "Dos"), (1, "Cuatro")]


def test_toc_html_lleva_las_clases_que_espera_el_css():
    s = soup(_build_toc_html(_extract_toc_entries(DOC)))
    assert s.select_one("div.toc p.toc-title").text == "Índice"
    assert [li["class"][0] for li in s.select("ul.toc-list li")] == \
        ["toc-h1", "toc-h2", "toc-h1"]
    assert s.select_one("a.toc-link")["href"] == "#uno"


def test_toc_vacio_no_emite_markup():
    assert _build_toc_html([]) == ""


def test_toc_escapa_el_texto_del_titulo():
    s = _build_toc_html([(1, "A & B <x>", "a-b")])
    assert "&amp;" in s and "<x>" not in s


def test_anclas_del_toc_resuelven_contra_los_ids_del_cuerpo():
    """El invariante del índice del PDF: todo href del TOC existe como id."""
    body, entries = _render_markdown(DOC)
    ids = {e["id"] for e in soup(body).find_all(id=True)}
    assert {slug for _, _, slug in entries} <= ids


def test_titulos_repetidos_no_rompen_las_anclas():
    """Dos secciones con el mismo nombre: los ids se desambiguan y el TOC
    tiene que seguir apuntando a uno distinto por entrada."""
    body, entries = _render_markdown("# Panorama\n\n## Panorama\n\n# Panorama\n")
    ids = {e["id"] for e in soup(body).find_all(id=True)}
    slugs = [slug for _, _, slug in entries]
    assert len(set(slugs)) == 3, "los slugs del TOC deben ser únicos"
    assert set(slugs) <= ids


# ── secciones del informe ───────────────────────────────────

def test_split_report_sections_con_marcadores():
    """Ojo con el `=` de más: es un bug preexistente, fijado a propósito.

    El lookahead está escrito `(?===THREAT_INTEL_DIGEST===`, que Python lee
    como `(?=` + `==THREAT...` (dos `=`, no tres), así que la sección se queda
    con el primer `=` del marcador siguiente. **No se arregló en G-6**: está
    fuera del ítem y sólo afecta a la rama legacy `PHASE_REPORTS=False` — con
    el default de producción el modelo no emite marcadores y esto cae a
    `{"full": ...}` (ver el test de abajo). Anotado como deuda en F-G.md.
    """
    md = ("===VULNERABILITY_BRIEFING===\nvuln\n"
          "===THREAT_INTEL_DIGEST===\nintel\n===END===")
    assert split_report_sections(md) == {
        "vulnerability": "vuln\n=", "threat_intel": "intel\n="}


def test_split_report_sections_sin_marcadores_cae_a_full():
    assert split_report_sections("informe suelto") == {"full": "informe suelto"}


# ── plantillas ──────────────────────────────────────────────

def html_de(template):
    return _render_html("# Título\n\ntexto", template, "2026-08-09", "2026-08-09 07:00",
                        116, 40, "claude", "TIR-20260809-AB12", "d" * 64)


def test_plantilla_pdf_trae_portada_indice_y_colofon():
    h = html_de(PDF_TEMPLATE)
    s = soup(h)
    assert s.select_one("div.cover h1") is not None
    assert s.select_one("div.toc") is not None, "el PDF lleva índice"
    assert s.select_one("div.colophon") is not None
    assert "TIR-20260809-AB12" in h and "d" * 64 in h
    assert "@page" in h, "el CSS de paginado A4 tiene que seguir estando"


def test_plantilla_web_no_lleva_indice_ni_portada():
    s = soup(html_de(WEB_TEMPLATE))
    assert s.select_one("div.toc") is None
    assert s.select_one("div.cover") is None
    assert s.select_one("div.meta") is not None
    assert "claude" in s.select_one("div.footer").text


def test_las_dos_plantillas_meten_el_cuerpo_como_html_no_escapado():
    for tpl in (PDF_TEMPLATE, WEB_TEMPLATE):
        assert "<h1 id=" in html_de(tpl), f"{tpl} escapó el cuerpo"


def test_provider_vacio_cae_a_pipeline():
    h = _render_html("x", WEB_TEMPLATE, "2026-08-09", "x", 1, 1, "")
    assert "pipeline" in soup(h).select_one("div.footer").text


def test_las_variables_de_las_plantillas_se_sustituyen_todas():
    """Si una plantilla queda con un placeholder sin pasar, Jinja lo deja
    vacío en silencio; esto detecta el caso contrario (llave suelta)."""
    for tpl in (PDF_TEMPLATE, WEB_TEMPLATE):
        h = html_de(tpl)
        assert "{{" not in h and "{%" not in h


# ── save_report ─────────────────────────────────────────────

MD_SPLIT = ("===VULNERABILITY_BRIEFING===\n# Vulns\n\ntexto\n"
            "===THREAT_INTEL_DIGEST===\n# Intel\n\ntexto\n===END===")


def test_save_report_escribe_md_y_html_de_cada_seccion(tmp_path):
    paths = save_report(MD_SPLIT, str(tmp_path), "2026-08-09", 10, 5, fmt="both")
    for k in ("vulnerability_markdown", "vulnerability_html",
              "threat_intel_markdown", "threat_intel_html",
              "full_markdown", "full_html"):
        assert k in paths, k
        assert (tmp_path / "reports").exists()
        assert open(paths[k], encoding="utf-8").read()


def test_save_report_combina_las_dos_secciones_en_el_full(tmp_path):
    paths = save_report(MD_SPLIT, str(tmp_path), "2026-08-09", 10, 5, fmt="markdown")
    combinado = open(paths["full_markdown"], encoding="utf-8").read()
    assert "# Vulns" in combinado and "# Intel" in combinado


def test_save_report_sin_split_escribe_un_solo_informe(tmp_path):
    paths = save_report("# Solo\n\ntexto", str(tmp_path), "2026-08-09", 10, 5,
                        fmt="markdown", split=False)
    assert set(paths) == {"full_markdown"}
    assert paths["full_markdown"].endswith("threat-briefing-2026-08-09.md")


def test_save_report_respeta_filename_prefix(tmp_path):
    paths = save_report("# Semanal", str(tmp_path), "2026-08-09", 10, 5,
                        fmt="markdown", split=False, filename_prefix="weekly-report")
    assert paths["full_markdown"].endswith("weekly-report-2026-08-09.md")


def test_save_report_markdown_no_pasa_por_el_parser(tmp_path):
    """El .md se guarda tal cual (menos emoji), no renderizado."""
    paths = save_report("# T\n\n- a", str(tmp_path), "2026-08-09", 1, 1,
                        fmt="markdown", split=False)
    assert open(paths["full_markdown"], encoding="utf-8").read() == "# T\n\n- a"


def test_save_report_html_es_html_renderizado(tmp_path):
    paths = save_report("# T\n\ntexto", str(tmp_path), "2026-08-09", 1, 1,
                        fmt="html", split=False)
    contenido = open(paths["full_html"], encoding="utf-8").read()
    assert contenido.startswith("<!DOCTYPE html>") and '<h1 id="t">' in contenido
