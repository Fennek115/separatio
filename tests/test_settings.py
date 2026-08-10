"""Tests de la configuración inyectable (F-G/G-2) — sin red, sin tocar el entorno.

Lo que fija este fichero, en orden de importancia:

1. **El aislamiento del `--dry-run`.** Hasta G-2 se conseguía mutando el módulo
   `config` en caliente; ahora es `Settings.derive(...)`. Si esto se rompe, un
   dry-run vuelve a pisar el informe real, el caché del día y `history.json` —
   que es exactamente el incidente del 2026-08-08.
2. Que `from_env()` lea el entorno **inyectado** y no el de la máquina, para que
   los tests sean deterministas corran donde corran.
3. Que la fachada `config` siga exponiendo todo, incluido el acceso **por nombre
   dinámico** del que dependen `hygiene.build_classifier` y `setup_check`.
"""

import dataclasses
from pathlib import Path
from types import SimpleNamespace

import pytest

from separatio import config
from separatio.pipeline import settings_for
from separatio.settings import Settings, env_bool


def args(**kw):
    """Los flags que mira `settings_for`, con los defaults de argparse."""
    base = dict(dry_run=False, categories=None)
    base.update(kw)
    return SimpleNamespace(**base)


# ── from_env: el entorno entra por parámetro ────────────────

def test_from_env_no_mira_la_maquina_si_le_pasan_entorno():
    s = Settings.from_env({})
    assert s.ANTHROPIC_API_KEY == ""
    assert s.MINIFLUX_API_TOKEN == ""
    assert s.OWN_IPS == ""


def test_from_env_toma_las_claves_del_entorno():
    s = Settings.from_env({
        "ANTHROPIC_API_KEY": "sk-x", "OPENAI_API_KEY": "oa-x",
        "GEMINI_API_KEY": "gm-x", "MINIFLUX_API_TOKEN": "mf-x",
        "OWN_IPS": "1.2.3.4,5.6.7.0/24",
    })
    assert (s.ANTHROPIC_API_KEY, s.OPENAI_API_KEY, s.GEMINI_API_KEY) == \
        ("sk-x", "oa-x", "gm-x")
    assert s.MINIFLUX_API_TOKEN == "mf-x"
    assert s.OWN_IPS == "1.2.3.4,5.6.7.0/24"


def test_from_env_no_toca_lo_que_no_viene_del_entorno():
    """Un valor fijo no se puede cambiar por variable de entorno: vive en
    settings.py y se edita ahí."""
    s = Settings.from_env({"MAX_ARTICLES": "5", "PROVIDER": "openai"})
    assert s.MAX_ARTICLES == 120
    assert s.PROVIDER == "claude"


@pytest.mark.parametrize("valor,esperado", [
    ("0", False), ("false", False), ("no", False), ("off", False), ("", False),
    ("FALSE", False), (" off ", False),
    ("1", True), ("true", True), ("sí", True), ("cualquiera", True),
])
def test_env_bool_interpreta_los_apagados(valor, esperado):
    assert env_bool("X", True, {"X": valor}) is esperado


def test_env_bool_sin_la_variable_usa_el_default():
    assert env_bool("X", True, {}) is True
    assert env_bool("X", False, {}) is False


def test_los_toggles_se_apagan_por_entorno():
    s = Settings.from_env({"STORE_ENABLED": "0", "LOCAL_LISTS_ENABLED": "off",
                           "SCANNER_PTR_LOOKUP": "false"})
    assert s.STORE_ENABLED is False
    assert s.LOCAL_LISTS_ENABLED is False
    assert s.SCANNER_PTR_LOOKUP is False
    assert s.SCANNER_CLASSIFY is True     # este no se tocó


def test_malwarebazaar_junta_las_keys_en_orden_y_saltea_las_vacias():
    s = Settings.from_env({"ABUSECH_API_KEY": "a", "MALWAREBAZAAR_AUTH_KEY": "c"})
    assert s.MALWAREBAZAAR_AUTH_KEYS == ["a", "c"]
    assert Settings.from_env({}).MALWAREBAZAAR_AUTH_KEYS == []


# ── inmutabilidad y derive ──────────────────────────────────

def test_settings_es_inmutable():
    s = Settings.from_env({})
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.MAX_ARTICLES = 5


def test_derive_devuelve_otro_sin_tocar_el_original():
    a = Settings.from_env({})
    b = a.derive(MAX_ARTICLES=5)
    assert (a.MAX_ARTICLES, b.MAX_ARTICLES) == (120, 5)
    assert a is not b
    assert b.PROVIDER == a.PROVIDER      # el resto viaja igual


def test_derive_rechaza_un_campo_que_no_existe():
    """Sin esto, un typo en el nombre se tragaría en silencio."""
    with pytest.raises(TypeError, match="NO_EXISTE"):
        Settings.from_env({}).derive(NO_EXISTE=1)


def test_as_dict_trae_todos_los_campos():
    s = Settings.from_env({})
    d = s.as_dict()
    assert d["MAX_ARTICLES"] == 120
    assert len(d) == len(dataclasses.fields(Settings))


# ── el aislamiento del --dry-run (incidente 2026-08-08) ─────

def test_dry_run_aisla_la_salida_bajo_dryrun():
    base = Settings.from_env({}).derive(OUTPUT_DIR="/tmp/reports")
    cfg = settings_for(args(dry_run=True), base)
    assert cfg.OUTPUT_DIR == str(Path("/tmp/reports") / "dryrun")
    assert cfg.HISTORY_FILE == str(Path("/tmp/reports") / "dryrun" / "history.json")


def test_dry_run_no_toca_el_settings_de_produccion():
    """El punto entero de G-2: derivar no muta al de al lado."""
    base = Settings.from_env({}).derive(
        OUTPUT_DIR="/tmp/reports", HISTORY_FILE="/tmp/reports/history.json")
    settings_for(args(dry_run=True), base)
    assert base.OUTPUT_DIR == "/tmp/reports"
    assert base.HISTORY_FILE == "/tmp/reports/history.json"


def test_sin_dry_run_las_rutas_quedan_como_estaban():
    base = Settings.from_env({}).derive(
        OUTPUT_DIR="/tmp/reports", HISTORY_FILE="/tmp/reports/history.json")
    cfg = settings_for(args(), base)
    assert cfg.OUTPUT_DIR == "/tmp/reports"
    assert cfg.HISTORY_FILE == "/tmp/reports/history.json"


def test_el_history_del_dry_run_cuelga_del_dryrun_no_del_real():
    """La línea que más importa: si HISTORY_FILE se quedara apuntando al real,
    un dry-run le metería un registro falso a la serie de trending."""
    base = Settings.from_env({}).derive(
        OUTPUT_DIR="/var/out", HISTORY_FILE="/var/out/history.json")
    cfg = settings_for(args(dry_run=True), base)
    assert cfg.HISTORY_FILE != base.HISTORY_FILE
    assert "dryrun" in cfg.HISTORY_FILE


def test_categories_sobreescribe_feed_categories():
    cfg = settings_for(args(categories="Vulnerability, Threat Intel"))
    assert cfg.FEED_CATEGORIES == ["Vulnerability", "Threat Intel"]


def test_categories_y_dry_run_se_combinan():
    base = Settings.from_env({}).derive(OUTPUT_DIR="/tmp/r")
    cfg = settings_for(args(categories="LATAM", dry_run=True), base)
    assert cfg.FEED_CATEGORIES == ["LATAM"]
    assert cfg.OUTPUT_DIR.endswith("dryrun")


def test_sin_base_arranca_del_config_global():
    cfg = settings_for(args())
    assert cfg.OUTPUT_DIR == config.SETTINGS.OUTPUT_DIR


# ── la fachada `config` ─────────────────────────────────────

def test_config_expone_todos_los_campos_del_settings():
    for f in dataclasses.fields(Settings):
        assert hasattr(config, f.name), f"config no expone {f.name}"
        assert getattr(config, f.name) == getattr(config.SETTINGS, f.name)


def test_config_sigue_soportando_el_acceso_por_nombre_dinamico():
    """`hygiene.build_classifier` y `setup_check` leen así; si un rename los
    dejara sin nombre, fallarían en silencio cayendo al default."""
    for nombre in ("OWN_IPS", "SCANNER_CLASSIFY", "SCANNER_PTR_TIMEOUT",
                   "OWN_IP_RESOLVE_URL", "SUMMARY_MODEL", "REPORT_MODEL"):
        centinela = object()
        assert getattr(config, nombre, centinela) is not centinela, nombre


def test_la_fachada_es_monkeypatcheable(monkeypatch):
    """Los tests que ya existían lo hacen así — tenía que seguir andando."""
    monkeypatch.setattr(config, "STORE_ENABLED", False)
    assert config.STORE_ENABLED is False


def test_build_classifier_acepta_un_settings():
    """El patrón que F-A tuvo que inventar a mano ahora recibe el objeto."""
    from separatio.hygiene import SELF, build_classifier
    s = Settings.from_env({}).derive(
        OWN_IPS="9.9.9.9", OWN_IP_RESOLVE=False, SCANNER_PTR_LOOKUP=False)
    clf = build_classifier(s)
    assert clf.classify("9.9.9.9")[0] == SELF
