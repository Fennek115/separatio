#!/usr/bin/env python3
"""
setup_check.py — Verifica que el entorno esté correctamente configurado.
Ejecutar antes de usar el pipeline por primera vez.
"""

import sys
import subprocess


def check(label: str, ok: bool, detail: str = ""):
    icon = "✅" if ok else "❌"
    print(f"  {icon}  {label}", end="")
    if detail:
        print(f"  ({detail})", end="")
    print()
    return ok


def main():
    print("\n🔍 Verificando entorno del pipeline de Threat Intelligence\n")
    all_ok = True

    # Python version
    v = sys.version_info
    ok = v.major == 3 and v.minor >= 10
    all_ok &= check(f"Python {v.major}.{v.minor}.{v.micro}", ok,
                    "Se requiere 3.10+" if not ok else "")

    # Dependencias Python
    deps = ["ollama", "trafilatura", "requests", "bs4"]
    for dep in deps:
        try:
            __import__(dep)
            all_ok &= check(f"Módulo: {dep}", True)
        except ImportError:
            all_ok &= check(f"Módulo: {dep}", False,
                            f"pip install {dep} --break-system-packages")

    # Miniflux
    print("\n  — Miniflux —")
    try:
        import requests, config
        r = requests.get(
            f"{config.MINIFLUX_URL}/v1/me",
            auth=(config.MINIFLUX_USERNAME, config.MINIFLUX_PASSWORD),
            timeout=5,
        )
        ok = r.status_code == 200
        user = r.json().get("username", "?") if ok else ""
        all_ok &= check("Conexión Miniflux API", ok,
                        f"usuario: {user}" if ok else f"HTTP {r.status_code}")
    except Exception as e:
        all_ok &= check("Conexión Miniflux API", False, str(e)[:60])

    # Ollama
    print("\n  — Ollama —")
    try:
        import ollama, config
        client = ollama.Client(host=config.OLLAMA_HOST)
        models_data = client.list()
        model_names = [m.model for m in models_data.models]
        all_ok &= check("Ollama en ejecución", True,
                        f"{len(model_names)} modelos disponibles")

        for model_key in ("SUMMARY_MODEL", "REPORT_MODEL"):
            model = getattr(config, model_key)
            # Buscar match parcial (ej: "mistral:7b-instruct" en "mistral:7b-instruct-q4_0")
            found = any(model in m or m in model for m in model_names)
            all_ok &= check(f"Modelo {model_key}: {model}", found,
                            "ollama pull " + model if not found else "encontrado")

    except Exception as e:
        all_ok &= check("Ollama en ejecución", False, str(e)[:60])

    # Directorio de salida
    print("\n  — Configuración —")
    try:
        import config
        from pathlib import Path
        Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
        check("Directorio de salida", True, config.OUTPUT_DIR)
    except Exception as e:
        all_ok &= check("Directorio de salida", False, str(e))

    # Resumen
    print()
    if all_ok:
        print("🎉 Todo listo. Puedes ejecutar: python pipeline.py --dry-run")
    else:
        print("⚠️  Hay problemas que resolver antes de ejecutar el pipeline.")
        print("   Revisa los ítems con ❌ arriba.")
    print()


if __name__ == "__main__":
    main()
