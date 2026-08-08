#!/usr/bin/env python3
"""
setup_check.py — Verifica que el entorno esté correctamente configurado.
Ejecutar antes de usar el pipeline por primera vez.
"""

import sys


def check(label: str, ok: bool, detail: str = "") -> bool:
    icon = "✅" if ok else "❌"
    print(f"  {icon}  {label}", end="")
    if detail:
        print(f"  ({detail})", end="")
    print()
    return ok


def main():
    print("\n🔍 Verificando entorno del pipeline de Threat Intelligence\n")
    all_ok = True

    # Python
    v = sys.version_info
    ok = v.major == 3 and v.minor >= 10
    all_ok &= check(f"Python {v.major}.{v.minor}.{v.micro}", ok,
                    "Se requiere 3.10+" if not ok else "")

    # Dependencias comunes (siempre necesarias)
    print("\n  — Módulos comunes —")
    for dep in ["trafilatura", "requests", "bs4"]:
        try:
            __import__(dep)
            all_ok &= check(f"Módulo: {dep}", True)
        except ImportError:
            all_ok &= check(f"Módulo: {dep}", False, f"pip install {dep}")

    # Provider
    try:
        import config
        provider = getattr(config, "PROVIDER", "ollama")
    except ImportError:
        all_ok &= check("config.py", False, "archivo no encontrado")
        print("\n⚠️  No se puede continuar sin config.py.")
        return

    print(f"\n  — Provider: {provider} —")

    if provider == "ollama":
        try:
            __import__("ollama")
            all_ok &= check("Módulo: ollama", True)
        except ImportError:
            all_ok &= check("Módulo: ollama", False, "pip install ollama")

        ollama_host = getattr(config, "OLLAMA_HOST", "")
        if not ollama_host or "<IP" in ollama_host:
            all_ok &= check("OLLAMA_HOST configurado", False,
                            "edita config.py con la IP del LXC 111")
        else:
            try:
                import ollama
                client = ollama.Client(host=ollama_host)
                models_data = client.list()
                model_names = [m.model for m in models_data.models]
                all_ok &= check("Ollama en ejecución", True,
                                f"{len(model_names)} modelos disponibles")
                for key in ("SUMMARY_MODEL", "REPORT_MODEL"):
                    model = getattr(config, key, "")
                    found = any(model in m or m in model for m in model_names)
                    all_ok &= check(f"Modelo {key}: {model}", found,
                                    "ollama pull " + model if not found else "encontrado")
            except Exception as e:
                all_ok &= check("Ollama en ejecución", False, str(e)[:80])

    elif provider == "openai":
        try:
            __import__("openai")
            all_ok &= check("Módulo: openai", True)
        except ImportError:
            all_ok &= check("Módulo: openai", False, "pip install openai")
        key = getattr(config, "OPENAI_API_KEY", "")
        all_ok &= check("OPENAI_API_KEY", bool(key),
                        "configurada" if key else "no configurada — revisa config.py o la variable de entorno")

    elif provider == "claude":
        try:
            __import__("anthropic")
            all_ok &= check("Módulo: anthropic", True)
        except ImportError:
            all_ok &= check("Módulo: anthropic", False, "pip install anthropic")
        key = getattr(config, "ANTHROPIC_API_KEY", "")
        all_ok &= check("ANTHROPIC_API_KEY", bool(key),
                        "configurada" if key else "no configurada — revisa config.py o la variable de entorno")

    elif provider == "gemini":
        try:
            __import__("google.generativeai")
            all_ok &= check("Módulo: google-generativeai", True)
        except ImportError:
            all_ok &= check("Módulo: google-generativeai", False,
                            "pip install google-generativeai")
        key = getattr(config, "GEMINI_API_KEY", "")
        all_ok &= check("GEMINI_API_KEY", bool(key),
                        "configurada" if key else "no configurada — revisa config.py o la variable de entorno")
    else:
        all_ok &= check(f"Provider válido", False,
                        f"'{provider}' no reconocido — opciones: ollama, openai, claude, gemini")

    # Miniflux
    print("\n  — Miniflux —")
    miniflux_url = getattr(config, "MINIFLUX_URL", "")
    if not miniflux_url or "localhost" in miniflux_url and provider != "ollama":
        pass  # puede ser correcto si el pipeline corre en el mismo host
    try:
        import requests
        api_token = getattr(config, "MINIFLUX_API_TOKEN", None)
        headers   = {"X-Auth-Token": api_token} if api_token else {}
        auth      = None if api_token else (
            getattr(config, "MINIFLUX_USERNAME", ""),
            getattr(config, "MINIFLUX_PASSWORD", ""),
        )
        r = requests.get(
            f"{config.MINIFLUX_URL}/v1/me",
            headers=headers, auth=auth, timeout=5,
        )
        ok   = r.status_code == 200
        user = r.json().get("username", "?") if ok else ""
        all_ok &= check("Conexión Miniflux API", ok,
                        f"usuario: {user}" if ok else f"HTTP {r.status_code}")
    except Exception as e:
        all_ok &= check("Conexión Miniflux API", False, str(e)[:80])

    # Directorio de salida
    print("\n  — Configuración —")
    try:
        from pathlib import Path
        Path(config.OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
        check("Directorio de salida", True, config.OUTPUT_DIR)
    except Exception as e:
        all_ok &= check("Directorio de salida", False, str(e))

    print()
    if all_ok:
        print("🎉 Todo listo. Puedes ejecutar: python pipeline.py --dry-run")
    else:
        print("⚠️  Hay problemas que resolver antes de ejecutar el pipeline.")
        print("   Revisa los ítems con ❌ arriba.")
    print()


if __name__ == "__main__":
    main()
