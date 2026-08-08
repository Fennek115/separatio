#!/usr/bin/env python3
"""
Orquestador SOC: Excel de Wazuh → procesar_excel.py → ip_threat_checker.py
Uso: python3 run.py alertas_wazuh.csv [opciones]
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

OUTPUT_DEFAULT    = "ips_publicas_output.txt"
HISTORIAL_DEFAULT = "ip_procesadas.txt"


def contar_ips_output(path):
    """Cuenta las IPs reales en el output (excluye líneas de comentario)."""
    if not os.path.exists(path):
        return 0
    count = 0
    with open(path) as f:
        for linea in f:
            linea = linea.strip()
            if linea and not linea.startswith('#'):
                count += 1
    return count


def separador(titulo):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {titulo}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline completo: Excel de Wazuh → procesado de IPs → consulta de APIs"
    )
    parser.add_argument("archivo", help="Archivo CSV o Excel exportado de Wazuh")
    parser.add_argument(
        "--historial", default=HISTORIAL_DEFAULT,
        metavar="PATH",
        help=f"Historial acumulativo de IPs ya procesadas (default: {HISTORIAL_DEFAULT})"
    )
    parser.add_argument(
        "--output", default=OUTPUT_DEFAULT,
        metavar="PATH",
        help=f"Archivo intermedio con IPs nuevas (default: {OUTPUT_DEFAULT})"
    )
    parser.add_argument(
        "--solo-procesar", action="store_true",
        help="Solo extrae las IPs del Excel, sin consultar APIs (útil para revisar antes de gastar cuota)"
    )
    parser.add_argument(
        "--expiry-dias", type=int, default=365,
        metavar="N",
        help="Días antes de que una IP expire del historial (default: 365, 0=nunca)"
    )
    parser.add_argument(
        "--no-excel", action="store_true",
        help="No generar ni actualizar el Excel de resultados"
    )
    parser.add_argument(
        "--excel", default="threat_results.xlsx",
        metavar="PATH",
        help="Ruta del Excel acumulativo de resultados (default: threat_results.xlsx)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.archivo):
        print(f"{RED}[!] Archivo no encontrado: {args.archivo}{RESET}")
        sys.exit(1)

    inicio = datetime.now()
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  SOC PIPELINE — WAZUH → THREAT INTEL{RESET}")
    print(f"{BOLD}{CYAN}  {inicio.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    # ── PASO 1: procesar_excel.py ──────────────────────────────
    separador("PASO 1/2 — PROCESAMIENTO DEL EXCEL")

    cmd_procesar = [
        sys.executable, "-m", "ipcheck.procesar_excel",
        args.archivo,
        "--historial",   args.historial,
        "--output",      args.output,
        "--expiry-dias", str(args.expiry_dias),
    ]
    resultado1 = subprocess.run(cmd_procesar)

    if resultado1.returncode != 0:
        print(f"\n{RED}[!] procesar_excel.py terminó con error (código {resultado1.returncode}).{RESET}")
        sys.exit(resultado1.returncode)

    # ── Verificar si hay IPs nuevas para consultar ─────────────
    n_ips = contar_ips_output(args.output)

    if n_ips == 0:
        fin = datetime.now()
        print(f"\n{GREEN}[✓] Sin IPs nuevas. No se consumen cuotas de API.{RESET}")
        print(f"{GRAY}    Duración: {int((fin - inicio).total_seconds())}s{RESET}\n")
        sys.exit(0)

    if args.solo_procesar:
        print(f"\n{YELLOW}[--solo-procesar] Consulta de APIs omitida.{RESET}")
        print(f"{GREEN}[✓] {n_ips} IPs listas en: {args.output}{RESET}")
        print(f"\n    Para continuar manualmente:")
        print(f"    ipcheck {args.output} --historial {args.historial}\n")
        sys.exit(0)

    # ── PASO 2: ip_threat_checker.py ──────────────────────────
    separador(f"PASO 2/2 — CONSULTA DE APIs ({n_ips} IPs nuevas)")

    cmd_checker = [
        sys.executable, "-m", "ipcheck.cli",
        args.output,
        "--historial", args.historial,
        "--excel",     args.excel,
    ]
    if args.no_excel:
        cmd_checker.append("--no-excel")
    resultado2 = subprocess.run(cmd_checker)

    # ── Resumen final ──────────────────────────────────────────
    fin = datetime.now()
    duracion = int((fin - inicio).total_seconds())
    minutos, segundos = divmod(duracion, 60)

    exito = resultado2.returncode == 0
    color_banner = CYAN if exito else RED
    estado       = "PIPELINE COMPLETADO" if exito else f"PIPELINE TERMINÓ CON ERROR (código {resultado2.returncode})"

    print(f"\n{BOLD}{color_banner}{'='*60}{RESET}")
    print(f"{BOLD}{color_banner}  {estado}{RESET}")
    print(f"{BOLD}{color_banner}{'='*60}{RESET}")
    print(f"  IPs analizadas:   {n_ips}")
    print(f"  Duración total:   {minutos}m {segundos}s")
    print(f"  Historial:        {args.historial}")
    if not args.no_excel:
        print(f"  Excel:            {args.excel}")
    print(f"  Reporte JSON:     threat_report_*.json\n")

    sys.exit(resultado2.returncode)


if __name__ == "__main__":
    main()
