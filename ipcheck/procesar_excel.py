#!/usr/bin/env python3
"""
Procesador de exports de Wazuh → ips_publicas_output.txt
Uso: python3 procesar_excel.py <archivo.csv|xlsx> [--historial ip_procesadas.txt] [--output ips_publicas_output.txt]
"""

import argparse
import ipaddress
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

try:
    import pandas as pd
except ImportError:
    print("[!] Falta pandas. Ejecuta: pip install pandas openpyxl")
    sys.exit(1)

# ─── COLORES ──────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

HISTORIAL_DEFAULT = "ip_procesadas.txt"
OUTPUT_DEFAULT    = "ips_publicas_output.txt"

# ─── PUERTOS ──────────────────────────────────────────────────
PUERTOS_CONOCIDOS = {
    20: "FTP-data",  21: "FTP",      22: "SSH",    23: "Telnet",
    25: "SMTP",      53: "DNS",      67: "DHCP",   80: "HTTP",
    110: "POP3",    123: "NTP",     143: "IMAP",  161: "SNMP",
    443: "HTTPS",   445: "SMB",     514: "Syslog", 587: "SMTP-sub",
    636: "LDAPS",   993: "IMAPS",   995: "POP3S",
    1194: "OpenVPN", 1433: "MSSQL", 1514: "Wazuh",
    3306: "MySQL",  3389: "RDP",   4789: "VXLAN",
    5432: "PostgreSQL", 5985: "WinRM", 5986: "WinRM-SSL",
    6667: "IRC",    8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# Puertos que ameritan atención especial en el reporte
PUERTOS_SOSPECHOSOS = {
    4444, 1337, 31337, 6666, 6667, 7777, 8888, 9999,
    12345, 54321, 1234, 2222, 5555,
}


# ─── LECTURA DEL ARCHIVO ──────────────────────────────────────

def limpiar_nombre_columna(nombre):
    """Quita los sufijos de ordenamiento que agrega el export de Wazuh/Kibana."""
    return re.sub(r':\s*(Descending|Ascending)$', '', str(nombre)).strip()


def leer_archivo(path):
    """
    Lee el CSV o Excel exportado de Wazuh.
    Normaliza los nombres de columna (elimina ': Descending' / ': Ascending').
    """
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext in ('.xlsx', '.xls'):
            df = pd.read_excel(path)
        else:
            df = pd.read_csv(path, encoding='utf-8', on_bad_lines='skip')
    except Exception as e:
        print(f"{RED}[!] Error leyendo el archivo: {e}{RESET}")
        sys.exit(1)

    # Renombrar columnas: quita los sufijos de Wazuh
    df = df.rename(columns={c: limpiar_nombre_columna(c) for c in df.columns})

    print(f"{GREEN}[+] Archivo cargado: {len(df):,} filas, {len(df.columns)} columnas{RESET}")
    return df


# ─── SELECCIÓN INTERACTIVA DE COLUMNAS ───────────────────────

def detectar_columnas_ip(columnas):
    """Devuelve columnas que probablemente contienen IPs por su nombre."""
    return [c for c in columnas if 'ip' in c.lower()]


def seleccionar_columnas(df):
    """
    Muestra las columnas del archivo y pide al usuario cuáles contienen IPs
    y cuál tiene el puerto de destino (opcional).
    Retorna: (lista_cols_ip, col_puerto_o_None)
    """
    todas = list(df.columns)

    print(f"\n{BOLD}Columnas disponibles:{RESET}")
    for i, col in enumerate(todas, 1):
        valores = df[col].dropna()
        muestra = str(valores.iloc[0])[:25] if not valores.empty else "—"
        print(f"  [{i:2d}] {col:<40}  ej: {muestra}")

    sugeridas = detectar_columnas_ip(todas)
    if sugeridas:
        print(f"\n{CYAN}[✓] Columnas detectadas con IPs:{RESET} {', '.join(sugeridas)}")

    # Selección de columnas IP
    while True:
        entrada = input(
            f"\n¿Qué columnas contienen IPs? (números separados por coma, ej: 1,2): "
        ).strip()
        try:
            indices = [int(x.strip()) - 1 for x in entrada.split(',') if x.strip()]
            if not indices:
                raise ValueError
            cols_ip = [todas[i] for i in indices]
            break
        except (ValueError, IndexError):
            print(f"{YELLOW}[!] Entrada inválida. Usa números del 1 al {len(todas)}.{RESET}")

    # Selección de columna de puerto (opcional)
    col_puerto = None
    candidatos_puerto = [c for c in todas if 'port' in c.lower() or 'puerto' in c.lower()]
    if candidatos_puerto:
        sugerido = candidatos_puerto[0]
        resp = input(
            f"\n¿Usar '{sugerido}' para contexto de puertos? (s/n) [s]: "
        ).strip().lower()
        if resp in ('s', 'si', 'sí', 'y', 'yes', ''):
            col_puerto = sugerido

    print(f"\n{GREEN}[✓] Columnas IP: {cols_ip}{RESET}")
    if col_puerto:
        print(f"{GREEN}[✓] Columna de puertos: {col_puerto}{RESET}")
    return cols_ip, col_puerto


# ─── CLASIFICACIÓN DE IPs ─────────────────────────────────────

def clasificar_ip(ip_str):
    """
    Valida y clasifica una cadena como dirección IP.
    Retorna: ('publica'|'privada'|'loopback'|'link-local'|'multicast'|'reservada'|'invalida', ip_obj|None)
    """
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return 'invalida', None

    if ip.is_loopback:     return 'loopback',   ip
    if ip.is_link_local:   return 'link-local',  ip
    if ip.is_multicast:    return 'multicast',   ip
    if ip.is_private:      return 'privada',     ip
    if ip.is_reserved:     return 'reservada',   ip
    if ip.is_global:       return 'publica',     ip
    return 'reservada', ip


# ─── EXTRACCIÓN DE IPs DEL DATAFRAME ─────────────────────────

def extraer_ips(df, cols_ip, col_puerto=None):
    """
    Recorre el DataFrame y extrae todas las IPs de las columnas indicadas.
    Usa la representación canónica de ipaddress como clave para evitar duplicados
    por formato (ej: '::ffff:1.1.1.1' y '1.1.1.1' serían la misma entrada).
    Retorna: (dict {ip_canonico: {"tipo", "puertos", "count_total"}}, n_invalidas)
    """
    resultado = defaultdict(lambda: {
        "tipo": "",
        "puertos": defaultdict(int),
        "count_total": 0,
    })
    invalidas = 0   # strings que no son una IP válida (ej: "hostname.local", "-")
    vacias    = 0   # celdas NaN / vacías / "N/A" que pandas convierte a null

    # Detectar columna de conteo (Wazuh la llama "Count")
    col_count = next(
        (c for c in df.columns if c.lower() in ('count', 'conteo', 'total', '_count')),
        None
    )

    for _, fila in df.iterrows():
        # Conteo de esta fila
        count = 1
        if col_count is not None:
            try:
                # Maneja separadores de miles (ej: "165,353" en algunos locales)
                count = int(str(fila[col_count]).replace(',', '').strip())
            except (ValueError, TypeError):
                count = 1

        # Puerto de esta fila
        puerto = None
        if col_puerto is not None:
            try:
                puerto = int(fila[col_puerto])
            except (ValueError, TypeError):
                puerto = None

        # Procesar cada columna IP seleccionada
        for col_ip in cols_ip:
            if pd.isna(fila[col_ip]):
                vacias += 1
                continue
            ip_str = str(fila[col_ip]).strip()
            if not ip_str or ip_str.lower() in ('nan', 'none', ''):
                vacias += 1
                continue

            tipo, ip_obj = clasificar_ip(ip_str)
            if tipo == 'invalida':
                invalidas += 1
                continue

            # Clave canónica: evita duplicados por distintas representaciones del mismo IP
            ip_clave = str(ip_obj)
            resultado[ip_clave]["tipo"] = tipo
            resultado[ip_clave]["count_total"] += count
            if puerto is not None:
                resultado[ip_clave]["puertos"][puerto] += count

    return dict(resultado), invalidas, vacias


# ─── HISTORIAL ────────────────────────────────────────────────

def leer_historial(path, expiry_dias=365):
    """
    Lee el historial y devuelve solo las IPs cuyo timestamp de verificación
    sea más reciente que expiry_dias. Con expiry_dias=0 no expira nada.
    El historial lo escribe el checker (no este script) para que la expiración
    coincida con cuándo se verificó realmente, no con cuándo se extrajo del Excel.
    """
    historial  = set()
    expiradas  = 0
    sin_fecha  = 0
    if not os.path.exists(path):
        print(f"{YELLOW}[!] Historial no encontrado ({path}), se creará al verificar.{RESET}")
        return historial

    ahora = datetime.now()
    fecha_bloque = None

    try:
        with open(path, 'r') as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                if linea.startswith('#'):
                    m = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', linea)
                    if m:
                        try:
                            fecha_bloque = datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            fecha_bloque = None
                    continue

                ip = linea.split(',')[0].strip()
                if not ip:
                    continue

                if expiry_dias > 0:
                    if fecha_bloque is None:
                        sin_fecha += 1
                        historial.add(ip)   # sin fecha → conservar por precaución
                    elif (ahora - fecha_bloque).days > expiry_dias:
                        expiradas += 1      # demasiado antiguo → se re-analizará
                    else:
                        historial.add(ip)
                else:
                    historial.add(ip)

        partes = [f"{len(historial):,} IPs vigentes"]
        if expiradas:
            partes.append(f"{expiradas} expiradas → se re-analizarán")
        if sin_fecha:
            partes.append(f"{sin_fecha} sin fecha → conservadas por precaución")
        print(f"{GREEN}[+] Historial: {', '.join(partes)}{RESET}")
    except Exception as e:
        print(f"{YELLOW}[!] Error leyendo historial: {e}{RESET}")

    return historial


# ─── OUTPUT ───────────────────────────────────────────────────

def nombre_puerto(puerto):
    """Devuelve etiqueta legible para un número de puerto."""
    nombre = PUERTOS_CONOCIDOS.get(puerto, "?")
    sufijo = " ⚠" if puerto in PUERTOS_SOSPECHOSOS else ""
    return f"{puerto}/{nombre}{sufijo}"


def generar_etiqueta(ip_data):
    """
    Genera la etiqueta que acompaña a la IP en el output (campo 'user' del checker).
    Ejemplo: "p:53/DNS,443/HTTPS c:14371"
    """
    puertos = ip_data.get("puertos", {})
    count_total = ip_data.get("count_total", 1)
    if not puertos:
        return f"c:{count_total}"
    top = sorted(puertos.items(), key=lambda x: x[1], reverse=True)[:3]
    partes = [nombre_puerto(p) for p, _ in top]
    return f"p:{','.join(partes)} c:{count_total}"


def guardar_output(ips_nuevas, ips_data, path):
    """
    Escribe el archivo de salida en el formato que consume ip_threat_checker.py.
    Formato: ip,etiqueta_con_contexto_de_puertos
    """
    try:
        with open(path, 'w') as f:
            f.write(f"# Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# {len(ips_nuevas)} IPs públicas nuevas\n")
            # Ordenar: IPv4 primero (versión 4), luego IPv6 (versión 6), numéricamente dentro de cada familia
            for ip_str in sorted(ips_nuevas, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x)))):
                etiqueta = generar_etiqueta(ips_data[ip_str])
                f.write(f"{ip_str},{etiqueta}\n")
        print(f"{GREEN}[✓] Output guardado: {path} ({len(ips_nuevas)} IPs){RESET}")
    except Exception as e:
        print(f"{RED}[!] Error guardando output: {e}{RESET}")


# ─── RESUMEN EN CONSOLA ───────────────────────────────────────

def mostrar_resumen(stats, ips_data, ips_nuevas):
    """Imprime el resumen completo del procesamiento."""
    descartadas = (
        stats["privadas"] + stats["loopback"] +
        stats["link_local"] + stats["multicast"] + stats["reservada"]
    )

    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  RESUMEN DEL PROCESAMIENTO{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"\n  Filas leídas del archivo:  {stats['filas_totales']:>10,}")
    print(f"  Celdas vacías/NaN:         {stats['vacias']:>10,}  {GRAY}[OMITIDAS]{RESET}")
    print(f"  Strings no-IP:             {stats['invalidas']:>10,}  {GRAY}[OMITIDAS]{RESET}")
    print(f"  IPs únicas válidas:        {stats['total_unicas']:>10,}")
    print(f"  ├─ Privadas/reservadas:    {descartadas:>10,}  {GRAY}[DESCARTADAS]{RESET}")
    print(f"  ├─ Públicas totales:       {stats['publicas']:>10,}")
    print(f"  │  ├─ Ya en historial:     {stats['ya_procesadas']:>10,}  {GRAY}[SALTADAS]{RESET}")
    print(f"  │  └─ {GREEN}NUEVAS para revisar:{RESET}  {len(ips_nuevas):>10,}  {GREEN}← OUTPUT{RESET}")

    # Análisis de puertos entre las IPs nuevas
    if ips_nuevas:
        puerto_stats = defaultdict(lambda: {"ips": set(), "conexiones": 0})
        for ip_str in ips_nuevas:
            for puerto, count in ips_data[ip_str].get("puertos", {}).items():
                puerto_stats[puerto]["ips"].add(ip_str)
                puerto_stats[puerto]["conexiones"] += count

        if puerto_stats:
            print(f"\n{BOLD}  PUERTOS ENTRE IPs NUEVAS{RESET}")
            print(f"  {'Puerto':<22} {'IPs':>5}  {'Conexiones':>12}  Alerta")
            print(f"  {'-'*22} {'-'*5}  {'-'*12}  {'-'*15}")
            ordenados = sorted(puerto_stats.items(), key=lambda x: -x[1]["conexiones"])[:12]
            for puerto, data in ordenados:
                alerta = f"{YELLOW}⚠  PUERTO INUSUAL{RESET}" if puerto in PUERTOS_SOSPECHOSOS else ""
                nom = PUERTOS_CONOCIDOS.get(puerto, "?")
                print(f"  {puerto:<6}{nom:<16} {len(data['ips']):>5,}  {data['conexiones']:>12,}  {alerta}")

    # Estimación de cuota API
    # El análisis por niveles reduce el consumo real: IPs RIOT (Nivel 1) no consumen
    # AbuseIPDB/VT/OTX, e IPs sin señales (Nivel 2) no consumen VT.
    # Aquí mostramos el peor caso (todas en Nivel 3) y el mejor caso estimado.
    n = len(ips_nuevas)
    print(f"\n{BOLD}  ESTIMACIÓN DE CUOTA API{RESET}")
    abuso_ok = "✅" if n <= 1000 else f"{RED}⚠  PUEDE EXCEDER LÍMITE FREE{RESET}"
    vt_ok    = "✅" if n <= 500  else f"{RED}⚠  PUEDE EXCEDER LÍMITE FREE{RESET}"
    print(f"  AbuseIPDB:  ≤{n:>3} requests  (free: 1.000/día)  {abuso_ok}  {GRAY}(Nivel 1 ahorra){RESET}")
    print(f"  VirusTotal: ≤{n:>3} requests  (free:   500/día)  {vt_ok}  {GRAY}(Nivel 1+2 ahorran){RESET}")
    if n > 0:
        mins_max = (n * 15) / 60
        print(f"  Tiempo máx con VT (15s/IP, todos en Nivel 3): ~{mins_max:.0f} min"
              f"  {GRAY}(el análisis por niveles lo reduce){RESET}")

    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")


# ─── MAIN ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Procesa exports de Wazuh y extrae IPs públicas nuevas para threat intelligence"
    )
    parser.add_argument("archivo", help="Archivo CSV o Excel exportado de Wazuh")
    parser.add_argument(
        "--historial", default=HISTORIAL_DEFAULT,
        help=f"Archivo de historial acumulativo (default: {HISTORIAL_DEFAULT})"
    )
    parser.add_argument(
        "--output", default=OUTPUT_DEFAULT,
        help=f"Archivo de salida (default: {OUTPUT_DEFAULT})"
    )
    parser.add_argument(
        "--expiry-dias", type=int, default=365,
        metavar="N",
        help="Días antes de que una IP expire del historial y se re-analice (default: 365, 0=nunca)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.archivo):
        print(f"{RED}[!] Archivo no encontrado: {args.archivo}{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  PROCESADOR DE IPs WAZUH → THREAT INTEL{RESET}")
    print(f"{BOLD}{CYAN}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")

    # 1. Leer archivo
    df = leer_archivo(args.archivo)

    # 2. Selección interactiva de columnas
    cols_ip, col_puerto = seleccionar_columnas(df)

    # 3. Extraer y clasificar todas las IPs
    print(f"\n{CYAN}[*] Extrayendo y clasificando IPs...{RESET}")
    ips_data, n_invalidas, n_vacias = extraer_ips(df, cols_ip, col_puerto)

    # 4. Separar por tipo
    publicas = {ip: d for ip, d in ips_data.items() if d["tipo"] == "publica"}
    tipos_count = defaultdict(int)
    for d in ips_data.values():
        tipos_count[d["tipo"]] += 1

    # 5. Leer historial y filtrar IPs ya verificadas
    print(f"{CYAN}[*] Leyendo historial...{RESET}")
    historial = leer_historial(args.historial, expiry_dias=args.expiry_dias)

    ips_nuevas    = [ip for ip in publicas if ip not in historial]
    ya_procesadas = [ip for ip in publicas if ip in historial]

    stats = {
        "filas_totales":  len(df),
        "total_unicas":   len(ips_data),   # solo IPs válidas; invalidas/vacias se muestran por separado
        "invalidas":      n_invalidas,
        "vacias":         n_vacias,
        "privadas":       tipos_count["privada"],
        "loopback":       tipos_count["loopback"],
        "link_local":     tipos_count["link-local"],
        "multicast":      tipos_count["multicast"],
        "reservada":      tipos_count["reservada"],
        "publicas":       len(publicas),
        "ya_procesadas":  len(ya_procesadas),
    }

    # 6. Mostrar resumen
    mostrar_resumen(stats, ips_data, ips_nuevas)

    if not ips_nuevas:
        print(f"{YELLOW}[!] No hay IPs públicas nuevas para procesar.{RESET}")
        sys.exit(0)

    # 7. Confirmar antes de escribir
    resp = input(
        f"¿Guardar {len(ips_nuevas)} IPs en '{args.output}' y actualizar historial? (s/n): "
    ).strip().lower()
    if resp not in ('s', 'si', 'sí', 'y', 'yes'):
        print(f"{YELLOW}[!] Cancelado.{RESET}")
        sys.exit(0)

    # 8. Escribir output
    # El historial NO se actualiza aquí — lo actualiza ip_threat_checker.py
    # después de verificar cada IP, para que las interrupciones no pierdan progreso.
    guardar_output(ips_nuevas, ips_data, args.output)

    print(f"\n{BOLD}{GREEN}[✓] Listo. Siguiente paso:{RESET}")
    print(f"    python3 ip_threat_checker.py {args.output} --historial {args.historial}\n")


if __name__ == "__main__":
    main()
