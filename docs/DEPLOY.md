# DEPLOY — dónde y cada cuánto corre Separatio

Escrito el 2026-08-08, al activar la infraestructura de pruebas. Dos partes: lo que **está
corriendo hoy** (laptop) y el **diseño definitivo** (LXC en `motherbase`), para ejecutarlo
tal cual cuando el usuario esté cerca del server.

**Regla heredada: verificar contra la máquina.** El estado real de los timers se consulta con
los comandos de §2.3, no leyendo este documento.

---

## 1. Cadencia (decidida 2026-08-08)

| Corrida | Cuándo | Comando | Por qué |
|---|---|---|---|
| Diaria | **07:00** (±5 min de jitter) | `separatio` | El pipeline está diseñado para un briefing por día: `history.json` guarda un registro diario, el caché de resúmenes es por fecha, y `MAX_ARTICLES=120` + `PER_FEED_LIMIT=10` acotan el costo por corrida. Correr más seguido fragmenta el informe sin ganar señal |
| Semanal | **Lunes 08:00** | `separatio --weekly` | Sintetiza desde el histórico de 7 días; no vuelve a llamar por artículo, es barata |

El backlog de Miniflux (~26 mil no leídos históricos) no es un problema: cada corrida toma como
máximo 120 artículos priorizados con tope por feed, y marca leídos solo esos.

---

## 2. Infraestructura de PRUEBAS — laptop `thinkfox` (ACTIVA desde 2026-08-08)

Timers de systemd **de usuario** (no root). Elegida porque el usuario está lejos del server y
la `ANTHROPIC_API_KEY` actual es temporal: cero impacto en `motherbase`, fácil de apagar.

### 2.1 Qué hay instalado

En `~/.config/systemd/user/`:

- `separatio.service` + `separatio.timer` — diaria 07:00, `Persistent=true`
- `separatio-weekly.service` + `separatio-weekly.timer` — lunes 08:00, `Persistent=true`

`Persistent=true`: si el laptop estaba apagado o suspendido a la hora del timer, la corrida se
dispara al despertar en lugar de perderse. Los secretos salen del `.env` de la raíz del repo
(los entry points lo cargan por ruta absoluta, así que no dependen del working directory).

### 2.2 Limitación conocida

El informe del día sale solo si el laptop se enciende ese día. Para el criterio de F0 («dos
semanas de informes sin intervención») sirve mientras el laptop sea de uso diario; el LXC
elimina esa dependencia.

### 2.3 Operación

```bash
systemctl --user list-timers | grep separatio      # próximas corridas
journalctl --user -u separatio.service -n 50       # log de la última corrida (también reports/pipeline.log)
systemctl --user start separatio.service           # forzar una corrida ahora
systemctl --user disable --now separatio.timer separatio-weekly.timer   # APAGAR (obligatorio antes de encender el LXC)
```

---

## 3. Diseño DEFINITIVO — LXC en `motherbase` (pendiente de ejecución)

**Prerrequisitos, en orden:**

1. `ANTHROPIC_API_KEY` definitiva (la temporal caduca).
2. **Reinicio pendiente del host** (kernel instalado sin cargar, uptime >90 días). Hacerlo
   con el usuario cerca del server, vigilando que el zram levante `zstd 8G` y los 10 CTs
   vuelvan (ver `Motherbase/ESTADO.md`).
3. Usuario en la LAN o con vía de rescate, por si el CT nuevo da problemas.

### 3.1 El contenedor

| Parámetro | Valor | Nota |
|---|---|---|
| Plantilla | Debian 13 (misma base que el resto) | |
| Tipo | **Unprivileged**, sin features extra | Solo corre Python |
| vCPU / RAM | 1 vCPU, **512 MiB** + swap zram del host | La corrida es I/O de red + llamadas API; los 8 workers son threads esperando red. Si OOMea en la práctica, subir a 768 MiB — el host quedó con ~5 GiB libres tras F1 |
| Disco | 4 GiB | Repo + venv + reports (texto) |
| Red | DHCP estático en la LAN, como los demás CTs | Necesita salida a internet (feeds, APIs) y llegar a `192.168.1.7:8080` (CT 112 Miniflux) |
| Onboot | `onboot=1`, `order` después del CT 112 | Miniflux tiene que estar arriba antes de las 07:00 |

Registrar el CT en `Motherbase/INVENTARIO.md` al crearlo (regla del proyecto madre).

### 3.2 Aprovisionamiento

```bash
apt install -y git python3-venv
git clone https://github.com/Fennek115/separatio.git /opt/intel     # repo público, clone por https
cd /opt/intel && python3 -m venv venv && venv/bin/pip install -e '.[dev]'
venv/bin/pytest tests/ -q                                            # 24 tests, sin red
```

### 3.3 Secretos (esquema de PLAN-REORDEN §4)

**Sin `.env` en el repo clonado.** Las 12 variables van en `/etc/intel/intel.env`,
`root:root 0600`, copiadas a mano desde la bóveda rbw/Bitwarden (nota «Intel API keys»).
El `load_dotenv()` de los entry points no encuentra `.env` y no hace nada; las variables
llegan por `EnvironmentFile=` de systemd. Diseño ya previsto — no hay que tocar código.

### 3.4 Units (system, no user)

`/etc/systemd/system/separatio.service`:

```ini
[Unit]
Description=Separatio — informe diario de threat intel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=intel
WorkingDirectory=/opt/intel
EnvironmentFile=/etc/intel/intel.env
ExecStart=/opt/intel/venv/bin/separatio
TimeoutStartSec=2h
Nice=10
```

(Usuario de sistema `intel` sin login, dueño de `/opt/intel`. El timer es idéntico al del
laptop: `OnCalendar=*-*-* 07:00`, `Persistent=true`, `RandomizedDelaySec=5m`; y el par
`-weekly` con `Mon *-*-* 08:00` y `--weekly`.)

### 3.5 Conmutación (evitar corridas dobles)

⚠️ **Nunca los dos timers activos a la vez**: dos corridas el mismo día se pisan los leídos
de Miniflux y el informe del día. El orden es:

1. Aprovisionar el CT y probar **a mano** una corrida completa (`venv/bin/separatio`).
2. Verificar el informe en `/opt/intel/separatio/reports/<fecha>/`.
3. **Apagar los timers del laptop** (§2.3, última línea).
4. Encender los timers del CT: `systemctl enable --now separatio.timer separatio-weekly.timer`.
5. Al día siguiente, verificar que el informe salió solo. Desde ahí cuentan las dos semanas
   del criterio de cierre de F0.

### 3.6 Mantenimiento

- Actualizar código: `git -C /opt/intel pull && venv/bin/pip install -e '.[dev]' && venv/bin/pytest tests/ -q`.
- Los reports crecen en texto plano; revisar tamaño cada tanto (`du -sh /opt/intel/separatio/reports`).
  Si molesta, rotar carpetas de más de N meses — el corpus histórico es insumo de F4, no borrar sin criterio.
