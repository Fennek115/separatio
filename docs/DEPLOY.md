# DEPLOY — dónde y cada cuánto corre Separatio

Escrito el 2026-08-08. **El pipeline corre en el LXC 113 (`intel`) de `motherbase`** — abajo
está el as-built completo. Hubo una versión efímera con timers en el laptop ese mismo día;
se desmontó a las horas (decisión del usuario: las pruebas van en contenedores, no en la
máquina de trabajo) y no queda nada de ella en `thinkfox`.

**Regla heredada: verificar contra la máquina.** El estado real se consulta con los comandos
de §4, no leyendo este documento.

---

## 1. Cadencia (decidida 2026-08-08)

| Corrida | Cuándo | Comando | Por qué |
|---|---|---|---|
| Diaria | **07:00** (±5 min de jitter) | `separatio` | El pipeline está diseñado para un briefing por día: `history.json` guarda un registro diario, el caché de resúmenes es por fecha, y `MAX_ARTICLES=120` + `PER_FEED_LIMIT=10` acotan el costo por corrida. Correr más seguido fragmenta el informe sin ganar señal |
| Semanal | **Lunes 08:00** | `separatio --weekly` | Sintetiza desde el histórico de 7 días; no vuelve a llamar por artículo, es barata |

El backlog de Miniflux (~26 mil no leídos históricos) no es un problema: cada corrida toma como
máximo 120 artículos priorizados con tope por feed, y marca leídos solo esos.

`Persistent=true` en ambos timers: si el CT estaba apagado a la hora del timer, la corrida
sale al arrancar en lugar de perderse.

---

## 2. As-built — LXC 113 `intel` (activo desde 2026-08-08)

Creado con el helper de community-scripts en modo desatendido (variables `var_*` + `mode=default`
por entorno, `TERM` seteado porque el script llama `clear`):

```bash
# en el host PVE
export TERM=xterm-256color mode=default var_ctid=113 var_hostname=intel \
       var_cpu=1 var_ram=512 var_disk=4 var_os=debian var_version=13 \
       var_unprivileged=1 var_tags=intel var_container_storage=local-zfs var_template_storage=local
bash -c "$(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/ct/debian.sh)"
```

| Parámetro | Valor |
|---|---|
| CT | **113**, hostname `intel`, Debian 13, unprivileged, `onboot=1` |
| Recursos | 1 vCPU, 512 MiB RAM + 512 MiB swap, 4 GiB en `local-zfs` (si OOMea en la práctica, subir a 768 MiB) |
| Red | DHCP en vmbr0 → **192.168.1.55**. Llega a Miniflux (CT 112, `192.168.1.7:8080`) y a internet |
| Código | `/opt/intel/app` — clone **https** del repo público, dueño `intel` (usuario de sistema sin login). Venv en `/opt/intel/app/venv` con `pip install -e '.[dev]'` (Python 3.13); los 28 tests pasan |
| Secretos | `/etc/intel/intel.env`, `root:root 0600` — copia de las 12 variables del `.env` del laptop. **No hay `.env` en el clone**: el `load_dotenv()` no encuentra nada y las variables llegan por `EnvironmentFile=` de systemd. ⚠️ La `ANTHROPIC_API_KEY` que tiene es la **temporal** |
| Units | `/etc/systemd/system/`: `separatio.{service,timer}` y `separatio-weekly.{service,timer}`. Service: `Type=oneshot`, `User=intel`, `WorkingDirectory=/opt/intel/app`, `EnvironmentFile=/etc/intel/intel.env`, `TimeoutStartSec=2h`, `Nice=10` |
| Salidas | `/opt/intel/app/separatio/reports/YYYY-MM-DD/` + `history.json` + `pipeline.log`, y el journal del CT |

Verificado al desplegar: `separatio-check` todo verde bajo las condiciones exactas del service
(`systemd-run -p User=intel -p EnvironmentFile=...`), y un `--dry-run --limit 5` completo OK.

---

## 3. Pendientes de este deploy

1. ⚠️ **Key definitiva:** cuando el usuario salga de pruebas, editar `/etc/intel/intel.env`
   (solo la línea `ANTHROPIC_API_KEY=`) — no hace falta tocar nada más. Actualizar también la
   bóveda rbw (nota «Intel API keys»).
2. **Backup:** el CT 113 no está en los jobs (`backup-4bb41709` local ni `backup-036d95d7`
   offsite) — los jobs listan CTs por ID. Decidir si se agrega: el CT es reconstruible desde
   git + `intel.env`, pero `reports/` (el corpus, insumo de F4) solo vive ahí.
3. **Reinicio pendiente del host:** al reiniciar `motherbase`, verificar que el 113 vuelva con
   los demás y que el timer siga armado (§4).

---

## 4. Operación

```bash
ssh proxmox 'pct exec 113 -- systemctl list-timers'                     # próximas corridas
ssh proxmox 'pct exec 113 -- journalctl -u separatio.service -n 50'     # log de la última corrida
ssh proxmox 'pct exec 113 -- ls /opt/intel/app/separatio/reports/'      # informes generados
ssh proxmox 'pct exec 113 -- systemctl start separatio.service'         # forzar una corrida ahora
```

Actualizar código:

```bash
ssh proxmox 'pct exec 113 -- sudo -u intel git -C /opt/intel/app pull'
ssh proxmox 'pct exec 113 -- bash -c "cd /opt/intel/app && sudo -u intel venv/bin/pip install -q -e \".[dev]\" && sudo -u intel venv/bin/pytest tests/ -q"'
```

Los reports crecen en texto plano; revisar tamaño cada tanto
(`du -sh /opt/intel/app/separatio/reports`). El corpus histórico es insumo de F4 — no borrar
sin criterio.

---

## 5. Criterio de cierre de F0

**Dos semanas de informes generados solos, sin intervención**, contando desde la primera
corrida automática del CT (2026-08-08 a las 07:00 si el timer ya estaba armado ese día, o la
primera que salga). Verificar con la primera línea de §4: debe aparecer una carpeta de fecha
nueva cada día.
