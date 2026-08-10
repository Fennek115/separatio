# F3 — Honeypot y dato propio

**Estado:** ☐ Pendiente · **Prerrequisitos:** **F1** (hay que bajar `wg0` antes) · **Bloquea:** F4 (parcialmente)

> **Objetivo:** un sensor propio que capture exploits y webshells, y que su dato entre al pipeline.
> Es lo que convierte el proyecto de "otro agregador de feeds" en algo tuyo.

---

## ¿Ya está hecho?

```bash
ssh proxmox 'systemctl is-active wg-quick@wg0'    # DEBE decir inactive antes de empezar
ls ~/Projects/Intel/separatio/enrichers/honeypot.py 2>/dev/null || echo "enricher pendiente"
ssh proxmox 'pct exec 113 -- crontab -l 2>/dev/null | grep -i honeypot' # ¿existe el pull? (el pipeline vive en el CT 113)
```

---

## Contexto necesario

**La pregunta que responde:** cuánto del escaneo que recibe un servidor expuesto es agéntico/IA y
cuánto es plantilla tonta. El marco conceptual —que salió del caso `ft-correction`— distingue dos
poblaciones: **mass-exploiters** que escanean para *plantar* shells, y **shell-finders** que cazan
shells ya existentes de otros para parasitarlos.

**Decisiones ya tomadas** (no re-litigar, detalle en [`../LABS-PLAN.md`](../LABS-PLAN.md) §2):

- **T-Pot descartado.** 47 puertos TCP + 9 UDP que colisionan con 22/80/443/53; el instalador
  reescribe el `sshd_config` del host y pone el firewall en ACCEPT; pide 16 GB de RAM.
- **Catch-all propio de Nginx**, porque la pregunta vive en los puertos 80 y 443, no en Modbus.
- **No en casa, y no por túnel.** Los cuatro túneles evaluados hacen SNAT: el honeypot vería una sola
  IP de origen para todos los atacantes, que es justo el dato que se quiere capturar.
- **Recolección por PULL.** El honeypot no guarda ninguna credencial ni URL que apunte a casa.

**Herramientas muertas que NO usar** (verificado 2026-08-07): SNARE y TANNER (último commit
2024-06-10, SNARE aún pide Python 3.6), Dionaea (2021), Honeytrap (2021). Cowrie sí está muy vivo,
pero **≥2.9.0** por CVE-2025-34469.

---

## Paso 1 — Aprovisionar el sensor

**Oracle VM1**, VCN **propia sin peering**, no reusar la Security List del redirector.

⚠️ **Requiere que `wg0` esté abajo primero.** Honeypot + túnel al hipervisor personal en la misma
máquina sería el peor combo posible. Ver `ESTADO-Y-REDISENO.md` §3.3.

⚠️ Oracle Always Free tiene un patrón documentado de baneos sin aviso ni apelación. No poner ahí nada
que duela perder.

## Paso 2 — Egress default-deny (antes que el sensor)

**Esto va primero, no último.** No hace falta que comprometan la máquina para volverse parte del
problema: **CVE-2025-34469** es un SSRF en Cowrie **en configuración por defecto** que lo convierte en
amplificador de DDoS. Del advisory: *"honeypot operators may face abuse complaints or have their
infrastructure blocklisted"*.

Referencia (Honeynet GenII, ENISA): default-deny saliente con allowlist mínima, **25/TCP bloqueado
duro**, del orden de **5-15 conexiones nuevas salientes por día**, dos capas independientes, alerta a
la primera conexión saliente. Se construye en la Security List del proveedor, fuera del host.

## Paso 3 — El catch-all

Config completa y comentada en [`../honeypot/PLAN.md`](../honeypot/PLAN.md).

⚠️ **La receta que circula está mal y falla en silencio.** `client_body_in_file_only on` —que por el
nombre suena como la directiva clave— es la que **rompe** `$request_body`. Va **`clean`**. Y
`$request_body` solo se puebla si hay un content handler tipo `proxy_pass`/`mirror` **y** el body
entró en memoria (`client_body_buffer_size`, default 8k/16k); si no, queda vacío sin warning y se
pierden justo los payloads grandes.

## Paso 4 — Pull desde casa

Un cron en casa se conecta por SSH **saliente** al sensor y trae los logs con `rsync`. Nunca al
revés: la máquina sacrificable no debe tener token, clave ni URL que apunte a la red personal.

## Paso 5 — `enrichers/honeypot.py`

Un archivo. La interfaz ya existe. Cruza los logs traídos contra los IOCs del día y responde:

1. **¿Alguna IP, hash o dominio de las noticias de hoy me tocó a mí?** ← lo que justifica todo
2. ¿Los que me atacan aparecen en IPsum/GreyNoise, o son nuevos?

⚠️ **Los logs vienen de una máquina hostil: son datos no confiables.** Parseo estricto, nada de
`eval`, y cuidado con log injection en user-agent y URI (por eso `escape=json` en la config de Nginx).

**Quick win previo** (`IMPROVEMENTS.md` §6.5): hoy `export_iocs` corre **antes** de Stage 2.7, así que
el veredicto de reputación no queda en el CSV/JSON de IOCs. Reordenarlo hace el export mucho más útil
para este cruce.

---

## Verificación

- [ ] El sensor está en una VCN propia, sin ruta a nada personal
- [ ] Egress default-deny probado: una conexión saliente no permitida falla
- [ ] `$request_body` aparece poblado en `honey.json` para un POST de prueba con cuerpo >16 KB
- [ ] `client_body_temp_path` no crece sin límite (o sea, `clean` está aplicado)
- [ ] El pull trae logs y **el sensor no tiene ninguna credencial de casa**
- [ ] El enricher aparece en Stage 2.7 sin abortar la corrida

## Al terminar

1. Marcar F3 como ☑ en [`../ESTADO.md`](../ESTADO.md).
2. Actualizar [`../honeypot/PLAN.md`](../honeypot/PLAN.md) con lo realmente desplegado.
3. Actualizar `ESTADO-Y-REDISENO.md`: el punto 4 del orden sugerido queda hecho.
4. **F4 gana su tool más valioso** (`cruce_honeypot`).
