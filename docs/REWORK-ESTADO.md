# REWORK-ESTADO — punto de entrada del rework de Intel

> **Si estás empezando una sesión del rework, leé este archivo primero y nada más.**
> Te dice en qué fase está, qué sigue, y qué archivo abrir para hacerlo.

Última actualización: **2026-08-09** (cierre de F-I)

Diseño y fundamentos: [`PLAN-REWORK.md`](PLAN-REWORK.md) (el *qué* y el *por qué*).
Este archivo es el *cuándo* y el *cómo se ejecuta*.

> **Las ocho fases están planificadas al detalle** (2026-08-09): cada `fases/F-*.md` trae el DDL,
> las firmas de función, los nombres de test y los comandos de verificación. **Una sesión no
> planifica: ejecuta y documenta.** Si al ejecutar aparece algo que el documento no previó, se
> corrige el documento y se anota en el as-built — es la regla de verificar contra la máquina.

---

## Cómo funciona esta cadena

El rework está partido en **fases, una por sesión**. Cada fase vive en [`fases/`](fases/) y es
autocontenida: trae el contexto que necesita, los pasos, cómo verificar, y cómo saber si ya está
hecha.

### Protocolo de cada sesión

1. Leer este archivo → identificar la fase activa.
2. Abrir `fases/<la que toque>.md` y **correr su bloque "¿Ya está hecho?"** antes de tocar nada.
3. Planificar la fase (esta sesión, con lo que el bloque haya dicho), ejecutarla y verificarla.
4. **Cerrar** con el ritual de abajo.

### Prompt para arrancar una sesión

Desde `~/Projects/Intel`, pegar esto cambiando la fase:

```
Continuamos el rework. Leé docs/REWORK-ESTADO.md y después docs/fases/F-B1.md.
Corré el bloque "¿Ya está hecho?" antes de tocar nada y decime el estado real.
La fase ya está planificada al detalle: ejecutala tal como está escrita y cerrala
con el ritual. Si algo del documento no coincide con la máquina, gana la máquina:
corregí el documento y anotalo en el as-built.
```

### Ritual de cierre de fase

Una fase no está cerrada hasta que estas cuatro cosas pasaron:

1. **As-built con salida real** en `fases/<la fase que toque>.md` — la salida **literal** de los comandos de
   verificación, no lo que se esperaba. Si el documento y la máquina no coinciden, gana la máquina.
2. **`CLAUDE.md` de la raíz actualizado** — es lo que lee la sesión siguiente.
3. **La tabla de acá actualizada**, con una línea de qué quedó realmente hecho.
4. **Una línea breve** en `~/Projects/Motherbase/ESTADO.md` (fila F3) apuntando acá. La
   documentación real vive en **este** repo; allá va sólo el puntero.

Commit y push **no** son automáticos: se hacen cuando el usuario lo pida. Ojo con eso: mientras no
haya push, **el CT 113 sigue corriendo la versión vieja** del código.

### La regla que hace que esto no se pudra

**Verificar contra la máquina, no contra el documento.**

Los documentos describen intenciones; el servidor describe hechos. Ya pasó en este proyecto: el
plan del rework daba por existentes `events.jsonl`, `payloads/` y `hashes.log`, y en disco no había
ninguno de los tres (el colector los genera desde un commit posterior a la única corrida real).

Por eso cada fase tiene un bloque **"¿Ya está hecho?"** con comandos que responden desde el estado
real.

---

## Estado actual

| # | Fase | Qué es | Estado |
|---|---|---|---|
| — | **F-A** | [Higiene de la entrada](fases/F-A.md) | ☑ **Hecha el 2026-08-09** — clasificador `separatio/hygiene.py` (propias se descartan, escáneres se etiquetan por CIDR + PTR), consolidador extraído del heredoc a `separatio/honeypot_collector.py` y testeable, rutas de datos ancladas a `REPO_ROOT`. 73 tests. **Pendiente: desplegar al CT 113** |
| — | **F-H** | [Observabilidad de la corrida](fases/F-H.md) | ☑ **Hecha el 2026-08-09** — `separatio/runlog.py` (manifiesto de la corrida), diez puntos de recorte instrumentados con `shown`/`total`, tokens a INFO, log con rotación, `status`/exit code y `separatio --last-run`. 94 tests. Verificada con corrida real: 5 llamadas, 52.897 in / 21.076 out. **Pendiente: desplegar al CT 113** |
| — | **F-I** | [Afinado de prompts](fases/F-I.md) | ☑ **Hecha el 2026-08-09** — `runlog.coverage_block()` (el informe declara sus faltantes: 5 líneas "Limitaciones de esta corrida" contra 0 antes), topes a `config.PROMPT_CAPS` (IOCs 8→20, veredictos 25→60), **enrichment a las cuatro fases** (LATAM y general ya citan Ransomware.live/IPsum/ipcheck), campos `attack_techniques`/`exploitation_status`/`confidence` + técnicas ATT&CK corroboradas, salida estructurada en Stage 2 (0 reintentos) y `PHASE_EFFORT` cableado. 115 tests. A/B: **+$0,09 por corrida**. **Pendiente: desplegar al CT 113** |
| **1** | **F-B1** | [Store: esquema y capa de acceso](fases/F-B1.md) | ☐ **← ACÁ ESTAMOS** — El DDL, las migraciones y `models.py`. No toca nada que esté corriendo |
| **2** | **F-B2** | [Ingesta idempotente y backfill](fases/F-B2.md) | ☐ El colector empieza a escribir; backfill de lo que ya hay en disco |
| **3** | **F-E** | [Listas locales](fases/F-E.md) | ☐ **Adelantada**: el filtro gratis tiene que estar antes de gastar cuota |
| **4** | **F-C** | [Enricher inverso y triage](fases/F-C.md) | ☐ La pieza central — responde la pregunta de estudio |
| **5** | **F-D** | [Reincidencia](fases/F-D.md) | ☐ Convierte el dato en conocimiento. Cierre real bloqueado por tráfico SSH |
| — | **F-F** | [YARA sobre el corpus](fases/F-F.md) | ☐ **Bloqueada por corpus real** (hoy 0 payloads en disco) |
| — | **F-G** | [Deuda técnica](fases/F-G.md) | ☐ Track paralelo, un ítem por vez — cuando moleste |

### Dependencias y orden

```
F-A ──→ F-H ──→ F-I        (el informe que ya corre: verlo, y después afinarlo)
☑ hecha ☑ hecha ☑ hecha
                  │
                  └──→ F-B1 ──→ F-B2 ──┬─→ F-E ──→ F-C ──→ F-D
                       store   ingesta │   listas   triage  reincidencia
                                       │
                                       └─→ F-F (YARA)   [+ requiere corpus real]

F-G (deuda técnica) — en paralelo, un ítem por sesión
```

El orden no es decorativo:

- Sin **higiene**, todo lo demás destila ruido propio.
- **F-H fue primero** (hecha el 2026-08-09): el pipeline ya corría solo todos los días y el criterio
  de cierre de F0 —"dos semanas de informes sin intervención"— sólo se verificaba mirando si aparecía
  el fichero. Ahora cada corrida deja un `run-manifest.json` y once líneas de resumen. La fase dejó
  además un hallazgo que el plan no preveía: una fuente habilitada **sin key no falla, se calla**, y
  el informe salía como si esa fuente no hubiera encontrado nada.
- **F-I siguió a F-H** (hecha el 2026-08-09) porque el manifiesto de la corrida es también material
  de prompt: la mejora más grande era que el modelo **sepa lo que no tiene**. Confirmado en el A/B:
  el informe pasó de declarar cero faltantes a declarar cinco, y el hallazgo de la sesión es que no
  alcanza con darle el dato — hay que **pedirle explícitamente que lo escriba**, o lo sabe y se lo
  calla. La fase dejó además el enrichment llegando a las cuatro fases: LATAM y general nunca habían
  visto un veredicto de IOC.
- Sin **store**, no hay memoria; sin memoria, el triage no puede priorizar por reincidencia.
- **F-E va antes que F-C**: el filtro gratis —jamesbrine 1,06 M IPs + IPsum + FireHOL— tiene que
  estar completo *antes* de que el enricher inverso empiece a gastar las **25 consultas semanales**
  de GreyNoise. Cada consulta desperdiciada es el 4 % del presupuesto.

### Invariantes del rework

Valen para todas las fases y no se rediscuten sesión a sesión:

1. **El pipeline nunca se rompe por una fase nueva.** Todo componente nuevo va envuelto en
   try/except a nivel de etapa, como ya hace `pipeline.stage27_enrich`. El informe diario está en
   producción y es el criterio de cierre de F0.
2. **El colector escribe en el store; el pipeline sólo lee** (salvo el cache de `enrichment`, que
   escribe F-C). El productor es el que ingiere, 4 veces al día.
3. **Los artefactos en disco son la fuente de verdad.** El store es una vista reconstruible con el
   backfill.
4. **Toggle por fase**, arrancando en OFF, en `config.ENRICHERS` o su equivalente.
5. **Sin dependencias nuevas salvo justificación explícita.** SQLite es stdlib; YARA va como extra
   opcional. El CT tiene 512 MiB.
6. **Idempotencia en todo lo que corre por timer.** El pull va cada 6 h.
7. **Nada de números mágicos:** cuotas, TTLs y umbrales en `config.py`, en un solo lugar.
8. **El honeypot sigue sin saber nada de casa** y **los payloads no se ejecutan nunca.**

---

## Criterio de cierre del rework

Una corrida diaria que, con los honeypots expuestos, procese las IPs del día, gaste **menos de 5
consultas de GreyNoise**, y produzca en el informe al menos una afirmación del tipo *"esta IP volvió
N días, no está en ninguna blocklist, y GreyNoise no la ve escanear internet"*.

Ese enunciado es, literalmente, lo sutil separado de lo burdo.

Y —agregado el 2026-08-09— que esa corrida sea **verificable sin leer el log entero**: el
`run-manifest.json` de F-H dice qué corrió, qué falló y qué no llegó al modelo, y el informe declara
sus propios faltantes (F-I). Una afirmación que no se puede auditar no sirve como inteligencia.

---

## Pendientes de despliegue acumulados

Lo que está hecho en el repo pero **todavía no corre en el CT 113**:

| De | Qué falta |
|---|---|
| F-A | `git pull` en `/opt/intel/app` + agregar `OWN_IPS=` a `/etc/intel/intel.env`. Sin eso el pull de cada 6 h sigue metiendo la IP de casa como atacante. Comandos exactos en [`fases/F-A.md`](fases/F-A.md) §Pendientes |
| F-H | El mismo `git pull` lo lleva. A partir de ahí `journalctl -u separatio.service` muestra el resumen de cada corrida y `separatio --last-run` funciona en el CT. Opcional: `OnFailure=` en la unit, ahora que el exit code significa algo |
| F-I | El mismo `git pull`, sin variables nuevas. Ojo con dos cosas al desplegar: el informe del CT va a **crecer ~9 %** y costar **~$0,09 más por corrida**, y la primera corrida con el esquema de Stage 2 paga una compilación (se cachea 24 h, así que se paga una vez por día) |
