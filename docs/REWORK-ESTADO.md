# REWORK-ESTADO — punto de entrada del rework de Intel

> **Si estás empezando una sesión del rework, leé este archivo primero y nada más.**
> Te dice en qué fase está, qué sigue, y qué archivo abrir para hacerlo.

Última actualización: **2026-08-10** (despliegue de las nueve fases, honeypots expuestos y los cuatro bugs que eso destapó)

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
Continuamos el rework. Leé docs/REWORK-ESTADO.md y después docs/fases/F-B2.md.
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
| — | **F-A** | [Higiene de la entrada](fases/F-A.md) | ☑ **Hecha el 2026-08-09** — clasificador `separatio/hygiene.py` (propias se descartan, escáneres se etiquetan por CIDR + PTR), consolidador extraído del heredoc a `separatio/honeypot_collector.py` y testeable, rutas de datos ancladas a `REPO_ROOT`. 73 tests. **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-H** | [Observabilidad de la corrida](fases/F-H.md) | ☑ **Hecha el 2026-08-09** — `separatio/runlog.py` (manifiesto de la corrida), diez puntos de recorte instrumentados con `shown`/`total`, tokens a INFO, log con rotación, `status`/exit code y `separatio --last-run`. 94 tests. Verificada con corrida real: 5 llamadas, 52.897 in / 21.076 out. **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-I** | [Afinado de prompts](fases/F-I.md) | ☑ **Hecha el 2026-08-09** — `runlog.coverage_block()` (el informe declara sus faltantes: 5 líneas "Limitaciones de esta corrida" contra 0 antes), topes a `config.PROMPT_CAPS` (IOCs 8→20, veredictos 25→60), **enrichment a las cuatro fases** (LATAM y general ya citan Ransomware.live/IPsum/ipcheck), campos `attack_techniques`/`exploitation_status`/`confidence` + técnicas ATT&CK corroboradas, salida estructurada en Stage 2 (0 reintentos) y `PHASE_EFFORT` cableado. 115 tests. A/B: **+$0,09 por corrida**. **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-B1** | [Store: esquema y capa de acceso](fases/F-B1.md) | ☑ **Hecha el 2026-08-09** — paquete `separatio/store/` (`schema.sql` con 5 tablas + 5 índices, `db.py` con `open_store`/`migrate`/`store`, `models.py` con las 9 funciones de acceso), `data/archivo.db` creado en WAL con `schema_version=1`, migración idempotente y toggle `STORE_ENABLED`. 134 tests. El pipeline **no cambió de conducta**: nadie escribe el store todavía. **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-B2** | [Ingesta idempotente y backfill](fases/F-B2.md) | ☑ **Hecha el 2026-08-09** — `separatio/store/ingest.py` (`ingest_run()`, punto único de escritura), `honeypot_collector.consolidate()` cablea la escritura envuelta en try/except, `separatio/store/backfill.py` (recorre `by-date/*/`, reclasifica snapshots anteriores a F-A). 146 tests. Verificado con IP sintética: reingerir la misma ventana deja `times_seen=1` y `count(*) observation` sin cambios. El único snapshot real (`2026-08-08/`) es la IP propia del laptop — el backfill la excluyó correctamente (0 IOCs). **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-E** | [Listas locales](fases/F-E.md) | ☑ **Hecha el 2026-08-09** — `separatio/lists.py` (`LocalLists`: `array('I')` + bisect para IPs sueltas, rangos `(inicio,fin)` + bisect para CIDR), cache en `data/feeds/` con TTL de 12h y fail-open a copia vencida, `IPSUM_URL` corregido a la base (`levels/3.txt` no trae score, el plan lo asumía mal). 157 tests. Verificado con techo duro en el CT: **79,8 MB de pico** (techo 120 MB) tras corregir dos fugas de RAM que el plan no había previsto. Cableada por F-C. **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-C** | [Enricher inverso y triage](fases/F-C.md) | ☑ **Hecha el 2026-08-09** — `separatio/enrichers/honeypot_recon.py` (`HoneypotReconEnricher`): triage en 4 etapas (higiene → cache → listas locales de F-E → residuo), presupuesto declarativo (`config.QUOTAS`) contado contra el store, sólo el resultado NEGATIVO de GreyNoise escala a la cascada de `ipcheck`. 171 tests (14 nuevos). Verificado con 3 IOCs / 2 candidatas del store y GreyNoise mockeado a propósito — **corrección del 2026-08-10: esos IOCs no eran reales, eran fixtures que `pytest` inyectó en el store** (ver §Bugs abiertos); el triage quedó ejercitado igual, pero no contra tráfico real (no gastar cuota real sin pedirlo) y `separatio --dry-run` intacto. **☑ desplegada al CT 113 el 2026-08-10.** Pendiente: prender el toggle con GreyNoise real (gasta cuota, decisión del usuario) |
| — | **F-D** | [Reincidencia](fases/F-D.md) | ☑ **Código y tests hechos el 2026-08-09** — `separatio/store/queries.py` (`ip_recurrence`/`payload_history`/`hassh_fanout`/`top_recurrent`), `HoneypotReconEnricher` suma la reincidencia al `detail` de la señal fuerte y a tres notas nuevas, `config.RECURRENCE_WINDOW_DAYS`/`HASSH_MIN_IPS`/`HASSH_WINDOW_DAYS`. 180 tests (9 nuevos). **Cierre real bloqueado por tráfico SSH** — la verificación en vivo queda pendiente explícito, no se declaró hecha con datos sintéticos. **2026-08-10: se desbloqueó a medias.** Con los honeypots expuestos, el store pasó de 0 a **28 IOCs (9 escáneres, 19 desconocidas), 75 observaciones y 2 payloads** en el primer pull. Pero `days_seen >= 2` sigue en 0 **por definición**: hace falta que pase un segundo día. Revisar el 2026-08-11: si una IP vuelve, F-D se cierra con la frase que el criterio del rework pide. **☑ desplegada al CT 113 el 2026-08-10** |
| — | **F-F** | [YARA sobre el corpus](fases/F-F.md) | ◐ **Desbloqueándose**: con los honeypots expuestos el 2026-08-10 el primer pull ya trajo 2 payloads (1 nuevo). Reevaluar en días, cuando haya corpus de verdad |
| **3** | **F-G** | [Deuda técnica](fases/F-G.md) | ☑ **HECHA el 2026-08-09 — los siete ítems (G-1…G-7) cerrados.** Era el único track sin dependencia de tráfico real, y se cerró entero en el día. **G-2 (el último)**: dataclass congelado `separatio/settings.py:Settings` + `config.py` como fachada de 40 líneas; las etapas de `pipeline.py` reciben `settings` por parámetro y **se eliminó la mutación global de `config` en caliente** de la que dependía el aislamiento del `--dry-run` (el fix del incidente del 2026-08-08) — ahora es `settings_for(args)`, función pura. Los 97 valores verificados idénticos (valor y tipo) contra el config previo; acoplamiento 187 → 45 referencias; 339 tests (32 nuevos). G-3: `pipeline.py` 985 → 839 líneas, tres módulos hoja nuevos (`deduplicator.py`, `ioc_processor.py`, `router.py`), 228 tests (45 nuevos — `pipeline.py` no tenía ninguno). G-5: paquete `separatio/providers/` (ABC `LLMProvider` + 4 subclases + fábrica) reemplaza el `if provider ==` de `_llm_chat` y el streaming de Ollama duplicado; `analyzer.py` 1241 → 1154 líneas, 264 tests (36 nuevos), verificado con una llamada real contra Claude. **G-6: el único ítem de F-G que cambió la salida a propósito** (decisión explícita del usuario, variante completa de §6.2) — plantillas a `separatio/templates/*.html.j2` (Jinja2) y parser de regex → librería `markdown`; `reporter.py` 830 → 400 líneas, 307 tests (43 nuevos — tampoco tenía ninguno), +2 dependencias (2,1 MB, +13,3 MB RSS) |

### Dependencias y orden

```
F-A ──→ F-H ──→ F-I        (el informe que ya corre: verlo, y después afinarlo)
☑ hecha ☑ hecha ☑ hecha
                  │
                  └──→ F-B1 ──→ F-B2 ──┬─→ F-E ──→ F-C ──→ F-D
                       ☑ store ☑ ingesta │  ☑ listas ☑ triage  reincidencia
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
  **F-B1 (hecha el 2026-08-09) dejó la capa lista sin cablearla**: el fichero existe, migra y está
  testeado, pero nadie lo escribe todavía — el pipeline en producción no cambió de conducta. El
  hallazgo de la sesión fue de formato, no de esquema: las ventanas del store comparan **cadenas**
  de tiempo, y el colector emite `…Z` mientras Python emite `…+00:00`; en ASCII `'+' < 'Z'`, así que
  un formato mezclado habría roto `quota_used` y la poda **en silencio**. Todo timestamp que entra
  se normaliza.
- **F-E va antes que F-C**: el filtro gratis —jamesbrine 1,06 M IPs + IPsum + FireHOL— tiene que
  estar completo *antes* de que el enricher inverso empiece a gastar las **25 consultas semanales**
  de GreyNoise. Cada consulta desperdiciada es el 4 % del presupuesto.
- **F-B2 (hecha el 2026-08-09) cablea la escritura**: `honeypot_collector.consolidate()` ya vuelca
  cada pull a `data/archivo.db` vía `ingest_run()`, y `store/backfill.py` reconstruye desde
  `by-date/*/` lo que hubiera antes. El hallazgo de la sesión fue otra trampa de FK que F-B1 no había
  anotado: `observation.payload_sha256` también es clave foránea, así que un evento con `sha256`
  necesita su fila en `payload` **antes** de insertar la observación — el mismo patrón que ya existía
  para `ioc`. Se resolvió la trampa de `times_seen` que F-B1 dejó pendiente con la opción (b):
  `upsert_ioc` ganó un `count: bool = True` para poder asegurar la fila sin contarla.
- **F-E (hecha el 2026-08-09) deja el filtro gratis, listo pero sin cablear**: `separatio/lists.py`
  responde pertenencia en cuatro blocklists agregadas sin gastar cuota, pero todavía no lo llama
  nadie — F-C es quien lo va a consultar sobre las IPs del honeypot. La fase encontró dos cosas que
  el plan había dado por sentadas y no eran así: `levels/3.txt` de IPsum **no trae score por línea**
  (sólo el agregado `ipsum.txt` lo trae; se corrigió `config.IPSUM_URL` en el documento y en el
  código), y la primera implementación (`text.splitlines()` sobre 1 M de líneas) rompía el techo de
  RAM del CT por RAM transitoria, no por el tamaño final de las estructuras — 128,8 MB de pico contra
  un techo de 120 MB. Se arregló iterando el archivo línea a línea en vez de materializar la lista
  completa, y sacando el `set()` intermedio de la deduplicación: quedó en 79,8 MB de pico real,
  medido en el CT con `systemd-run -p MemoryMax=120M`.
- **F-C (hecha el 2026-08-09) es la pieza central**: `HoneypotReconEnricher` responde "esta IP me
  pegó, ¿es actor conocido o ruido de internet?" gastando cuota sólo en el residuo que ni el cache
  ni las listas locales de F-E resuelven gratis. Sólo el resultado **negativo** de GreyNoise
  (`noise=False`, no la ve escanear internet) escala a la cascada completa de `ipcheck` — es la
  única señal disponible que se parece a "dirigido a mí", porque ninguna blocklist contiene
  negativos. El presupuesto se cuenta contra `enrichment` (F-B1), no en una variable de proceso. El
  hallazgo de la sesión fue de alcance, no de diseño: el plan no decía qué hacer con las IPs
  `noise=False` que exceden `RECON_MAX_ESCALATE` — se resolvió emitiéndoles igual el veredicto (sin
  el detalle de la cascada) en vez de perderlas en silencio, y `models.recent_ips` (F-B1) ganó dos
  columnas (`sensors`, `has_payload`) que el criterio de prioridad del residuo necesitaba y la
  función original no traía. Verificada con las 2 IPs candidatas del store (**fixtures, no dato real** — §Bugs abiertos, 2026-08-10) (`45.9.148.99`,
  `45.9.148.52`) con GreyNoise **mockeado a propósito**: gastar la cuota real semanal es una
  decisión del usuario, no algo que una sesión de verificación tome sola.
- **F-D (código y tests hechos el 2026-08-09) convierte dato en conocimiento — literalmente el
  criterio de cierre del rework**: `HoneypotReconEnricher` ya no dice sólo "no la ve escanear
  internet", dice "volvió N de los últimos 14 días; no la ve escanear internet". Fue casi gratis
  porque F-B2 ya mantenía `days_seen`/`times_seen` y el HASSH ya entraba como IOC propio — la fase
  fue sobre todo consultas (`store/queries.py`) y redacción (tres notas nuevas). El único ajuste al
  diseño original de F-C fue de precisión: la prioridad del residuo pasó del `days_seen` denormalizado
  (la vida entera del indicador) a `ip_recurrence()` (acotado a `RECURRENCE_WINDOW_DAYS`), que es lo
  que el enunciado "de los últimos 14 días" necesita para no mentir. **No se pudo cerrar contra dato
  real**: el store de producción tiene 0 IPs con `days_seen >= 2` y 0 HASSH — el honeypot todavía no
  vio tráfico SSH repetido. Se documentó como pendiente explícito en vez de forzar el cierre con
  datos sintéticos, según la regla del rework.

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

## Despliegue al CT 113 — ☑ hecho el 2026-08-10

**Las nueve fases corren en producción.** El CT venía de `88dc851` (previo al rework) y pasó a
`dc5e850` de un solo `git pull`. As-built:

```
$ git -C /opt/intel/app pull --ff-only && git log --oneline -1
dc5e850 rework F-G: cierre de la fase — reporter con plantillas (G-6) y config inyectable (G-2)

$ venv/bin/pip install -e '.[dev]'
Successfully installed MarkupSafe-3.0.3 intel-0.1.0 jinja2-3.1.6 markdown-3.10.3

$ venv/bin/pytest tests/ -q
339 passed in 5.22s          # ⚠️ este paso contamina el store — ver §Bugs abiertos

$ systemctl start honeypot-pull.service
[pull] higiene: 0 IP(s) propia(s) descartada(s) (0 hits) · 0 escáner(es) etiquetado(s)
[pull]   store: 0 IOCs nuevos, 0 observaciones nuevas, 0 payload(s) nuevo(s)
Result=success · ExecMainStatus=0

$ separatio-check
🎉 Todo listo.   (Miniflux OK, ANTHROPIC_API_KEY configurada, salida en /opt/intel/app/separatio/reports)

$ separatio --last-run
No hay manifiestos en /opt/intel/app/separatio/reports (ninguna corrida instrumentada todavía).
```

Lo que se hizo, en orden, y lo que hay que saber:

| Paso | Resultado |
|---|---|
| `git pull` | `88dc851` → `dc5e850`. **Ojo:** hay que correrlo como `intel`; como root, git aborta con *dubious ownership* |
| `pip install -e '.[dev]'` | obligatorio por G-6. Trajo `jinja2` 3.1.6, `markdown` 3.10.3, `MarkupSafe` 3.0.3 |
| `OWN_IPS=` (F-A) | agregado a `/etc/intel/intel.env`, root:600, backup en `intel.env.bak-preF-A`. Las dos IPs propias, copiadas del `.env` del laptop |
| backfill (F-B2) | `2 carpeta(s), 0 IOC(s), 0 observación(es), 1 payload(s)` |
| G-6 (plantillas) | verificado **fuera** de `/opt/intel/app` para probar que resuelven como *package-data*: `pdf.html.j2` y `web.html.j2` presentes y compilan |
| F-H (`--last-run`) | la CLI responde; el primer manifiesto lo escribe el timer diario de las 07:04 |

**Rutas reales, contra lo que decían los documentos:** el venv es **`/opt/intel/app/venv`**, no
`/opt/intel/venv`. Gana la máquina.

**Los ceros del pull son correctos, no un fallo:** los honeypots siguen sin exponer, así que la
ventana de 24 h no trajo ni un atacante (`"attackers": []` en los dos snapshots). El único dato del
corpus es un payload de **2 bytes** de `vm1-cowrie` — por eso F-F sigue bloqueada aunque el conteo
de payloads ya no sea literalmente 0.

**Lo que todavía no se verificó en el CT** (cuesta plata, es decisión del usuario): una corrida
completa del pipeline. Con eso se cierran las tres cosas que sólo se ven corriendo — el manifiesto
de F-H, las "Limitaciones de esta corrida" de F-I, y **el primer PDF con las plantillas de G-6**
(el único cambio de esta tanda que se ve en el informe). El timer diario lo hace solo a las 07:04.

### Los informes se publican al share (2026-08-10)

Pedido del usuario: poder leer los informes desde **copyparty**, como ya se hace con
Kavita/Navidrome. Se siguió el patrón que ya usa el host: una carpeta del share montada en el CT.

```
host   /mnt/pve/nvme-data/cloud/Intel      (uid 100999:100991)
CT 113 /mnt/informes                        (mp0, bind mount)
CT 104 /media/storage/Intel                 (copyparty ya sirve /media/storage entero)
```

Salió gratis por una coincidencia que conviene no perder: **el usuario `intel` del CT 113 es
uid 999 / gid 991**, los mismos que ya poseen las carpetas del share (`100999:100991` en el host,
porque todos los CT son unprivileged). Cero idmap, igual que navidrome y kavita.

Qué se publica y qué no: `/usr/local/bin/publicar-informes.sh` copia **sólo el PDF y el HTML** de
cada carpeta con nombre de fecha, y corre como `ExecStartPost=-` (con guión: que fallar la copia no
marque la corrida como fallida, invariante 1) de `separatio.service` y `separatio-weekly.service`.
El directorio de trabajo sigue local, así que los dry-run, el caché de resúmenes y los
`run-manifest.json` **no** llegan al share. El filtro es por forma del nombre (`^\d{4}-\d\d-\d\d$`),
no por lista de exclusiones, para que no se pudra.

Verificado: los dos informes que ya existían (`2026-08-08`, `2026-08-09`) quedaron publicados y se
ven desde el CT de copyparty.

### Bugs encontrados desplegando — ☑ los cuatro arreglados el 2026-08-10

**1. `pytest` escribía en el store de producción.** Descubierto el 2026-08-10 desplegando. Desde
F-B2, `honeypot_collector.consolidate()` abre el store con `store.db.store()` **sin ruta**, así que
cae al default `REPO_ROOT/data/archivo.db`. Los tests de `test_honeypot_collector.py` y
`test_store_ingest.py` le pasan un `out` en `tmp_path` pero **no redirigen el store**, así que cada
corrida de la suite inyecta sus fixtures (`45.9.148.99`, `45.9.148.52`, `162.142.125.7`,
`vm1-web`/`GET /.env`, un `hassh` `abc123`) en el archivo real y las acumula: el store del laptop
llegó a `times_seen` 50/57/42 y **150 observaciones**, todas falsas.

Impacto: contamina el dataset del que dependen F-C (triage) y F-D (reincidencia), y **puede hacer
gastar cuota real de GreyNoise en IPs de fixture** cuando se prenda `honeypot_recon`. Además
invalida una afirmación ya escrita: la verificación de F-C dice *"las 2 IPs candidatas **reales**
del store"* y no lo son.

**Arreglado**, en tres capas: `consolidate()` tomó un parámetro `db_path=None` que llega hasta
`store()`; los tests que la llaman pasan `db.MEMORY`; y `tests/conftest.py` estrena un fixture
`autouse` que manda el store por default a `tmp_path` —pisando **los dos** lados de la fachada de
G-2, `config.STORE_PATH` y `config.SETTINGS`, porque `db.default_path()` acepta un `settings=` y
resuelve por ahí cuando se lo pasan—, así que un test que se escriba mañana tampoco puede
reintroducirlo. El store del CT se reconstruyó desde disco (backup en
`data/archivo.db.bak-contaminado`) y quedó en `0 ioc / 0 observation / 1 payload`; el del laptop se
sacó de en medio igual.

Verificado en las dos direcciones: con el guard puesto, la suite pasa y `data/archivo.db` **no se
crea**; sin el guard, el test de regresión nuevo (`test_la_suite_no_toca_el_store_del_repo`, que
corre a propósito **sin** `db_path`) falla y el fichero aparece. 341 tests.

**2. `backfill --dry-run` contaba de más.** Informaba `len(attackers)` y `len(events)` sin
comprobar si insertarían: dijo `2 observaciones nuevas` donde el run real insertó `0`, porque los
eventos de Cowrie traen `"ip": "?"` y no generan observación. Un dry-run que no predice no sirve.

**Arreglado**: ahora ingiere de verdad, pero contra una **copia temporal** del store hecha con
`sqlite3.Connection.backup()` (y no `copy2`, que se perdería los commits que estén sólo en el WAL),
y devuelve los totales del mismo `ingest_run` que la corrida real. Test nuevo
`test_el_dry_run_predice_exacto_y_no_toca_el_store`: el dry-run no crea el fichero y sus totales
son **iguales** a los de la corrida real sobre el mismo `by-date/`.

**3. El CT no generaba ningún PDF, y no se notaba.** Encontrado el 2026-08-10 al ir a publicar los
informes. Eran **dos causas encadenadas**, y la primera hipótesis de la sesión era la menos
importante — queda anotado porque es justo el error que la regla del rework existe para evitar:

- *Lo que se vio primero:* `weasyprint` estaba instalado como paquete Python pero **sin las
  librerías del sistema** (`libpango`), así que `import weasyprint` moría con `OSError`. Se dio por
  sentado que ésa era la causa, razonando sobre el `except Exception` genérico de `_write_pdf`.
- *La causa de fondo, verificada contra la máquina:* **`OUTPUT_FORMAT` estaba declarado en
  `Settings` pero `from_env()` nunca lo leía**, así que valía siempre su default `"both"` (md+html)
  y **`_write_pdf` no se llamaba jamás**. El `OSError` de weasyprint ni siquiera llegaba a ocurrir
  dentro del pipeline. El README documentaba `OUTPUT_FORMAT` como configurable y no lo era: ponerlo
  en `/etc/intel/intel.env` no hacía absolutamente nada — comprobado, seguía valiendo `'both'` con
  la variable presente en el entorno del proceso.

Arreglado en las dos capas: las librerías del sistema en el CT (`libpango-1.0-0 libpangoft2-1.0-0
libharfbuzz0b libfontconfig1 libgdk-pixbuf-2.0-0 fonts-dejavu-core`), y `OUTPUT_FORMAT` cableado al
entorno en `settings.from_env()` —encaja en la definición que da su propio docstring, "los toggles
que existen para poder apagar algo en el CT sin editar código"— con `OUTPUT_FORMAT=all` en el env
file del CT. El default no se repite en `from_env`: sale del campo del dataclass, así no divergen.

Y de yapa, **la cuarta vez del mismo modo de fallo**: un `OUTPUT_FORMAT` con typo dejaba los tres
flags de escritura en `False` y el informe **no se escribía en silencio**. Ahora `reporter` valida
contra la lista de formatos y cae al default avisando. Verificado de punta a punta: PDF de 85.368
bytes con cabecera `%PDF-`, publicado y visible desde el CT de copyparty.

**4. Un test que era una bomba de tiempo.** `test_el_pull_sigue_funcionando_sin_store` usaba la
constante `DAY` (fecha **fija**) para un evento que pasa por `consolidate()`, que descarta lo que
caiga fuera de una ventana **relativa** de 24 h. O sea que fallaba solo todos los días pasadas las
07:00 UTC; explotó a mitad de esta sesión, y se confirmó contra el código sin tocar que no era una
regresión. Pasó a un timestamp relativo. Los demás usos de `DAY` van a `ingest_run`/backfill, que no
filtran por tiempo, y ahí la fecha fija está bien.

<details>
<summary>Pendientes de despliegue acumulados (histórico — todos cerrados el 2026-08-10)</summary>

| De | Qué faltaba |
|---|---|
| F-A | `git pull` en `/opt/intel/app` + agregar `OWN_IPS=` a `/etc/intel/intel.env`. Sin eso el pull de cada 6 h sigue metiendo la IP de casa como atacante. Comandos exactos en [`fases/F-A.md`](fases/F-A.md) §Pendientes |
| F-H | El mismo `git pull` lo lleva. A partir de ahí `journalctl -u separatio.service` muestra el resumen de cada corrida y `separatio --last-run` funciona en el CT. Opcional: `OnFailure=` en la unit, ahora que el exit code significa algo |
| F-I | El mismo `git pull`, sin variables nuevas. Ojo con dos cosas al desplegar: el informe del CT va a **crecer ~9 %** y costar **~$0,09 más por corrida**, y la primera corrida con el esquema de Stage 2 paga una compilación (se cachea 24 h, así que se paga una vez por día) |
| F-B1 | El mismo `git pull`, **sin variables nuevas** — pero esta vez conviene rehacer `venv/bin/pip install -e '.[dev]'` para que el subpaquete `separatio.store` quede registrado. Nada cambia de conducta: el store se crea solo (`data/archivo.db`, ~64 KB) y nadie lo escribe hasta F-B2. Verificar de paso que el usuario `intel` pueda escribir en `/opt/intel/app/data/` |
| F-B2 | El mismo `git pull`, sin variables nuevas. A partir de acá **el colector empieza a escribir de verdad** en cada pull (cada 6 h) — conviene correr `python3 -m separatio.store.backfill` una vez después del pull, para meter al store lo que ya haya en `by-date/` del colector viejo |
| F-E | El mismo `git pull`, sin variables nuevas. `data/feeds/` se crea sola en el primer `load()` (~15-16 MB). Nadie llama a `LocalLists` todavía — no cambia la conducta del pipeline hasta que F-C lo cablee |
| F-C | El mismo `git pull`, sin variables nuevas (`QUOTAS`/`RECON_*`/`ENRICH_TTL_DAYS` tienen default en `config.py`). El toggle `honeypot_recon` sigue en `False`: no cambia conducta hasta que se prenda a propósito (gasta cuota real de GreyNoise) |
| F-D | El mismo `git pull`, sin variables nuevas (`RECURRENCE_WINDOW_DAYS`/`HASSH_MIN_IPS`/`HASSH_WINDOW_DAYS` tienen default en `config.py`). No cambia conducta hasta que `honeypot_recon` esté en `True` **y** el honeypot tenga tráfico SSH repetido — hoy ninguna de las dos |
| F-G (G-1/G-3/G-4/G-7) | El mismo `git pull`, sin variables nuevas y **sin reinstalar** (los módulos nuevos de G-3 —`deduplicator.py`, `ioc_processor.py`, `router.py`— viven dentro del paquete `separatio`, que ya está registrado). Por diseño **ningún** ítem de F-G cambia la salida del pipeline; lo único visible en el CT es lo de G-4 (la columna `reputation` en `iocs.csv`) y lo de G-7 (dos líneas de ruido menos en el log) |
| F-G (G-5) | El mismo `git pull`, sin variables nuevas — pero esta vez **sí hay que reinstalar** (`venv/bin/pip install -e '.[dev]'`): `separatio.providers` es un subpaquete nuevo, mismo caso que F-B1 dejó anotado para `separatio.store`. No cambia la salida del pipeline (mismo dispatch, ahora por clases en vez de `if/elif`) |
| F-G (G-2) | El mismo `git pull`, **sin variables nuevas y sin dependencias nuevas**. `separatio/settings.py` vive dentro del paquete `separatio`, que ya está registrado, así que no obliga a reinstalar por sí mismo (G-6 sí). No cambia la salida ni la conducta: los 97 valores efectivos son idénticos y `/etc/intel/intel.env` se sigue leyendo igual (`load_dotenv` → `Settings.from_env()` al importar `config`). Lo único que conviene mirar en el CT es que el primer `--dry-run` siga escribiendo bajo `reports/dryrun/` |
| F-G (G-6) | El mismo `git pull` **+ reinstalar obligatorio** (`venv/bin/pip install -e '.[dev]'`): hay **dos dependencias nuevas** (`jinja2`, `markdown` — 2,1 MB) y las plantillas van como *package-data*, así que sin reinstalar el render falla por plantilla no encontrada. Sin variables nuevas. **Es el único ítem de F-G que cambia lo que se ve**: el informe HTML/PDF sale distinto (sublistas anidadas de verdad, hard breaks respetados, ~1 página menos de PDF) — a mejor, pero conviene mirar el primer PDF del CT. RAM: +13,3 MB de RSS, pico de 34,3 MB contra el techo de 120 MB |

</details>
