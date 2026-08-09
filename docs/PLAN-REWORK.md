# PLAN DE REWORK — del pipeline de informes al archivo de inteligencia

> Escrito el **2026-08-09**. Este documento es el **diseño**: el qué y el por qué.
>
> ## ⚠️ La ejecución vive en [`REWORK-ESTADO.md`](REWORK-ESTADO.md)
>
> El rework se hace **una fase por sesión**, cada una documentada al cerrar. El punto de entrada de
> cada sesión es [`REWORK-ESTADO.md`](REWORK-ESTADO.md) (tabla de estado + protocolo + prompt de
> arranque) y el detalle de cada fase está en [`fases/`](fases/). **Empezar siempre por ahí, no por
> este archivo.**
>
> Estado: **F-A hecha el 2026-08-09** ([`fases/F-A.md`](fases/F-A.md)). El resto está **planificado
> al detalle** — cada `fases/F-*.md` trae DDL, firmas, nombres de test y comandos de verificación,
> para que una sesión ejecute sin volver a diseñar.
>
> ### Cambios de ejecución decididos el 2026-08-09
>
> Afectan **cómo** se ejecuta el plan de abajo, no su contenido:
>
> - **Dos fases nuevas al frente, que este plan no contemplaba: [`F-H`](fases/F-H.md)
>   (observabilidad) y [`F-I`](fases/F-I.md) (afinado de prompts).** El plan de abajo asume que el
>   informe diario funciona bien porque se genera, pero **nadie puede verificarlo**: el consumo de
>   tokens se loguea en `DEBUG` (invisible), `pipeline.log` no rota, y hay ocho puntos donde se
>   descartan datos en silencio antes de llegar al LLM — el más grave, que el enrichment nunca
>   alcanza a las fases `latam` y `general`. Van primero porque el pipeline **ya está en
>   producción** y son independientes del honeypot.
>
> - **F-B se parte en [`F-B1`](fases/F-B1.md) (esquema y capa de acceso) y
>   [`F-B2`](fases/F-B2.md) (ingesta idempotente y backfill).** Entera era una sesión demasiado
>   larga y cortarla a la mitad dejaría un store a medio cablear.
> - **F-E se ejecuta ANTES que F-C.** El §5 gasta las 25 consultas semanales de GreyNoise en el
>   residuo, y el §F-E es justamente lo que achica ese residuo. Construir el consumidor antes que
>   el filtro quema cuota sin necesidad. Las letras no cambian (están referenciadas acá y en
>   Motherbase); el orden de ejecución está en [`REWORK-ESTADO.md`](REWORK-ESTADO.md).
> - **El colector escribe en el store; el pipeline sólo lee.** El §F-B no decía quién ingiere.
>   Decisión: el productor (`honeypot_collector.py`, 4 corridas diarias), porque la idempotencia
>   por ventana es natural ahí y deja el informe de las 07:00 fuera del camino de escritura.
>   `sqlite3` es stdlib, así que el colector sigue sin dependencias.
> - **F-E no es un `Enricher`**: es un servicio de pertenencia (`separatio/lists.py`) que consulta
>   F-C. Y su duda de RAM quedó resuelta con medición: `array('I')` + `bisect` da **4,3 MB** para
>   1,06 M de IPs, contra 91,3 MB de un `set` de strings.
>
> ### Correcciones al texto de abajo, verificadas contra la máquina el 2026-08-09
>
> 1. **§F-B da por existentes `by-date/*/events.jsonl` y `hashes.log`. En disco no están.** El
>    colector los genera desde los commits `8dcbae8`/`5859848`, pero la única corrida real
>    (`by-date/2026-08-08/`) es anterior. La ingesta tiene que tolerar snapshots con sólo
>    `attackers.json`.
> 2. **§F-F dice "hoy hay 1 payload de 2 bytes". En este laptop hay cero**: no existe
>    `data/honeypot/payloads/` ni `hashes.log`.
> 3. **§F-A hablaba de poner la allowlist en `tools/pull_honeypot.sh`.** Se hizo mejor: el
>    consolidador salió del heredoc a `separatio/honeypot_collector.py` (testeable) y el
>    clasificador vive en `separatio/hygiene.py`. Además se sumó lo que el plan no preveía —
>    clasificación de escáneres **por PTR**, que es la que no se pudre, y autoresolución de la IP
>    pública propia, porque es dinámica.
> 4. **Hallazgo lateral:** `HONEYPOT_DATA` y `MALWAREBAZAAR_CORPUS` eran rutas **relativas** que
>    sólo resolvían si el cwd era la raíz del repo. Corregido en F-A con `config.REPO_ROOT`.
>
> Complementa, no reemplaza:
> - [`IMPROVEMENTS.md`](IMPROVEMENTS.md) — auditoría de junio y refactors pendientes (§6). Siguen vigentes.
> - [`CAPAS-Y-FUENTES.md`](CAPAS-Y-FUENTES.md) — qué fuentes existen, verificadas contra el servidor.
> - `Motherbase/honeypot/COLECTOR-CT113.md` — el as-built del sensor propio.
>
> **Regla del proyecto:** verificar contra la máquina, no contra el documento.

---

## 1. El diagnóstico en una frase

Separatio hoy **produce informes y los olvida**. Cada corrida sale a buscar todo de nuevo, analiza
el día, escribe un Markdown y descarta el trabajo intermedio. No hay memoria de qué IOC ya se
consultó, ni de qué IP ya se vio, ni de qué payload ya se analizó.

Eso funcionaba cuando la única entrada eran noticias. Con el honeypot propio dando dato crudo cada
6 horas, deja de funcionar por tres razones concretas:

1. **Se quema cuota repitiendo consultas.** GreyNoise da 25 por semana. Sin cache, tres IPs
   repetidas se comen el 12 % del presupuesto semanal para no aprender nada nuevo.
2. **No se puede responder la pregunta interesante.** "¿Esta IP ya vino antes?" y "¿este payload ya
   lo vi?" requieren memoria entre corridas. Hoy la respuesta está en el disco (en `by-date/` y
   `hashes.log`) pero **nadie la consulta**.
3. **El enriquecimiento apunta al lado equivocado.** `run_enrichment()` hace
   `iocs = collect_iocs(summaries)`: solo enriquece los indicadores que salen en las **noticias**.
   Las IPs que atacan el honeypot nunca entran a la cascada de `ipcheck`.

El nombre del proyecto ya describe la solución: **separatio** es separar lo sutil de lo burdo. Hoy
todo entra al informe con el mismo peso. Lo que falta es el aparato que **destile**: descartar el
ruido de fondo de internet barato y temprano, para gastar las consultas caras solo en lo que puede
ser señal.

---

## 2. Las tres restricciones que mandan sobre el diseño

No son negociables y cualquier propuesta que las ignore está mal:

| Restricción | Valor real (medido) | Qué implica |
|---|---|---|
| **RAM del CT 113** | 512 MiB (~490 disponibles) | Nada de ArangoDB, OpenSearch ni Elastic. El proceso entero debe correr en decenas de MB |
| **Disco del CT 113** | 4 G, **3.2 G libres** | El corpus de payloads crece sin techo. El store debe ser compacto y con política de retención |
| **Cuotas de API** | GreyNoise **25/semana**, VT ~500/día, AbuseIPDB 1.000/día | El presupuesto de consultas es **el recurso escaso**. Todo el diseño gira alrededor de gastarlo bien |

Y una cuarta, de proceso: **sin dinero**. Todo tier gratuito. Eso ya descarta Pulsedive Feed
(1.500–3.000 USD/mes) y cualquier SIEM comercial.

---

## 3. Decisión de arquitectura: SQLite, no Yeti ni MISP

El pedido fue "una DB tipo SIEM, o Yeti". La respuesta es **SQLite embebido dentro de Separatio**.

### Por qué no Yeti

Yeti usa **ArangoDB**, que reserva memoria de forma agresiva y crece con el dataset. En 512 MiB no
entra, y subirle RAM al CT sale del presupuesto del host (que ya tiene solo ~5 GiB libres tras F1).
Ya estaba descartado en `LABS-PLAN.md`; esta revisión lo confirma.

### Por qué no MISP

MISP es una plataforma de **compartición** entre organizaciones. Su valor está en los feeds
sincronizados y el modelo de eventos/atributos/galaxias. Para un operador solo, es infraestructura
pesada (MySQL + Redis + workers) resolviendo un problema que no tenés. Y ya se genera `iocs.csv`
importable por si algún día se monta.

### Por qué SQLite es la respuesta correcta

- **Cero infraestructura.** Es un fichero. Va en la biblioteca estándar de Python — **no agrega una
  sola dependencia** al `pyproject.toml`.
- **Es exactamente la forma de los datos.** IOCs, observaciones y cache son tablas con índices y
  consultas por clave. Es un problema relacional, no un grafo ni un índice de texto completo.
- **Consultable a mano.** `sqlite3 archivo.db "select ..."` para estudiar, que es el objetivo
  declarado. Un grafo no te da eso sin una UI.
- **Transaccional.** El pull corre cada 6 h y el pipeline a las 07:00; pueden solaparse. SQLite en
  modo WAL maneja eso; un JSON reescrito entero, no (y hoy `history.py` ya necesitó escritura
  atómica para evitar corrupción).
- **Migrable.** Si algún día el corpus justifica MISP, exportar desde tablas es trivial.

> **Principio rector:** el store es una **capa nueva y opcional**. El pipeline debe seguir
> corriendo si el fichero `.db` no existe. Ninguna fase de este plan puede dejar el informe diario
> roto — hoy corre en producción y es el criterio de cierre de F0.

---

## 4. El modelo de datos

Un solo fichero, `data/archivo.db`, con esquema versionado. Cinco tablas y una vista.

```sql
-- Identidad: una fila por indicador, para siempre.
CREATE TABLE ioc (
  value       TEXT PRIMARY KEY,      -- normalizado (lowercase, defanged)
  kind        TEXT NOT NULL,         -- ip | domain | url | hash | hassh
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  times_seen  INTEGER NOT NULL DEFAULT 0,
  days_seen   INTEGER NOT NULL DEFAULT 0   -- nº de días DISTINTOS: la métrica de reincidencia
);

-- Cada avistamiento. Append-only. Es el log crudo del SIEM.
CREATE TABLE observation (
  id        INTEGER PRIMARY KEY,
  ioc       TEXT NOT NULL REFERENCES ioc(value),
  ts        TEXT NOT NULL,
  origin    TEXT NOT NULL,       -- honeypot | news | feed
  sensor    TEXT,                -- vm1-cowrie | vm1-web | vm2-services | <feed> | <medio>
  service   TEXT,                -- ssh | web | redis | docker | ...
  action    TEXT,                -- comando/URI/técnica, recortado
  payload_sha256 TEXT REFERENCES payload(sha256)
);

-- El cache de enriquecimiento: el corazón del ahorro de cuota.
CREATE TABLE enrichment (
  ioc        TEXT NOT NULL,
  source     TEXT NOT NULL,      -- greynoise | abuseipdb | virustotal | otx | ipsum | ...
  verdict    TEXT,               -- etiqueta corta
  detail     TEXT,               -- JSON crudo de la respuesta
  fetched_at TEXT NOT NULL,
  expires_at TEXT,               -- NULL = no expira (p.ej. familia de un hash)
  PRIMARY KEY (ioc, source)
);

-- Corpus de payloads, content-addressed. Refleja payloads/ en disco.
CREATE TABLE payload (
  sha256     TEXT PRIMARY KEY,
  size       INTEGER,
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  times_seen INTEGER NOT NULL DEFAULT 1,
  family     TEXT,               -- de MalwareBazaar, si se conoce
  yara_hits  TEXT                -- CSV de reglas que matchearon
);

-- Metadatos del esquema (versionado de migraciones).
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
```

**La columna que cambia todo es `days_seen`.** Es lo que permite decir *"esta IP volvió 5 de los
últimos 14 días"*, que es la diferencia entre escaneo de fondo y alguien que insiste.

**Retención:** `observation` se poda a 180 días; `ioc`, `payload` y `enrichment` son permanentes
(son chicos). Estimación: ~100 bytes/observación ⇒ 50k observaciones/mes ≈ 5 MB/mes. Con 3.2 G
libres hay margen de años, pero la poda evita que el índice se degrade.

---

## 5. El triage: cómo se gasta el presupuesto de consultas

Esta es la pieza central y la razón de ser del rework. Una corrida procesa las IPs del honeypot en
cascada, **de lo barato a lo caro**, y cada filtro descarta trabajo para el siguiente:

```
IPs del honeypot en la ventana          (puede ser de 5 a miles)
  │
  ├─ 0. ALLOWLIST            → descartar      IPs propias, escáneres conocidos (coste 0)
  ├─ 1. CACHE del store      → reutilizar     ya enriquecida y sin expirar (coste 0)
  ├─ 2. LISTAS LOCALES       → etiquetar      IPsum + jamesbrine + FireHOL, en memoria (coste 0)
  │       └─ ¿aparece? → "ruido conocido, N listas". NO se consulta API. Fin.
  │
  └─ 3. RESIDUO: las que no están en ninguna lista        ← el subconjunto interesante
          │
          ├─ priorizar por interés (hits, payload enviado, visto por >1 sensor, reincidente)
          ├─ tomar top-K según presupuesto disponible
          └─ GreyNoise → si noise=false ⇒ SEÑAL FUERTE: "no escanea internet, puede ser dirigido"
                  └─ solo esas escalan a AbuseIPDB / OTX / VirusTotal
```

Dos ideas que hay que tener claras al implementar esto:

**Un acierto en blocklist NO es una señal interesante — es la definición de ruido.** Que una IP esté
en IPsum significa que atacó a mucha otra gente. Confirma que sos uno más en la lista. Por eso el
paso 2 **termina** el procesamiento en vez de escalarlo: ya sabés lo que necesitás saber, y gratis.

**Lo valioso de GreyNoise es el resultado negativo.** Si una IP te pegó y GreyNoise no la ve
escanear internet, eso es lo único disponible que se parece a "esto podría ir dirigido a mí".
Ninguna blocklist puede dar esa señal porque solo contienen positivos.

### Presupuesto declarativo

En `config.py`, explícito y auditable — no números mágicos repartidos por el código:

```python
QUOTAS = {                      # consultas máximas por ventana
    "greynoise":  {"limit": 20, "window": "week"},   # medido: 25/sem sin key. Margen de 5
    "virustotal": {"limit": 400, "window": "day"},
    "abuseipdb":  {"limit": 800, "window": "day"},
    "otx":        {"limit": 500, "window": "day"},
}
```

El consumo se contabiliza **en el store** (tabla `enrichment` por `fetched_at`), así que el
presupuesto sobrevive a reinicios y es real, no una variable en memoria.

### TTL del cache por fuente

| Fuente | TTL | Por qué |
|---|---|---|
| GreyNoise | 7 días | Coincide con su ventana de cuota y su lookback |
| AbuseIPDB / OTX / VirusTotal | 30 días | La reputación de una IP no cambia en horas |
| Listas locales (IPsum, jamesbrine, FireHOL) | 12 h | Se redescargan enteras; no son consultas por IOC |
| MalwareBazaar por hash | **nunca expira** | Un SHA-256 no cambia de familia |

---

## 6. Las fases

Cada fase es **autocontenida, entregable y reversible**. El orden respeta las dependencias reales:
sin higiene, todo lo demás estudia basura; sin store, no hay memoria; sin memoria, el triage no
puede priorizar por reincidencia.

---

### F-A · Higiene de la entrada — *prerrequisito de todo*

**Problema concreto:** la primera corrida del colector reportó como atacante al **laptop del propio
usuario**. Y cuando los honeypots se expongan, Shodan, Censys, Shadowserver, ONYPHE
y los crawlers académicos van a ser una fracción enorme del tráfico.

**Sin esto, todas las fases siguientes destilan ruido con cariño.**

- Allowlist en `tools/pull_honeypot.sh` (o mejor: en un módulo Python, ver F-B) con dos categorías
  separadas, porque significan cosas distintas:
  - **IPs propias** — se descartan, no son dato.
  - **Escáneres legítimos** — se **etiquetan**, no se descartan: saber que Shadowserver te escanea
    es información válida, pero no es un ataque.
- La lista vive en configuración, no hardcodeada, y las IPs propias se resuelven en tiempo de
  ejecución (son dinámicas: la pública de casa y la del laptop; los valores viven en `OWN_IPS`,
  en el entorno, porque el repo es público).

**Hecho cuando:** una corrida del pull sobre datos con la IP del laptop la excluye, y un test lo
verifica con un fixture.

---

### F-B · El store: fundación sin cambiar comportamiento

Introducir `separatio/store/` sin que **nada** del pipeline cambie de conducta todavía. Es la fase
de menor riesgo y la que habilita el resto.

- `store/schema.sql` — el DDL de §4, con `PRAGMA journal_mode=WAL`.
- `store/db.py` — apertura, migraciones por número de versión en `meta`, context manager.
- `store/models.py` — funciones de acceso (`upsert_ioc`, `add_observation`, `get_cached`,
  `put_cached`, `quota_used`). **Nada de ORM**: son consultas parametrizadas, es más simple y no
  agrega dependencias.
- **Ingesta idempotente** del honeypot: leer `by-date/*/events.jsonl` y `hashes.log` y volcarlos al
  store. Correr dos veces la misma fecha no debe duplicar (clave natural: `ts + ioc + action`).
- Backfill de lo que ya hay en disco.

**Buenas prácticas obligatorias en esta fase**, porque marcan el estándar del resto:
- El store se abre con una ruta de `config.py` (absoluta, como ya hace el resto).
- Si el fichero no se puede abrir, el pipeline **loguea y sigue** — nunca aborta.
- Tests con `:memory:` — rápidos y sin tocar disco.

**Hecho cuando:** `pytest` pasa con tests nuevos del store; ingerir dos veces el mismo día deja el
mismo número de filas; y `separatio --dry-run` sigue funcionando igual que antes.

---

### F-C · El enricher inverso — *la pieza que responde la pregunta de estudio*

Un enricher nuevo, `enrichers/honeypot_recon.py`, que implementa el triage de §5. **No es una
capacidad nueva**: la cascada de `ipcheck` ya sabe consultar GreyNoise → AbuseIPDB → VT → OTX. Lo
que falta es invocarla con las IPs del honeypot en vez de con los IOCs de las noticias.

- Se registra en `build_enrichers()` con toggle propio, siguiendo el patrón que ya existe.
- Lee las IPs del store (F-B), aplica allowlist (F-A), consulta cache, cruza listas locales, y solo
  entonces gasta cuota en el residuo.
- Escribe los veredictos **de vuelta al cache** del store.
- Emite dos cosas al informe: la nota de contexto y —lo importante— un `IocVerdict` de **señal
  fuerte** cuando una IP no está en ninguna lista y GreyNoise no la ve como ruido.

> **Ojo con la dirección del cruce.** El enricher `honeypot.py` actual hace lo inverso (IOC de
> noticia → ¿me pegó?) y **se conserva**: son dos preguntas distintas y ambas valen. No refactorizar
> uno dentro del otro.

**Hecho cuando:** con datos reales del honeypot, el log muestra el desglose del triage (cuántas
descartadas por allowlist, cuántas por cache, cuántas por listas locales, cuántas consultadas) y el
consumo de cuota registrado en el store coincide con las consultas hechas.

---

### F-D · Memoria temporal: reincidencia

Con el store poblado, esto es casi gratis y es lo que convierte datos en conocimiento.

- Actualizar `days_seen` en cada ingesta.
- Extender el enricher para emitir: *"IP reincidente: 5 de los últimos 14 días"*, *"payload ya
  conocido desde el 2026-07-02, visto 4 veces"*, *"HASSH ya visto desde otra IP"*.
- **El HASSH es la joya escondida acá**: es el fingerprint del cliente SSH, robusto al cambio de IP.
  Ya se extrae y se guarda, pero nadie lo correlaciona. Un mismo HASSH desde 40 IPs distintas es la
  huella de una botnet, y eso **ninguna blocklist te lo dice**.

**Hecho cuando:** el informe cita al menos una reincidencia real y el dato se puede verificar a mano
con una consulta SQL.

---

### F-E · Listas locales nuevas (baratas, sin cuota)

Solo lo que aporta señal distinta, con la evidencia de `CAPAS-Y-FUENTES.md`:

| Fuente | Rol |
|---|---|
| `jamesbrine.com.au/iplist.txt` | 1,06 M IPs de honeypots reales — el feed que más se parece a nuestro sensor |
| IPsum `levels/3.txt` | **ya integrado** — cada línea trae en cuántas listas aparece: confianza gratis |
| FireHOL `tor_exits.ipset` | Señal **distinta**: anonimización, no reputación |
| FireHOL `firehol_level1.netset` | Señal de **infraestructura** (bogons, secuestros), no de conducta |

Descargar una vez por corrida, cachear en disco con TTL de 12 h, cruzar en memoria (un `set` de un
millón de IPs son ~50 MB — cabe, pero **hay que medirlo** contra los 490 MiB del CT; si aprieta, usar
una tabla del store con índice en vez de un set).

**Hecho cuando:** el cruce corre dentro del presupuesto de RAM del CT, verificado con `systemd-run
--scope -p MemoryMax=`.

---

### F-F · YARA sobre el corpus

Ya estaba en el punto-5 pendiente. Ahora tiene dónde guardar el resultado (`payload.yara_hits`).

- `yara-python` como dependencia **opcional** (extra `[yara]`), para no romper el despliegue si el
  binario no está.
- Reglas propias en `rules/`, más un set público curado.
- Correr solo sobre payloads **nuevos** (el store sabe cuáles).

**Prerrequisito real:** corpus con volumen. Hoy hay **1 payload de 2 bytes**, de un test. Esta fase
no arranca hasta que los honeypots estén expuestos y haya material.

---

### F-G · Deuda técnica de `IMPROVEMENTS.md` §6

No inventar trabajo nuevo: el roadmap de junio sigue vigente y ahora hay más razones para atenderlo.
En particular **§6.3 modularizar `pipeline.py`** (855 líneas) y **§6.4 configuración inyectable** —
los dos se vuelven más urgentes al sumar el store, porque `config.py` como módulo global dificulta
los tests.

---

## 7. Decisiones de fuentes — con la evidencia

Verificado por HTTP directo el **2026-08-09**. Esto responde las preguntas abiertas:

| Fuente | Veredicto | Evidencia medida |
|---|---|---|
| **Feodo Tracker** | ❌ **NO integrar** | `ipblocklist.json` tiene **5 entradas** en total (Emotet, QakBot). `ipblocklist_recommended.txt`: **0 líneas útiles**. Está prácticamente vacío |
| **SSLBL — lista de IPs** | ❌ **NO integrar** | `sslipblacklist.csv`: **1 línea útil**. Vacío |
| **SSLBL — fingerprints** | ❌ No aplica | `sslblacklist.csv` sí tiene 10.355 entradas, pero son **SHA-1 de certificados TLS**. Requiere inspeccionar el certificado de una conexión: ni Cowrie ni Beelzebub lo hacen |
| **AlienVault OTX** | ✅ **Ya integrado** | `ipcheck` consulta `/api/v1/indicators/IPv4/{ip}/general` con `OTX_API_KEY` y lee `pulse_info`. Funciona |
| **Pulsedive** | ❌ **Quitar la key** | Sin feed bulk gratis; ToS prohíben automatización *y* redistribución. `PULSEDIVE_API_KEY` está en el `.env` y **ningún código la usa** |

> **Aclaración importante:** *Pulsedive* y *AlienVault OTX* son **dos servicios distintos**. OTX es
> el de AlienVault (hoy LevelBlue), ya integrado y con valor real por sus *pulses*. Pulsedive es
> otra empresa, y es el que hay que descartar. Se confundieron en una conversación previa.

**Mejora pendiente sobre OTX que sí vale:** hoy solo se consulta **por IP**. OTX además permite
**suscribirse a pulses** (colecciones temáticas de IOCs mantenidas por la comunidad), que es una
fuente de feed completa y gratuita que no se está aprovechando. Candidato natural a enricher nuevo
después de F-E.

---

## 8. Buenas prácticas transversales (aplican a todas las fases)

Estas no son decoración: son lo que evita que el rework se convierta en la próxima deuda.

1. **El pipeline nunca se rompe por una fase nueva.** Todo componente nuevo va envuelto en
   try/except a nivel de etapa, como ya hace `run_enrichment()`. El informe diario está en
   producción.
2. **Toggle por fase.** Cada capacidad nueva entra apagada en `config.ENRICHERS` y se prende cuando
   está verificada. Es el patrón que ya usa el proyecto y funciona.
3. **Sin dependencias nuevas salvo justificación explícita.** SQLite es stdlib. YARA va como extra
   opcional. Cada `pip install` es superficie de ataque y peso en un CT de 512 MiB.
4. **Tests con el patrón que ya existe** (`tests/test_*.py`, hoy 5 archivos). Todo módulo nuevo
   llega con tests; el store se testea en `:memory:`.
5. **Idempotencia en todo lo que corre por timer.** El pull va cada 6 h: reingerir el mismo día no
   puede duplicar filas ni gastar cuota de nuevo.
6. **Nada de números mágicos.** Cuotas, TTLs y umbrales viven en `config.py`, en un solo lugar.
7. **El honeypot sigue sin saber nada de casa.** Ninguna fase introduce credenciales, push desde el
   sensor, ni conexiones salientes desde las VMs.
8. **Los payloads no se ejecutan nunca.** El corpus es cuarentena: se hashea, se analiza estáticamente
   con YARA, y nada más.
9. **Documentar contra la máquina.** Cada fase cerrada actualiza su as-built con la salida real de
   los comandos de verificación, no con lo que se esperaba.

---

## 9. Lo que este plan NO hace (y por qué)

- **No monta un SIEM de verdad** (Wazuh, Elastic). No entra en el hardware y el objetivo es estudio,
  no operación 24/7. `LABS-PLAN.md` ya lo evaluó.
- **No contribuye a plataformas públicas.** Decisión del 2026-08-08: los honeypots son para estudio
  personal. Ver `Motherbase/honeypot/CONTRIBUIR.md`.
- **No agrega más blocklists agregadas.** Se midió: IPsum L3 está **98 % contenido** en AbuseIPDB,
  CINS **89 %** en IPsum. Rendimiento decreciente.
- **No reemplaza `history.json`.** El trending de actores y CVEs de las noticias funciona bien. El
  store es para el dato propio; convivir es más barato que migrar.
- **No toca la exposición de los honeypots.** Sigue bloqueada por la AUP de Oracle, y es
  independiente de este plan — salvo que **F-F depende** de que haya tráfico real.

---

## 10. Orden de ejecución y dependencias

```
F-A (higiene) ──┬─→ F-B (store) ──┬─→ F-C (enricher inverso) ──→ F-D (reincidencia)
                │                 │
                │                 └─→ F-E (listas locales)
                │
                └─────────────────────→ F-F (YARA)   [+ requiere corpus real]

F-G (deuda técnica) — en paralelo, cuando moleste
```

**Por dónde empezar: F-A.** Es chica, no depende de nada, y sin ella todo lo demás estudia la IP del
propio laptop. Después F-B, que es la fundación y la de menor riesgo.

**Criterio de cierre del rework:** una corrida diaria que, con los honeypots expuestos, procese
las IPs del día, gaste menos de 5 consultas de GreyNoise, y produzca en el informe al menos una
afirmación del tipo *"esta IP volvió N días, no está en ninguna blocklist, y GreyNoise no la ve
escanear internet"*. Ese enunciado es, literalmente, lo sutil separado de lo burdo.
