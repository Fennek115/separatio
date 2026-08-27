# Central de inteligencia — capas, fuentes y dónde encaja cada cosa

Escrito el 2026-08-07 a partir de conversaciones del usuario sobre arquitectura de intel y edge
computing. **Es un documento de diseño/visión**, no de estado.
Alimenta la sesión de *rediseño de `~/Projects/Intel/`* que ya está pendiente (ver `CLAUDE.md`).

> ## ⚠️ Verificación contra el código (2026-08-08) — gana la máquina
>
> Se revisó el repo y **este documento subestimaba lo que ya está implementado**. Correcciones:
>
> - **GreyNoise ya está integrado** — `ipcheck/ip_enricher.py` lo consulta en `check_greynoise()`
>   contra `https://api.greynoise.io/v3/community/{ip}`, endpoint **público sin API key**, en el
>   **Nivel 1** de la cascada.
>   > ⚠️ **Pero la nota original sobre Proton era correcta en el fondo, y peor de lo que parecía.**
>   > Medido el 2026-08-09: sin API key la cuota real es **25 consultas por semana** (cabecera
>   > `x-ratelimit-limit: 25`, ventana de 7 días — **no** las "10 por día" que dice la doc), y
>   > **los 404 también consumen cuota**. Y la doc de GreyNoise nombra a ProtonMail **literalmente**:
>   > *"Accounts created with free email accounts like Hotmail, Gmail, ProtonMail, iCloud, etc., do
>   > not have API key-level access."* No te bloquean el alta: te dan cuenta sin API key. Con el
>   > correo del usuario, registrarse **no sirve de nada**.
>   > **Consecuencia de diseño:** GreyNoise no se puede usar para enriquecer cientos de IPs de
>   > honeypot. Hay que reservarlo para el **residuo** (§ recomendación abajo).
> - **abuse.ch está más cubierto de lo que dice la tabla.** `ipcheck` ya consulta **URLhaus**
>   (`urlhaus-api.abuse.ch/v1/host/`) y **ThreatFox** (`threatfox-api.abuse.ch/api/v1/`), y desde
>   el 2026-08-08 hay además un enricher **MalwareBazaar** propio (`enrichers/malwarebazaar.py`,
>   ON). Falta solo Feodo Tracker y SSLBL.
> - **Fuentes ya integradas:** ip-api, GreyNoise, Shodan InternetDB, AbuseIPDB, VirusTotal, OTX,
>   URLhaus y ThreatFox (las 8 de `ipcheck`), más IPsum, OpenPhish, Ransomware.live, onion-lookup,
>   MalwareBazaar y el honeypot propio como enrichers.
> - **La capa 4 ya no es "por construir":** el colector pull está operativo y automatizado en el
>   CT 113 desde el 2026-08-08 (ver `Motherbase/honeypot/COLECTOR-CT113.md`).
>
> ### El gap real que esto destapa
>
> **Los enrichers solo se aplican a los IOCs extraídos de las NOTICIAS.** En
> `enrichment.run_enrichment()` se hace `iocs = collect_iocs(summaries)`: el universo a enriquecer
> son los indicadores que aparecen en los artículos del día. Las IPs que atacan tu honeypot
> **nunca pasan por esa cascada** — salvo que casualmente salgan en una noticia.
>
> El cruce existente va en una sola dirección: *"¿esta IP de la que hablan los feeds además me
> pegó?"*. Falta la inversa, que es justamente la pregunta de estudio: *"esta IP me pegó, ¿es
> actor conocido o ruido de internet?"*. La cascada de `ipcheck` (GreyNoise → decidir nivel →
> AbuseIPDB/VT/OTX) **ya sabe responder eso**; simplemente nadie la invoca con las IPs del
> honeypot. Es un enricher nuevo, no una capacidad nueva.

---

## Verificación de los feeds candidatos (2026-08-08, por HTTP directo)

No se creyó a la awesome-list: se pidió cada feed y se miró el contenido.

| Feed | Estado | Frescura medida | Volumen | Veredicto |
|---|---|---|---|---|
| **jamesbrine `iplist.txt`** | ✅ 200 | `Last-Modified` **2 h antes** (declara cada 30 min) | **1.063.680 IPv4**, 0 líneas malformadas | ✅ **El mejor del lote.** Es *el* feed a usar |
| **jamesbrine `/csv`** | ✅ 200 | ventana móvil 7 d, hasta 2026-08-06 | 10 MB, 221.564 filas | ⚠️ **Usar `iplist.txt` en su lugar** — ver defectos abajo |
| **jamesbrine STIX2** | ✅ 200 **con UA de navegador** | bundle del 2026-08-06 | 11.099 objetos (5.450 indicadores) | ✅ Lo más rico gratis: sensor, protocolo, kill-chain, CVE |
| **FireHOL** | ✅ 200 | último commit **2026-08-08**; `firehol_level2` declara *update 1 min* | level1 3.891 subnets · abuseipdb_30d 105.027 · blocklist_de_ssh 4.891 · tor_exits 1.415 | ✅ Solo 2 ficheros — el resto es redundante |
| **IPsum** | ✅ 200 | último commit **2026-08-09** | L1 113.228 → L3 16.782 → L5 1.947 | ✅ **Ya integrado.** Cada línea trae en cuántas listas aparece |
| **CINS `ci-badguys.txt`** | ✅ 200 | `Last-Modified` de hoy | **exactamente 15.000** (cap duro desde 2017) | ❌ 89 % ya contenido en IPsum |
| **DigitalSide** | ❌ **sitio no responde** (timeout HTTP y HTTPS) | repo: **último commit 2024-10-18** | congelado | ❌ **Muerto hace ~22 meses** |
| **Pulsedive** | ✅ vivo | — | sin bulk gratis | ❌ ToS prohíben automatización *y* redistribución |
| **GreyNoise community** | ✅ sin API key | — | **25 consultas/semana** | ⚠️ Ya integrado, pero cuota ínfima — ver arriba |

### Defectos reales del `/csv` de jamesbrine (medidos, no documentados en ningún lado)

1. **Es acumulativo, no incremental.** De las 32.597 IPs del 2026-08-05, **32.596 se repiten** al día
   siguiente: solo **241 son nuevas**. Leerlo como "32k IPs nuevas por día" es un error de lectura.
2. **~3,5 % de las filas están corruptas** (7.854 de 221.564) por saltos de línea perdidos:
   `103101.66.10.237`, `1031.10.144.169`. Se verificó que el fichero coincide byte a byte con el
   `Content-Length`, así que **la corrupción viene del feed**, no del transporte.
3. Un solo valor en `activity`: `brute force host`.

### Sub-feeds de jamesbrine: separar vivos de muertos

Vivos: `iplist.txt` (2026-08-08), `/protocols/` (2026-08-08), Tor exits en `/anonproxies/`
(2026-08-08), `/phishing/` (2026-08-07). Rezagado: proxies anónimos (2026-07-29).
**Muerto: `/forumspam/` — última actualización 2024-08-16.**

> ⚠️ **Dos trampas de automatización:** el JSON de STIX2 devuelve **403 con el User-Agent por
> defecto** de curl (con UA de navegador da 200). Y la API de GitHub reporta commits viejos para
> FireHOL aunque el contenido esté fresco — mirar el `Source File Date` de la cabecera del
> `.netset`, no la fecha del commit.

### Licencias

- **jamesbrine:** TLP:White, *"free to use in any form for non-commercial purposes"* — **encaja
  exacto** con el uso de estudio personal.
- **FireHOL: no hay licencia.** El repo **no tiene fichero `LICENSE`**; cada ipset hereda la de su
  fuente original, y algunas son restrictivas. No tratarlo como un bloque.
- **CINS:** no hay términos formales. No prohíbe nada — permisivo por omisión, no por licencia.
- **Pulsedive:** la más restrictiva. Prohíbe robots/automatización y redistribución.

---

## La conclusión que ordena todo: las blocklists agregadas son casi el mismo fichero

Solapamientos medidos el 2026-08-09:

| Cruce | Solapamiento |
|---|---|
| **IPsum L3 ∩ AbuseIPDB 30d** | **98,0 %** |
| CINS ∩ IPsum L1 | 89,1 % |
| IPsum L3 ∩ jamesbrine | 79,5 % |
| AbuseIPDB 30d ∩ jamesbrine | 47,1 % |

**Sumar una cuarta blocklist agregada no aporta casi nada**: todas responden la misma pregunta,
*"¿alguien más reportó esta IP?"*.

Y el punto conceptual que cambia el diseño: **un acierto en blocklist no distingue "actor conocido"
de "ruido" — es la definición misma de ruido.** Que una IP esté en IPsum significa que atacó a
mucha otra gente: confirma que sos *uno más* en la lista.

**Lo valioso de GreyNoise es el resultado NEGATIVO.** Si una IP te pegó y GreyNoise devuelve 404 o
`noise: false`, no está escaneando internet masivamente — y eso es lo único que se parece a "esto
podría ir dirigido a mí". Ninguna blocklist puede dar esa señal, porque solo tienen positivos.

**Caso concreto que lo demuestra** (`1.14.206.78`, del STIX de jamesbrine del 2026-08-06): ausente
de IPsum L1/L3, CINS, AbuseIPDB 30d y blocklist_de_ssh — las cinco. GreyNoise la clasifica
`malicious`, `noise: true`, vista el 2026-08-08.

### Arquitectura recomendada (forzada por la cuota de 25/semana)

1. **Base local:** `jamesbrine.com.au/iplist.txt` — 1,06 M IPs, sin key, TLP:White no comercial,
   cada 30 min. Y es el feed que **más se parece a nuestro sensor**: SSH/Telnet/portscan de
   honeypots reales, no reportes de terceros.
2. **Score de confianza:** IPsum `levels/3.txt` — ya integrado; cada línea trae el número de listas
   en que aparece, o sea confianza incorporada y gratis.
3. **Solo dos ficheros de FireHOL**, los no redundantes: `tor_exits.ipset` (anonimización) y
   `firehol_level1.netset` (bogons/secuestros: señal de *infraestructura*, no de conducta).
4. **GreyNoise para el residuo:** reservar las ~25 consultas semanales para las IPs que pegaron y
   **no** están en ninguna lista local. Ese subconjunto es chico y es el interesante.
5. **Descartar:** DigitalSide (muerto), CINS (89 % redundante y capado), Pulsedive (sin bulk gratis
   y ToS restrictivos).

> **Advertencia honesta:** ninguna fuente gratuita va a decir "esto es APT-X". En el tier gratis,
> *"actor conocido"* significa realistamente *"escáner masivo conocido"* o *"abusador ya reportado"*.
> La atribución a un actor no está disponible gratis en ninguna de las seis.

### Feodo Tracker y SSLBL — medidos el 2026-08-09: **NO integrar**

Eran el "falta solo…" de abuse.ch. Se pidieron y están vacíos:

| Fichero | Entradas útiles |
|---|---|
| `feodotracker.abuse.ch/downloads/ipblocklist.json` | **5** (Emotet, QakBot) |
| `feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt` | **0** |
| `sslbl.abuse.ch/blacklist/sslipblacklist.csv` | **1** |
| `sslbl.abuse.ch/blacklist/sslblacklist.csv` | 10.355 — pero son **SHA-1 de certificados TLS** |

Los dos primeros no tienen volumen. El de fingerprints sí, pero requiere inspeccionar el
certificado de una conexión TLS, y **ni Cowrie ni Beelzebub lo hacen**. Con esto, la cobertura de
abuse.ch queda **cerrada**: lo que faltaba no valía la pena.

### El plan de ejecución

Todo lo de arriba se convierte en fases concretas en **[`PLAN-REWORK.md`](PLAN-REWORK.md)**, que es
el documento activo. Este archivo es el inventario de fuentes; aquel es qué hacer con ellas.

### No verificado

- La cadencia de 30 min de `iplist.txt` (se observó un solo `Last-Modified`, no se muestreó).
- Si GreyNoise **rechaza el alta** con Proton o solo niega la API key — la doc solo afirma lo segundo.
- Límites de la cuenta gratis registrada de Pulsedive (50/día, 500/mes): de su página de precios,
  no medidos.
- Si `osint.digitalside.it` está caído de forma permanente o transitoria.
- **`PULSEDIVE_API_KEY` está en el `.env` pero ningún código del repo la usa** — declarada y sin
  consumir. Con los ToS verificados, conviene **quitarla**.

> **Regla heredada:** verificar contra la máquina, no contra el documento. Y una específica de acá:
> **Separatio ya es el cerebro CTI** — no se construye una plataforma nueva. Las fuentes nuevas entran
> como *enrichers* del pipeline existente, salvo que haya una razón fuerte para lo contrario.
> (Decidido en `Motherbase/INTEL-ARQUITECTURA.md` §2: "Separatio ya tiene el 80%".)

---

## El modelo de 4 capas

La idea central que ordena todo: **no mezclar noticias con IOCs, ni montar plataformas pesadas;
consumir APIs livianas cuando hacen falta.** Cuatro capas con roles distintos:

| Capa | Qué es | Cómo entra | Dónde vive |
|---|---|---|---|
| **1. Noticias / análisis** | Blogs, medios, reportes APT en prosa | RSS → Miniflux (CT 112) → Separatio Stage 1–4 | Ya funciona |
| **2. IOCs accionables** | Indicadores crudos (IPs, hashes, URLs maliciosas) para **cruzar**, no para leer | Enrichers de Separatio (Stage 2.7) + correlación | Parcial (IPsum/OpenPhish ya) |
| **3. Enriquecimiento bajo demanda** | Scoring/contexto puntual sobre un IOC o campaña | API/SDK llamada desde el pipeline cuando la necesita | Por construir |
| **4. Dato propio** | Lo que ataca a *tu* infra (honeypot) | Pull SSH desde casa → enricher | **Construido 2026-08-08** (honeypot en Oracle VM1; `enrichers/honeypot.py` + `tools/pull_honeypot.sh`). Toggle `honeypot` OFF hasta que el pull traiga dato real — ver `Motherbase/honeypot/DEPLOY.md` |

**La sinergia real:** Miniflux dice *qué está pasando*; los feeds de IOC dan *indicadores para cruzar*;
el enriquecimiento agrega *contexto*; el honeypot valida *qué de todo eso te toca a vos*.

---

## Fuentes nuevas, mapeadas a dónde encajan en Separatio

Separatio ya tiene el modelo de extensión perfecto para esto (de su `CLAUDE.md`):
> *"Add a source = new `enrichers/*.py` subclass + register in `build_enrichers()` + toggle in
> `config.ENRICHERS`. No pipeline/analyzer edits."*

Así que casi todo esto son **enrichers nuevos**, no una arquitectura nueva.

### Capa 2 — IOCs accionables (nuevos enrichers de Stage 2.7)

| Fuente | Qué aporta | API key | Cómo entra |
|---|---|---|---|
| **abuse.ch completo** (URLhaus, ThreatFox, MalwareBazaar, Feodo, SSLBL) | La columna vertebral de IOCs. `ipcheck` ya toca URLhaus/ThreatFox — falta el resto | Auth-key gratis (2024+) | Enricher(s) nuevos, o extender `ipcheck` |
| **IPsum** | 30+ blocklists de IP en un `.txt` con score de ocurrencias | No | **Ya está** (`IpsumEnricher`) |
| **FireHOL IP Lists** | 400+ feeds curados con histórico | No | Enricher nuevo (mismo patrón que IPsum) |
| **DigitalSide (osint.digitalside.it)** | Sale en STIX2/CSV/MISP | No | Enricher nuevo |
| **jamesbrine.com.au** (referefref) | **Feed de honeypots internacionales**, CSV+STIX2 diario. Cruzar "¿las IPs que me pegan a mí también le pegan a su red global?" | No | Enricher nuevo — **alto valor**, es dato de sensor real |
| **ANCI / CSIRT Nacional de Chile** (`csirt.gob.cl/api/v1/`) | La única fuente **estructurada** de intel local: IOCs tipados y CVEs con CVSS+EPSS ya calculados, emitidos por el CSIRT nacional | No (ni registro) | **Ya está** (`AnciEnricher` + `anci_client.py`, 2026-08-19) — ver la medición abajo |

### ANCI / CSIRT Chile — medido por HTTP el 2026-08-19

API pública, **sin API key y sin registro**, licencia **CC BY-SA 4.0** (atribución obligatoria;
la pone el `name` del enricher, y el bloque de notas del prompt pide citar la fuente).
Cinco endpoints: `alerts`, `news`, `documents`, `events`, `galleries` — el cliente cubre los cinco,
el informe usa tres.

| Qué | Medido |
|---|---|
| Alertas | **978** históricas · **189 en 2026** (~0,8/día) · 79 en los últimos 90 días |
| IOCs | **604 en 2026** · 204 en los últimos 90 días (url 78, ipv4 51, mitre-attck 39, sha256 15…) |
| CVEs | **1.235** en los últimos 90 días, con CVSS y EPSS ya calculados por ellos |
| Tipos de alerta | Campaña Fraudulenta 66 · Vulnerabilidad Crítica 12 · Investigación de Amenazas 1 (90 d) |
| Coste por corrida | **1 petición** el caso normal (caché en disco: alertas 6 h, noticias 24 h, documentos 7 d) |

**Las seis trampas, todas medidas** (varias contradicen la documentación del propio endpoint):

1. **`/alerts/` NO viene en orden de publicación**, aunque su `description` lo afirme: viene por
   `latest_revision_created_at` desc (1049 pares invertidos respecto de `date` en la página 1
   real, 0 respecto de la revisión). El cliente **pagina por revisión y filtra por publicación**.
2. **`from_date`/`to_date` filtran por revisión**, no por publicación → no se usan.
3. **`/news/` no viene ordenado**: la noticia más nueva estaba en la **página 3 de 3**. Hay que
   paginar entero y ordenar en local.
4. **`/documents/` no trae fecha.** Dos categorías reales: `boletines/ediciones-anteriores` (256)
   y `documentos/informes-historicos` (44). "Qué es nuevo" se resuelve por diff contra el snapshot
   de la corrida anterior; la primera corrida sólo fija la línea base.
5. **Rate limit no documentado, detrás de Cloudflare**: responde `429` o un cuerpo de texto plano
   `error code: 1015` que **no es JSON**. Saltó encadenando alertas + noticias + documentos con
   0,5 s entre peticiones. De ahí el throttle de cliente (2 s **entre peticiones**, no entre
   páginas) y la caché con fail-open a copia vencida.
6. `page_size` topea en **100 en silencio** (pedir 200 devuelve 100, sin error).

**Y la trampa del dato, que es la más importante para quien lo consuma:** las IPs de ANCI son las
del **alojamiento** del sitio fraudulento, no las del atacante — **17 de las 42 IPs del volcado real
son direcciones de borde de Cloudflare** (40 %). `data/feeds/anci-ips.txt` **no es una blocklist
para meter en un firewall**; el enricher, cuando una IP cruza, emite además una nota de cautela
para que el modelo no lea "figura en una alerta" como "es maliciosa". Las URLs y los hashes sí son
del atacante.

Lo que **no** se hizo, y por qué: **cruzar el host de las URLs**. En el corpus real hay campañas
cuyo IOC es un redirector abusado (`https://www.google.com/share.google?q=…`, ACF26-01147) o un
hosting compartido (`*.cpanel.site`); indexar el host emitiría "google.com aparece en una alerta
del CSIRT". El cruce va por **valor exacto**: acierta poco, pero no miente.

**No publican RSS** (verificado: `/rss/` y `/feed/` dan 404 y el HTML no declara
`<link rel=alternate>`), así que la API es la única vía y no hay feed que dar de alta en Miniflux.

### Capa 3 — Enriquecimiento bajo demanda (no son feeds; se consultan puntualmente)

| Fuente | Qué aporta | Cómo entra |
|---|---|---|
| **GreyNoise Community** | Distingue "ruido de internet" (scanners masivos) de algo dirigido. Clave contra falsos positivos del honeypot | ⚠️ **Sin clave**: GreyNoise no emite keys a correos Proton (bloqueado). Necesita otro correo o queda fuera |
| **Pulsedive** | Scoring comunitario de riesgo sobre feeds OSINT | Feed/API — enricher o consulta on-demand |
| **WorldMonitor CII** (worldmonitor.app) | Country Instability Index geopolítico. Correlacionar: pico de ataques desde un país que escala en el CII = contexto de campaña | SDK Python / MCP público. **No self-hostear el dashboard** (pesa 10x, WebGL, no entra en el ThinkPad) — solo consumir el SDK |

### El puente que falta — extracción de IOCs de reportes (OCR de imágenes)

El gap real: muchos blogs de threat intel meten los IOCs en **capturas de pantalla**, que el parser
de texto de Separatio **no ve hoy**. **AIOCRIOC** (referefref, `github.com/referefref/aiocrioc`,
Apache-2.0) resuelve eso con OCR + LLM.

**Decisión tras leer su fuente (2026-08-07): reimplementar la idea, NO vendorizar la herramienta.**

- AIOCRIOC es un script CLI de ~1 archivo (`extract.py`), **atado a OpenAI** (`gpt-4-turbo-preview`,
  SDK `openai`), sin frontera de función reutilizable (toma una URL, escribe a disco, imprime). Su
  mitad de LLM se descartaría igual porque Separatio usa Claude.
- Lo único genuinamente reutilizable son ~15 líneas: **sacar los `<img>` del HTML del artículo →
  OCR con Tesseract (`pytesseract`) → concatenar ese texto al prompt de extracción que Separatio
  YA corre con Claude.** No hace falta una segunda llamada LLM por imagen (la ventana de contexto de
  Claude lo cubre), ni un segundo proveedor, ni una dependencia nueva más allá de `pytesseract` +
  el binario `tesseract` + `Pillow`.
- **Cómo entra:** enricher/etapa nueva en Stage 1–2 (antes de la extracción), no en Stage 2.7.
  Maneja tanto `<img>` remotas como `data:` base64 (igual que hace `download_images` del original).

Esto es lo de **mejor relación esfuerzo/valor** de todas las fuentes nuevas: gap concreto, ~15 líneas,
cero infra nueva, todo dentro del pipeline Claude existente. **Es por donde arrancar.**

### Lo que NO agregar

- **A Miniflux**: nada de feeds de IOC crudos — ahogarían las noticias. Miniflux es solo capa 1.
- **Plataformas pesadas**: MISP / OpenCTI / Yeti — descartadas en este hardware (ya evaluado). Yeti
  usa ArangoDB que crece en RAM; no hay headroom.
- **WorldMonitor self-hosted**: solo el SDK/MCP bajo demanda.

---

## La pregunta abierta de arquitectura: ¿edge (Cloudflare) o local (Separatio)?

La conversación proponía un "cerebro" en **Cloudflare Worker → D1 → R2** para ingerir los feeds de
IOC. Hay que decidir esto con cuidado, porque **se solapa con lo que Separatio ya hace**:

- **A favor del edge (Worker + D1):** corre siempre, aunque el laptop esté apagado; tira los feeds
  24/7; almacén de IOCs consultable; usa infra gratis y es un buen ejercicio de aprendizaje.
- **En contra / a tener en cuenta:** Separatio **ya ingiere IPsum y correlaciona localmente** (KEV,
  EPSS, actores, IOCs) con Python liviano — el argumento "no cargar el ThinkPad" no aplica tanto
  porque Separatio no es pesado. Duplicar la ingesta en dos lados (edge + local) es complejidad.

**Recomendación para la sesión de rediseño:** decidir *dónde vive el almacén de IOCs* —
- Si Separatio corre en un CT/timer fijo → el almacén local (SQLite, ya existe `history.json`) alcanza
  y el Worker+D1 es redundante.
- El Worker+D1 se justifica sobre todo como **capa 4** (recolector del honeypot siempre-encendido) o
  como **API pública de enriquecimiento**, no como duplicado de la correlación que Separatio ya hace.

No cerrar esto sin resolver primero la reestructuración de `~/Projects/Intel/` (ver `CLAUDE.md`).

### Usos concretos de edge/Workers en este proyecto

Más allá del recolector del honeypot, dónde el free tier de Cloudflare (Workers + Cron + D1 + KV +
R2) aporta de verdad. **Restricción clave:** un Worker **no llega a la LAN privada** sin un túnel
(`cloudflared`) — así que sirve para lo que mira hacia afuera o para cachear/servir, no para tocar
los CTs directamente.

1. **Agregador de feeds siempre-encendido (capa 2).** Un Worker con Cron tira abuse.ch / IPsum /
   FireHOL / jamesbrine cada X horas, dedup/normaliza y deja un único JSON en KV/D1. El pipeline (o
   el laptop) baja **un** blob cacheado en vez de pegarle a 5 APIs, y los feeds siguen frescos aunque
   el laptop esté apagado. Es el mismo patrón que el recolector del honeypot, generalizado.
2. **API/lookup de IOCs + informe, accesible desde el teléfono sin exponer la casa.** D1 guarda los
   IOCs y el briefing diario; el Worker sirve consultas read-only. Desacopla "leer mi intel desde
   afuera" de "abrir puertos en casa". (Con Cloudflare Access adelante para que sea solo tuyo.)
3. **Relay de notificaciones.** Un Worker recibe webhooks (del honeypot, de CrowdSec, de Wazuh) y
   los reenvía a Telegram/email. La lógica de aviso vive afuera, siempre-encendida, sin credenciales
   en la máquina sacrificable.
4. **R2 como offsite de lo crítico.** 10 GB gratis: no entran los 167 G de datos, pero **sí** los
   configs y exports chicos que hoy no tienen copia fuera del equipo (ver el gap de F1). Cifrar antes
   de subir.
5. **Cache de enriquecimiento (capa 3).** Worker Cron refresca KEV/EPSS/GreyNoise-community en KV
   para que el pipeline lea un cache tibio en vez de pegarle en vivo en cada corrida.

### CrowdSec ↔ Separatio — los 3 puntos de integración

Si para el monitoreo se usa **CrowdSec** (plan en `Motherbase/LABS-PLAN.md` §3.5), se integra en tres
lugares distintos, y juntos cierran el círculo *detección → inteligencia → detección*:

1. **CrowdSec → Separatio (capa 4, dato propio).** Un enricher nuevo lee la Local API de CrowdSec y
   trae las IPs que te atacaron/baneó, y las cruza contra los feeds (IPsum, abuse.ch, jamesbrine):
   *¿la IP que me baneó es actor conocido / le pega también a la red global?*
   - `cscli decisions list -o json` (simple, por CLI/SSH), **o**
   - REST LAPI: `GET http://<lapi>:8080/v1/decisions` con header `X-Api-Key` (un bouncer key que se
     emite con `cscli bouncers add separatio`). También `cscli alerts list -o json` da el *scenario*
     que disparó (SSH bruteforce, http-scan…), que es contexto extra para el informe.
   - Encaja como enricher de Stage 2.7 (mismo patrón que `IpsumEnricher`).

2. **Separatio → CrowdSec (feedback loop, lo más potente).** Las IPs que Separatio correlaciona con
   alta confianza (en ≥N feeds) se **empujan como blocklist propia** a CrowdSec, que las banea:
   - `cscli decisions add --ip <ip> --duration 24h --reason "separatio-corr"`, **o**
   - servir un `.txt` de IPs (p. ej. desde el Worker agregador) y consumirlo como *blocklist* con el
     componente `crowdsec-blocklist-mirror` / una fuente custom.
   - Así tu inteligencia se vuelve **bloqueo activo**. (Cobra sentido real cuando haya un servicio
     expuesto o el honeypot — hoy sin exposición el bloqueo no tiene tráfico que filtrar.)

3. **CrowdSec CTI API (capa 3, enriquecimiento on-demand).** CrowdSec tiene su propia API de threat
   intel (tier *community/smoke* gratis, con límite diario de consultas) que da reputación y
   clasificación de una IP. Otro enricher posible, en la misma capa que GreyNoise/Pulsedive.
   Verificar límites actuales antes de depender de ella.

**CrowdSec + honeypot = dos sensores de capa 4** (dato propio), ambos consumibles por Separatio.

---

## La decisión inmediata que quedó pendiente en la conversación

Por dónde empezar a construir, dos caminos (los dos útiles, pero uno da datos y el otro mejora el
informe que ya recibís):

1. **Ingesta de IOCs** (capa 2): sumar los enrichers nuevos (abuse.ch completo, FireHOL, DigitalSide,
   jamesbrine) → da indicadores para correlacionar. Encaja directo en el modelo de Stage 2.7.
2. **Enriquecimiento de tus noticias** (el puente): extender el pipeline con **AIOCRIOC** para sacar
   IOCs de los reportes (incluidas imágenes) → mejora el informe existente y tapa un gap real.

Mi lectura: **(2) AIOCRIOC es la de mejor relación esfuerzo/valor** — es un gap concreto (IOCs en
imágenes que hoy se pierden), no depende de infra nueva, y encaja como un enricher más. (1) es más
fuentes del mismo tipo que ya tenés. Pero es decisión del usuario.

---

## Puntos de unión con Motherbase (cuando todo esté corriendo)

Esto vive en `~/Projects/Intel/` por ahora, pero se une con el proyecto Proxmox en:

- **Honeypot (capa 4)** = fase **F3** de Motherbase. El sensor (Beelzebub, no Cowrie) iría en una VM
  de Oracle **reconstruida y aislada**, con recolección **pull** (casa se conecta y trae logs; el
  honeypot no guarda credenciales que apunten a casa). Prerrequisito ya cumplido: bajamos `wg0` en F1.
- **Lab de detección (Wazuh)** = track FL de Motherbase. Si se corre Wazuh *manager-only* en un LXC,
  sus alertas son otra fuente de **dato propio** que puede alimentar esta central.
- **Dónde corre Separatio** = Paso 5 de F0, aún sin decidir (CT nuevo vs timer en `thinkfox`). Tras F1
  hay ~5 GiB libres + zram, así que sumar el CT del pipeline ya es seguro.

**Prioridad declarada por el usuario (2026-08-07):** primero la central de intel (defensa); el red
team (redirector, C2, payload server) queda para después, no es prioridad.
