# F2 — Fuentes nuevas: leak sites y MCP oficiales

**Estado:** ☑ **Hecha el 2026-08-08** (implementación completa; ver bloque de cierre abajo) ·
**Prerrequisitos:** F0 (el pipeline tiene que estar corriendo) · **Bloquea:** nada

> **Objetivo:** sumar monitoreo de leak sites de ransomware al pipeline, y dejar dos MCP oficiales
> listos para investigación manual. Todo clearnet, sin Tor.

---

## ¿Ya está hecho?

```bash
# (rutas del monorepo desde 2026-08-08; en producción el clone vive en el CT 113: /opt/intel/app)
ls ~/Projects/Intel/separatio/enrichers/               # ¿existe ransomware.py?
grep -A6 "^ENRICHERS" ~/Projects/Intel/separatio/config.py
ls ~/Projects/Intel/.mcp.json 2>/dev/null || echo "sin MCP configurado"
```

**Al 2026-08-07:** enrichers son `ipsum`, `openphish`, `ip_reputation`. Ningún MCP configurado
(`mcpServers` vacío en `~/.claude.json` y `~/.claude/settings.json`).

**Al 2026-08-08 — hecho (commit `1fbc5ad`, desplegado en el CT 113):**

- **Parte A:** `enrichers/ransomware.py` (`RansomwareLiveEnricher`) — una llamada por run a
  `/v2/recentvictims`, sin `net.py` a propósito (sus reintentos ante 429 violarían los ToS).
  Notas de contexto al prompt de Stage 3 (víctimas de las últimas 26h, tope 15) vía un mecanismo
  nuevo de `EnrichmentContext.add_note()` que **no** contamina el export CSV de IOCs; cruce de
  dominios de víctimas contra los IOCs del día como `IocVerdict`. `screenshot`, `claim_url` e
  `infostealer` se descartan en el parseo (GDPR/licencia — con test que lo verifica). La
  atribución "Source: Ransomware.live" va en el bloque del prompt. Bonus: `onionlookup.py`
  (CIRCL/AIL) para `.onion` entre los IOCs — 0 llamadas si no hay. 35 tests pasan.
- **Parte B:** `.mcp.json` en `~/Projects/Intel/` con HIBP hosted (handshake verificado, 200) y
  AbuseIPDB por `uvx` (arranque verificado; la key sale del `.env` al lanzar, nada secreto
  commiteado). `uv` instalado vía mise en el laptop.
- **No implementado (decisión):** RansomLook como fuente activa — queda anotado como complemento
  futuro; su `misp_uuid` es el puente al `MispEnricher` de `IMPROVEMENTS.md` §7. El tier PRO de
  ransomware.live (registro gratuito) queda opcional: con 1 llamada/run el free tier alcanza.
- **Verificación pendiente de la próxima corrida real:** que Stage 2.7 liste las fuentes nuevas
  en el log del CT y que el informe cite la fuente. Los MCP se confirman al abrir Claude Code
  en `~/Projects/Intel/`.

---

## Parte A — Enricher de leak sites

### Contexto

Los servicios hacen el scraping de `.onion` ellos y entregan JSON por HTTPS clearnet. **No hace falta
Tor ni tocar un leak site directamente** — que además es la postura correcta desde una IP doméstica.

Verificado en vivo el 2026-08-07:

| Fuente | API sin key | Estado | Rol |
|---|---|---|---|
| **ransomware.live v2** | Sí, **1 req/min estricto** | Activo, dato más nuevo `2026-08-07T16:30` | Base |
| **RansomLook** | Sí, 49 endpoints | Commit del 2026-08-06, el más vivo | Complemento |
| **onion-lookup (CIRCL)** | Sí, *"without restrictions"* | Activo | Enriquecer `.onion` sin tocar Tor |
| **ransomwatch** | — | 🔴 **ARCHIVADO** | **No usar** |

⚠️ **Trampa con ransomwatch:** está archivado pero su `posts.json` **sigue devolviendo HTTP 200**, y
el registro más nuevo es de **2025-06-16**. Un monitor que solo mire el status code creería que
funciona mientras consume datos congelados hace 14 meses.

⚠️ **Rate limit:** ransomware.live v2 aplica **1 req/minuto por endpoint** de verdad (segunda llamada
seguida → 429). Hay un **tier PRO gratuito con registro**, 500.000 llamadas/mes. Pedirlo — evadir el
límite con reintentos es lo que prohíben los ToS.

### Implementación

Un enricher más. La interfaz ya existe; del `CLAUDE.md` de Separatio: *"Add a source = new
`enrichers/*.py` subclass + register in `build_enrichers()` + toggle in `config.ENRICHERS`."*

Llamadas directas con `httpx`, **no MCP** (ver Parte B para el porqué).

### Obligaciones que hay que respetar

- **Atribución `"Source: Ransomware.live"`** — su licencia de datos es no comercial con atribución.
  (El *código* es Unlicense; los *datos* no. No es lo mismo.)
- **GDPR:** los feeds traen campos `screenshot`/`screen` que apuntan a capturas de leak sites con
  datos personales de víctimas. **Guardar metadatos, nunca imágenes.**
- **Que el pipeline no resuelva nunca `claim_url` (.onion) ni `magnet`.**
- RansomLook tiene `_audit_torrent()` con el comentario *"Record who accessed what, for LEA
  traceability"* — quedarse en los endpoints de lectura.

### Dos enganches con lo que ya existe

- **ransomware.live sirve reglas YARA por grupo** en `/yara/<group>`. Ya hay una regla YARA escrita a
  mano en [`../casos/ft-correction.md`](../casos/ft-correction.md); esto da corpus para el mismo flujo.
- **RansomLook expone `misp_uuid`** en sus perfiles de actores. `IMPROVEMENTS.md` §7 ya plantea un
  `MispEnricher` como próximo paso natural — ese campo es el puente directo, sin reconciliación.

---

## Parte B — Dos MCP oficiales para investigación manual

**Esto no toca el pipeline.** Es para cuando el usuario está investigando un caso —como fue
`ft-correction`— y prefiere preguntar en lenguaje natural antes que armar `curl`. Coste de
infraestructura: cero.

| Servidor | Cómo | Por qué este |
|---|---|---|
| **HIBP** | Hosted en `haveibeenpwned.com/mcp` — **no se instala nada** | Único vendor con entrada propia en el registry oficial. 17 tools; breaches públicos y Pwned Passwords **sin autenticación** |
| **AbuseIPDB** | `uvx mcp-server-abuseipdb` (efímero) | Oficial, actualizado 2026-08-03. **1.000 checks/día gratis**, el mejor tier. La key ya está en el `.env` |

Se registran en un **`.mcp.json` dentro de `~/Projects/Intel/`**, no global — así solo existen cuando
se trabaja en ese proyecto.

**No sumar:** VirusTotal (4 req/min, 500/día — se agota en una sesión de agente), Censys (100
créditos/mes que las llamadas consumen), GreyNoise (**no emite keys a Proton**).

### Por qué MCP no va en el cron

El valor de MCP es la descubribilidad dinámica: que un LLM lea `tools/list` y decida qué llamar. En
batch eso vale cero porque ya se sabe qué endpoints consultar. Lo que agrega: un proceso Node por
corrida (los servidores suelen ser stdio-only), handshake JSON-RPC, y respuestas que son JSON
serializado *dentro de un campo de texto* que hay que volver a parsear. Y los rate limiters viven en
memoria del proceso: se pierden entre corridas, justo lo que no querés con 1 req/min.

**Criterio para no repetir el error del `darknet-mcp-server`:** un MCP corre con las API keys en el
entorno de su proceso. Solo servidores del vendor de la fuente, o escritos por uno mismo. Nunca un
agregador de terceros que junte diez claves en un proceso sin auditar.

---

## Verificación

- [ ] El enricher aparece en el log de Stage 2.7 sin abortar la corrida
- [ ] No hay 429 en el log (rate limit respetado / key PRO en uso)
- [ ] El informe cita `"Source: Ransomware.live"`
- [ ] No se guardó ninguna imagen de `screenshot`/`screen`
- [ ] Los MCP responden desde Claude Code al abrir `~/Projects/Intel/`

## Al terminar

1. Marcar F2 como ☑ en [`../ESTADO.md`](../ESTADO.md).
2. Actualizar la tabla de capas de [`../INTEL-ARQUITECTURA.md`](../INTEL-ARQUITECTURA.md) §2.
