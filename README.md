# Threat Intelligence Pipeline

Pipeline de análisis automático de amenazas de seguridad con Miniflux + Ollama (qwen3.5).

## Instalación

```bash
pip install -r requirements.txt
```

Instalar modelos en Ollama:
```bash
ollama pull qwen3.5:4b   # Stage 2 — resúmenes por artículo (~3.2 GB RAM)
ollama pull qwen3.5:9b   # Stage 3 — informe consolidado (~7.2 GB RAM)
```

## Configuración

Editar `config.py`:
```python
OLLAMA_HOST       = "http://<IP_LXC_111>:11434"
MINIFLUX_URL      = "http://localhost:8080"
MINIFLUX_USERNAME = "threat_user"
MINIFLUX_PASSWORD = "tu_password"
# Alternativa recomendada (Settings → API Keys en Miniflux UI):
# MINIFLUX_API_TOKEN = "tu-api-token"
```

Crear usuario en Miniflux (UI → Settings → Users) e importar `threat-analysis-feeds.opml`.

Verificar entorno:
```bash
python setup_check.py
```

## Uso

```bash
python pipeline.py                  # ejecución completa
python pipeline.py --dry-run        # sin llamadas a Ollama (prueba de fetch)
python pipeline.py --limit 10       # limitar artículos (útil para pruebas)
python pipeline.py --report-only    # regenerar informe desde caché JSON del día
python pipeline.py --no-mark-read   # no marcar como leídos en Miniflux
```

## Arquitectura

```
Miniflux API (artículos no leídos)
     │
     ▼ extractor.py
  Prioridad: contenido del feed → trafilatura → BeautifulSoup → título
  Truncado a ~800 tokens

     │  (2 workers en paralelo)
     ▼ analyzer.py → qwen3.5:4b (think=False, num_ctx=2048)
  Extrae JSON: threat_type, severity, actors, CVEs, IOCs → ArticleSummary
  Caché: reports/summaries-cache-YYYY-MM-DD.json

     │  (swap de modelo)
     ▼ analyzer.py → qwen3.5:9b (think=True, num_ctx=16384)
  Genera informe con secciones: Resumen Ejecutivo, Amenazas Críticas,
  Vulnerabilidades, Actores APT, Contexto LATAM, Acciones Recomendadas

     ▼ reporter.py
  reports/threat-briefing-YYYY-MM-DD.{md,html}
```

Los modelos se cargan **secuencialmente** (nunca simultáneos). Peak RAM: ~7.2 GB de 10 GB disponibles en el LXC.

## Rendimiento estimado (i7-10510U, CPU-only)

| Etapa | 100 artículos |
|-------|---------------|
| Fetch + scraping | 3–8 min |
| Resúmenes qwen3.5:4b (2 workers) | 20–35 min |
| Informe qwen3.5:9b | 8–15 min |
| **Total** | **~35–55 min** |

## Cron (LXC 112)

```cron
30 6 * * * root cd /opt/threat-pipeline && source venv/bin/activate && python pipeline.py >> /var/log/threat-pipeline.log 2>&1
```
