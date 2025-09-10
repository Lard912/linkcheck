# LinkCheck – schneller Broken‑Link‑Checker (für beliebige Websites)

Einfaches CLI‑Tool, um Websites zu crawlen und alle Links (intern + optional extern) auf Fehlerseiten zu prüfen.
Läuft lokal oder in CI (z. B. GitHub Actions).

## Features
- Start-URL crawlen (oder komplette Domain per Sitemap, wenn vorhanden)
- Alle `<a href>`-Links einsammeln und prüfen (HEAD → GET‑Fallback)
- 4xx/5xx als *broken*, 3xx verfolgt (bis 5 Hops)
- Soft‑404‑Heuristik (z. B. „Seite nicht gefunden“, „404“ im Titel/Body)
- Respektiert `robots.txt` (sofern nicht `--ignore-robots`)
- Rate‑Limit via `--concurrency` und Timeouts
- CSV/JSON/HTML‑Report

## Installation
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Schnelleinstieg
```bash
python linkcheck.py --start https://example.com --output out --max-pages 5000 --concurrency 8
```
Ergebnis liegt in `out/broken_links.csv`, `out/broken_links.json`, `out/report.html`.

## Wichtige Optionen
- `--start` (Pflicht): Start‑URL (z. B. die Homepage). Der Crawler bleibt standardmäßig auf der Host‑Domain.
- `--include-external`: auch externe Links prüfen.
- `--sitemap`: explizite Sitemap‑URL (sonst wird `/sitemap.xml` versucht).
- `--max-pages`: maximale Anzahl zu crawlender Seiten (Default 2000).
- `--concurrency`: parallele Anfragen (Default 8).
- `--timeout`: Timeout pro Anfrage in Sekunden (Default 12).
- `--ignore-robots`: Robots.txt nicht beachten (nicht empfohlen).
- `--user-agent`: eigener User-Agent String.

## CI (täglich via GitHub Actions)
1. Lege dieses Repo bei GitHub an und pushe die Dateien.
2. Aktiviere den Workflow `.github/workflows/daily.yml` (Cron kannst du anpassen).
3. Finde den Report als Artefakt im jeweiligen Workflow-Run.

## Hinweise
- Große Sites: Concurrency ggf. reduzieren.
- Externe Links führen öfter zu 403/429 (Bot‑Schutz). Diese werden als „unklar“ markiert.
- Soft‑404 ist heuristisch – prüfe die Treffer im Report.
