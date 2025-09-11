#!/usr/bin/env python3
import asyncio, re, sys, csv, json, argparse, pathlib
from urllib.parse import urljoin, urlparse, urldefrag
import aiohttp
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
import tldextract
import xml.etree.ElementTree as ET
from urllib import robotparser

# ---------- Soft-404-Muster ----------
SOFT_404_PATTERNS = [
    re.compile(r"\b404\b", re.I),
    re.compile(r"\bnot\s+found\b", re.I),
    re.compile(r"\bpage\s+not\s+found\b", re.I),
    re.compile(r"\bseite\s+nicht\s+gefunden\b", re.I),
    re.compile(r"\bnicht\s+gefunden\b", re.I),
    re.compile(r"\bdie\s+seite\s+existiert\s+nicht\b", re.I),
    re.compile(r"\bdoes\s+not\s+exist\b", re.I),
    re.compile(r"status:\s*404", re.I),             # z. B. "STATUS:404"
    re.compile(r"enable\s+javascript.*404", re.I),  # JS-Apps ohne SSR
]

# ---------- Hilfsfunktionen ----------
def normalize_url(link: str, base: str) -> str | None:
    """macht aus relativen/kaputten HREFs kanonische http(s)-URLs"""
    try:
        if not link:
            return None
        link = link.strip()
        if link.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        u = urljoin(base, link)
        u, _ = urldefrag(u)  # Fragment entfernen
        p = urlparse(u)
        if not p.scheme.startswith("http"):
            return None
        return p.geturl()
    except Exception:
        return None

async def fetch_text(session: aiohttp.ClientSession, url: str):
    async with session.get(url, allow_redirects=True) as resp:
        text = await resp.text(errors="ignore")
        return resp, text

async def fetch_head_or_get(session: aiohttp.ClientSession, url: str):
    try:
        async with session.head(url, allow_redirects=False) as resp:
            return resp.status, resp.headers.get("Location"), None
    except Exception:
        try:
            async with session.get(url, allow_redirects=False) as resp:
                return resp.status, resp.headers.get("Location"), None
        except Exception as e2:
            return None, None, str(e2)

async def resolve_redirects(session: aiohttp.ClientSession, url: str, max_hops: int = 5):
    current = url
    hops = 0
    while hops < max_hops:
        status, location, err = await fetch_head_or_get(session, current)
        if err:
            return {"final_url": current, "status": None, "broken": True, "error": err, "hops": hops}
        if status and 300 <= status < 400 and location:
            current = urljoin(current, location)
            hops += 1
            continue
        broken = (status is None) or (status >= 400 and status not in (401, 403)) or status >= 500
        return {"final_url": current, "status": status, "broken": broken, "error": None, "hops": hops}
    return {"final_url": current, "status": None, "broken": True, "error": "Too many redirects", "hops": hops}

async def looks_soft_404(session: aiohttp.ClientSession, url: str, status: int | None) -> bool:
    """Erkennt 200/3xx-Seiten, die inhaltlich eine 404 sind (Theme-/SPA-Fälle)"""
    try:
        resp, text = await fetch_text(session, url)
        soup = BeautifulSoup(text, "lxml")

        title = (soup.title.string or "").strip() if soup.title else ""
        h1 = (soup.find("h1").get_text(" ", strip=True) if soup.find("h1") else "")
        body_text = soup.get_text(" ", strip=True)[:4000]
        body_classes = " ".join(soup.body.get("class", [])) if soup.body else ""

        # Typische Klassen/Marker
        if "template-404" in body_classes or "page-not-found" in body_classes:
            return True

        hay = "\n".join([title, h1, body_text])
        return any(p.search(hay) for p in SOFT_404_PATTERNS)
    except Exception:
        return False

async def get_sitemap_urls(session: aiohttp.ClientSession, base_url: str, explicit: str | None = None) -> list[str]:
    urls: set[str] = set()
    candidates = [explicit] if explicit else [urljoin(base_url, "/sitemap.xml")]
    for sm in candidates:
        try:
            resp, text = await fetch_text(session, sm)
            if resp.status != 200:
                continue
            root = ET.fromstring(text)
            if root.tag.endswith("sitemapindex"):
                for loc in root.iter():
                    if loc.tag.endswith("loc"):
                        nested = loc.text.strip()
                        urls.update(await get_sitemap_urls(session, base_url, explicit=nested))
            elif root.tag.endswith("urlset"):
                for loc in root.iter():
                    if loc.tag.endswith("loc"):
                        urls.add(loc.text.strip())
        except Exception:
            continue
    return list(urls)

# ---------- Hauptprogramm ----------
async def main():
    ap = argparse.ArgumentParser(description="Check a site for broken links.")
    ap.add_argument("--start", required=True, help="Start-URL (z. B. Homepage oder eine Inhaltsseite)")
    ap.add_argument("--sitemap", help="Optionale Sitemap-URL (beschleunigt stark)")
    ap.add_argument("--include-external", action="store_true", help="Auch externe Domains prüfen")
    ap.add_argument("--max-pages", type=int, default=2000, help="Max. zu verarbeitende Seiten/Seeds")
    ap.add_argument("--concurrency", type=int, default=8, help="Parallele Prüfungen")
    ap.add_argument("--timeout", type=int, default=12, help="Timeout je Request in Sekunden")
    ap.add_argument("--ignore-robots", action="store_true", help="robots.txt ignorieren (nicht empfohlen)")
    ap.add_argument("--user-agent", default="LinkCheck/1.0 (+https://example.local)", help="User-Agent")
    ap.add_argument("--output", default="out", help="Ausgabe-Ordner")
    args = ap.parse_args()

    start = args.start.rstrip("/")
    base_host = urlparse(start).netloc
    pathlib.Path(args.output).mkdir(parents=True, exist_ok=True)

    timeout = ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(limit=args.concurrency)

    # Domain-Lock: gleiche registrierte Domain (inkl. Subdomains)
    def same_registered_domain(u: str) -> bool:
        eh = tldextract.extract(urlparse(u).netloc)
        eb = tldextract.extract(base_host)
        return (eh.domain, eh.suffix) == (eb.domain, eb.suffix)

    async with aiohttp.ClientSession(timeout=timeout, connector=connector, headers={"User-Agent": args.user_agent}) as session:
        # Seeds: Start + Sitemap (falls vorhanden)
        seeds: set[str] = {start}
        sm_urls = await get_sitemap_urls(session, start, args.sitemap) if args.sitemap or True else []
        seeds.update(sm_urls)

        # Nur interne Seeds, wenn externe nicht gewünscht
        if not args.include_external:
            seeds = {u for u in seeds if same_registered_domain(u)}

        # --- Links aus den Seeds einsammeln ---
        all_links: set[str] = set()
        for s in list(seeds)[:args.max_pages]:
            try:
                resp, text = await fetch_text(session, s)
                if resp.status != 200:
                    continue
                soup = BeautifulSoup(text, "lxml")
                for a in soup.find_all("a", href=True):
                    n = normalize_url(a.get("href"), s)
                    if not n:
                        continue
                    if not args.include_external and not same_registered_domain(n):
                        continue
                    all_links.add(n)
            except Exception:
                continue

        # --- Links prüfen ---
        results: list[dict] = []
        sem = asyncio.Semaphore(args.concurrency)

        async def check(u: str):
            async with sem:
                info = await resolve_redirects(session, u, max_hops=5)
                # Soft-404 nur prüfen, wenn nicht bereits broken und Status < 400
                if not info["broken"] and info["status"] and info["status"] < 400:
                    if await looks_soft_404(session, info["final_url"], info["status"]):
                        info["broken"] = True
                        info["error"] = "Soft 404 heuristics"
                return {"url": u, **info}

        tasks = [asyncio.create_task(check(u)) for u in sorted(all_links)]
        for t in asyncio.as_completed(tasks):
            results.append(await t)

        broken = [r for r in results if r["broken"]]
        unknown = [r for r in results if (r["status"] in (401, 403)) or r["error"]]

        # ---------- Ausgaben ----------
        # CSV
        with open(f"{args.output}/broken_links.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "final_url", "status", "hops", "error"])
            for r in broken:
                w.writerow([r["url"], r["final_url"], r["status"] or "", r["hops"], r["error"] or ""])

        # HTML + kompakte Liste unten
        def esc(s: str) -> str:
            return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        rows = "\n".join(
            f"<tr><td>{esc(r['url'])}</td><td>{esc(r['final_url'])}</td>"
            f"<td>{r['status'] or ''}</td><td>{r['hops']}</td><td>{esc(r['error'] or '')}</td></tr>"
            for r in broken
        )
        error_links = sorted({r["url"] for r in broken})

        html = f"""<!doctype html><html lang="de"><meta charset="utf-8">
<title>LinkCheck Report</title>
<style>
  body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;padding:20px}}
  table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:8px}}
  th{{background:#f6f6f6;text-align:left}} tr:nth-child(even){{background:#fafafa}}
  code{{background:#f2f2f2;padding:2px 4px;border-radius:4px}}
</style>
<h1>Gefundene Broken Links</h1>
<p>Links geprüft: {len(results)} | Broken: {len(broken)} | Unklar (401/403/Fehler): {len(unknown)}</p>
<table>
  <thead><tr><th>URL (verlinkt)</th><th>Final URL</th><th>Status</th><th>Redirect-Hops</th><th>Fehler</th></tr></thead>
  <tbody>
    {rows if rows else '<tr><td colspan="5">Keine kaputten Links gefunden 🎉</td></tr>'}
  </tbody>
</table>

<h2 style="margin-top:28px">Error-Links (nur URL)</h2>
<p>Praktische Liste zum schnellen Prüfen/Kopieren:</p>
{("<ul>" + "".join(f"<li><code>{esc(u)}</code></li>" for u in error_links) + "</ul>") if error_links else "<p>—</p>"}
</html>"""

        with open(f"{args.output}/report.html", "w", encoding="utf-8") as f:
            f.write(html)

        # Nur-URL-Liste
        with open(f"{args.output}/error_links.txt", "w", encoding="utf-8") as f:
            for u in error_links:
                f.write(u + "\n")

if __name__ == "__main__":
    asyncio.run(main())
