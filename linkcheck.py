#!/usr/bin/env python3
import asyncio, re, sys, csv, json, argparse
from urllib.parse import urljoin, urlparse, urldefrag
import aiohttp
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
import tldextract
import xml.etree.ElementTree as ET
from urllib import robotparser
import pathlib

# Muster für Soft-404
SOFT_404_PATTERNS = [
    re.compile(r"\b404\b", re.I),
    re.compile(r"\bnot\s+found\b", re.I),
    re.compile(r"\bpage\s+not\s+found\b", re.I),
    re.compile(r"\bseite\s+nicht\s+gefunden\b", re.I),
    re.compile(r"\bnicht\s+gefunden\b", re.I),
    re.compile(r"\bdie\s+seite\s+existiert\s+nicht\b", re.I),
    re.compile(r"\bdoes\s+not\s+exist\b", re.I),
    re.compile(r"status:\s*404", re.I),            # NEU: erkennt „STATUS:404“
    re.compile(r"enable javascript.*404", re.I),   # NEU: für Bauhaus-Servicebuchung
]

def normalize_url(link, base):
    try:
        link = link.strip()
        if not link or link.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        u = urljoin(base, link)
        u, _ = urldefrag(u)
        parts = urlparse(u)
        if not parts.scheme.startswith("http"):
            return None
        return parts.geturl()
    except Exception:
        return None

async def fetch_text(session, url):
    async with session.get(url, allow_redirects=True) as resp:
        text = await resp.text(errors="ignore")
        return resp, text

async def fetch_head_or_get(session, url):
    try:
        async with session.head(url, allow_redirects=False) as resp:
            return resp.status, resp.headers.get("Location"), None
    except Exception as e:
        try:
            async with session.get(url, allow_redirects=False) as resp:
                return resp.status, resp.headers.get("Location"), None
        except Exception as e2:
            return None, None, str(e2)

async def resolve_redirects(session, url, max_hops=5):
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
        broken = (status is None) or (status >= 400 and status not in (401,403)) or status >= 500
        return {"final_url": current, "status": status, "broken": broken, "error": None, "hops": hops}
    return {"final_url": current, "status": None, "broken": True, "error": "Too many redirects", "hops": hops}

async def looks_soft_404(session, url, status):
    try:
        resp, text = await fetch_text(session, url)
        soup = BeautifulSoup(text, "lxml")

        title = (soup.title.string or "").strip() if soup.title else ""
        h1 = (soup.find("h1").get_text(" ", strip=True) if soup.find("h1") else "")
        body_text = soup.get_text(" ", strip=True)[:4000]
        body_classes = " ".join(soup.body.get("class", [])) if soup.body else ""

        if "template-404" in body_classes or "page-not-found" in body_classes:
            return True

        hay = "\n".join([title, h1, body_text])
        return any(p.search(hay) for p in SOFT_404_PATTERNS)
    except Exception:
        return False

async def get_sitemap_urls(session, base_url, explicit=None):
    urls = set()
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
                        sub = await get_sitemap_urls(session, base_url, explicit=nested)
                        urls.update(sub)
            elif root.tag.endswith("urlset"):
                for loc in root.iter():
                    if loc.tag.endswith("loc"):
                        urls.add(loc.text.strip())
        except Exception:
            continue
    return list(urls)

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", required=True)
    ap.add_argument("--sitemap")
    ap.add_argument("--include-external", action="store_true")
    ap.add_argument("--max-pages", type=int, default=2000)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--ignore-robots", action="store_true")
    ap.add_argument("--user-agent", default="LinkCheck/1.0")
    ap.add_argument("--output", default="out")
    args = ap.parse_args()

    start = args.start.rstrip("/")
    parsed = urlparse(start)
    base_host = parsed.netloc
    session_timeout = ClientTimeout(total=args.timeout)
    pathlib.Path(args.output).mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession(timeout=session_timeout, headers={"User-Agent": args.user_agent}) as session:
        seeds = {start}
        if args.sitemap:
            sm_urls = await get_sitemap_urls(session, start, args.sitemap)
            seeds.update(sm_urls)
        else:
            sm_urls = await get_sitemap_urls(session, start, None)
            seeds.update(sm_urls)

        all_links = set()
        for s in list(seeds)[:args.max_pages]:
            try:
                resp, text = await fetch_text(session, s)
                if resp.status != 200:
                    continue
                soup = BeautifulSoup(text, "lxml")
                for a in soup.find_all("a", href=True):
                    n = normalize_url(a.get("href"), s)
                    if n:
                        all_links.add(n)
            except Exception:
                continue

        results = []
        sem = asyncio.Semaphore(args.concurrency)
        async def check(u):
            async with sem:
                info = await resolve_redirects(session, u)
                if info["broken"] is False and info["status"] and info["status"] < 400:
                    if await looks_soft_404(session, info["final_url"], info["status"]):
                        info["broken"] = True
                        info["error"] = "Soft 404 heuristics"
                return {"url": u, **info}
        tasks = [asyncio.create_task(check(u)) for u in sorted(all_links)]
        for t in asyncio.as_completed(tasks):
            results.append(await t)

        broken = [r for r in results if r["broken"]]

        with open(f"{args.output}/broken_links.csv","w",newline="",encoding="utf-8") as f:
            w=csv.writer(f)
            w.writerow(["url","final_url","status","hops","error"])
            for r in broken:
                w.writerow([r["url"],r["final_url"],r["status"] or "",r["hops"],r["error"] or ""])

with open(f"{args.output}/report.html","w",encoding="utf-8") as f:
    def esc(s: str) -> str:
        return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    rows = "\n".join(
        f"<tr><td>{esc(r['url'])}</td><td>{esc(r['final_url'])}</td><td>{r['status'] or ''}</td><td>{r['hops']}</td><td>{esc(r['error'] or '')}</td></tr>"
        for r in broken
    )
    # >>> NEU: Liste nur mit den gefundenen Error-Links (Ziel-URLs)
    error_links = sorted({ r["url"] for r in broken })
    error_list_html = (
        "<ul>" + "".join(f"<li><code>{esc(u)}</code></li>" for u in error_links) + "</ul>"
        if error_links else "<p>—</p>"
    )
    html = f"""<!doctype html><html lang="de"><meta charset="utf-8">
    <title>LinkCheck Report</title>
    <style>
      body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;padding:20px}}
      table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:8px}}
      th{{background:#f6f6f6;text-align:left}} tr:nth-child(even){{background:#fafafa}}
      code{{background:#f2f2f2;padding:2px 4px;border-radius:4px}}
    </style>
    <h1>Gefundene Broken Links</h1>
    <p>Links geprüft: {len(results)} | Broken: {len(broken)}</p>
    <table>
      <thead><tr><th>URL (verlinkt)</th><th>Final URL</th><th>Status</th><th>Redirect-Hops</th><th>Fehler</th></tr></thead>
      <tbody>
      {rows if rows else '<tr><td colspan="5">Keine kaputten Links gefunden 🎉</td></tr>'}
      </tbody>
    </table>

    <h2 style="margin-top:28px">Error-Links (nur URL)</h2>
    <p>Diese Liste ist praktischer zum schnellen Kopieren/Überprüfen:</p>
    {error_list_html}
    </html>"""
    f.write(html)

# Zusätzlich (optional): reine Textliste der „Error-Links“ mitschreiben
with open(f"{args.output}/error_links.txt","w",encoding="utf-8") as f:
    for u in sorted({ r["url"] for r in broken }):
        f.write(u + "\n")


if __name__ == "__main__":
    asyncio.run(main())
