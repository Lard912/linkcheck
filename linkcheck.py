#!/usr/bin/env python3
import asyncio, re, sys, csv, json, argparse, time
from urllib.parse import urljoin, urlparse, urldefrag
import aiohttp
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
import tldextract
import xml.etree.ElementTree as ET
from urllib import robotparser
import pathlib

SOFT_404_PATTERNS = [
    re.compile(r"\b404\b", re.I),
    re.compile(r"not\s+found", re.I),
    re.compile(r"seite\s+nicht\s+gefunden", re.I),
    re.compile(r"page\s+not\s+found", re.I),
    re.compile(r"does\s+not\s+exist", re.I),
]

def normalize_url(link, base):
    try:
        link = link.strip()
        if not link or link.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        u = urljoin(base, link)
        u, _ = urldefrag(u)  # remove fragments
        parts = urlparse(u)
        if not parts.scheme.startswith("http"):
            return None
        # normalize: remove default ports
        netloc = parts.hostname or ""
        if parts.port:
            if parts.scheme == "http" and parts.port == 80: netloc = parts.hostname
            elif parts.scheme == "https" and parts.port == 443: netloc = parts.hostname
            else: netloc = f"{parts.hostname}:{parts.port}"
        normalized = parts._replace(netloc=netloc).geturl()
        return normalized
    except Exception:
        return None

def same_reg_domain(a, b):
    ea = tldextract.extract(a)
    eb = tldextract.extract(b)
    return (ea.domain, ea.suffix) == (eb.domain, eb.suffix)

async def fetch_text(session, url):
    async with session.get(url, allow_redirects=True) as resp:
        text = await resp.text(errors="ignore")
        return resp, text

async def fetch_head_or_get(session, url):
    # Try HEAD first; fallback to GET
    try:
        async with session.head(url, allow_redirects=False) as resp:
            status = resp.status
            location = resp.headers.get("Location")
            return status, location, None
    except Exception as e:
        # Fallback to GET without body reading
        try:
            async with session.get(url, allow_redirects=False) as resp:
                status = resp.status
                location = resp.headers.get("Location")
                return status, location, None
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
            try:
                current = urljoin(current, location)
            except Exception:
                return {"final_url": current, "status": status, "broken": True, "error": "Bad redirect location", "hops": hops}
            hops += 1
            continue
        # finished
        broken = (status is None) or (status >= 400 and status not in (401,403)) or status >= 500
        return {"final_url": current, "status": status, "broken": broken, "error": None, "hops": hops}
    return {"final_url": current, "status": None, "broken": True, "error": "Too many redirects", "hops": hops}

async def looks_soft_404(session, url, status):
    # Only check when status is 200..399
    try:
        resp, text = await fetch_text(session, url)
        title = ""
        try:
            soup = BeautifulSoup(text, "lxml")
            title = (soup.title.string or "").strip() if soup.title else ""
            body_text = soup.get_text(" ", strip=True)[:2000]
        except Exception:
            body_text = text[:2000]
        hay = f"{title}\n{body_text}"
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

async def crawl(session, start_url, max_pages, domain_lock, rp, include_external):
    queue = asyncio.Queue()
    await queue.put(start_url)
    seen_pages = set([start_url])
    page_to_links = {}
    pages_crawled = 0

    async def worker():
        nonlocal pages_crawled
        while True:
            url = await queue.get()
            try:
                if rp and not rp.can_fetch(session.headers.get("User-Agent","LinkCheck/1.0"), url):
                    queue.task_done()
                    continue
                resp, text = await fetch_text(session, url)
                if resp.status != 200:
                    page_to_links[url] = []
                    queue.task_done()
                    continue
                soup = BeautifulSoup(text, "lxml")
                hrefs = set()
                for a in soup.find_all("a", href=True):
                    n = normalize_url(a.get("href"), url)
                    if not n: 
                        continue
                    hrefs.add(n)
                    # enqueue internal links for crawling
                    if (include_external is False) and domain_lock(urlparse(n).netloc) and (n not in seen_pages) and (pages_crawled + queue.qsize() < max_pages):
                        seen_pages.add(n)
                        await queue.put(n)
                page_to_links[url] = list(hrefs)
                pages_crawled += 1
            except Exception:
                page_to_links[url] = []
            finally:
                queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(8)]
    await queue.join()
    for w in workers: w.cancel()
    return page_to_links

def make_robot_parser(base_url, text):
    rp = robotparser.RobotFileParser()
    rp.set_url(base_url)
    rp.parse(text.splitlines())
    return rp

async def fetch_robots(session, base_url):
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp, text = await fetch_text(session, robots_url)
        if resp.status == 200:
            return make_robot_parser(robots_url, text)
    except Exception:
        pass
    return None

async def main():
    ap = argparse.ArgumentParser(description="Check a site for broken links.")
    ap.add_argument("--start", required=True, help="Start URL (Homepage oder Einstiegsseite)")
    ap.add_argument("--sitemap", help="Optionale Sitemap-URL")
    ap.add_argument("--include-external", action="store_true", help="Auch externe Links prüfen")
    ap.add_argument("--max-pages", type=int, default=2000, help="Max. zu crawlende Seiten")
    ap.add_argument("--concurrency", type=int, default=8, help="Parallele Anfragen")
    ap.add_argument("--timeout", type=int, default=12, help="Timeout pro Request in Sekunden")
    ap.add_argument("--ignore-robots", action="store_true", help="Robots.txt ignorieren (nicht empfohlen)")
    ap.add_argument("--user-agent", default="LinkCheck/1.0 (+https://example.local)", help="User-Agent")
    ap.add_argument("--output", default="out", help="Ausgabe-Ordner")
    args = ap.parse_args()

    start = args.start.rstrip("/")
    parsed = urlparse(start)
    base_host = parsed.netloc
    session_timeout = ClientTimeout(total=args.timeout)

    sem = asyncio.Semaphore(args.concurrency)
    conn = aiohttp.TCPConnector(limit=args.concurrency)

    headers = {"User-Agent": args.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    def domain_lock(host):
        return tldextract.extract(host).registered_domain == tldextract.extract(base_host).registered_domain

    pathlib.Path(args.output).mkdir(parents=True, exist_ok=True)

    async with aiohttp.ClientSession(timeout=session_timeout, connector=conn, headers=headers) as session:
        rp = None if args.ignore_robots else await fetch_robots(session, start)

        # 1) Seed URLs: Sitemap (falls vorhanden) + Startseite
        seeds = set([start])
        if args.sitemap:
            sm_urls = await get_sitemap_urls(session, start, args.sitemap)
            seeds.update(sm_urls)
        else:
            sm_urls = await get_sitemap_urls(session, start, None)
            seeds.update(sm_urls)

        # Filter seeds auf selbe Domain (wenn include_external False)
        if not args.include_external:
            seeds = {u for u in seeds if domain_lock(urlparse(u).netloc)}

        # 2) Crawl
        page_to_links = {}
        # Begrenze seeds auf max-pages
        seeds_list = list(seeds)[:args.max_pages]

        async def guard_fetch(url):
            async with sem:
                return await fetch_text(session, url)

        # Erst Seiten-Inhalte laden, Links extrahieren + interne Seiten weiter-crawlen (vereinfachte Strategie)
        # Hier verwenden wir einen einfachen BFS über seeds; für große Sites empfiehlt sich eine dedizierte Frontier.
        for s in seeds_list:
            try:
                if rp and not rp.can_fetch(headers["User-Agent"], s): 
                    page_to_links[s] = []
                    continue
                resp, text = await fetch_text(session, s)
                if resp.status != 200:
                    page_to_links[s] = []
                    continue
                soup = BeautifulSoup(text, "lxml")
                hrefs = set()
                for a in soup.find_all("a", href=True):
                    n = normalize_url(a.get("href"), s)
                    if not n: continue
                    hrefs.add(n)
                page_to_links[s] = list(hrefs)
            except Exception:
                page_to_links[s] = []

        # 3) Link-Prüfung (HEAD → GET; Redirects folgen)
        all_links = set()
        for links in page_to_links.values():
            all_links.update(links)

        if not args.include_external:
            all_links = {u for u in all_links if domain_lock(urlparse(u).netloc)}

        results = []
        # Batches parallel prüfen
        sem2 = asyncio.Semaphore(args.concurrency)
        async def check(u):
            async with sem2:
                info = await resolve_redirects(session, u, max_hops=5)
                # Soft-404-Heuristik (nur wenn 2xx/3xx)
                if info["broken"] is False and info["status"] and info["status"] < 400:
                    if await looks_soft_404(session, info["final_url"], info["status"]):
                        info["broken"] = True
                        info["error"] = "Soft 404 heuristics"
                return {"url": u, **info}

        tasks = [asyncio.create_task(check(u)) for u in sorted(all_links)]
        for t in asyncio.as_completed(tasks):
            results.append(await t)

        broken = [r for r in results if r["broken"]]
        unknown = [r for r in results if r["status"] in (401,403) or r["error"]]

        # 4) Ausgabe
        csv_path = f"{args.output}/broken_links.csv"
        json_path = f"{args.output}/broken_links.json"
        html_path = f"{args.output}/report.html"

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url","final_url","status","hops","error"])
            for r in broken:
                w.writerow([r["url"], r["final_url"], r["status"] or "", r["hops"], r["error"] or ""])

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({"summary": {
                "checked": len(results), "broken": len(broken), "unknown": len(unknown)
            }, "broken": broken, "all": results}, f, ensure_ascii=False, indent=2)

        # Minimaler HTML-Report
        def esc(s): 
            return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        rows = "\n".join(
            f"<tr><td>{esc(r['url'])}</td><td>{esc(r['final_url'])}</td><td>{r['status'] or ''}</td><td>{r['hops']}</td><td>{esc(r['error'] or '')}</td></tr>"
            for r in broken
        )
        summary = f"<p>Links geprüft: {len(results)} | Broken: {len(broken)} | Unklar: {len(unknown)}</p>"
        html = f"""<!doctype html>
<html lang="de"><meta charset="utf-8"><title>LinkCheck Report</title>
<style>body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;padding:20px}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:8px}} th{{background:#f3f3f3;text-align:left}} tr:nth-child(even){{background:#fafafa}}</style>
<h1>LinkCheck Report</h1>
{summary}
<table>
<thead><tr><th>URL (Quelle)</th><th>Final URL</th><th>Status</th><th>Redirect-Hops</th><th>Fehler</th></tr></thead>
<tbody>
{rows if rows else '<tr><td colspan="5">Keine kaputten Links gefunden 🎉</td></tr>'}
</tbody></table>
</html>"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"Fertig. Reporte unter: {csv_path}, {json_path}, {html_path}")

if __name__ == "__main__":
    asyncio.run(main())
