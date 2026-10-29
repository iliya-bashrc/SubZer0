#!/usr/bin/env python3
"""Assemble the static GitHub Pages site: app shell + verified snapshot + RSS/JSON feeds.

Layout of the output directory (default: _site/):
  index.html, 404.html, app.js, app.css, sw.js, fonts/, ...   <- copied from site/
  snapshot/                                                   <- copied from public/snapshot/
  feed.xml                                                    <- RSS of "patch now" CVEs
  api/latest.json                                             <- small machine-readable summary
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape

import briefing as brief
import hub_pages as hub
import seo_pages as seo
import verify_data_snapshot as verifier

try:  # optional: per-page share cards need Pillow; without it pages keep the default og.png
    import share_cards
except ImportError:  # pragma: no cover
    share_cards = None

ROOT = Path(__file__).resolve().parents[1]
SITE_URL = "https://iliya-bashrc.github.io/SubZer0/"
FEED_LIMIT = 50


def _read_verified(snapshot: Path, meta: dict | None):
    """Load a manifest-declared data file, or None when it is absent or does not match its hash."""
    if not isinstance(meta, dict) or not meta.get("path"):
        return None
    try:
        raw = (snapshot / str(meta["path"])).read_bytes()
    except OSError:
        return None
    if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
        return None
    return json.loads(raw)


def load_index(snapshot: Path) -> tuple[dict, list[list], dict]:
    """Return (manifest, search-index rows, context) where context holds the PoC set and intel map."""
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    index = json.loads((snapshot / manifest["search_index"]["path"]).read_text(encoding="utf-8"))
    rows = index["rows"] if isinstance(index, dict) and "rows" in index else index
    poc = _read_verified(snapshot, manifest.get("poc_ids"))
    intel = _read_verified(snapshot, manifest.get("intel"))
    ctx = {
        "poc": set(poc) if isinstance(poc, list) else set(),
        "intel": (intel or {}).get("cves") or {} if isinstance(intel, dict) else {},
    }
    return manifest, rows, ctx


def facts(row: list, ctx: dict) -> dict:
    """Signals used by the priority rules. Mirror of facts() in site/app.js."""
    entry = ctx.get("intel", {}).get(row[0]) or {}
    ssvc = entry.get("s") or [None, None, None, None, None]
    score = float(row[3] or 0)
    if not score and isinstance(ssvc[3], (int, float)):
        score = float(ssvc[3])  # CISA ADP score when NVD has not scored it yet
    good_repos = [g for g in entry.get("g") or [] if "bait" not in (g[5] or [])]
    return {
        "c": score,
        "kev": bool(row[4]),
        "e": row[5] if isinstance(row[5], (int, float)) else 0.0,
        "poc": row[0] in ctx.get("poc", set()) or bool(good_repos) or ssvc[0] == "poc",
        "weap": bool(entry.get("m") or entry.get("n")),
        "active": ssvc[0] == "active",
        "auto": ssvc[1] == "yes" and ssvc[2] == "total",
        "patch": bool(entry.get("f")),
    }


def priority(row: list, ctx: dict) -> int:
    """Mirror of prio() in site/app.js. Keep the two in sync."""
    return priority_reason(row, ctx)[0]


def priority_reason(row: list, ctx: dict) -> tuple[int, str]:
    f = facts(row, ctx)
    c, e = f["c"], f["e"]
    if f["kev"]:
        return 1, "on CISA KEV"
    if f["active"]:
        return 1, "CISA says it is exploited"
    if f["weap"] and (c >= 7 or e >= 0.1):
        return 1, "Metasploit/Nuclei can already hit it"
    if f["poc"] and e >= 0.1:
        return 1, "public exploit, high EPSS"
    if c >= 9 or (c >= 7 and (f["poc"] or e >= 0.05)) or f["weap"] or f["auto"]:
        return 2, "this week"
    if c >= 7:
        return 3, "planned"
    return 4, "track"


def summarize(manifest: dict, rows: list[list], ctx: dict) -> dict:
    patch_now = [r for r in rows if priority(r, ctx) == 1]
    patch_now.sort(key=lambda r: (str(r[6] or ""), r[5] or 0), reverse=True)
    return {
        "generated_at": manifest.get("generated_at"),
        "window": manifest.get("window"),
        "totals": manifest.get("totals"),
        "patch_now": [
            {
                "id": r[0], "title": r[1], "severity": r[2], "cvss": r[3] or None, "kev": bool(r[4]),
                "epss": r[5], "public_exploit": facts(r, ctx)["poc"], "weaponized": facts(r, ctx)["weap"],
                "why": priority_reason(r, ctx)[1], "date": r[6], "products": r[8],
                "url": f"{SITE_URL}cve/{r[0]}",
            }
            for r in patch_now[:FEED_LIMIT]
        ],
        "manifest": f"{SITE_URL}snapshot/manifest.json",
    }


def rss(summary: dict) -> str:
    now = format_datetime(datetime.now(timezone.utc))
    items = []
    for item in summary["patch_now"]:
        bits = [item["why"][:1].upper() + item["why"][1:]]
        if item["cvss"]:
            bits.append(f"CVSS {item['cvss']:.1f}")
        if item["epss"] is not None:
            bits.append(f"EPSS {item['epss'] * 100:.1f}%")
        try:
            pub = format_datetime(datetime.fromisoformat(str(item["date"])[:10]).replace(tzinfo=timezone.utc))
        except ValueError:
            pub = now
        items.append(
            "<item>"
            f"<title>{escape(item['id'])}: {escape(str(item['title'])[:160])}</title>"
            f"<link>{escape(item['url'])}</link><guid isPermaLink=\"true\">{escape(item['url'])}</guid>"
            f"<pubDate>{pub}</pubDate><description>{escape(' · '.join(bits))}</description>"
            "</item>"
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>'
        "<title>SubZer0 · Patch now</title>"
        f"<link>{SITE_URL}</link>"
        "<description>CVEs that are being exploited, are weaponized in Metasploit/Nuclei, or have public exploit code with a high EPSS. Updated every 6 hours.</description>"
        f"<lastBuildDate>{now}</lastBuildDate>{''.join(items)}</channel></rss>\n"
    )


def build(site: Path, snapshot: Path, out: Path, archive: Path | None = None) -> None:
    verifier.validate_snapshot(snapshot)
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(site, out)
    shutil.copytree(snapshot, out / "snapshot")
    shell = (out / "index.html").read_text(encoding="utf-8")
    (out / "404.html").write_text(seo.render(shell, site_url=SITE_URL, path="", title="Not found · SubZer0",
                                             desc="This page is not in the SubZer0 snapshot.", robots="noindex"), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    manifest, rows, ctx = load_index(snapshot)
    summary = summarize(manifest, rows, ctx)
    (out / "api").mkdir(exist_ok=True)
    (out / "api" / "latest.json").write_text(json.dumps(summary, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (out / "feed.xml").write_text(rss(summary), encoding="utf-8")
    brief_bytes = brief.write(out, manifest, rows, ctx, _read_verified(snapshot, manifest.get("intel")), facts, priority)
    if brief_bytes > brief.MAX_BYTES:
        raise SystemExit(f"brief/briefing.json is {brief_bytes:,} bytes, over the {brief.MAX_BYTES:,} budget")
    pages = write_seo(out, shell, snapshot, manifest, rows, ctx, summary, archive if archive is not None else ROOT / "public" / "archive")
    print(f"Built {out}: {len(rows)} CVEs, {len(summary['patch_now'])} in the patch-now feed, {pages} static CVE pages, briefing {brief_bytes:,} bytes")


def cve_api(rec: dict, row: list | None, prio, fx, archived_at: str | None = None) -> dict:
    """Small per-CVE JSON (api/cve/<id>.json) for the Telegram bot and other lightweight clients."""
    kev = rec.get("kev") if isinstance(rec.get("kev"), dict) else {}
    v, prod = str(kev.get("vendor") or "").strip(), str(kev.get("product") or "").strip()
    product = (prod if v and prod.lower().startswith(v.lower()) else " ".join(x for x in (v, prod) if x)) \
        or (str(row[8]) if row and len(row) > 8 and row[8] else "")
    fx = fx or {}
    score = float(fx.get("c") or 0)
    sev = (row[2] if row else rec.get("sev")) or "unknown"
    if sev in ("unknown", "none") and score:  # CISA ADP score when NVD has not rated it yet
        sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    out = {
        "id": rec["id"],
        "title": str(rec.get("title") or "")[:200],
        "desc": str(rec.get("desc") or "")[:600],
        "severity": sev,
        "cvss": score or None,
        "epss": row[5] if row and isinstance(row[5], (int, float)) else None,
        "kev": bool(row[4]) if row else bool(rec.get("kev")),
        "public_exploit": bool(fx.get("poc")),
        "weaponized": bool(fx.get("weap")),
        "priority": prio[0] if prio else None,
        "why": prio[1] if prio else "",
        "published": seo.dates(rec)[0],
        "products": product[:120],
        "cwe": [c for c in rec.get("cwe") or [] if isinstance(c, str) and re.fullmatch(r"CWE-\d{1,5}", c)][:4],
        "url": f"{SITE_URL}cve/{rec['id']}",
    }
    if archived_at:
        out["archived"] = str(archived_at)[:10]
    return out


def hub_item(rec: dict, row: list | None, prio, fx: dict | None, archived: bool = False) -> dict:
    """Compact view of one CVE for vendor/product/weekly pages and share cards."""
    kev = rec.get("kev") if isinstance(rec.get("kev"), dict) else {}
    pairs = [(a.get("vendor") or "", a.get("product") or "") for a in rec.get("affected") or [] if isinstance(a, dict)][:30]
    if kev.get("vendor") or kev.get("product"):
        pairs.append((kev.get("vendor") or "", kev.get("product") or ""))
    if row and len(row) > 8 and row[8]:
        pairs.append(("", str(row[8])))
    fx = fx or {}
    return {"id": rec["id"], "title": str(rec.get("title") or "")[:300], "sev": seo.severity(rec, fx).lower(),
            "score": float(fx.get("c") or rec.get("score") or 0) or None,
            "epss": row[5] if row and isinstance(row[5], (int, float)) else None,
            "kev": bool(kev) or bool(row and row[4]), "p": prio[0] if prio else None, "why": prio[1] if prio else "",
            "date": seo.dates(rec)[0], "wdate": max(seo.dates(rec)[0], str(kev.get("date_added") or "")[:10], str(rec.get("window_date") or "")[:10]), "pairs": pairs, "weap": bool(fx.get("weap")), "poc": bool(fx.get("poc")), "archived": archived,
            "cwe": [c for c in rec.get("cwe") or [] if isinstance(c, str) and re.fullmatch(r"CWE-\d{1,5}", c)][:6]}


def llms_txt(manifest: dict, hubs: dict, count: int) -> str:
    """Plain-text map of the site for AI assistants and answer engines (llmstxt.org)."""
    t = manifest.get("totals") or {}
    top = sorted([(f"product/{k}", v) for k, v in hubs["products"].items()] + [(f"vendor/{k}", v) for k, v in hubs["vendors"].items()],
                 key=lambda kv: -len(kv[1]["items"]))[:15]
    weak = list(hubs.get("weaknesses") or {})[:12]
    lines = ["# SubZer0", "",
             "> Free CVE tracker that ranks the last 30 days of vulnerabilities by what to patch first, using CISA KEV, "
             "FIRST EPSS, public exploits (Exploit-DB, Metasploit, Nuclei) and CVSS. Data refreshes every 6 hours.", "",
             f"Snapshot {str(manifest.get('generated_at') or '')[:16]} UTC: {t.get('cves') or 0:,} CVEs in the live window, "
             f"{t.get('known_exploited') or 0} on CISA KEV, {count:,} CVE pages including the archive.", "",
             "## Key pages", "",
             f"- [CVE briefing]({SITE_URL}): what to patch today",
             f"- [Research]({SITE_URL}research): search and filter every recent CVE",
             f"- [Vendors and products]({SITE_URL}vendors): CVEs grouped by vendor and product",
             f"- [Weekly recaps]({SITE_URL}weekly): the vulnerabilities that mattered each week",
             f"- [Vulnerability types]({SITE_URL}weaknesses): common weaknesses (CWE) explained with live CVEs",
             f"- [About]({SITE_URL}about): sources and ranking method", "",
             "## Popular vendors and products", ""]
    lines += [f"- [{v['name']}]({SITE_URL}{p}): {len(v['items']):,} CVEs" for p, v in top]
    if weak:
        lines += ["", "## Vulnerability types", ""]
        lines += [f"- [{hub.CWE[c][0]} ({c})]({SITE_URL}weakness/{c.lower()})" for c in weak]
    lines += ["", "## Data (JSON, free, no key)", "",
              f"- [{SITE_URL}api/latest.json]({SITE_URL}api/latest.json): today's patch-now list and newest CVEs",
              f"- {SITE_URL}api/cve/CVE-YYYY-NNNN.json: one CVE with CVSS, EPSS, KEV status, exploits and priority",
              f"- [{SITE_URL}api/hubs.json]({SITE_URL}api/hubs.json): weekly recap and vendor/product index",
              f"- [{SITE_URL}feed.xml]({SITE_URL}feed.xml): RSS feed of patch-now CVEs", "",
              "## Optional", "",
              "- [Telegram channel](https://t.me/RootAccessClub): daily alerts and weekly digest", ""]
    return "\n".join(lines)


def write_seo(out: Path, shell: str, snapshot: Path, manifest: dict, rows: list[list], ctx: dict, summary: dict, archive: Path) -> int:
    """Crawlable pages: home/tab routes with real titles, one HTML page per CVE, and sitemap.xml."""
    by_id = {r[0]: r for r in rows}
    known = set(by_id)
    totals = manifest.get("totals") or {}
    n = totals.get("cves") or len(rows)
    patch = [(i["id"], f"P1 · {i['why']}", i["title"]) for i in summary["patch_now"]]
    latest = sorted(rows, key=lambda r: str(r[6] or ""), reverse=True)[: seo.LATEST_LINKS]
    latest_items = [(r[0], seo.SEV_LABEL.get(r[2] or "unknown", ""), r[1]) for r in latest]
    home_desc = (f"Free CVE tracker: {n:,} CVEs from the last 30 days, {totals.get('known_exploited', 0)} on CISA KEV, "
                 "ranked by what to patch first with EPSS and public exploits. Updated every 6 hours.")
    intro = (f'<article class="seo wrap"><h1 class="credit-name">SubZer0 · CVE briefing</h1><p class="seo-lede">{seo.esc(home_desc)}</p>'
             + seo.link_list("Patch now", patch) + "</article>")
    (out / "index.html").write_text(seo.render(shell, site_url=SITE_URL, path="", title="SubZer0 · CVE tracker: what to patch first (KEV, EPSS, exploits)",
                                               desc=home_desc, ld=seo.home_ld(SITE_URL, manifest), panel=("p0", intro)), encoding="utf-8")
    tabs = {
        "research": ("Research every CVE from the last 30 days · SubZer0", f"Search and filter {n:,} recent CVEs by severity, CVSS, EPSS, CISA KEV, public exploit and vendor.",
                     ("p0", '<article class="seo wrap"><h1 class="credit-name">Latest CVEs</h1>' + seo.link_list("Newest", latest_items) + "</article>")),
        "dossier": ("CVE dossier · SubZer0", "Full dossier for a CVE: CVSS, EPSS trend, CISA KEV status, public exploits, affected products and references.", None),
        "terminal": ("CVE terminal · SubZer0", "Query recent CVEs from a terminal: kev:yes, epss>50, sev:critical and more.", None),
        "about": ("About SubZer0", "How SubZer0 collects, verifies and ranks CVEs from NVD, GitHub, CISA KEV, FIRST EPSS, Exploit-DB, Metasploit and Nuclei.", None),
    }
    for slug, (title, desc, panel) in tabs.items():
        (out / f"{slug}.html").write_text(seo.render(shell, site_url=SITE_URL, path=slug, title=title, desc=desc, panel=panel), encoding="utf-8")
    cve_dir = out / "cve"
    cve_dir.mkdir(exist_ok=True)
    api_dir = out / "api" / "cve"
    api_dir.mkdir(parents=True, exist_ok=True)

    def put_api(doc: dict) -> None:
        (api_dir / f"{doc['id']}.json").write_text(json.dumps(doc, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    entries: list[tuple[str, str | None]] = [("", manifest.get("generated_at")), ("research", manifest.get("generated_at")), ("about", None)]
    import archive as arch  # local module; imported lazily because it imports this file
    archived = arch.load(archive) if archive.exists() else {}
    live: list[tuple[str, int]] = []  # (day, index) of every live record, read twice to keep memory flat
    items: list[dict] = []
    seen: set[str] = set()
    for day in manifest.get("days") or []:
        records = _read_verified(snapshot, day)
        for rec in records if isinstance(records, list) else []:
            cid = rec.get("id") if isinstance(rec, dict) else None
            if not cid or not seo.CVE_RE.match(cid) or cid in seen:
                continue
            seen.add(cid)
            row = by_id.get(cid)
            fx = facts(row, ctx) if row else None
            items.append(hub_item(rec, row, priority_reason(row, ctx) if row else None, fx))
    known |= set(archived)
    arch_rows = {}
    for cid, rec in sorted(archived.items()):
        if cid in seen or not seo.CVE_RE.match(cid):
            continue
        sig = rec.get("signals") or {}
        row = [cid, rec.get("title"), rec.get("sev"), rec.get("score"), 1 if rec.get("kev") else 0, sig.get("epss"), None, None, ""]
        fx = {"c": rec.get("score") or 0, "poc": bool(sig.get("poc")), "weap": bool(sig.get("weap"))}
        prio = (int(sig["p"]), str(sig.get("why") or "")) if sig.get("p") in (1, 2, 3, 4) else None
        arch_rows[cid] = (row, fx, prio)
        items.append(hub_item(rec, row, prio, fx, archived=True))
    hubs = hub.build(items, window_start=str((manifest.get("window") or {}).get("start") or ""), today=datetime.now(timezone.utc).date(),
                     updated=str(manifest.get("generated_at") or ""))
    links = hubs["links"]
    (out / "api" / "hubs.json").write_text(json.dumps(hub.summary(hubs), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    cards = share_cards.render_all(out, items, hubs) if share_cards else set()
    for path, title, desc, art, ld, lastmod, og in hubs["pages"]:
        (out / f"{path}.html").parent.mkdir(parents=True, exist_ok=True)
        (out / f"{path}.html").write_text(seo.render(shell, site_url=SITE_URL, path=path, title=title, desc=desc, ld=ld, panel=("p0", art),
                                                    image=f"og/{og}.jpg" if og in cards else None), encoding="utf-8")
        entries.append((path, lastmod or manifest.get("generated_at")))
    count = 0
    seen.clear()
    for day in manifest.get("days") or []:
        records = _read_verified(snapshot, day)
        for rec in records if isinstance(records, list) else []:
            cid = rec.get("id") if isinstance(rec, dict) else None
            if not cid or not seo.CVE_RE.match(cid) or cid in seen:
                continue
            seen.add(cid)
            row = by_id.get(cid)
            fx = facts(row, ctx) if row else None
            prio = priority_reason(row, ctx) if row else None
            title, desc = seo.cve_meta(rec, row, prio, fx)
            doc = seo.render(shell, site_url=SITE_URL, path=f"cve/{cid}", title=title, desc=desc, og_type="article",
                             ld=seo.cve_ld(SITE_URL, rec, desc), panel=("p0", seo.cve_article(rec, row, prio, fx, known, links=links.get(cid))),
                             image=f"og/{cid}.jpg" if cid in cards else None)
            (cve_dir / f"{cid}.html").write_text(doc, encoding="utf-8")
            put_api(cve_api(rec, row, prio, fx))
            entries.append((f"cve/{cid}", seo.dates(rec)[1] or None))
            count += 1
    for cid, rec in sorted(archived.items()):
        if cid not in arch_rows:
            continue
        row, fx, prio = arch_rows[cid]
        title, desc = seo.cve_meta(rec, row, prio, fx)
        doc = seo.render(shell, site_url=SITE_URL, path=f"cve/{cid}", title=title, desc=desc, og_type="article",
                         ld=seo.cve_ld(SITE_URL, rec, desc),
                         panel=("p0", seo.cve_article(rec, row, prio, fx, known, archived_at=rec.get("last_seen"), links=links.get(cid))),
                         image=f"og/{cid}.jpg" if cid in cards else None)
        (cve_dir / f"{cid}.html").write_text(doc, encoding="utf-8")
        put_api(cve_api(rec, row, prio, fx, rec.get("last_seen")))
        entries.append((f"cve/{cid}", seo.dates(rec)[1] or None))
        count += 1
    # one sitemap per page type (easier to read in Search Console), tied together by a sitemap index
    pages = [e for e in entries if not e[0].startswith("cve/")]
    cves = [e for e in entries if e[0].startswith("cve/")]
    (out / "sitemap-pages.xml").write_text(seo.sitemap(SITE_URL, pages), encoding="utf-8")
    (out / "sitemap-cves.xml").write_text(seo.sitemap(SITE_URL, cves), encoding="utf-8")
    (out / "sitemap.xml").write_text(seo.sitemap_index(SITE_URL, [("sitemap-pages.xml", manifest.get("generated_at")),
                                                                   ("sitemap-cves.xml", manifest.get("generated_at"))]), encoding="utf-8")
    (out / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}sitemap.xml\n", encoding="utf-8")
    (out / "llms.txt").write_text(llms_txt(manifest, hubs, count), encoding="utf-8")
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "site")
    parser.add_argument("--snapshot", type=Path, default=ROOT / "public" / "snapshot")
    parser.add_argument("--out", type=Path, default=ROOT / "_site")
    args = parser.parse_args()
    build(args.site, args.snapshot, args.out)


if __name__ == "__main__":
    main()
