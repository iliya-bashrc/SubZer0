"""Static, crawlable pages for SubZer0 (one per CVE + tab routes + sitemap).

GitHub Pages serves ``cve/CVE-2026-1234.html`` for the clean URL ``cve/CVE-2026-1234``, so every
dossier link the app already uses becomes a real 200 page with its own title, description,
canonical URL, Open Graph tags, JSON-LD and readable content. The app shell boots on top of it
exactly as before; the static article only lives in the Research panel until the app replaces it.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "none": "Unscored", "unknown": "Unscored"}
P_LABEL = {1: "P1 · Patch now", 2: "P2 · This week", 3: "P3 · Planned", 4: "P4 · Track"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
LATEST_LINKS = 300


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def clip(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    if " " in cut[limit // 2 :]:
        cut = cut[: cut.rfind(" ")]
    return cut.rstrip(" ,.;:-") + "…"


def _sub_meta(doc: str, attr: str, name: str, value: str) -> str:
    pattern = re.compile(rf'(<meta {attr}="{re.escape(name)}" content=")[^"]*(")')
    if pattern.search(doc):
        return pattern.sub(lambda m: m.group(1) + esc(value) + m.group(2), doc, count=1)
    return doc.replace("</head>", f'<meta {attr}="{name}" content="{esc(value)}">\n</head>', 1)


def render(shell: str, *, site_url: str, path: str, title: str, desc: str, ld: list | None = None,
           panel: tuple[str, str] | None = None, og_type: str = "website", robots: str | None = None) -> str:
    url = site_url + path
    doc = re.sub(r"<title>.*?</title>", lambda _m: f"<title>{esc(title)}</title>", shell, count=1, flags=re.S)
    doc = _sub_meta(doc, "name", "description", desc)
    doc = _sub_meta(doc, "property", "og:type", og_type)
    doc = _sub_meta(doc, "property", "og:title", title)
    doc = _sub_meta(doc, "property", "og:description", desc)
    doc = _sub_meta(doc, "property", "og:url", url)
    doc = _sub_meta(doc, "property", "og:site_name", "SubZer0")
    doc = _sub_meta(doc, "name", "twitter:title", title)
    doc = _sub_meta(doc, "name", "twitter:description", desc)
    if robots:
        doc = _sub_meta(doc, "name", "robots", robots)
    head = f'<link rel="canonical" href="{esc(url)}">\n'
    for block in ld or []:
        data = json.dumps(block, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
        head += f'<script type="application/ld+json">{data}</script>\n'
    doc = doc.replace("</head>", head + "</head>", 1)
    if panel:
        pid, inner = panel
        doc = re.sub(rf'(<section class="panel" id="{pid}"[^>]*>)(</section>)', lambda m: m.group(1) + inner + m.group(2), doc, count=1)
    return doc


def org(site_url: str) -> dict:
    return {"@type": "Organization", "name": "SubZer0", "url": site_url, "logo": site_url + "icon.svg",
            "sameAs": ["https://github.com/iliya-bashrc/SubZer0", "https://t.me/RootAccessClub"]}


def home_ld(site_url: str, manifest: dict) -> list:
    return [
        {"@context": "https://schema.org", "@type": "WebSite", "name": "SubZer0", "url": site_url,
         "description": "Free CVE tracker that ranks every new vulnerability by what to patch first, using CISA KEV, EPSS and public exploits.",
         "potentialAction": {"@type": "SearchAction", "target": site_url + "research?q={search_term_string}",
                             "query-input": "required name=search_term_string"},
         "publisher": org(site_url)},
        {"@context": "https://schema.org", "@type": "Dataset", "name": "SubZer0 CVE snapshot (last 30 days)",
         "description": "Every CVE published in the last 30 days with CVSS, EPSS, CISA KEV and public exploit signals. SHA-256 verified, refreshed every 6 hours.",
         "url": site_url, "license": "https://github.com/iliya-bashrc/SubZer0/blob/main/LICENSE",
         "isAccessibleForFree": True, "creator": org(site_url), "dateModified": manifest.get("generated_at"),
         "distribution": [{"@type": "DataDownload", "encodingFormat": "application/json", "contentUrl": site_url + "snapshot/manifest.json"},
                          {"@type": "DataDownload", "encodingFormat": "application/json", "contentUrl": site_url + "api/latest.json"}]},
    ]


def severity(rec: dict, fx: dict | None) -> str:
    sev = rec.get("sev") or "unknown"
    score = rec.get("score") or (fx or {}).get("c") or 0
    if sev in ("none", "unknown") and score:
        sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return SEV_LABEL.get(sev, "Unscored")


def _facts_line(rec: dict, row: list | None, prio: tuple[int, str] | None, fx: dict | None) -> list[str]:
    bits = [f"Severity: {severity(rec, fx)}"]
    score = rec.get("score") or (fx or {}).get("c")
    if score:
        bits.append(f"CVSS {float(score):.1f}")
    epss = row[5] if row and isinstance(row[5], (int, float)) else None
    if epss is not None:
        bits.append(f"EPSS {epss * 100:.2f}%")
    if rec.get("kev"):
        bits.append("On CISA KEV")
    if fx and fx.get("weap"):
        bits.append("Weaponized (Metasploit/Nuclei)")
    elif fx and fx.get("poc"):
        bits.append("Public exploit")
    if prio:
        bits.append(P_LABEL[prio[0]])
    return bits


def cve_article(rec: dict, row: list | None, prio: tuple[int, str] | None, fx: dict | None, known: set, archived_at: str | None = None) -> str:
    cid = rec["id"]
    title = rec.get("title") or cid
    desc = rec.get("desc") or title
    kev = rec.get("kev") if isinstance(rec.get("kev"), dict) else None
    attr = f' data-archived="{esc(cid)}"' if archived_at else ""
    out = [f'<article class="seo wrap"{attr} aria-label="{esc(cid)}">',
           f'<nav class="seo-crumbs" aria-label="Breadcrumb"><a href="./">SubZer0</a> › <a href="research">CVEs</a> › <span>{esc(cid)}</span></nav>',
           f'<h1 class="credit-name">{esc(cid)}</h1>',
           f'<p class="seo-lede">{esc(clip(title, 220))}</p>',
           (f'<p class="seo-arch"><b>Archived.</b> This CVE has left SubZer0\'s live 30-day window. Signals below are as of {esc(str(archived_at)[:10])}; check the references for anything newer.</p>' if archived_at else ""),
           '<ul class="seo-facts">' + "".join(f"<li>{esc(b)}</li>" for b in _facts_line(rec, row, prio, fx)) + "</ul>"]
    if prio:
        out.append(f'<p class="seo-why"><b>Why {P_LABEL[prio[0]].split(" ")[0]}:</b> {esc(prio[1])}.</p>')
    out.append(f"<h2>Description</h2><p>{esc(desc)}</p>")
    if kev:
        out.append("<h2>CISA Known Exploited Vulnerability</h2><p>"
                   f"Added {esc(kev.get('date_added'))}, remediation due {esc(kev.get('due_date'))}. "
                   f"Ransomware use: {esc(kev.get('ransomware') or 'Unknown')}. {esc(clip(kev.get('required_action') or '', 400))}</p>")
    aff = [a for a in rec.get("affected") or [] if isinstance(a, dict)][:20]
    if aff:
        out.append("<h2>Affected products</h2><ul>" + "".join(
            f"<li>{esc(a.get('vendor'))} {esc(a.get('product'))}{(' ' + esc(a.get('versions'))) if a.get('versions') else ''}</li>" for a in aff) + "</ul>")
    cwe = [c for c in rec.get("cwe") or [] if isinstance(c, str) and re.fullmatch(r"CWE-\d{1,5}", c)]
    if cwe:
        out.append("<h2>Weakness</h2><ul>" + "".join(
            f'<li><a href="https://cwe.mitre.org/data/definitions/{c[4:]}.html" rel="noopener nofollow">{c}</a></li>' for c in cwe) + "</ul>")
    vec = rec.get("cvss_vector")
    if isinstance(vec, str) and vec.startswith("CVSS:"):
        out.append(f'<h2>CVSS vector</h2><p><code>{esc(vec)}</code></p>')
    refs = [r for r in rec.get("refs") or [] if isinstance(r, dict) and str(r.get("url", "")).startswith("https://")][:25]
    if refs:
        out.append("<h2>References</h2><ul>" + "".join(
            f'<li><a href="{esc(r["url"])}" rel="noopener nofollow">{esc(r.get("label") or r["url"])}</a> <small>{esc(r.get("source") or "")}</small></li>' for r in refs) + "</ul>")
    rel = [c for c in rec.get("related_cves") or [] if isinstance(c, str) and c in known and c != cid][:12]
    if rel:
        out.append("<h2>Related CVEs</h2><ul>" + "".join(f'<li><a href="cve/{c}">{c}</a></li>' for c in rel) + "</ul>")
    pub, mod = dates(rec)
    meta = [f"Published {pub}" if pub else "", f"updated {mod}" if mod and mod != pub else "",
            f"sources: {', '.join(rec.get('sources') or [])}" if rec.get("sources") else ""]
    out.append(f'<p class="seo-meta">{esc(" · ".join(m for m in meta if m))}</p>')
    out.append("</article>")
    return "".join(out)


def dates(rec: dict) -> tuple[str, str]:
    kev = rec.get("kev") if isinstance(rec.get("kev"), dict) else {}
    pub = str(rec.get("published") or kev.get("date_added") or rec.get("window_date") or "")[:10]
    mod = str(rec.get("modified") or "")[:10] or pub
    return pub, mod


def cve_meta(rec: dict, row: list | None, prio, fx) -> tuple[str, str]:
    cid = rec["id"]
    head = clip(rec.get("title") or "", 70 - len(cid))
    title = f"{cid}: {head}" if head else f"{cid} · SubZer0"
    facts = " · ".join(b.replace("Severity: ", "") for b in _facts_line(rec, row, prio, fx)[:4])
    desc = clip(f"{facts}. {rec.get('desc') or rec.get('title') or ''}", 158)
    return title, desc


def cve_ld(site_url: str, rec: dict, desc: str) -> list:
    cid = rec["id"]
    url = f"{site_url}cve/{cid}"
    return [
        {"@context": "https://schema.org", "@type": "TechArticle", "headline": clip(f"{cid}: {rec.get('title') or ''}", 110),
         "description": desc, "url": url, "mainEntityOfPage": url, "identifier": cid,
         "datePublished": dates(rec)[0] or None, "dateModified": dates(rec)[1] or None,
         "author": org(site_url), "publisher": org(site_url), "isAccessibleForFree": True,
         "about": {"@type": "Thing", "name": cid, "sameAs": f"https://www.cve.org/CVERecord?id={cid}"}},
        {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "SubZer0", "item": site_url},
            {"@type": "ListItem", "position": 2, "name": "CVEs", "item": site_url + "research"},
            {"@type": "ListItem", "position": 3, "name": cid, "item": url}]},
    ]


def link_list(title: str, items: list[tuple[str, str, str]]) -> str:
    lis = "".join(f'<li><a href="cve/{esc(i)}">{esc(i)}</a> <span class="chip-txt">{esc(s)}</span> {esc(clip(t, 140))}</li>' for i, s, t in items)
    return f'<h2>{esc(title)}</h2><ul class="seo-list">{lis}</ul>'


def sitemap(site_url: str, entries: list[tuple[str, str | None]]) -> str:
    body = "".join(f"<url><loc>{esc(site_url + p)}</loc>{f'<lastmod>{esc(m[:10])}</lastmod>' if m else ''}</url>" for p, m in entries)
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{body}</urlset>\n'
