"""Vendor, product and weekly hub pages for SubZer0.

Every CVE page already exists, but nobody searches for "CVE-2026-12345". People search for
"nginx vulnerabilities" or "this week's critical CVEs". These pages answer those searches with the same
verified data: one page per vendor and per popular product, one recap per ISO week, and two index pages.
They are plain static articles; the app shows them in its side sheet (see STATIC in site/app.js).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import date, timedelta

import seo_pages as seo
from cwe_info import CWE

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unscored": 4}
SEV_CHIP = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "unscored": "none"}
MIN_VENDOR, MIN_PRODUCT, MIN_WEEK, MIN_CWE = 5, 3, 5, 10
LIST_LIMIT, TOP_LIMIT = 200, 10
STATIC_RE = re.compile(r"^(vendors|weekly|weaknesses|(vendor|product)/[a-z0-9][a-z0-9-]{0,60}|week/\d{4}-w\d{2}|weakness/cwe-\d{1,5})$")

# Package ecosystems arrive from the GitHub Advisory Database as "vendors".
ECOSYSTEMS = {"npm": "npm packages", "pip": "PyPI (pip) packages", "go": "Go modules", "nuget": "NuGet packages",
              "maven": "Maven (Java) packages", "composer": "Composer (PHP) packages", "rust": "Rust crates",
              "rubygems": "RubyGems", "erlang": "Erlang/Hex packages", "pub": "Dart/Flutter packages", "swift": "Swift packages"}
DISPLAY = {"ibm": "IBM", "hp": "HP", "hpe": "HPE", "sap": "SAP", "f5": "F5", "linuxfoundation": "Linux Foundation",
           "redhat": "Red Hat", "freerdp": "FreeRDP", "mediatek": "MediaTek", "gitlab": "GitLab", "jetbrains": "JetBrains",
           "imagemagick": "ImageMagick", "wolfssl": "wolfSSL", "openssl": "OpenSSL", "mariadb": "MariaDB", "pfsense": "pfSense",
           "watchguard": "WatchGuard", "freebsd": "FreeBSD", "payloadcms": "Payload CMS", "vllm": "vLLM", "tox-dev": "tox-dev",
           "pyjwt": "PyJWT", "qnap": "QNAP", "tp-link": "TP-Link", "d-link": "D-Link", "zyxel": "Zyxel", "sonicwall": "SonicWall"}
SUFFIXES = re.compile(r"[\s,]+(inc\.?|incorporated|corp\.?|corporation|llc|ltd\.?|limited|gmbh|co\.?|project|software foundation|foundation|team)$", re.I)
# Curated products people actually search for: (slug, name, pattern over "title | vendor product; ...", bot /watch term).
PRODUCTS = [
    ("wordpress", "WordPress", r"\bwordpress\b", "wordpress"),
    ("woocommerce", "WooCommerce", r"\bwoocommerce\b", "woocommerce"),
    ("chrome", "Google Chrome", r"\bgoogle chrome\b|\bchromium\b", "chrome"),
    ("windows", "Microsoft Windows", r"\bmicrosoft windows\b|^windows\b|\bwindows (server|10|11|kernel|smb|ntlm|hyper-v)\b", "windows"),
    ("microsoft-office", "Microsoft Office", r"\bmicrosoft (office|365 apps|excel|word|outlook|powerpoint)\b|\boffice (2016|2019|2021|2024|online server)\b", "office"),
    ("exchange", "Microsoft Exchange", r"\bexchange server\b", "exchange"),
    ("sharepoint", "Microsoft SharePoint", r"\bsharepoint\b", "sharepoint"),
    ("linux-kernel", "Linux kernel", r"\blinux[ _]kernel\b", "linux kernel"),
    ("android", "Android", r"\bandroid\b", "android"),
    ("apple-ios", "Apple iOS & iPadOS", r"\bipados\b|\bapple ios\b", "ios"),
    ("macos", "Apple macOS", r"\bmacos\b", "macos"),
    ("firefox", "Mozilla Firefox", r"\bfirefox\b", "firefox"),
    ("nginx", "nginx", r"\bnginx\b", "nginx"),
    ("apache-http-server", "Apache HTTP Server", r"\bapache http server\b|\bapache httpd\b|\bhttp_server\b", "apache"),
    ("tomcat", "Apache Tomcat", r"\btomcat\b", "tomcat"),
    ("php", "PHP", r"\bphp php\b|\bphp versions?\b", "php"),
    ("openssl", "OpenSSL", r"\bopenssl\b", "openssl"),
    ("openssh", "OpenSSH", r"\bopenssh\b", "openssh"),
    ("curl", "curl", r"\blibcurl\b|\bcurl curl\b|\bhaxx curl\b", "curl"),
    ("jenkins", "Jenkins", r"\bjenkins\b", "jenkins"),
    ("gitlab", "GitLab", r"\bgitlab\b", "gitlab"),
    ("gitea", "Gitea", r"\bgitea\b", "gitea"),
    ("docker", "Docker", r"\bdocker\b", "docker"),
    ("kubernetes", "Kubernetes", r"\bkubernetes\b", "kubernetes"),
    ("fortinet", "Fortinet", r"\bforti(net|os|gate|web|manager|analyzer|proxy|client|siem|switch|sandbox|mail|voice|portal)\b", "fortinet"),
    ("cisco", "Cisco", r"\bcisco\b", "cisco"),
    ("ivanti", "Ivanti", r"\bivanti\b", "ivanti"),
    ("citrix", "Citrix NetScaler", r"\bcitrix\b|\bnetscaler\b", "citrix"),
    ("vmware", "VMware", r"\bvmware\b|\besxi\b|\bvcenter\b", "vmware"),
    ("palo-alto", "Palo Alto Networks", r"\bpalo alto\b|\bpan-os\b|\bglobalprotect\b", "pan-os"),
    ("sonicwall", "SonicWall", r"\bsonicwall\b", "sonicwall"),
    ("juniper", "Juniper", r"\bjuniper\b|\bjunos\b", "juniper"),
    ("f5-big-ip", "F5 BIG-IP", r"\bbig-ip\b", "big-ip"),
    ("oracle", "Oracle", r"\boracle\b", "oracle"),
    ("mysql", "MySQL", r"\bmysql\b", "mysql"),
    ("postgresql", "PostgreSQL", r"\bpostgres(ql)?\b", "postgresql"),
    ("redis", "Redis", r"\bredis\b", "redis"),
    ("mongodb", "MongoDB", r"\bmongodb\b", "mongodb"),
    ("elastic", "Elastic (Elasticsearch, Kibana)", r"\belasticsearch\b|\bkibana\b|\belastic\b", "elastic"),
    ("grafana", "Grafana", r"\bgrafana\b", "grafana"),
    ("nodejs", "Node.js", r"\bnode\.js\b|\bnodejs\b", "node.js"),
    ("django", "Django", r"\bdjango\b", "django"),
    ("laravel", "Laravel", r"\blaravel\b", "laravel"),
    ("spring", "Spring", r"\bspring (framework|boot|security|cloud)\b|\bvmware spring\b", "spring"),
    ("drupal", "Drupal", r"\bdrupal\b", "drupal"),
    ("joomla", "Joomla", r"\bjoomla\b", "joomla"),
    ("magento", "Adobe Commerce / Magento", r"\bmagento\b|\badobe commerce\b", "magento"),
    ("moodle", "Moodle", r"\bmoodle\b", "moodle"),
    ("tp-link", "TP-Link", r"\btp-?link\b", "tp-link"),
    ("d-link", "D-Link", r"\bd-?link\b", "d-link"),
    ("totolink", "TOTOLINK", r"\btotolink\b", "totolink"),
    ("tenda", "Tenda", r"\btenda (ac|ax|f|fh|g|i|o|w|tx)\d|\btenda tenda\b|\bshenzhen tenda\b", "tenda"),
    ("netgear", "NETGEAR", r"\bnetgear\b", "netgear"),
    ("zyxel", "Zyxel", r"\bzyxel\b", "zyxel"),
    ("hikvision", "Hikvision", r"\bhikvision\b", "hikvision"),
    ("qnap", "QNAP", r"\bqnap\b", "qnap"),
    ("synology", "Synology", r"\bsynology\b", "synology"),
    ("wireshark", "Wireshark", r"\bwireshark\b", "wireshark"),
    ("imagemagick", "ImageMagick", r"\bimagemagick\b", "imagemagick"),
    ("ffmpeg", "FFmpeg", r"\bffmpeg\b", "ffmpeg"),
    ("vim", "Vim", r"\bvim vim\b|\bin vim\b|^vim\b", "vim"),
    ("langflow", "Langflow", r"\blangflow\b", "langflow"),
    ("vllm", "vLLM", r"\bvllm\b", "vllm"),
    ("ollama", "Ollama", r"\bollama\b", "ollama"),
    ("n8n", "n8n", r"\bn8n\b", "n8n"),
]
_PRODUCT_RE = [(slug, name, re.compile(pat, re.I), term) for slug, name, pat, term in PRODUCTS]


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")[:60]


def vendor_key(raw) -> str:
    name = SUFFIXES.sub("", str(raw or "").strip()).strip().lower()
    return "" if name in ("", "n/a", "na", "unknown", "-", "*", "none") else name


def vendor_display(key: str, seen: Counter) -> str:
    if key in ECOSYSTEMS:
        return ECOSYSTEMS[key]
    if key in DISPLAY:
        return DISPLAY[key]
    best = SUFFIXES.sub("", seen.most_common(1)[0][0]).strip() if seen else key
    return best if any(c.isupper() for c in best) else best[:1].upper() + best[1:]


def haystack(item: dict) -> str:
    pairs = "; ".join(f"{v} {p}" for v, p in item.get("pairs") or [])
    return f"{item.get('title') or ''} | {pairs}"


def sev_key(item: dict) -> str:
    sev = str(item.get("sev") or "").lower()
    return sev if sev in SEV_ORDER else "unscored"


def rank(item: dict) -> tuple:
    """Most urgent first: priority, KEV, weaponized, EPSS, CVSS, newest."""
    return (item.get("p") or 9, 0 if item.get("kev") else 1, 0 if item.get("weap") else 1,
            -(item.get("epss") or 0), -(item.get("score") or 0), _neg_date(item.get("date")))


def _neg_date(d) -> int:
    try:
        return -date.fromisoformat(str(d)[:10]).toordinal()
    except ValueError:
        return 0


def newest(items: list[dict]) -> list[dict]:
    return sorted(items, key=lambda i: (str(i.get("date") or ""), i["id"]), reverse=True)


def stats(items: list[dict]) -> dict:
    return {"n": len(items), "p1": sum(1 for i in items if i.get("p") == 1),
            "crit": sum(1 for i in items if sev_key(i) == "critical"), "kev": sum(1 for i in items if i.get("kev")),
            "exp": sum(1 for i in items if i.get("weap") or i.get("poc")),
            "last": max((str(i.get("date") or "") for i in items), default="")}


# ---------- grouping ----------

def group(items: list[dict]) -> tuple[dict, dict, dict]:
    """Return (products, vendors, weeks): slug -> {"name", "term", "items"} (weeks keyed by 2026-w43)."""
    products: dict[str, dict] = {}
    for slug, name, rx, term in _PRODUCT_RE:
        hits = [i for i in items if rx.search(haystack(i))]
        if len(hits) >= MIN_PRODUCT:
            products[slug] = {"name": name, "term": term, "items": hits}
    by_vendor: dict[str, list] = defaultdict(list)
    seen: dict[str, Counter] = defaultdict(Counter)
    for item in items:
        keys = set()
        for raw_v, _p in item.get("pairs") or []:
            key = vendor_key(raw_v)
            if key:
                keys.add(key)
                seen[key][str(raw_v).strip()] += 1
        for key in keys:
            by_vendor[key].append(item)
    vendors: dict[str, dict] = {}
    for key, hits in by_vendor.items():
        slug = slugify(key)
        if len(hits) < MIN_VENDOR or not slug or slug in products:
            continue
        name = vendor_display(key, seen[key])
        vendors[slug] = {"key": key, "name": name, "term": key if key not in ECOSYSTEMS else "", "items": hits,
                         "products": Counter(p for i in hits for v, p in i.get("pairs") or [] if vendor_key(v) == key and p).most_common(12)}
    weeks: dict[str, dict] = defaultdict(lambda: {"items": []})
    for item in items:
        try:
            y, w, _ = date.fromisoformat(str(item.get("wdate") or item.get("date") or "")[:10]).isocalendar()
        except ValueError:
            continue
        weeks[f"{y}-w{w:02d}"]["items"].append(item)
    weeks = {k: v for k, v in weeks.items() if len(v["items"]) >= MIN_WEEK}
    return products, vendors, weeks


def week_range(key: str) -> tuple[date, date]:
    y, w = int(key[:4]), int(key[6:])
    start = date.fromisocalendar(y, w, 1)
    return start, start + timedelta(days=6)


def week_label(key: str) -> str:
    a, b = week_range(key)
    span = f"{a:%b} {a.day}–{b.day}" if a.month == b.month else f"{a:%b} {a.day} – {b:%b} {b.day}"
    return f"Week {int(key[6:])}, {key[:4]} ({span})"


# ---------- HTML pieces ----------

def chip(item: dict) -> str:
    k = sev_key(item)
    return f'<span class="chip {SEV_CHIP[k]}">{k if k != "unscored" else "n/a"}</span>'


def meta_line(item: dict) -> str:
    bits = []
    if item.get("score"):
        bits.append(f"CVSS {float(item['score']):.1f}")
    if isinstance(item.get("epss"), (int, float)):
        bits.append(f"EPSS {item['epss'] * 100:.1f}%")
    if item.get("kev"):
        bits.append("KEV")
    if item.get("weap"):
        bits.append("weaponized")
    elif item.get("poc"):
        bits.append("public exploit")
    if item.get("p"):
        bits.append(f"P{item['p']}")
    if item.get("date"):
        bits.append(str(item["date"])[:10])
    return " · ".join(bits)


def rows_html(items: list[dict]) -> str:
    lis = "".join(
        f'<li><a class="hub-row{" p1" if i.get("p") == 1 else ""}" href="cve/{seo.esc(i["id"])}">{chip(i)}'
        f'<b>{seo.esc(i["id"])}</b><span class="hub-m">{seo.esc(meta_line(i))}</span>'
        f'<span class="hub-t">{seo.esc(seo.clip(i.get("title") or "", 150))}</span></a></li>' for i in items)
    return f'<ul class="hub-list">{lis}</ul>'


def stat_html(s: dict, extra: str = "") -> str:
    cells = [("CVEs", s["n"]), ("Patch now", s["p1"]), ("Critical", s["crit"]), ("On CISA KEV", s["kev"]), ("With exploit", s["exp"])]
    return '<div class="hub-stats">' + "".join(f'<div><b>{v:,}</b><span>{seo.esc(k)}</span></div>' for k, v in cells) + "</div>" + extra


def cta_html(term: str = "", name: str = "") -> str:
    watch = (f'<span>Use <code>/watch {seo.esc(term)}</code> on <a href="https://t.me/SubZer0Robot" rel="noopener">@SubZer0Robot</a> '
             f'to get a DM when a {seo.esc(name)} CVE lands in patch now.</span>') if term else \
        '<span>Ask <a href="https://t.me/SubZer0Robot" rel="noopener">@SubZer0Robot</a> about any CVE with <code>/cve</code>.</span>'
    return ('<aside class="hub-cta"><a class="hub-cta-main" href="https://t.me/RootAccessClub" rel="noopener">'
            '<b>🔔 Get patch-now alerts on Telegram</b><small>Exploited and weaponized CVEs, the moment they land · @RootAccessClub</small>'
            f'<span class="go">Join →</span></a>{watch}</aside>')


def crumbs(*parts: tuple[str, str | None]) -> str:
    out = ['<a href="./">SubZer0</a>']
    for label, href in parts:
        out.append(f'<a href="{seo.esc(href)}">{seo.esc(label)}</a>' if href else f"<span>{seo.esc(label)}</span>")
    return '<nav class="seo-crumbs" aria-label="Breadcrumb">' + " › ".join(out) + "</nav>"


def article(path: str, title: str, inner: str) -> str:
    return f'<article class="seo wrap hub" data-static="{seo.esc(path)}" data-title="{seo.esc(title)}">{inner}</article>'


def collection_ld(site_url: str, path: str, name: str, desc: str, trail: list[tuple[str, str]], items: list[dict]) -> list:
    url = site_url + path
    crumbs_ld = [{"@type": "ListItem", "position": n + 1, "name": label, "item": site_url + href}
                 for n, (label, href) in enumerate([("SubZer0", "")] + trail)]
    return [{"@context": "https://schema.org", "@type": "CollectionPage", "name": name, "description": desc, "url": url,
             "isPartOf": {"@type": "WebSite", "name": "SubZer0", "url": site_url}, "publisher": seo.org(site_url),
             "mainEntity": {"@type": "ItemList", "numberOfItems": len(items), "itemListElement": [
                 {"@type": "ListItem", "position": n + 1, "url": f"{site_url}cve/{i['id']}", "name": i["id"]} for n, i in enumerate(items[:20])]}},
            {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": crumbs_ld}]


# ---------- insights: unique, data-driven context per page ----------

def _when(i: dict) -> str:
    return str(i.get("wdate") or i.get("date") or "")[:10]


def cwe_counts(items: list[dict]) -> Counter:
    return Counter(c for i in items for c in set(i.get("cwe") or []) if c in CWE)


def _pct(a: int, b: int) -> str:
    return f"{round(100 * a / b)}%" if b else "0%"


def insights(name: str, items: list[dict], today: date, kind: str = "topic", products: list | None = None) -> list[str]:
    """3-5 short facts that only this page can say (HTML)."""
    out: list[str] = []
    s = stats(items)
    if kind != "week":
        d7, d14 = (today - timedelta(days=7)).isoformat(), (today - timedelta(days=14)).isoformat()
        now = sum(1 for i in items if _when(i) > d7)
        before = sum(1 for i in items if d14 < _when(i) <= d7)
        if now or before:
            trend = "up from" if now > before else "down from" if now < before else "same as"
            out.append(f"<b>{now}</b> new {seo.esc(name)} CVE{'s' if now != 1 else ''} in the last 7 days, {trend} {before} the week before.")
    kev = sorted((i for i in items if i.get("kev")), key=lambda i: _when(i), reverse=True)
    if kev:
        out.append(f"<b>{len(kev)}</b> {'are' if len(kev) != 1 else 'is'} exploited in the wild (CISA KEV). Newest: "
                   f'<a href="cve/{seo.esc(kev[0]["id"])}">{seo.esc(kev[0]["id"])}</a>, added {seo.esc(_when(kev[0]))}.')
    elif s["exp"]:
        out.append(f"None are on CISA KEV yet, but <b>{s['exp']}</b> {'have' if s['exp'] != 1 else 'has'} public exploit code.")
    cw = cwe_counts(items)
    if cw:
        top = cw.most_common(2)
        bits = [f'<a href="weakness/{c.lower()}">{seo.esc(CWE[c][0])}</a> ({_pct(n, s["n"])})' for c, n in top]
        out.append("Most common weakness: " + " and ".join(bits) + ".")
    if products:
        p = [f"{seo.esc(n)} ({c})" for n, c in products[:3] if n.lower() != name.lower() and c >= 3]
        if p:
            out.append("Most affected: " + ", ".join(p) + ".")
    hot = max((i for i in items if isinstance(i.get("epss"), (int, float))), key=lambda i: i["epss"], default=None)
    if hot and hot["epss"] >= 0.01:
        out.append(f'Highest exploit probability (EPSS): <a href="cve/{seo.esc(hot["id"])}">{seo.esc(hot["id"])}</a> at {hot["epss"] * 100:.1f}%.')
    return out[:5]


def glance_html(facts: list[str]) -> str:
    return ('<ul class="hub-glance">' + "".join(f"<li>{f}</li>" for f in facts) + "</ul>") if facts else ""


def faq_items(name: str, items: list[dict], kind: str = "topic") -> list[tuple[str, str]]:
    """Questions people ask, answered from the live data (plain text, reused for FAQPage JSON-LD)."""
    s = stats(items)
    ranked = sorted(items, key=rank)
    kev = [i for i in ranked if i.get("kev")]
    first = ranked[0] if ranked else None
    qa = []
    if kind == "week":
        qa.append((f"What were the most important vulnerabilities in {name}?",
                   (f"{first['id']} tops the list" + (f" ({first['why']})" if first.get("why") else "") + ". " if first else "")
                   + f"SubZer0 tracked {s['n']:,} CVEs that week: {s['p1']} patch-now, {s['crit']} critical and {s['kev']} on CISA KEV."))
        if kev:
            qa.append((f"Which vulnerabilities were exploited in {name}?",
                       f"{len(kev)} on CISA KEV: " + ", ".join(i["id"] for i in kev[:5]) + ("…" if len(kev) > 5 else "") + "."))
        return qa
    qa.append((f"Is {name} being exploited right now?",
               (f"Yes. {len(kev)} {name} CVE{'s are' if len(kev) != 1 else ' is'} on the CISA Known Exploited Vulnerabilities list, "
                f"most recently {kev[0]['id']}." if kev else
                f"No {name} CVE in SubZer0's data is on the CISA KEV list right now"
                + (f", but {s['exp']} have public exploit code." if s["exp"] else "."))))
    if first:
        bits = [b for b in (f"CVSS {first['score']:.1f}" if first.get("score") else "",
                            f"EPSS {first['epss'] * 100:.1f}%" if isinstance(first.get("epss"), (int, float)) else "",
                            "on CISA KEV" if first.get("kev") else "") if b]
        qa.append((f"Which {name} vulnerability should I patch first?",
                   f"{first['id']}" + (f" ({', '.join(bits)})" if bits else "") + (f": {first['why']}." if len(first.get("why") or "") > 12 else ".")
                   + (f" {s['p1']} {name} CVE{'s are' if s['p1'] != 1 else ' is'} marked patch now." if s["p1"] else
                      f" None of the {name} CVEs is marked patch now yet.")))
    qa.append((f"How many {name} vulnerabilities are there?",
               f"SubZer0 tracks {s['n']:,} {name} CVEs from the last 30 days plus its archive of notable CVEs: "
               f"{s['crit']} critical, {s['kev']} exploited in the wild. Newest: {s['last'] or 'n/a'}."))
    return qa


def faq_html(qa: list[tuple[str, str]]) -> str:
    return ('<section class="hub-faq"><h2>Questions</h2>' +
            "".join(f"<h3>{seo.esc(q)}</h3><p>{seo.esc(a)}</p>" for q, a in qa) + "</section>") if qa else ""


def faq_ld(qa: list[tuple[str, str]]) -> dict:
    return {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [
        {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in qa]}


def updated_html(updated: str) -> str:
    if not updated:
        return ""
    return (f'<p class="hub-updated">Updated <time datetime="{seo.esc(updated)}">{seo.esc(updated[:16].replace("T", " "))} UTC</time>'
            " · data refreshed every 6 hours</p>")


def weakness_links(items: list[dict], limit: int = 8) -> str:
    cw = cwe_counts(items).most_common(limit)
    return ("<h2>Common weaknesses</h2><div class=\"hub-tags\">" + "".join(
        f'<a href="weakness/{c.lower()}">{seo.esc(CWE[c][0])} <i>{n}</i></a>' for c, n in cw) + "</div>") if cw else ""


# ---------- pages ----------

def topic_page(kind: str, slug: str, t: dict, others: list[tuple[str, str, int]], today: date, updated: str = "") -> tuple[str, str, str, str, list]:
    """Return (path, title, desc, article) for a vendor or product page."""
    items, name = t["items"], t["name"]
    s = stats(items)
    path = f"{kind}/{slug}"
    title = f"{name} vulnerabilities (CVEs): what to patch first · SubZer0"
    desc = seo.clip(f"{s['n']:,} {name} CVEs tracked by SubZer0: {s['p1']} patch-now, {s['crit']} critical, {s['kev']} on CISA KEV. "
                    "Ranked by real exploitation, EPSS and CVSS. Updated every 6 hours.", 158)
    urgent = [i for i in sorted(items, key=rank) if (i.get("p") or 9) <= 2][:TOP_LIMIT]
    listed = newest(items)[:LIST_LIMIT]
    prods = t.get("products") or []
    parts = [crumbs(("Vendors", "vendors"), (name, None)),
             f'<h1 class="credit-name">{seo.esc(name)} vulnerabilities</h1>',
             f'<p class="seo-lede">Every {seo.esc(name)} CVE SubZer0 is tracking, from the live 30-day window and the archive, ranked by what to patch first.'
             f'{" Newest: " + seo.esc(s["last"]) + "." if s["last"] else ""}</p>',
             updated_html(updated), stat_html(s),
             glance_html(insights(name, items, today, products=prods or Counter(p for i in items for _v, p in i.get("pairs") or [] if p).most_common(4)))]
    if prods:
        parts.append("<h2>Products</h2><div class=\"hub-tags\">" + "".join(f'<span>{seo.esc(p)} <i>{c}</i></span>' for p, c in prods) + "</div>")
    if urgent:
        parts.append(f"<h2>Patch first</h2>{rows_html(urgent)}")
    parts.append(cta_html(t.get("term") or "", name))
    more = f' <a href="research?q={seo.esc(t["term"])}">Filter live in Research →</a>' if t.get("term") else ""
    parts.append(f'<h2>All {seo.esc(name)} CVEs · {s["n"]:,}</h2>'
                 f'<p class="hub-note">Newest first{" (latest " + str(LIST_LIMIT) + " shown)" if s["n"] > LIST_LIMIT else ""}.{more}</p>{rows_html(listed)}')
    parts.append(weakness_links(items))
    qa = faq_items(name, items)
    parts.append(faq_html(qa))
    if others:
        parts.append("<h2>More vendors &amp; products</h2><div class=\"hub-tags\">" +
                     "".join(f'<a href="{seo.esc(h)}">{seo.esc(n)} <i>{c}</i></a>' for h, n, c in others) + "</div>")
    return path, title, desc, article(path, title, "".join(parts)), qa


def index_page(products: dict, vendors: dict) -> tuple[str, str, str, str]:
    path = "vendors"
    title = "CVEs by vendor and product · SubZer0"
    desc = (f"Browse recent vulnerabilities for {len(products) + len(vendors)} vendors and products, from WordPress and Chrome to "
            "Fortinet and Cisco, each ranked by what to patch first.")

    def block(kind: str, d: dict) -> str:
        ordered = sorted(d.items(), key=lambda kv: (-len(kv[1]["items"]), kv[1]["name"].lower()))
        return '<ul class="hub-index">' + "".join(
            f'<li><a href="{kind}/{seo.esc(slug)}"><b>{seo.esc(t["name"])}</b><span>{len(t["items"]):,} CVEs'
            f'{" · " + str(stats(t["items"])["p1"]) + " patch now" if stats(t["items"])["p1"] else ""}</span></a></li>' for slug, t in ordered) + "</ul>"
    eco = {k: v for k, v in vendors.items() if k in ECOSYSTEMS}
    ven = {k: v for k, v in vendors.items() if k not in ECOSYSTEMS}
    inner = (crumbs(("Vendors", None)) + '<h1 class="credit-name">CVEs by vendor &amp; product</h1>'
             f'<p class="seo-lede">{seo.esc(desc)}</p>' + "<h2>Popular products</h2>" + block("product", products)
             + "<h2>Vendors</h2>" + block("vendor", ven) + (("<h2>Package ecosystems</h2>" + block("vendor", eco)) if eco else "")
             + cta_html())
    return path, title, desc, article(path, title, inner)


def week_page(key: str, items: list[dict], keys: list[str], window_start: str, today: date, topics: list[tuple[str, str, dict]],
              updated: str = "") -> tuple[str, str, str, str, list]:
    a, b = week_range(key)
    label = week_label(key)
    partial = window_start and a.isoformat() < window_start[:10]
    live = today <= b
    s = stats(items)
    path = f"week/{key}"
    title = f"{label}: top CVEs to patch · SubZer0"
    desc = seo.clip(f"{label}: {s['n']:,} {'notable ' if partial else ''}CVEs, {s['p1']} patch-now, {s['crit']} critical, {s['kev']} on CISA KEV. "
                    "The vulnerabilities that mattered, ranked.", 158)
    top = sorted(items, key=rank)[:TOP_LIMIT]
    kev = [i for i in sorted(items, key=rank) if i.get("kev")][:25]
    weap = [i for i in sorted(items, key=rank) if i.get("weap") and not i.get("kev")][:25]
    crit = [i for i in sorted(items, key=rank) if sev_key(i) == "critical" and not i.get("kev") and not i.get("weap")][:25]
    note = ("This week is still running; the list updates every 6 hours." if live else
            "Older than SubZer0's live 30-day window, so this recap lists the notable CVEs kept in the archive." if partial else "")
    hits = []
    ids = {i["id"] for i in items}
    for href, name, t in topics:
        c = sum(1 for i in t["items"] if i["id"] in ids)
        if c:
            hits.append((href, name, c))
    hits.sort(key=lambda h: -h[2])
    i = keys.index(key)
    nav = '<div class="hub-pager">' + (f'<a href="week/{keys[i + 1]}">← {seo.esc(week_label(keys[i + 1]).split(" (")[0])}</a>' if i + 1 < len(keys) else "<span></span>") \
        + '<a href="weekly">All weeks</a>' + (f'<a href="week/{keys[i - 1]}">{seo.esc(week_label(keys[i - 1]).split(" (")[0])} →</a>' if i > 0 else "<span></span>") + "</div>"
    parts = [crumbs(("Weekly", "weekly"), (label.split(" (")[0], None)),
             f'<h1 class="credit-name">{seo.esc(label.split(" (")[0])}</h1>',
             f'<p class="seo-lede">{seo.esc(label.split("(")[1].rstrip(")"))}: the vulnerabilities that mattered, ranked by what to patch first.</p>',
             updated_html(updated) if live else "",
             stat_html(s, f'<p class="hub-note">{seo.esc(note)}</p>' if note else ""),
             glance_html(insights(label.split(" (")[0], items, today, kind="week", products=[(n, c) for _h, n, c in hits[:4]])),
             f"<h2>Top {len(top)} this week</h2>{rows_html(top)}"]
    if kev:
        parts.append(f"<h2>Exploited in the wild · CISA KEV</h2>{rows_html(kev)}")
    if weap:
        parts.append(f"<h2>Weaponized (Metasploit / Nuclei)</h2>{rows_html(weap)}")
    parts.append(cta_html())
    if crit:
        parts.append(f"<h2>Other critical CVEs</h2>{rows_html(crit)}")
    if hits:
        parts.append("<h2>Most affected this week</h2><div class=\"hub-tags\">" + "".join(f'<a href="{seo.esc(h)}">{seo.esc(n)} <i>{c}</i></a>' for h, n, c in hits[:16]) + "</div>")
    parts.append(weakness_links(items))
    qa = faq_items(label.split(" (")[0], items, kind="week")
    parts.append(faq_html(qa))
    parts.append(nav)
    return path, title, desc, article(path, title, "".join(parts)), qa


def weakness_page(cwe: str, items: list[dict], topics: list[tuple[str, str, dict]], others: list[tuple[str, str, int]], today: date,
                  updated: str = "") -> tuple[str, str, str, str, list]:
    short, what, fix = CWE[cwe]
    s = stats(items)
    path = f"weakness/{cwe.lower()}"
    title = seo.clip(f"{short} ({cwe}): what it is, how to fix it, live CVEs · SubZer0", 90)
    desc = seo.clip(f"What is {short}? {what.split('. ')[0]}. {s['n']:,} recent CVEs, {s['kev']} exploited in the wild.", 158)
    ids = {i["id"] for i in items}
    hits = sorted(((h, n, sum(1 for i in t["items"] if i["id"] in ids)) for h, n, t in topics), key=lambda x: -x[2])
    hits = [h for h in hits if h[2]][:12]
    urgent = [i for i in sorted(items, key=rank) if (i.get("p") or 9) <= 2][:TOP_LIMIT]
    qa = [(f"What is {short}?", what), (f"How do you prevent {short}?", fix)] + faq_items(short, items)[:2]
    parts = [crumbs(("Weaknesses", "weaknesses"), (cwe, None)),
             f'<h1 class="credit-name">{seo.esc(short)}</h1>',
             f'<p class="seo-lede">{seo.esc(cwe)} · {seo.esc(what)}</p>',
             f'<div class="hub-fix"><b>How to prevent it</b><p>{seo.esc(fix)}</p></div>',
             updated_html(updated), stat_html(s),
             glance_html([f for f in insights(short, items, today, products=[(n, c) for _h, n, c in hits[:4]]) if not f.startswith("Most common weakness")])]
    if urgent:
        parts.append(f"<h2>Patch first</h2>{rows_html(urgent)}")
    parts.append(cta_html())
    if hits:
        parts.append("<h2>Most affected</h2><div class=\"hub-tags\">" + "".join(f'<a href="{seo.esc(h)}">{seo.esc(n)} <i>{c}</i></a>' for h, n, c in hits) + "</div>")
    parts.append(f'<h2>Newest {seo.esc(short)} CVEs</h2><p class="hub-note">Newest first (latest {min(LIST_LIMIT, s["n"])} of {s["n"]:,}). '
                 f'Definition: <a href="https://cwe.mitre.org/data/definitions/{cwe[4:]}.html" rel="noopener nofollow">MITRE {seo.esc(cwe)}</a>.</p>'
                 f"{rows_html(newest(items)[:LIST_LIMIT])}")
    parts.append(faq_html(qa[2:]))
    if others:
        parts.append("<h2>Other weaknesses</h2><div class=\"hub-tags\">" + "".join(f'<a href="{seo.esc(h)}">{seo.esc(n)} <i>{c}</i></a>' for h, n, c in others) + "</div>")
    return path, title, desc, article(path, title, "".join(parts)), qa


def weakness_index(cwes: dict) -> tuple[str, str, str, str]:
    path = "weaknesses"
    title = "Vulnerability types explained: XSS, SQL injection, RCE and more · SubZer0"
    desc = "Plain-English explanations of the most common vulnerability types (CWE), how to prevent them, and the live CVEs for each."
    ordered = sorted(cwes.items(), key=lambda kv: -len(kv[1]))
    lis = "".join(f'<li><a href="weakness/{c.lower()}"><b>{seo.esc(CWE[c][0])}</b><span>{c} · {len(v):,} CVEs · {stats(v)["kev"]} exploited</span></a></li>'
                  for c, v in ordered)
    inner = (crumbs(("Weaknesses", None)) + '<h1 class="credit-name">Vulnerability types</h1>' f'<p class="seo-lede">{seo.esc(desc)}</p>'
             f'<ul class="hub-index">{lis}</ul>' + cta_html())
    return path, title, desc, article(path, title, inner)


def weekly_index(weeks: dict, keys: list[str]) -> tuple[str, str, str, str]:
    path = "weekly"
    title = "Weekly CVE recap: the vulnerabilities that mattered · SubZer0"
    desc = "Every week's most important CVEs in one page: exploited in the wild, weaponized, and critical, ranked by what to patch first."
    lis = "".join(f'<li><a href="week/{k}"><b>{seo.esc(week_label(k))}</b><span>{stats(weeks[k]["items"])["n"]:,} CVEs · '
                  f'{stats(weeks[k]["items"])["p1"]} patch now · {stats(weeks[k]["items"])["kev"]} KEV</span></a></li>' for k in keys)
    inner = (crumbs(("Weekly", None)) + '<h1 class="credit-name">Weekly CVE recap</h1>' f'<p class="seo-lede">{seo.esc(desc)}</p>'
             f'<ul class="hub-index wide">{lis}</ul>' + cta_html())
    return path, title, desc, article(path, title, inner)


def build(items: list[dict], *, window_start: str, today: date, updated: str = "") -> dict:
    """All hub pages as {"pages": [(path, title, desc, article, ld, lastmod, og)], "weeks": [...keys], "links": {cve: [(href, name)]}}."""
    products, vendors, weeks = group(items)
    topics = [(f"product/{s}", t["name"], t) for s, t in products.items()] + [(f"vendor/{s}", t["name"], t) for s, t in vendors.items()]
    topics.sort(key=lambda x: -len(x[2]["items"]))
    pages = []
    for kind, d in (("product", products), ("vendor", vendors)):
        for slug, t in d.items():
            others = [(h, n, len(tt["items"])) for h, n, tt in topics if h != f"{kind}/{slug}"][:18]
            path, title, desc, art, qa = topic_page(kind, slug, t, others, today, updated)
            ld = collection_ld(SITE, path, f"{t['name']} vulnerabilities", desc, [("Vendors", "vendors"), (t["name"], path)], sorted(t["items"], key=rank))
            if qa:
                ld.append(faq_ld(qa))
            pages.append((path, title, desc, art, ld, stats(t["items"])["last"], None))
    path, title, desc, art = index_page(products, vendors)
    pages.append((path, title, desc, art, collection_ld(SITE, path, "CVEs by vendor and product", desc, [("Vendors", "vendors")], []), None, None))
    keys = sorted(weeks, reverse=True)
    for key in keys:
        path, title, desc, art, qa = week_page(key, weeks[key]["items"], keys, window_start, today, topics, updated)
        ld = collection_ld(SITE, path, week_label(key), desc, [("Weekly", "weekly"), (week_label(key).split(" (")[0], path)], sorted(weeks[key]["items"], key=rank))
        if qa:
            ld.append(faq_ld(qa))
        pages.append((path, title, desc, art, ld, stats(weeks[key]["items"])["last"], f"week/{key}"))
    path, title, desc, art = weekly_index(weeks, keys)
    pages.append((path, title, desc, art, collection_ld(SITE, path, "Weekly CVE recap", desc, [("Weekly", "weekly")], []), None, None))
    by_cwe: dict[str, list] = defaultdict(list)
    for i in items:
        for c in set(i.get("cwe") or []):
            if c in CWE:
                by_cwe[c].append(i)
    cwes = {c: v for c, v in by_cwe.items() if len(v) >= MIN_CWE}
    wlist = sorted(cwes, key=lambda c: -len(cwes[c]))
    for c in wlist:
        others = [(f"weakness/{o.lower()}", CWE[o][0], len(cwes[o])) for o in wlist if o != c][:16]
        path, title, desc, art, qa = weakness_page(c, cwes[c], topics, others, today, updated)
        ld = collection_ld(SITE, path, f"{CWE[c][0]} ({c})", desc, [("Weaknesses", "weaknesses"), (c, path)], sorted(cwes[c], key=rank))
        ld.append(faq_ld(qa))
        pages.append((path, title, desc, art, ld, stats(cwes[c])["last"], None))
    if cwes:
        path, title, desc, art = weakness_index(cwes)
        pages.append((path, title, desc, art, collection_ld(SITE, path, "Vulnerability types", desc, [("Weaknesses", "weaknesses")], []), None, None))
    links: dict[str, list] = defaultdict(list)
    for href, name, t in topics:
        for i in t["items"]:
            links[i["id"]].append((href, name))
    for key in keys:
        for i in weeks[key]["items"]:
            links[i["id"]].append((f"week/{key}", week_label(key).split(" (")[0] + " recap"))
    for c in wlist:
        for i in cwes[c]:
            links[i["id"]].append((f"weakness/{c.lower()}", CWE[c][0]))
    return {"today": today, "pages": pages, "weeks": {k: weeks[k]["items"] for k in keys}, "products": products, "vendors": vendors,
            "weaknesses": {c: len(cwes[c]) for c in wlist}, "links": dict(links)}


def summary(hubs: dict) -> dict:
    """Small api/hubs.json for the app (briefing card, research hint, dossier links) and the Telegram bot."""
    keys = list(hubs["weeks"])
    week = None
    if keys:
        # early in a new week (Mon/Tue) the last full week is the better recap to point people at
        key = keys[1] if len(keys) > 1 and hubs.get("today") and hubs["today"] < week_range(keys[0])[0] + timedelta(days=2) else keys[0]
        items = hubs["weeks"][key]
        s, label = stats(items), week_label(key)
        week = {"key": key, "path": f"week/{key}", "label": label.split(" (")[0], "span": label.split("(")[1].rstrip(")"),
                "n": s["n"], "p1": s["p1"], "kev": s["kev"], "crit": s["crit"],
                "top": [{"id": i["id"], "title": seo.clip(i.get("title") or "", 120), "sev": sev_key(i), "cvss": i.get("score"),
                         "p": i.get("p"), "why": i.get("why") or "", "kev": bool(i.get("kev"))} for i in sorted(items, key=rank)[:5]]}
    topics = [{"path": f"{kind}/{slug}", "name": t["name"], "term": (t.get("term") or "").lower(), "n": len(t["items"]),
               "p1": stats(t["items"])["p1"]} for kind, d in (("product", hubs["products"]), ("vendor", hubs["vendors"])) for slug, t in d.items()]
    topics.sort(key=lambda t: (-t["p1"], -t["n"]))
    weak = [{"path": f"weakness/{c.lower()}", "id": c, "name": CWE[c][0], "n": n} for c, n in (hubs.get("weaknesses") or {}).items()]
    return {"week": week, "weeks": [{"key": k, "label": week_label(k)} for k in keys[:12]], "topics": topics, "weaknesses": weak}


SITE = "https://iliya-bashrc.github.io/SubZer0/"
