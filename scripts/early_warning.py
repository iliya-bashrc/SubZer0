#!/usr/bin/env python3
"""SubZer0 fast lane: what happened since the last full snapshot.

Runs on every deploy (scheduled every ~15 minutes) and writes live/early.json
into the built site. It never touches the SHA-256 verified snapshot; the browser
merges it as a clearly-labelled "live" layer on top.

  * new CVE records from CVE.org (cvelistV5 delta log) and GitHub advisories
  * CISA KEV additions since the snapshot
  * early warning: named / leaked / pre-disclosure vulnerabilities clustered from
    security news and CERT feeds (php2shell-style events show up before NVD has them)

Every source is fail-open: one broken feed never breaks the deploy.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Iterable

SITE_URL = "https://iliya-bashrc.github.io/SubZer0/"
UA = "SubZer0/1.0 (+https://github.com/iliya-bashrc/SubZer0)"
DELTA_LOG = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
CVE_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{id}.json"
CVE_API = "https://cveawg.mitre.org/api/cve/{id}"
GHSA_API = "https://api.github.com/advisories?per_page=100&sort=published&direction=desc"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_ID = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)
CVE_OK = re.compile(r"^CVE-\d{4}-\d{4,}$")

# (display name, url, weight). Weight 2 = CERT / government / vendor PSIRT.
FEEDS: list[tuple[str, str, int]] = [
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml", 2),
    ("CISA News", "https://www.cisa.gov/news.xml", 2),
    ("CERT-EU", "https://cert.europa.eu/publications/security-advisories-rss", 2),
    ("NCSC-NL", "https://advisories.ncsc.nl/rss/advisories", 2),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml", 1),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", 1),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/", 1),
    ("SecurityWeek", "https://www.securityweek.com/feed/", 1),
    ("Security Affairs", "https://securityaffairs.com/feed", 1),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/", 1),
    ("Dark Reading", "https://www.darkreading.com/rss.xml", 1),
    ("Cybersecurity Dive", "https://www.cybersecuritydive.com/feeds/news/", 1),
    ("The Register", "https://www.theregister.com/security/headlines.atom", 1),
    ("watchTowr Labs", "https://labs.watchtowr.com/rss/", 1),
    ("Tenable", "https://www.tenable.com/blog/feed", 1),
    ("Rapid7", "https://www.rapid7.com/blog/rss/", 1),
    ("Huntress", "https://www.huntress.com/blog/rss.xml", 1),
    ("Wiz", "https://www.wiz.io/feed/rss.xml", 1),
    ("Aikido", "https://www.aikido.dev/blog/rss.xml", 1),
]

SIGNALS = [
    ("rce", re.compile(r"\b(rce|remote code execution|code execution|command injection|arbitrary code)\b", re.I), 3),
    ("exploited", re.compile(r"\b(actively exploited|exploited in the wild|in the wild|under (active )?attack|mass exploitation|exploitation (has been )?(reported|observed|detected)|being exploited)\b", re.I), 4),
    ("zero-day", re.compile(r"\b(zero[- ]day|0[- ]day)\b", re.I), 3),
    ("unpatched", re.compile(r"\b(unpatched|no patch|without a patch|patch (is )?(not yet|expected)|emergency (fix|patch|update))\b", re.I), 2),
    ("poc", re.compile(r"\b(proof[- ]of[- ]concept|poc|exploit code|public exploit|exploit (is )?(released|published|available))\b", re.I), 2),
    ("critical", re.compile(r"\b(critical|cvss (score )?(of )?(9\.\d|10(\.0)?))\b", re.I), 1),
    ("unauth", re.compile(r"\b(unauthenticated|pre-auth|without authentication)\b", re.I), 2),
]
URGENT = {"rce", "exploited", "zero-day", "unpatched", "unauth"}
# Named bugs: php2shell, React2Shell, Log4Shell, Citrix Bleed, regreSSHion, ...
NAMED = re.compile(r"\b([A-Za-z][A-Za-z0-9]{1,24}(?:2shell|4shell|shell|bleed|hammer|pwn|jack|leak|ghost|doom|storm))\b", re.I)
NAMED_STOP = {"powershell", "webshell", "webshells", "shell", "reverseshell", "bashshell", "cshell", "nutshell",
              "eggshell", "seashell", "bombshell", "hijack", "hijacks", "carjack", "ransomleak", "dataleak", "subshell",
              "theshell", "ashell", "aishell"}

MAX_FEED_BYTES = 4 * 1024 * 1024
FEED_WINDOW = timedelta(days=4)
EMERGING_TTL = timedelta(days=7)
MAX_LIVE_CVES = 1500
MAX_CVE_FETCH = 1500
MAX_EMERGING = 12


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = parsedate_to_datetime(v)
        except (TypeError, ValueError, IndexError):
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def http_get(url: str, limit: int = MAX_FEED_BYTES, timeout: int = 25, headers: dict | None = None,
             byte_range: int | None = None) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("https only")
    h = {"User-Agent": UA, "Accept": "*/*"}
    if byte_range:
        h["Range"] = f"bytes=0-{byte_range - 1}"
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    last: Exception | None = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(limit + 1)
            if len(body) > limit:
                raise ValueError(f"response over {limit} bytes")
            return body
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 403, 401):
                raise
            last = exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
        time.sleep(2 + attempt * 3)
    raise last or RuntimeError("fetch failed")


def http_json(url: str, **kw: Any) -> Any:
    return json.loads(http_get(url, **kw).decode("utf-8"))


def clean(text: Any, limit: int) -> str:
    s = re.sub(r"<[^>]+>", " ", str(text or ""))
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) <= limit:
        return s
    cut = s[:limit].rsplit(" ", 1)[0].rstrip(" ,;:.(-–")
    return (cut or s[:limit]) + "…"


def sev_for(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def safe_link(u: Any) -> str | None:
    try:
        p = urllib.parse.urlsplit(str(u or "").strip())
    except ValueError:
        return None
    if p.scheme not in ("https", "http") or not p.netloc:
        return None
    return urllib.parse.urlunsplit(p)[:500]


# ---------------------------------------------------------------- snapshot
def load_snapshot(site: Path) -> tuple[dict, dict[str, list]]:
    snap = site / "snapshot"
    manifest = json.loads((snap / "manifest.json").read_text(encoding="utf-8"))
    idx = json.loads((snap / manifest["search_index"]["path"]).read_text(encoding="utf-8"))
    return manifest, {row[0]: row for row in idx if isinstance(row, list) and row and isinstance(row[0], str)}


def load_previous(url: str | None, path: Path | None) -> dict:
    try:
        if path and path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
        elif url:
            data = http_json(url + ("&" if "?" in url else "?") + f"t={int(time.time())}", limit=8 * 1024 * 1024)
        else:
            return {}
        return data if isinstance(data, dict) and data.get("schema") == 1 else {}
    except Exception as exc:  # first run, offline, or not deployed yet
        print(f"early_warning: no previous live state ({type(exc).__name__})", file=sys.stderr)
        return {}


# ---------------------------------------------------------------- CVE.org
def parse_delta_log(raw: bytes, since: datetime) -> list[str]:
    """Return CVE ids that are new or updated after `since`. Tolerates a truncated (ranged) download."""
    text = raw.decode("utf-8", errors="ignore")
    dec = json.JSONDecoder()
    pos = text.find("[")
    if pos < 0:
        return []
    pos += 1
    out: list[str] = []
    seen: set[str] = set()
    while True:
        while pos < len(text) and text[pos] in " \r\n\t,":
            pos += 1
        if pos >= len(text) or text[pos] == "]":
            break
        try:
            obj, pos = dec.raw_decode(text, pos)
        except json.JSONDecodeError:
            break  # truncated tail of the ranged download
        when = parse_time(obj.get("fetchTime")) if isinstance(obj, dict) else None
        if when is None or when < since:
            break  # newest first: everything after this is older
        for key in ("new", "updated"):
            for item in obj.get(key) or []:
                cid = str(item.get("cveId") or "").upper() if isinstance(item, dict) else ""
                if CVE_OK.match(cid) and cid not in seen:
                    seen.add(cid)
                    out.append(cid)
    return out


def _cvss_from(metrics: Iterable[Any]) -> tuple[float, str]:
    best = (0.0, "")
    for m in metrics or []:
        if not isinstance(m, dict):
            continue
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            d = m.get(key)
            if isinstance(d, dict) and isinstance(d.get("baseScore"), (int, float)):
                score = float(d["baseScore"])
                if 0 < score <= 10:
                    return score, str(d.get("baseSeverity") or "").lower()
    return best


def cve_record_row(doc: dict) -> list | None:
    meta = doc.get("cveMetadata") or {}
    cid = str(meta.get("cveId") or "").upper()
    if not CVE_OK.match(cid) or meta.get("state") != "PUBLISHED":
        return None
    cna = (doc.get("containers") or {}).get("cna") or {}
    adps = (doc.get("containers") or {}).get("adp") or []
    desc = ""
    for d in cna.get("descriptions") or []:
        if isinstance(d, dict) and str(d.get("lang", "")).lower().startswith("en"):
            desc = d.get("value") or ""
            break
    title = cna.get("title") or desc
    score, sev = _cvss_from(cna.get("metrics") or [])
    if not score:
        for adp in adps:
            if isinstance(adp, dict):
                score, sev = _cvss_from(adp.get("metrics") or [])
                if score:
                    break
    sev = sev if sev in ("critical", "high", "medium", "low") else sev_for(score)
    products = " ".join(f"{a.get('vendor', '')} {a.get('product', '')}".strip()
                        for a in (cna.get("affected") or [])[:4] if isinstance(a, dict))
    products = re.sub(r"\bn/a\b", "", products, flags=re.I)
    published = str(meta.get("datePublished") or "")[:10]
    updated = str(meta.get("dateUpdated") or meta.get("datePublished") or "")[:10]
    return [cid, clean(title, 110), sev, round(score, 1), 0, None, updated or published, published, clean(products, 80), "cve.org"]


def fetch_cve_record(cid: str) -> dict:
    year, num = cid.split("-")[1:]
    bucket = num[:-3] if len(num) > 3 else "0"
    return http_json(CVE_RAW.format(year=year, bucket=bucket, id=cid), limit=2 * 1024 * 1024, timeout=20)


def cve_org_new(snapshot_ids: set[str], since: datetime, prev: dict[str, list], deadline: float,
                getter: Callable[[str], dict] = fetch_cve_record) -> tuple[dict[str, list], dict]:
    raw = http_get(DELTA_LOG, limit=8 * 1024 * 1024, timeout=40, byte_range=6 * 1024 * 1024)
    ids = [c for c in parse_delta_log(raw, since) if c not in snapshot_ids]
    out: dict[str, list] = {cid: prev[cid] for cid in ids if cid in prev}
    todo = [cid for cid in ids if cid not in prev][:MAX_CVE_FETCH]

    def one(cid: str) -> list | None:
        if time.monotonic() > deadline:
            return None
        try:
            return cve_record_row(getter(cid))
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        for row in pool.map(one, todo):
            if row:
                out[row[0]] = row
    fetched = len(todo)
    return out, {"name": "CVE.org", "ok": True, "count": len(out), "fetched": fetched}


# ---------------------------------------------------------------- GitHub advisories
def ghsa_new(snapshot_ids: set[str], since: datetime, token: str | None) -> tuple[dict[str, list], dict]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = http_json(GHSA_API, headers=headers, limit=8 * 1024 * 1024)
    out: dict[str, list] = {}
    for adv in data if isinstance(data, list) else []:
        cid = str(adv.get("cve_id") or "").upper()
        pub = parse_time(adv.get("published_at"))
        if not CVE_OK.match(cid) or cid in snapshot_ids or not pub or pub < since - timedelta(hours=6):
            continue
        score = 0.0
        c = adv.get("cvss") or {}
        if isinstance(c.get("score"), (int, float)):
            score = float(c["score"])
        for k in ("cvss_v4", "cvss_v3"):
            v = (adv.get("cvss_severities") or {}).get(k) or {}
            if not score and isinstance(v.get("score"), (int, float)):
                score = float(v["score"])
        sev = str(adv.get("severity") or "").lower()
        sev = sev if sev in ("critical", "high", "medium", "low") else sev_for(score)
        pkgs = " ".join(f"{(v.get('package') or {}).get('ecosystem', '')} {(v.get('package') or {}).get('name', '')}".strip()
                        for v in (adv.get("vulnerabilities") or [])[:3] if isinstance(v, dict))
        out[cid] = [cid, clean(adv.get("summary") or adv.get("description"), 110), sev, round(score, 1), 0, None,
                    pub.strftime("%Y-%m-%d"), pub.strftime("%Y-%m-%d"), clean(pkgs, 80), "ghsa"]
    return out, {"name": "GitHub advisories", "ok": True, "count": len(out)}


# ---------------------------------------------------------------- KEV
def kev_new(index: dict[str, list], since: datetime) -> tuple[list[str], dict[str, list], dict]:
    data = http_json(KEV_URL, limit=16 * 1024 * 1024, timeout=40)
    flagged: list[str] = []
    rows: dict[str, list] = {}
    for v in data.get("vulnerabilities") or []:
        cid = str(v.get("cveID") or "").upper()
        if not CVE_OK.match(cid):
            continue
        added = str(v.get("dateAdded") or "")[:10]
        if cid in index:
            if not index[cid][4]:
                flagged.append(cid)
            continue
        when = parse_time(added + "T00:00:00Z") if added else None
        if when and when >= since - timedelta(days=1):
            title = v.get("vulnerabilityName") or v.get("shortDescription") or ""
            rows[cid] = [cid, clean(title, 110), "unknown", 0.0, 1, None, added, added,
                         clean(f"{v.get('vendorProject', '')} {v.get('product', '')}", 80), "kev"]
    return flagged, rows, {"name": "CISA KEV", "ok": True, "count": len(flagged) + len(rows)}


# ---------------------------------------------------------------- news / CERT feeds
def _tag(el: ET.Element) -> str:
    return el.tag.rsplit("}", 1)[-1].lower()


def parse_feed(raw: bytes) -> list[dict]:
    if b"<!ENTITY" in raw[:4096].upper():
        raise ValueError("feed declares entities; refusing")
    root = ET.fromstring(raw)
    items = []
    for el in root.iter():
        if _tag(el) not in ("item", "entry"):
            continue
        rec: dict[str, str] = {}
        for ch in el:
            t = _tag(ch)
            if t == "title":
                rec["title"] = "".join(ch.itertext())
            elif t == "link":
                rec.setdefault("link", ch.get("href") or (ch.text or ""))
            elif t in ("description", "summary", "content", "encoded") and len(rec.get("body", "")) < 200:
                rec["body"] = "".join(ch.itertext())
            elif t in ("pubdate", "published", "updated", "date") and "date" not in rec:
                rec["date"] = ch.text or ""
        if rec.get("title"):
            items.append(rec)
    return items


def collect_news(now: datetime, deadline: float, fetch: Callable[[str], bytes] = http_get) -> tuple[list[dict], list[dict]]:
    articles: list[dict] = []
    status: list[dict] = []
    for name, url, weight in FEEDS:
        if time.monotonic() > deadline:
            status.append({"name": name, "ok": False, "count": 0, "note": "time budget"})
            continue
        try:
            items = parse_feed(fetch(url))
        except Exception as exc:
            status.append({"name": name, "ok": False, "count": 0, "note": type(exc).__name__})
            continue
        n = 0
        for it in items:
            when = parse_time(it.get("date")) or None
            if when is None or when < now - FEED_WINDOW or when > now + timedelta(hours=2):
                continue
            link = safe_link(it.get("link"))
            if not link:
                continue
            title = clean(it.get("title"), 200)
            body = clean(it.get("body"), 1500)
            articles.append({"src": name, "w": weight, "url": link, "title": title, "text": f"{title} {body}", "at": when})
            n += 1
        status.append({"name": name, "ok": True, "count": n})
    return articles, status


def _named(text: str) -> list[str]:
    out = []
    for m in NAMED.finditer(text):
        word = m.group(1)
        low = word.lower()
        if low in NAMED_STOP or low.endswith("powershell") or len(low) < 6:
            continue
        # must look like a name: mixed case, a digit, or a vendor-ish prefix (php2shell, Log4Shell, CitrixBleed)
        if not (re.search(r"\d", word) or re.search(r"[a-z][A-Z]", word) or word[0].isupper()):
            continue
        out.append(low)
    return out


def cluster(articles: list[dict]) -> list[dict]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    keyed: list[tuple[dict, list[str]]] = []
    for a in articles:
        keys = [f"cve:{y}-{n}" for y, n in {(m.group(1), m.group(2)) for m in CVE_ID.finditer(a["text"])}]
        keys += [f"name:{n}" for n in set(_named(a["text"]))]
        if not keys or len(keys) > 12:  # roundups that list dozens of CVEs are not a single event
            continue
        for k in keys[1:]:
            union(keys[0], k)
        for k in keys:
            find(k)
        keyed.append((a, keys))
    groups: dict[str, dict] = {}
    for a, keys in keyed:
        g = groups.setdefault(find(keys[0]), {"articles": [], "keys": set()})
        g["articles"].append(a)
        g["keys"].update(keys)
    return list(groups.values())


def build_emerging(articles: list[dict], index: dict[str, list], live: dict[str, list], prev: list[dict],
                   now: datetime, lookup: Callable[[str], str] | None = None, max_lookups: int = 25) -> list[dict]:
    prev_by_key = {p.get("key"): p for p in prev if isinstance(p, dict)}
    out: list[dict] = []
    lookups = 0
    for g in cluster(articles):
        arts = sorted(g["articles"], key=lambda a: a["at"])
        sources = {}
        for a in arts:
            sources.setdefault(a["src"], a)
        weight = sum(a["w"] for a in sources.values())
        text = " ".join(a["text"] for a in arts)
        sigs = [name for name, rx, _ in SIGNALS if rx.search(text)]
        cves = sorted({k[4:] for k in g["keys"] if k.startswith("cve:")}, key=lambda c: (len(c), c))
        cves = ["CVE-" + c for c in cves][:6]
        names = sorted({k[5:] for k in g["keys"] if k.startswith("name:")})
        if weight < 2 or not (set(sigs) & URGENT):
            continue
        status: dict[str, str] = {}
        for c in cves:
            if c in index:
                status[c] = "kev" if index[c][4] else "snapshot"
            elif c in live:
                status[c] = "live"
            elif lookup and lookups < max_lookups:
                lookups += 1
                status[c] = lookup(c)
            else:
                status[c] = "unknown"
        # a story about CVEs that are already old, scored and known is "Trending", not early warning
        fresh = any(s in ("live", "unpublished", "reserved", "unknown") for s in status.values()) or bool(names)
        if not fresh and not ({"exploited", "zero-day"} & set(sigs)):
            continue
        if not fresh and all(s == "kev" for s in status.values()):
            continue
        key = ("name:" + names[0]) if names else ("cve:" + ",".join(cves))
        old = prev_by_key.get(key) or {}
        first = parse_time(old.get("first_seen")) or arts[0]["at"]
        best = _best_title(arts, names)
        hit = re.search(re.escape(names[0]), best, re.I) if names else None
        nice = hit.group(0) if hit else _display_name(names, arts)
        score = weight * 2 + sum(w for name, _, w in SIGNALS if name in sigs) + (4 if "unpublished" in status.values() else 0)
        level = "p0" if ({"exploited", "zero-day"} & set(sigs)) or ("rce" in sigs and weight >= 3) else "watch"
        out.append({
            "key": key,
            "name": nice,
            "title": best,
            "cves": cves,
            "status": status,
            "signals": sigs,
            "level": level,
            "score": score,
            "first_seen": iso(min(first, arts[0]["at"])),
            "last_seen": iso(arts[-1]["at"]),
            "sources": [{"n": a["src"], "u": a["url"], "t": clean(a["title"], 160), "at": iso(a["at"])}
                        for a in sorted(sources.values(), key=lambda a: (-a["w"], a["at"]))][:8],
        })
    # keep recently-seen events that dropped out of the feed window
    keys = {e["key"] for e in out}
    for p in prev:
        if isinstance(p, dict) and p.get("key") not in keys:
            last = parse_time(p.get("last_seen"))
            if last and now - last < EMERGING_TTL:
                for c in p.get("cves") or []:
                    if c in index:
                        p.setdefault("status", {})[c] = "kev" if index[c][4] else "snapshot"
                    elif c in live:
                        p.setdefault("status", {})[c] = "live"
                out.append(p)
    out.sort(key=lambda e: (e.get("level") != "p0", -int(e.get("score") or 0), e.get("last_seen") or ""))
    return out[:MAX_EMERGING]


def _tidy_title(t: str) -> str:
    t = re.sub(r"\s*\[[^\]]{0,40}\]", "", t)  # "[infocon yellow]"
    t = re.sub(r",?\s*\((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)[^)]{0,30}\)", "", t)  # "(Wed, Oct 21st)"
    return t.strip(" ,-–|")


def _best_title(arts: list[dict], names: list[str]) -> str:
    pool = [a for a in arts if any(n in a["title"].lower() for n in names)] or arts
    # the most descriptive headline: prefer ones that carry urgency words, then a medium length
    def rank(a: dict) -> tuple:
        t = _tidy_title(a["title"])
        hits = sum(1 for name, rx, _ in SIGNALS if rx.search(t))
        return (hits, -abs(len(t) - 90))
    return clean(_tidy_title(max(pool, key=rank)["title"]), 160)


def _display_name(names: list[str], arts: list[dict]) -> str:
    if names:
        n = names[0]
        for a in arts:  # keep the casing the press uses (php2shell, React2Shell)
            m = re.search(re.escape(n), a["title"], re.I)
            if m:
                return m.group(0)
        return n
    return clean(_tidy_title(min((a["title"] for a in arts), key=len)), 90)


def cve_org_status(cid: str) -> str:
    try:
        doc = http_json(CVE_API.format(id=cid), limit=2 * 1024 * 1024, timeout=15)
    except urllib.error.HTTPError as exc:
        return "unpublished" if exc.code == 404 else "unknown"
    except Exception:
        return "unknown"
    state = str((doc.get("cveMetadata") or {}).get("state") or "").upper()
    if doc.get("error") == "CVE_RECORD_DNE":
        return "unpublished"
    return {"PUBLISHED": "published", "RESERVED": "reserved", "REJECTED": "rejected"}.get(state, "unpublished")


# ---------------------------------------------------------------- telegram
def telegram_alerts(doc: dict, prev: dict) -> int:
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN", ""), os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat or not prev:  # no previous state -> never flood the channel on first run
        return 0
    old_keys = {e.get("key") for e in prev.get("emerging") or [] if isinstance(e, dict)}
    old_kev = set(prev.get("kev") or []) | {r[0] for r in prev.get("cves") or [] if isinstance(r, list) and r[4]}
    lines = []
    for e in doc["emerging"]:
        if e["key"] in old_keys or e["level"] != "p0":
            continue
        ids = ", ".join(e["cves"][:3])
        src = ", ".join(s["n"] for s in e["sources"][:4])
        lines.append(f"🚨 <b>Early warning: {html.escape(e['name'])}</b>\n{html.escape(e['title'])}\n"
                     f"{html.escape(ids) + chr(10) if ids else ''}<i>{html.escape(' · '.join(e['signals']))} — {html.escape(src)}</i>")
    kev_now = [c for c in doc["kev"] if c not in old_kev] + [r[0] for r in doc["cves"] if r[4] and r[0] not in old_kev]
    if kev_now:
        lines.append("🔴 <b>Now on CISA KEV</b>\n" + "\n".join(f'<a href="{SITE_URL}cve/{c}">{c}</a>' for c in kev_now[:8]))
    if not lines:
        return 0
    text = "\n\n".join(lines[:6]) + f"\n\n{SITE_URL}"
    body = urllib.parse.urlencode({"chat_id": chat, "text": text[:3900], "parse_mode": "HTML",
                                   "disable_web_page_preview": "true"}).encode()
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return 1 if json.load(resp).get("ok") else 0
    except Exception as exc:
        print(f"early_warning: telegram failed ({type(exc).__name__})", file=sys.stderr)
        return 0


# ---------------------------------------------------------------- main
def run(site: Path, previous: dict, token: str | None, budget_s: int = 300, now: datetime | None = None) -> dict:
    now = now or now_utc()
    deadline = time.monotonic() + budget_s
    manifest, index = load_snapshot(site)
    snap_at = parse_time(manifest.get("generated_at")) or now - timedelta(hours=6)
    # NVD lags CVE.org by hours, so also look a bit before the snapshot for records it did not have yet
    since = snap_at - timedelta(hours=12)
    snapshot_ids = set(index)
    same_base = previous.get("snapshot") == manifest.get("generated_at")
    prev_rows = {r[0]: r for r in previous.get("cves") or [] if same_base and isinstance(r, list) and len(r) >= 10}
    sources: list[dict] = []
    live: dict[str, list] = {}

    def guard(name: str, fn: Callable[[], Any], fallback: Any) -> Any:
        try:
            return fn()
        except Exception as exc:
            print(f"early_warning: {name} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            sources.append({"name": name, "ok": False, "count": 0, "note": type(exc).__name__})
            return fallback

    r = guard("CVE.org", lambda: cve_org_new(snapshot_ids, since, {k: v for k, v in prev_rows.items() if v[9] == "cve.org"}, deadline - 120), None)
    if r:
        live.update(r[0]); sources.append(r[1])
    else:
        live.update({k: v for k, v in prev_rows.items() if v[9] == "cve.org"})
    r = guard("GitHub advisories", lambda: ghsa_new(snapshot_ids, since, token), None)
    if r:
        for k, v in r[0].items():
            live.setdefault(k, v)
        sources.append(r[1])
    kev_flag: list[str] = [c for c in previous.get("kev") or [] if same_base and c in index]
    r = guard("CISA KEV", lambda: kev_new(index, snap_at), None)
    if r:
        kev_flag = r[0]
        live.update(r[1])  # old CVEs that just landed on KEV (outside the 30-day window)
        sources.append(r[2])
    kev_set = set(kev_flag)
    articles, feed_status = collect_news(now, deadline)
    emerging = build_emerging(articles, index, live, previous.get("emerging") or [], now, cve_org_status)
    rows = sorted(live.values(), key=lambda x: (x[6], x[0]), reverse=True)[:MAX_LIVE_CVES]
    age_h = round((now - snap_at).total_seconds() / 3600, 1)
    return {
        "schema": 1,
        "generated_at": iso(now),
        "snapshot": manifest.get("generated_at"),
        "snapshot_age_hours": age_h,
        "cves": rows,
        "kev": sorted(kev_set),
        "emerging": emerging,
        "sources": sources,
        "feeds": feed_status,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", type=Path, required=True, help="built site root (contains snapshot/)")
    ap.add_argument("--previous-url", default=SITE_URL + "live/early.json")
    ap.add_argument("--previous-file", type=Path)
    ap.add_argument("--budget-seconds", type=int, default=300)
    ap.add_argument("--notify", action="store_true", help="post new P0 early warnings / KEV adds to Telegram")
    args = ap.parse_args(argv)
    out_dir = args.site / "live"
    out_dir.mkdir(parents=True, exist_ok=True)
    previous = load_previous(args.previous_url, args.previous_file)
    try:
        doc = run(args.site, previous, os.environ.get("GITHUB_TOKEN") or None, args.budget_seconds)
    except Exception as exc:  # never block a deploy: re-publish the last good live layer if we have one
        print(f"early_warning: run failed ({type(exc).__name__}: {exc}); keeping previous live layer", file=sys.stderr)
        if not previous:
            return 0
        doc = previous
    data = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (out_dir / "early.json").write_bytes(data)
    print(f"early_warning: {len(doc.get('cves') or [])} live CVEs, {len(doc.get('kev') or [])} KEV flags, "
          f"{len(doc.get('emerging') or [])} early warnings; snapshot age {doc.get('snapshot_age_hours')}h")
    if args.notify and doc is not previous:
        telegram_alerts(doc, previous)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
