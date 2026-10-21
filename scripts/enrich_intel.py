#!/usr/bin/env python3
"""Add exploit and chatter intelligence to a freshly built snapshot.

Writes snapshot/data/intel.json and registers it (with its SHA-256) in manifest.json.
Every source is optional: if one fails, its last good values from the previously
published snapshot are carried forward and the source is marked not ok. This step
never blocks a snapshot from being published.

Sources
  PoC-in-GitHub (nomi-sec)     GitHub repositories that claim to be PoCs, with stars and age
  Metasploit                   modules that reference the CVE (= weaponized)
  Nuclei templates             detection templates (= mass-scannable)
  CISA Vulnrichment (ADP)      SSVC: exploitation / automatable / technical impact, plus CVSS when NVD has none
  Bluesky, Mastodon, Reddit, Hacker News   how much people are talking about each CVE (last 7 days)
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import html
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "SubZer0/1.0 (+https://github.com/iliya-bashrc/SubZer0)"
CVE_IN_TEXT = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.I)
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
MSF_RE = re.compile(r"^(?:exploit|auxiliary|post|payload|evasion|encoder|nop)/[a-z0-9_/.-]{1,200}$")
NUCLEI_RE = re.compile(r"^[A-Za-z0-9_/.-]{1,200}\.yaml$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SSVC_VALUES = {"e": {"none", "poc", "active"}, "a": {"yes", "no"}, "i": {"partial", "total"}}
BUZZ_HOSTS = {"bsky.app", "mastodon.social", "www.reddit.com", "news.ycombinator.com"}
TRUSTED_OWNERS = {
    "projectdiscovery", "rapid7", "horizon3ai", "watchtowrlabs", "sinsinology", "assetnote",
    "chompie1337", "synacktiv", "google", "tenable", "qualys", "trickest", "cisagov",
}
MAX_POCS = 16
MAX_LINKS = 3
BUZZ_DAYS = 7


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def norm_cve(year: str, num: str) -> str:
    return f"CVE-{year}-{num}"


def fetch(url: str, limit: int = 40 * 1024 * 1024, timeout: int = 40, headers: dict[str, str] | None = None) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("only https sources are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(limit + 1)
            if len(body) > limit:
                raise ValueError(f"{parsed.hostname} response exceeded {limit} bytes")
            return body
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403, 404):
                raise
            last = exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            last = exc
        time.sleep(2 * (attempt + 1))
    raise last or RuntimeError("fetch failed")


def fetch_json(url: str, **kw: Any) -> Any:
    return json.loads(fetch(url, **kw).decode("utf-8"))


def git(*args: str, cwd: Path | None = None, timeout: int = 600) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout).stdout


def clean_text(value: Any, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def day(value: Any) -> str | None:
    text = str(value or "")[:10]
    return text if DATE_RE.fullmatch(text) else None


# ---------------------------------------------------------------- sources

def github_pocs(ids: set[str], workdir: Path, token: str | None) -> dict[str, list]:
    repo = workdir / "pig"
    git("clone", "-q", "--depth", "1", "--filter=blob:none", "--no-checkout",
        "https://github.com/nomi-sec/PoC-in-GitHub.git", str(repo), timeout=300)
    names = git("ls-tree", "-r", "--name-only", "HEAD", cwd=repo).split()
    wanted = [n for n in names if re.fullmatch(r"\d{4}/CVE-\d{4}-\d{4,7}\.json", n) and n.split("/")[1][:-5].upper() in ids]
    for i in range(0, len(wanted), 500):
        git("checkout", "-q", "HEAD", "--", *wanted[i:i + 500], cwd=repo, timeout=600)
    now = now_utc()
    out: dict[str, list] = {}
    owners: dict[str, int] = {}
    for name in wanted:
        cve = name.split("/")[1][:-5].upper()
        try:
            items = json.loads((repo / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = []
        for item in items if isinstance(items, list) else []:
            full = str(item.get("full_name") or "")
            if not REPO_RE.fullmatch(full):
                continue
            created = day(item.get("created_at"))
            stars = int(item.get("stargazers_count") or 0)
            forks = int(item.get("forks_count") or 0)
            desc = clean_text(item.get("description"), 140)
            owner = full.split("/")[0]
            flags: list[str] = []
            if item.get("fork"):
                flags.append("fork")
            if not desc:
                flags.append("nodesc")
            if created and (now.date() - datetime.fromisoformat(created).date()).days <= 14 and stars < 5:
                flags.append("fresh")
            if re.search(r"\b(download|\.exe|\.rar|\.zip|password|telegram|buy|sell|private exploit)\b", desc, re.I):
                flags.append("bait")
            if owner.lower() in TRUSTED_OWNERS:
                flags.append("known")
            owner_id = (item.get("owner") or {}).get("id")
            if isinstance(owner_id, int):
                owners[owner] = owner_id
            rows.append([full, stars, forks, created, desc, flags])
        rows.sort(key=lambda r: (-r[1], r[3] or ""))
        if rows:
            out[cve] = rows[:MAX_POCS]
    _flag_new_owners(out, token)
    return out


def _flag_new_owners(out: dict[str, list], token: str | None) -> None:
    """Look up account age for owners of low-star repos (the ones fake-PoC campaigns use)."""
    if not token:
        return
    risky = sorted({r[0].split("/")[0] for rows in out.values() for r in rows if r[1] < 20})[:300]
    ages: dict[str, str] = {}

    def look(login: str) -> None:
        try:
            data = fetch_json(f"https://api.github.com/users/{urllib.parse.quote(login)}", timeout=20,
                              headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
            created = day(data.get("created_at"))
            if created:
                ages[login] = created
        except Exception:
            pass

    with cf.ThreadPoolExecutor(8) as pool:
        list(pool.map(look, risky))
    today = now_utc().date()
    for rows in out.values():
        for r in rows:
            created = ages.get(r[0].split("/")[0])
            if created and (today - datetime.fromisoformat(created).date()).days <= 60 and "newacct" not in r[5]:
                r[5].append("newacct")


def metasploit(ids: set[str]) -> dict[str, list]:
    data = fetch_json("https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json", limit=64 * 1024 * 1024, timeout=120)
    out: dict[str, list] = {}
    for mod in data.values():
        full = str(mod.get("fullname") or "")
        if not MSF_RE.fullmatch(full):
            continue
        for ref in mod.get("references") or []:
            m = CVE_IN_TEXT.fullmatch(str(ref).strip())
            if not m:
                continue
            cve = norm_cve(*m.groups())
            if cve in ids:
                rank = mod.get("rank")
                row = [full, str(mod.get("type") or "")[:20], int(rank) if isinstance(rank, int) else None,
                       day(mod.get("disclosure_date")), day(mod.get("mod_time")), clean_text(mod.get("name"), 140),
                       bool(mod.get("check"))]
                if row not in out.setdefault(cve, []):
                    out[cve].append(row)
    return {k: v[:6] for k, v in out.items()}


def nuclei(ids: set[str]) -> dict[str, list]:
    raw = fetch("https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json", limit=32 * 1024 * 1024, timeout=120)
    out: dict[str, list] = {}
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        m = CVE_IN_TEXT.fullmatch(str(item.get("ID") or "").strip())
        path = str(item.get("file_path") or "")
        if not m or not NUCLEI_RE.fullmatch(path):
            continue
        cve = norm_cve(*m.groups())
        if cve in ids:
            info = item.get("Info") or {}
            out.setdefault(cve, []).append([path, clean_text(info.get("Severity"), 12).lower(), clean_text(info.get("Name"), 140)])
    return out


def vulnrichment(ids: set[str], workdir: Path) -> dict[str, list]:
    repo = workdir / "vr"
    git("clone", "-q", "--depth", "1", "--no-checkout", "https://github.com/cisagov/vulnrichment.git", str(repo), timeout=900)
    listing = git("ls-tree", "-r", "HEAD", cwd=repo, timeout=300).splitlines()
    wanted: list[tuple[str, str]] = []
    for line in listing:
        meta, _, path = line.partition("\t")
        name = path.rsplit("/", 1)[-1]
        if name.endswith(".json") and name[:-5].upper() in ids:
            wanted.append((meta.split()[2], name[:-5].upper()))
    out: dict[str, list] = {}
    proc = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repo, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert proc.stdin and proc.stdout
    for sha, cve in wanted:
        proc.stdin.write((sha + "\n").encode())
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        if len(header) < 3:
            continue
        body = proc.stdout.read(int(header[2]))
        proc.stdout.read(1)
        try:
            doc = json.loads(body)
        except ValueError:
            continue
        row = _ssvc_row(doc)
        if row:
            out[cve] = row
    proc.stdin.close()
    proc.wait(timeout=60)
    return out


def _ssvc_row(doc: dict) -> list | None:
    for adp in (doc.get("containers") or {}).get("adp") or []:
        if (adp.get("providerMetadata") or {}).get("shortName") != "CISA-ADP":
            continue
        e = a = i = None
        score = vector = None
        for metric in adp.get("metrics") or []:
            other = metric.get("other") or {}
            if other.get("type") == "ssvc":
                for opt in (other.get("content") or {}).get("options") or []:
                    for k, v in opt.items():
                        v = str(v).lower()
                        if k == "Exploitation":
                            e = v
                        elif k == "Automatable":
                            a = v
                        elif k == "Technical Impact":
                            i = v
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                cv = metric.get(key)
                if isinstance(cv, dict) and score is None:
                    try:
                        s = float(cv.get("baseScore"))
                    except (TypeError, ValueError):
                        continue
                    if math.isfinite(s) and 0 < s <= 10:
                        score = round(s, 1)
                        vec = str(cv.get("vectorString") or "")
                        vector = vec if re.fullmatch(r"CVSS:[34]\.[01](?:/[A-Za-z]{1,3}:[A-Za-z0-9]{1,3}){3,40}", vec) else None
        if e not in SSVC_VALUES["e"]:
            e = None
        if a not in SSVC_VALUES["a"]:
            a = None
        if i not in SSVC_VALUES["i"]:
            i = None
        if e or a or i or score:
            return [e, a, i, score, vector]
    return None


# ---------------------------------------------------------------- chatter

def _count(target: dict, src: str, text: str, url: str, when: str, ids: set[str]) -> None:
    seen = set()
    for m in CVE_IN_TEXT.finditer(text):
        cve = norm_cve(*m.groups()).upper()
        if cve in ids and cve not in seen:
            seen.add(cve)
            slot = target.setdefault(cve, {"bsky": 0, "masto": 0, "reddit": 0, "hn": 0, "d1": 0, "links": []})
            slot[src] += 1
            if when >= iso(now_utc() - timedelta(days=1)):
                slot["d1"] += 1
            if url and len(slot["links"]) < 12:
                slot["links"].append([src, url, when[:10]])


def bluesky(ids: set[str], buzz: dict, deadline: float) -> int:
    since = iso(now_utc() - timedelta(days=BUZZ_DAYS))
    posts = 0
    years = sorted({c.split("-")[1] for c in ids}, reverse=True)[:3]
    for year in years:
        cursor = ""
        for _ in range(25):
            if time.time() > deadline:
                return posts
            q = urllib.parse.urlencode({"q": f"CVE-{year}", "sort": "latest", "limit": 100, "since": since, **({"cursor": cursor} if cursor else {})})
            try:
                data = fetch_json(f"https://api.bsky.app/xrpc/app.bsky.feed.searchPosts?{q}", timeout=30)
            except urllib.error.HTTPError:
                if posts:
                    break  # deep pagination is sometimes refused; keep what we have
                raise
            for p in data.get("posts") or []:
                rec = p.get("record") or {}
                handle = str((p.get("author") or {}).get("handle") or "")
                rkey = str(p.get("uri") or "").rsplit("/", 1)[-1]
                url = f"https://bsky.app/profile/{handle}/post/{rkey}" if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", handle) and re.fullmatch(r"[A-Za-z0-9]{1,20}", rkey) else ""
                _count(buzz, "bsky", str(rec.get("text") or ""), url, str(rec.get("createdAt") or p.get("indexedAt") or ""), ids)
                posts += 1
            cursor = data.get("cursor") or ""
            if not cursor:
                break
    return posts


def mastodon(ids: set[str], buzz: dict, deadline: float) -> int:
    since = iso(now_utc() - timedelta(days=BUZZ_DAYS))
    posts = 0
    seen: set[str] = set()
    for tag in ("cve", "vulnerability", "infosec", "cybersecurity", "exploit"):
        max_id = ""
        for _ in range(15):
            if time.time() > deadline:
                return posts
            q = urllib.parse.urlencode({"limit": 40, **({"max_id": max_id} if max_id else {})})
            try:
                items = fetch_json(f"https://mastodon.social/api/v1/timelines/tag/{tag}?{q}", timeout=30)
            except urllib.error.HTTPError:
                if posts:
                    break
                raise
            if not items:
                break
            for s in items:
                sid = str(s.get("id") or "")
                when = str(s.get("created_at") or "")
                max_id = sid
                if sid in seen:
                    continue
                seen.add(sid)
                text = html.unescape(re.sub(r"<[^>]+>", " ", str(s.get("content") or "")))
                url = str(s.get("url") or "")
                url = url if url.startswith("https://mastodon.social/") else ""
                _count(buzz, "masto", text, url, when, ids)
                posts += 1
            if items and str(items[-1].get("created_at") or "") < since:
                break
    return posts


def reddit(ids: set[str], buzz: dict, deadline: float) -> int:
    ns = {"a": "http://www.w3.org/2005/Atom"}
    since = iso(now_utc() - timedelta(days=BUZZ_DAYS))
    posts = 0
    # one combined feed: Reddit rate-limits anonymous RSS hard, so a single request is safest
    root = ET.fromstring(fetch("https://www.reddit.com/r/netsec+cybersecurity+blueteamsec+sysadmin+AskNetsec/new/.rss?limit=100",
                               limit=8 * 1024 * 1024, timeout=30, headers={"User-Agent": "Mozilla/5.0 (compatible; SubZer0/1.0)"}))
    for entry in root.findall("a:entry", ns):
        when = (entry.findtext("a:updated", "", ns) or "").replace("+00:00", "Z")
        if when and when < since:
            continue
        link = entry.find("a:link", ns)
        url = link.get("href", "") if link is not None else ""
        url = url if url.startswith("https://www.reddit.com/r/") else ""
        text = (entry.findtext("a:title", "", ns) or "") + " " + html.unescape(re.sub(r"<[^>]+>", " ", entry.findtext("a:content", "", ns) or ""))
        _count(buzz, "reddit", text, url, when, ids)
        posts += 1
    return posts


def hackernews(ids: set[str], buzz: dict, deadline: float) -> int:
    since = int((now_utc() - timedelta(days=BUZZ_DAYS)).timestamp())
    posts = 0
    for page in range(5):
        if time.time() > deadline:
            break
        q = urllib.parse.urlencode({"query": "CVE", "tags": "(story,comment)", "numericFilters": f"created_at_i>{since}", "hitsPerPage": 1000, "page": page})
        data = fetch_json(f"https://hn.algolia.com/api/v1/search_by_date?{q}", timeout=30)
        hits = data.get("hits") or []
        for h in hits:
            oid = str(h.get("objectID") or "")
            url = f"https://news.ycombinator.com/item?id={oid}" if oid.isdigit() else ""
            text = " ".join(str(h.get(k) or "") for k in ("title", "story_text", "comment_text", "url"))
            _count(buzz, "hn", html.unescape(re.sub(r"<[^>]+>", " ", text)), url, str(h.get("created_at") or ""), ids)
            posts += 1
        if page + 1 >= int(data.get("nbPages") or 0):
            break
    return posts


def buzz_score(slot: dict) -> int:
    raw = slot["bsky"] + slot["masto"] + 2 * slot["reddit"] + 2 * slot["hn"]
    return int(round(min(100, 22 * math.log2(1 + raw))))


# ---------------------------------------------------------------- assembly

def patch_flags(snapshot: Path, manifest: dict) -> dict[str, int]:
    out: dict[str, int] = {}
    for d in manifest["days"]:
        for rec in json.loads((snapshot / d["path"]).read_text(encoding="utf-8")):
            tags = {str(t).lower() for ref in rec.get("refs") or [] for t in ref.get("tags") or []}
            urls = [str(ref.get("url") or "") for ref in rec.get("refs") or []]
            fix_url = any(re.search(r"github\.com/[^/]+/[^/]+/(?:commit/[0-9a-f]{7,}|releases/tag/)", u, re.I) for u in urls)
            if "patch" in tags or "vendor advisory" in tags or "release notes" in tags or rec.get("advisories") or fix_url:
                out[rec["id"]] = 1
    return out


def load_previous(previous: Path | None) -> dict:
    if not previous:
        return {}
    try:
        manifest = json.loads((previous / "manifest.json").read_text(encoding="utf-8"))
        meta = manifest.get("intel") or {}
        raw = (previous / str(meta.get("path") or "data/intel.json")).read_bytes()
        if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
            return {}
        return json.loads(raw)
    except (OSError, ValueError, AttributeError):
        return {}


def build(snapshot: Path, previous: Path | None, budget_s: int = 900, only: set[str] | None = None) -> dict:
    t0 = time.time()
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    rows = json.loads((snapshot / manifest["search_index"]["path"]).read_text(encoding="utf-8"))
    ids = {r[0] for r in rows}
    kev_dates = {}
    prev = load_previous(previous)
    prev_cves = prev.get("cves") or {}
    token = os.environ.get("GITHUB_TOKEN") or None
    status: list[dict] = []
    results: dict[str, dict] = {}

    def run(name: str, key: str, fn: Callable[[], dict]) -> None:
        if only and key not in only:
            results[key] = {c: v[key] for c, v in prev_cves.items() if key in v and c in ids}
            status.append({"name": name, "ok": False, "count": len(results[key]), "note": "skipped"})
            return
        started = time.time()
        try:
            data = fn()
            results[key] = data
            status.append({"name": name, "ok": True, "count": len(data), "seconds": round(time.time() - started, 1)})
        except Exception as exc:  # carry forward the last good values
            results[key] = {c: v[key] for c, v in prev_cves.items() if key in v and c in ids}
            status.append({"name": name, "ok": False, "count": len(results[key]), "note": f"{type(exc).__name__}: {clean_text(exc, 160)}; kept previous"})
        print(f"  {name}: {status[-1]}")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        run("PoC-in-GitHub", "g", lambda: github_pocs(ids, work, token))
        run("Metasploit", "m", lambda: metasploit(ids))
        run("Nuclei templates", "n", lambda: nuclei(ids))
        run("CISA Vulnrichment", "s", lambda: vulnrichment(ids, work))
        shutil.rmtree(work / "vr", ignore_errors=True)

    buzz: dict[str, dict] = {}
    deadline = t0 + budget_s
    chatter_ok = []
    for name, fn in (("Bluesky", bluesky), ("Mastodon", mastodon), ("Reddit", reddit), ("Hacker News", hackernews)):
        if only and "b" not in only:
            break
        started = time.time()
        try:
            n = fn(ids, buzz, deadline)
            status.append({"name": name, "ok": True, "count": n, "seconds": round(time.time() - started, 1)})
            chatter_ok.append(name)
        except Exception as exc:
            status.append({"name": name, "ok": False, "count": 0, "note": f"{type(exc).__name__}: {clean_text(exc, 160)}"})
        print(f"  {name}: {status[-1]}")
    if chatter_ok:
        results["b"] = {}
        for cve, slot in buzz.items():
            links = []
            for src in ("hn", "reddit", "bsky", "masto"):
                links += [l for l in slot["links"] if l[0] == src][:1]
            results["b"][cve] = [buzz_score(slot), slot["bsky"], slot["masto"], slot["reddit"], slot["hn"], slot["d1"], links[:MAX_LINKS]]
    else:
        results["b"] = {c: v["b"] for c, v in prev_cves.items() if "b" in v and c in ids}

    results["f"] = patch_flags(snapshot, manifest)

    today = now_utc().date().isoformat()
    cves: dict[str, dict] = {}
    for key, data in results.items():
        for cve, value in data.items():
            if cve in ids and value:
                cves.setdefault(cve, {})[key] = value
    # first-seen dates for the exploit timeline, carried across runs
    for cve, entry in cves.items():
        old = (prev_cves.get(cve) or {}).get("t") or {}
        seen = {}
        for key, label in (("g", "poc"), ("m", "msf"), ("n", "nuclei"), ("b", "buzz")):
            if key in entry:
                seen[label] = old.get(label) or today
        if "g" in entry:
            first_repo = min((r[3] for r in entry["g"] if r[3]), default=None)
            if first_repo and first_repo < seen["poc"]:
                seen["poc"] = first_repo
        if "s" in entry and entry["s"][0] == "active":
            seen["active"] = old.get("active") or today
        if seen:
            entry["t"] = seen
    return {
        "schema_version": 1,
        "generated_at": manifest["generated_at"],
        "built_at": iso(now_utc()),
        "sources": status,
        "cves": dict(sorted(cves.items())),
    }


def write(snapshot: Path, intel: dict) -> None:
    raw = (json.dumps(intel, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    (snapshot / "data" / "intel.json").write_bytes(raw)
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["intel"] = {
        "schema_version": 1,
        "path": "data/intel.json",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "count": len(intel["cves"]),
        "sources": [{k: s[k] for k in ("name", "ok", "count") if k in s} for s in intel["sources"]],
    }
    manifest_path.write_bytes((json.dumps(manifest, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", type=Path, default=ROOT / "snapshot")
    parser.add_argument("--previous", type=Path, default=ROOT / "public" / "snapshot")
    parser.add_argument("--budget-seconds", type=int, default=900)
    parser.add_argument("--only", default="", help="comma list of g,m,n,s,b for local testing")
    args = parser.parse_args()
    only = set(filter(None, args.only.split(","))) or None
    print("Enriching snapshot with exploit and chatter intel")
    intel = build(args.snapshot, args.previous if args.previous.exists() else None, args.budget_seconds, only)
    write(args.snapshot, intel)
    print(f"intel.json: {len(intel['cves'])} CVEs with extra intel")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
