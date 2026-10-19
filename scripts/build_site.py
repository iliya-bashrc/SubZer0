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
import shutil
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.sax.saxutils import escape

import verify_data_snapshot as verifier

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


def build(site: Path, snapshot: Path, out: Path) -> None:
    verifier.validate_snapshot(snapshot)
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(site, out)
    shutil.copytree(snapshot, out / "snapshot")
    shutil.copyfile(out / "index.html", out / "404.html")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    manifest, rows, ctx = load_index(snapshot)
    summary = summarize(manifest, rows, ctx)
    (out / "api").mkdir(exist_ok=True)
    (out / "api" / "latest.json").write_text(json.dumps(summary, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (out / "feed.xml").write_text(rss(summary), encoding="utf-8")
    print(f"Built {out}: {len(rows)} CVEs, {len(summary['patch_now'])} in the patch-now feed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "site")
    parser.add_argument("--snapshot", type=Path, default=ROOT / "public" / "snapshot")
    parser.add_argument("--out", type=Path, default=ROOT / "_site")
    args = parser.parse_args()
    build(args.site, args.snapshot, args.out)


if __name__ == "__main__":
    main()
