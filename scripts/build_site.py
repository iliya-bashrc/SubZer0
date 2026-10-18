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


def load_index(snapshot: Path) -> tuple[dict, list[list], set[str]]:
    manifest = json.loads((snapshot / "manifest.json").read_text(encoding="utf-8"))
    index = json.loads((snapshot / manifest["search_index"]["path"]).read_text(encoding="utf-8"))
    rows = index["rows"] if isinstance(index, dict) and "rows" in index else index
    poc = set(manifest.get("poc_ids") or [])
    return manifest, rows, poc


def priority(row: list, poc: set[str]) -> int:
    """Mirror of prio() in site/app.js. Keep the two in sync."""
    score = float(row[3] or 0)
    kev = bool(row[4])
    epss = row[5] if isinstance(row[5], (int, float)) else 0.0
    exploit = row[0] in poc
    if kev or (exploit and epss >= 0.1):
        return 1
    if score >= 9 or (score >= 7 and (exploit or epss >= 0.05)):
        return 2
    if score >= 7:
        return 3
    return 4


def summarize(manifest: dict, rows: list[list], poc: set[str]) -> dict:
    patch_now = [r for r in rows if priority(r, poc) == 1]
    patch_now.sort(key=lambda r: (str(r[6] or ""), r[5] or 0), reverse=True)
    return {
        "generated_at": manifest.get("generated_at"),
        "window": manifest.get("window"),
        "totals": manifest.get("totals"),
        "patch_now": [
            {
                "id": r[0], "title": r[1], "severity": r[2], "cvss": r[3] or None, "kev": bool(r[4]),
                "epss": r[5], "public_exploit": r[0] in poc, "date": r[6], "products": r[8],
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
        why = "On CISA KEV" if item["kev"] else "Public exploit, high EPSS"
        bits = [why]
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
        "<description>CVEs that are being exploited or have public exploit code with a high EPSS. Updated every 6 hours.</description>"
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
    manifest, rows, poc = load_index(snapshot)
    summary = summarize(manifest, rows, poc)
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
