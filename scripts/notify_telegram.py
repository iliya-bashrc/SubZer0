#!/usr/bin/env python3
"""Post newly urgent CVEs to Telegram after a snapshot refresh.

Compares the previous search index (from git) with the new one and announces CVEs that
just became "patch now": CISA KEV or SSVC "active", weaponized in Metasploit/Nuclei, or a
public exploit with a high EPSS.
Does nothing when TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from html import escape
from pathlib import Path

from build_site import SITE_URL, load_index, priority, priority_reason

ROOT = Path(__file__).resolve().parents[1]
MAX_ITEMS = 10


def previous_rows(rev: str) -> tuple[dict[str, list], dict]:
    """Rows and priority context of the snapshot committed at ``rev`` (empty when unavailable)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        def show(path: str) -> bytes:
            return subprocess.run(["git", "show", f"{rev}:public/snapshot/{path}"], cwd=ROOT, check=True, capture_output=True).stdout

        try:
            manifest = json.loads(show("manifest.json"))
            for meta in (manifest.get("search_index"), manifest.get("poc_ids"), manifest.get("intel")):
                if isinstance(meta, dict) and meta.get("path"):
                    target = root / str(meta["path"])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        target.write_bytes(show(str(meta["path"])))
                    except subprocess.CalledProcessError:
                        pass
            (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            _, rows, ctx = load_index(root)
        except (subprocess.CalledProcessError, KeyError, ValueError, OSError):
            return {}, {}
    return {r[0]: r for r in rows if isinstance(r, list) and r}, ctx


def message(new: list[list], ctx: dict) -> str:
    lines = [f"<b>SubZer0 · {len(new)} new to patch now</b>"]
    for r in new[:MAX_ITEMS]:
        why = priority_reason(r, ctx)[1]
        if why == "public exploit, high EPSS":
            why = f"public exploit, EPSS {(r[5] or 0) * 100:.0f}%"
        score = f" · CVSS {r[3]:.1f}" if r[3] else ""
        lines.append(f'\n<a href="{SITE_URL}cve/{r[0]}">{r[0]}</a> — {escape(str(r[1])[:120])}\n<i>{why}{score}</i>')
    if len(new) > MAX_ITEMS:
        lines.append(f"\n…and {len(new) - MAX_ITEMS} more: {SITE_URL}research?view=p1")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", default="HEAD~1", help="git revision holding the previous snapshot")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN", ""), os.environ.get("TELEGRAM_CHAT_ID", "")
    if not args.dry_run and (not token or not chat):
        print("Telegram is not configured; skipping.")
        return 0

    _, rows, ctx = load_index(ROOT / "public" / "snapshot")
    old, old_ctx = previous_rows(args.previous)
    if not old:
        print("No previous snapshot to compare with; skipping so the channel is not flooded.")
        return 0
    new = [r for r in rows if priority(r, ctx) == 1 and (r[0] not in old or priority(old[r[0]], old_ctx) != 1)]
    new.sort(key=lambda r: (bool(r[4]), r[5] or 0), reverse=True)
    if not new:
        print("Nothing newly urgent.")
        return 0
    text = message(new, ctx)
    if args.dry_run:
        print(text)
        return 0
    body = urllib.parse.urlencode({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": "true"}).encode()
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            ok = json.load(resp).get("ok")
    except Exception as exc:  # never fail the publish job because of a chat message
        print(f"Telegram request failed: {type(exc).__name__}")
        return 0
    print(f"Announced {len(new)} CVEs" if ok else "Telegram rejected the message")
    return 0


if __name__ == "__main__":
    sys.exit(main())
