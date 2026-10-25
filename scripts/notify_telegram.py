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
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from build_site import SITE_URL, facts, load_index, priority, priority_reason

sys.path.insert(0, str(Path(__file__).resolve().parent))
import digest  # noqa: E402
import digest_cards as cards  # noqa: E402

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


def reason(r: list, ctx: dict) -> str:
    why = priority_reason(r, ctx)[1]
    if why == "public exploit, high EPSS":
        why = f"public exploit, EPSS {(r[5] or 0) * 100:.0f}%"
    return why


def message(new: list[list], ctx: dict, limit: int = MAX_ITEMS) -> str:
    lines = [f"\U0001F6A8 <b>SubZer0 Alert</b> \u00b7 {len(new)} new to patch now"]
    for r in new[:limit]:
        why = reason(r, ctx)
        score = f" · CVSS {r[3]:.1f}" if r[3] else ""
        lines.append(f'\n<a href="{SITE_URL}cve/{r[0]}">{r[0]}</a> — {escape(str(r[1])[:120])}\n<i>{why}{score}</i>')
    if len(new) > limit:
        lines.append(f"\n…and {len(new) - limit} more: {SITE_URL}research?view=p1")
    lines.append(f"\n{digest.SIGN}")
    return "\n".join(lines)


def caption(new: list[list], ctx: dict) -> str:
    """The alert text, trimmed to fit Telegram's 1024-character photo caption."""
    for limit in range(min(MAX_ITEMS, len(new)), 0, -1):
        text = message(new, ctx, limit)
        if digest.visible_len(text) <= digest.CAPTION_MAX:
            return text
    return message(new, ctx, 1)[: digest.CAPTION_MAX]


def card_data(new: list[list], ctx: dict, stamp: str) -> dict:
    items = []
    for r in new[:3]:
        f = facts(r, ctx)
        items.append({"id": r[0], "name": digest.label(r, ctx, 28), "score": f["c"], "why": reason(r, ctx),
                      "epss": f["e"], "kev": f["kev"], "weap": f["weap"]})
    return {"count": len(new), "items": items, "stamp": stamp,
            "kev": sum(1 for r in new if r[4]), "weap": sum(1 for r in new if facts(r, ctx)["weap"])}


def add_names(ctx: dict, manifest: dict, snapshot: Path) -> None:
    """Product names for the banner: CISA KEV vendor/product, early-warning nicknames, title heuristics."""
    dates = [m.get("date") for m in manifest.get("days") or [] if isinstance(m, dict)]
    kev_map, ctx["titles"] = digest.shard_facts(snapshot, manifest, dates)
    ctx["names"] = {**digest.early_cve_names(digest.early_doc()), **kev_map}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", default="HEAD~1", help="git revision holding the previous snapshot")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--sample", type=int, default=0,
                        help="preview: announce the current top N patch-now CVEs instead of only new ones")
    parser.add_argument("--chat", default="", help="send to this chat id instead of TELEGRAM_CHAT_ID")
    parser.add_argument("--card-out", type=Path, default=None, help="where to keep the rendered banner")
    parser.add_argument("--no-card", action="store_true", help="plain text message only")
    args = parser.parse_args()

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = args.chat.strip() or os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not args.dry_run and (not token or not chat):
        print("Telegram is not configured; skipping.")
        return 0

    snapshot = ROOT / "public" / "snapshot"
    manifest, rows, ctx = load_index(snapshot)
    if args.sample > 0:
        new = [r for r in rows if priority(r, ctx) == 1]
    else:
        old, old_ctx = previous_rows(args.previous)
        if not old:
            print("No previous snapshot to compare with; skipping so the channel is not flooded.")
            return 0
        new = [r for r in rows if priority(r, ctx) == 1 and (r[0] not in old or priority(old[r[0]], old_ctx) != 1)]
    new.sort(key=lambda r: (bool(r[4]), r[5] or 0), reverse=True)
    if args.sample > 0:
        new = new[: args.sample]
    if not new:
        print("Nothing newly urgent.")
        return 0

    card = None
    if not args.no_card:
        try:
            add_names(ctx, manifest, snapshot)
            try:
                when = datetime.fromisoformat(str(manifest.get("generated_at")).replace("Z", "+00:00"))
            except ValueError:
                when = datetime.now(timezone.utc)
            out = args.card_out or Path(tempfile.gettempdir()) / "subzer0-alert.png"
            if digest.render_card(cards.alert(card_data(new, ctx, when.strftime("%d %b %Y \u00b7 %H:%M UTC"))), out):
                card = out
        except Exception as exc:  # the banner is a bonus; the text alert must still go out
            print(f"Banner skipped: {type(exc).__name__}")
    if args.dry_run:
        print(caption(new, ctx) if card else message(new, ctx))
        print(f"Banner: {card or 'not rendered'}")
        return 0
    ok = False
    if card:
        ok = digest.tg_call("sendPhoto", token, {"chat_id": chat, "caption": caption(new, ctx), "parse_mode": "HTML"},
                            photo=card)
    if not ok:  # no banner (or the photo was rejected): plain text, exactly as before
        ok = digest.tg_call("sendMessage", token, {"chat_id": chat, "text": message(new, ctx), "parse_mode": "HTML",
                                                   "disable_web_page_preview": True})
    print(f"Announced {len(new)} CVEs" if ok else "Telegram rejected the message")
    return 0


if __name__ == "__main__":
    sys.exit(main())
