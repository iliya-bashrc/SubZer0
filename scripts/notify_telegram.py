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
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
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


def alert_buttons(new: list[list]) -> dict:
    first = [("\U0001F4C2 " + new[0][0], f"{SITE_URL}cve/{new[0][0]}", "danger")] if new else []
    return digest.buttons(first + [("\U0001F3AF All patch-now", f"{SITE_URL}research?view=p1", "primary")], [digest.ALERTS_BTN])


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


# ------------------------------------------------------------------ /watch DMs
CF_API = "https://api.cloudflare.com/client/v4"
KV_TITLE = "subzer0-bot"
MAX_DMS = 500


def _norm(s: str) -> str:
    """Same normalisation as norm() in worker/bot.js."""
    return " ".join(re.sub(r"[^a-z0-9.+_\- ]", " ", str(s or "").lower()).split())


def _cf(token: str, path: str, raw: bool = False):
    req = urllib.request.Request(CF_API + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read(2_000_000)
    return body if raw else json.loads(body)


def kv_namespace(token: str, account: str) -> str | None:
    return next((n["id"] for n in _cf(token, f"/accounts/{account}/storage/kv/namespaces?per_page=100").get("result") or []
                 if n.get("title") == KV_TITLE), None)


def drop_watch(token: str, account: str, ns: str, chat: str) -> bool:
    """Delete w:<chat> (the user blocked the bot or deleted the chat)."""
    req = urllib.request.Request(f"{CF_API}/accounts/{account}/storage/kv/namespaces/{ns}/values/{urllib.parse.quote('w:' + chat)}",
                                 method="DELETE", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status == 200
    except Exception:
        return False


def send_dm(token: str, chat: str, text: str, markup: dict) -> tuple[bool, int]:
    """sendMessage that reports the HTTP status (403 = blocked) and waits out one 429."""
    body = json.dumps({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True, "reply_markup": markup}).encode()
    for attempt in range(2):
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return bool(json.load(r).get("ok")), 200
        except urllib.error.HTTPError as exc:
            try:
                wait = int((json.load(exc).get("parameters") or {}).get("retry_after") or 0)
            except Exception:
                wait = 0
            if exc.code == 429 and attempt == 0 and 0 < wait <= 30:
                time.sleep(wait)
                continue
            return False, exc.code
        except Exception:
            return False, 0
    return False, 429


def load_watches(token: str, account: str) -> dict[str, list[str]]:
    """chat id -> keywords, read from the bot's KV namespace (empty when Cloudflare is not set up)."""
    ns = next((n["id"] for n in _cf(token, f"/accounts/{account}/storage/kv/namespaces?per_page=100").get("result") or []
               if n.get("title") == KV_TITLE), None)
    if not ns:
        return {}
    out: dict[str, list[str]] = {}
    cursor = ""
    for _ in range(20):
        page = _cf(token, f"/accounts/{account}/storage/kv/namespaces/{ns}/keys?prefix=w:&limit=1000" + (f"&cursor={cursor}" if cursor else ""))
        for k in page.get("result") or []:
            name = str(k.get("name") or "")
            if not re.fullmatch(r"w:-?\d{1,20}", name):
                continue
            try:
                doc = json.loads(_cf(token, f"/accounts/{account}/storage/kv/namespaces/{ns}/values/{urllib.parse.quote(name)}", raw=True))
                kws = [_norm(x) for x in doc.get("k") or [] if isinstance(x, str)]
            except Exception:
                continue
            if kws:
                out[name[2:]] = [k for k in kws if 3 <= len(k) <= 40][:10]
        cursor = (page.get("result_info") or {}).get("cursor") or ""
        if not cursor:
            break
    return out


def watch_matches(new: list[list], watches: dict[str, list[str]], ctx: dict) -> dict[str, list[tuple[list, str]]]:
    """chat id -> [(row, keyword)] for every newly urgent CVE whose id, title or product names a watched keyword."""
    hay = {}
    for r in new:
        name = (ctx.get("names") or {}).get(r[0], "")
        hay[r[0]] = f" {_norm(' '.join(str(x or '') for x in (r[0], r[1], r[8] if len(r) > 8 else '', name)))} "
    out: dict[str, list[tuple[list, str]]] = {}
    for chat, kws in watches.items():
        for r in new:
            kw = next((k for k in kws if f" {k} " in hay[r[0]]), None)
            if kw:
                out.setdefault(chat, []).append((r, kw))
    return out


def watch_text(hits: list[tuple[list, str]], ctx: dict) -> str:
    lines = [f"\U0001F441 <b>Your watchlist</b> \u00b7 {len(hits)} new to patch now"]
    for r, kw in hits[:8]:
        lines.append(f'\n<a href="{SITE_URL}cve/{r[0]}">{r[0]}</a> \u2014 {escape(str(r[1])[:110])}\n<i>{escape(reason(r, ctx))} \u00b7 matched \u201c{escape(kw)}\u201d</i>')
    if len(hits) > 8:
        lines.append(f"\n\u2026and {len(hits) - 8} more: {SITE_URL}research?view=p1")
    lines.append("\n/list to see your watchlist \u00b7 /unwatch name to stop")
    return "\n".join(lines)


def watch_buttons(hits: list[tuple[list, str]]) -> dict:
    r = hits[0][0]
    return {"inline_keyboard": [[{"text": f"\U0001F4C2 {r[0]}", "web_app": {"url": f"{SITE_URL}cve/{r[0]}"}, "style": "danger"}],
                                [{"text": "\U0001F441 My watchlist", "callback_data": "l", "style": "success"},
                                 {"text": "\U0001F3AF Patch now", "callback_data": "t:0"}]]}


def send_watch_dms(new: list[list], ctx: dict, token: str, dry: bool) -> None:
    cf_token, account = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip(), os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    if not cf_token or not re.fullmatch(r"[0-9a-f]{32}", account):
        return
    try:
        watches = load_watches(cf_token, account)
    except Exception as exc:
        print(f"Watchlists unavailable: {type(exc).__name__}")
        return
    hits = watch_matches(new, watches, ctx)
    sent = dropped = 0
    ns = None
    for chat, items in list(hits.items())[:MAX_DMS]:
        text = watch_text(items, ctx)
        if dry:
            print(f"[watch DM to {chat}]\n{text}")
            continue
        ok, code = send_dm(token, chat, text, watch_buttons(items))
        if ok:
            sent += 1
        elif code == 403 and not chat.startswith("-"):  # blocked: stop trying every 6 hours
            try:
                ns = ns or kv_namespace(cf_token, account)
                dropped += bool(ns and drop_watch(cf_token, account, ns, chat))
            except Exception:
                pass
        time.sleep(0.05)
    print(f"Watchlists: {len(watches)} users, {len(hits)} matched, {sent} DMs sent, {dropped} blocked removed")


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
        if args.sample <= 0:
            send_watch_dms(new, ctx, token, dry=True)
        print(caption(new, ctx) if card else message(new, ctx))
        print(f"Banner: {card or 'not rendered'}")
        return 0
    ok = False
    if card:
        ok = digest.tg_call("sendPhoto", token, {"chat_id": chat, "caption": caption(new, ctx), "parse_mode": "HTML",
                                                 "reply_markup": alert_buttons(new)},
                            photo=card)
    if not ok:  # no banner (or the photo was rejected): plain text, exactly as before
        ok = digest.tg_call("sendMessage", token, {"chat_id": chat, "text": message(new, ctx), "parse_mode": "HTML",
                                                   "disable_web_page_preview": True, "reply_markup": alert_buttons(new)})
    print(f"Announced {len(new)} CVEs" if ok else "Telegram rejected the message")
    if args.sample <= 0:
        send_watch_dms(new, ctx, token, dry=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
