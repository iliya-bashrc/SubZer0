#!/usr/bin/env python3
"""Daily / weekly Telegram digest for SubZer0 (English).

Daily  (every day except Saturday): short text post with the CVEs that need action now (CISA KEV adds and
        priority-1 CVEs from the last ~24h). Quiet days post nothing.
Weekly (Saturday): a rendered summary card (photo) + caption covering the last 7 days.

Reads only the committed, hash-checked snapshot (public/snapshot). Needs TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID;
without them (or with --dry-run) it prints what it would post.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_site as bs  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SITE_URL = bs.SITE_URL
LIVE_EARLY = SITE_URL + "live/early.json"
CAPTION_MAX = 1024
TEXT_MAX = 3900


def clip(text: str, n: int) -> str:
    text = " ".join(str(text or "").replace("\u2026", " ").split())
    if len(text) <= n:
        return text
    cut = text[:n].rsplit(" ", 1)[0].rstrip(",;:.-(")
    return cut + "\u2026"


def visible_len(markup: str) -> int:
    """Telegram counts the caption limit on the rendered text, not on HTML tags or link targets."""
    return len(html.unescape(re.sub(r"<[^>]+>", "", markup)))


def period_dates(mode: str, now: datetime) -> list[str]:
    days = 7 if mode == "weekly" else 2  # daily: yesterday + today (UTC) = the last ~24-30h of data
    return [(now - timedelta(days=i)).date().isoformat() for i in range(days)]


def rank_key(row: list, ctx: dict) -> tuple:
    f = bs.facts(row, ctx)
    return (bs.priority(row, ctx), 0 if f["kev"] else 1, -f["c"], -f["e"])


def build_digest(rows: list[list], ctx: dict, mode: str, now: datetime) -> dict:
    dates = set(period_dates(mode, now))
    inside = [r for r in rows if str(r[6] or "")[:10] in dates]
    kev = sorted((r for r in inside if r[4]), key=lambda r: rank_key(r, ctx))
    p1 = sorted((r for r in inside if not r[4] and bs.priority(r, ctx) == 1), key=lambda r: rank_key(r, ctx))
    crit = [r for r in inside if r[2] == "critical"]
    pocs = [r for r in inside if bs.facts(r, ctx)["poc"] or bs.facts(r, ctx)["weap"]]
    top = sorted((r for r in inside if not r[4] and (bs.priority(r, ctx) == 1 or r[2] == "critical")),
                 key=lambda r: rank_key(r, ctx))
    return {
        "mode": mode,
        "dates": sorted(dates),
        "total": len(inside),
        "critical": len(crit),
        "high": sum(1 for r in inside if r[2] == "high"),
        "kev": kev,
        "p1": p1,
        "pocs": len(pocs),
        "top": top,
    }


def shard_facts(snapshot: Path, manifest: dict, dates: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """From the period's (hash-checked) day shards: CVE id -> "Vendor Product" for CISA KEV entries,
    and CVE id -> full (unclipped) title."""
    out: dict[str, str] = {}
    titles: dict[str, str] = {}
    for meta in manifest.get("days") or []:
        if not isinstance(meta, dict) or meta.get("date") not in dates:
            continue
        for rec in bs._read_verified(snapshot, meta) or []:
            if not isinstance(rec, dict) or not rec.get("id"):
                continue
            titles[rec["id"]] = str(rec.get("desc") or rec.get("title") or "")[:400]
            k = rec.get("kev")
            if isinstance(k, dict) and (k.get("vendor") or k.get("product")):
                name = " ".join(x for x in (k.get("vendor"), k.get("product")) if x)
                out[rec["id"]] = name
    return out, titles


_STOP = r"(?=\s+[a-z(]|[,;:(]|\.(?:\s|$)|$)"
_NAME = r"([A-Z0-9][\w+/-]*(?:\.[\w+/-]+)*(?:\s+[A-Z0-9][\w+/-]*(?:\.[\w+/-]+)*){0,4})"
_PATTERNS = [
    re.compile(r"\bvulnerabilit(?:y|ies) (?:exists? )?in (?:the )?(?:affected \w+ of )?" + _NAME + _STOP),
    re.compile(r"\b(?:exists?|found|identified|discovered|issue) in (?:the )?(?:affected \w+ of )?" + _NAME + _STOP),
    re.compile(r"^(?:In |The )?" + _NAME + r"\s+(?:before|through|up to|prior to|versions?|\d)"),
]


def short_title(title: str) -> str | None:
    t = " ".join(str(title or "").replace("\u2026", " ").split())
    for pat in _PATTERNS:
        m = pat.search(t)
        if m and 2 < len(m.group(1)) <= 48 and not m.group(1).upper().startswith(("CVE", "A ", "AN ")):
            return m.group(1).strip().rstrip(".-/")
    return None


def label(r: list, ctx: dict, n: int) -> str:
    name = ctx.get("names", {}).get(r[0]) or short_title(ctx.get("titles", {}).get(r[0]) or r[1])
    return clip(name, n) if name else clip(r[1], n)


def _line(r: list, ctx: dict, n: int = 70) -> str:
    f = bs.facts(r, ctx)
    tags = []
    if f["c"]:
        tags.append(f"{f['c']:.1f}")
    if f["weap"]:
        tags.append("weaponized")
    elif f["poc"]:
        tags.append("public PoC")
    if f["active"] and not f["kev"]:
        tags.append("exploited")
    meta = f" <i>{html.escape(' · '.join(tags))}</i>" if tags else ""
    return (f'\u2022 <a href="{SITE_URL}cve/{r[0]}">{r[0]}</a>{meta}\n'
            f'   {html.escape(label(r, ctx, n))}')


def _span(d: dict) -> str:
    a, b = d["dates"][0], d["dates"][-1]
    fa, fb = datetime.fromisoformat(a), datetime.fromisoformat(b)
    if d["mode"] == "weekly":
        return f"{fa:%b %-d} \u2013 {fb:%b %-d}"
    return f"{fb:%a, %b %-d}"


def daily_text(d: dict, ctx: dict) -> str | None:
    if not d["kev"] and not d["p1"]:
        return None  # quiet day: nothing that needs action
    parts = [f"\U0001F4E1 <b>SubZer0 Daily</b> \u00b7 {_span(d)}",
             f"<i>{d['total']} new CVEs \u00b7 {d['critical']} critical \u00b7 {len(d['kev'])} added to CISA KEV</i>"]
    if d["kev"]:
        parts.append("\U0001F534 <b>Actively exploited (CISA KEV)</b>\n" + "\n".join(_line(r, ctx) for r in d["kev"][:4]))
    if d["p1"]:
        parts.append("\U0001F3AF <b>Patch now</b>\n" + "\n".join(_line(r, ctx) for r in d["p1"][:4]))
    more = len(d["kev"]) + len(d["p1"]) - min(4, len(d["kev"])) - min(4, len(d["p1"]))
    tail = f"+{more} more \u2192 " if more > 0 else "Full list \u2192 "
    parts.append(f"{tail}{SITE_URL}\n\U0001F916 @SubZer0Robot")
    return "\n\n".join(parts)[:TEXT_MAX]


def weekly_caption(d: dict, ctx: dict, early: list[str]) -> str:
    head = [f"\U0001F4CA <b>SubZer0 Weekly</b> \u00b7 {_span(d)}",
            f"<i>{d['total']:,} new CVEs \u00b7 {d['critical']} critical \u00b7 {len(d['kev'])} added to KEV \u00b7 {d['pocs']} with public exploits</i>"]
    body = []
    if d["kev"]:
        body.append("\U0001F534 <b>Exploited this week</b>\n" + "\n".join(
            f'\u2022 <a href="{SITE_URL}cve/{r[0]}">{r[0]}</a> {html.escape(label(r, ctx, 50))}' for r in d["kev"][:4]))
    top = [r for r in d["top"] if r not in d["kev"]][:4]
    if top:
        body.append("\U0001F3AF <b>Top to patch</b>\n" + "\n".join(
            f'\u2022 <a href="{SITE_URL}cve/{r[0]}">{r[0]}</a> {html.escape(label(r, ctx, 50))}' for r in top))
    if early:
        body.append("\U0001F6A8 <b>Early warnings</b>: " + html.escape(", ".join(early[:4])))
    foot = f"Full dossier \u2192 {SITE_URL}\n\U0001F916 @SubZer0Robot"
    # Drop list items until the caption fits Telegram's 1024-char limit (visible text, tags included to be safe).
    while True:
        text = "\n\n".join(head + body + [foot])
        if visible_len(text) <= CAPTION_MAX or not body:
            return text
        last = body[-1].split("\n")
        body[-1:] = ["\n".join(last[:-1])] if len(last) > 2 else []


def early_doc(fetch=None) -> dict:
    try:
        if fetch:
            doc = fetch(LIVE_EARLY)
        else:
            req = urllib.request.Request(LIVE_EARLY, headers={"User-Agent": "SubZer0-digest"})
            with urllib.request.urlopen(req, timeout=15) as r:
                doc = json.loads(r.read(2_000_000))
        return doc if isinstance(doc, dict) else {}
    except Exception:
        return {}


def early_names(doc: dict) -> list[str]:
    return [str(e.get("name"))[:40] for e in doc.get("emerging") or [] if isinstance(e, dict) and e.get("name")]


def early_cve_names(doc: dict) -> dict[str, str]:
    """CVE id -> campaign nickname (PHP2Shell, ...) for named early-warning stories."""
    out: dict[str, str] = {}
    for e in doc.get("emerging") or []:
        if isinstance(e, dict) and e.get("name") and not str(e["name"]).startswith("CVE-"):
            for c in e.get("cves") or []:
                out.setdefault(str(c), str(e["name"])[:40])
    return out


# ------------------------------------------------------------------ card
def card_html(d: dict, ctx: dict, early: list[str]) -> str:
    fonts = (ROOT / "site" / "fonts").as_uri()
    rest = [r for r in d["top"] if r not in d["kev"]]
    top = (d["kev"][:3] + rest)[:5]
    top += [r for r in d["kev"][3:] if r not in top][:5 - len(top)]
    rows = "".join(
        f'<div class="r"><span class="id">{r[0]}</span><span class="sc {html.escape(r[2] or "")}">'
        f'{(f"{bs.facts(r, ctx)['c']:.1f}" if bs.facts(r, ctx)["c"] else "\u2014")}</span><span class="t">{html.escape(label(r, ctx, 70))}</span>'
        f'{"<b class=k>KEV</b>" if r[4] else ("<b class=w>PoC</b>" if bs.facts(r, ctx)["poc"] else "")}</div>'
        for r in top) or '<div class="r"><span class="t">Quiet week.</span></div>'
    ew = html.escape(" \u00b7 ".join(early[:3])) if early else "none this week"
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{{font-family:CP;src:url({fonts}/ChakraPetch-700.woff2);font-weight:700}}
@font-face{{font-family:IN;src:url({fonts}/Inter.woff2);font-weight:100 900}}
@font-face{{font-family:JB;src:url({fonts}/JetBrainsMono.woff2);font-weight:100 900}}
*{{box-sizing:border-box;margin:0}}
body{{width:1600px;height:900px;overflow:hidden;position:relative;color:#EDE6DA;font-family:IN;
background:radial-gradient(circle at 18% 30%,#141A20 0,#07080A 60%)}}
.grid{{position:absolute;inset:0;background-image:linear-gradient(#ffffff08 1px,transparent 1px),linear-gradient(90deg,#ffffff08 1px,transparent 1px);background-size:40px 40px}}
.strip{{position:absolute;top:0;bottom:0;right:7%;width:16px;background:#F29A2E}}
.brand{{position:absolute;left:72px;top:56px;display:flex;align-items:center;gap:18px}}
.brand i{{width:7px;height:34px;background:#F29A2E}}.brand b{{font:700 32px CP}}.brand span{{font:500 15px JB;letter-spacing:.3em;color:#8A929A}}
.wk{{position:absolute;right:190px;top:52px;padding:11px 18px;border:1px solid #23292F;background:#07080Acc;font:500 16px JB;letter-spacing:.25em;color:#C9C2B6}}
h1{{position:absolute;left:68px;top:118px;font:700 112px/1 CP}}h1 em{{font-style:normal;color:#8FD3EE}}
.stats{{position:absolute;left:72px;top:262px;display:flex;border:1px solid #23292F;background:#0A0C0Ee6}}
.stats div{{width:230px;padding:20px 22px}}.stats div+div{{border-left:1px solid #23292F}}
.stats small{{font:500 13px JB;letter-spacing:.22em;color:#6B747C}}.stats b{{display:block;font:700 50px/1.2 CP;margin-top:6px}}
.list{{position:absolute;left:72px;top:418px;width:1220px}}
.list h2{{font:500 14px JB;letter-spacing:.25em;color:#6B747C;margin-bottom:10px}}
.r{{display:flex;align-items:center;gap:18px;padding:13px 0;border-top:1px solid #1C2126;font-size:21px}}
.id{{font:600 20px JB;width:250px;color:#EDE6DA}}.sc{{font:700 22px CP;width:56px}}
.sc.critical{{color:#E5323F}}.sc.high{{color:#F08A24}}.sc.medium{{color:#E9C548}}.t{{flex:1;color:#A7AFB6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.k,.w{{font:700 13px CP;letter-spacing:.12em;padding:5px 9px}}.k{{background:#E5323F;color:#fff}}.w{{border:1.5px solid #E9C548;color:#E9C548}}
.ew{{position:absolute;left:72px;bottom:58px;font:500 17px JB;color:#C9C2B6}}.ew span{{color:#6B747C;letter-spacing:.22em;margin-right:16px}}
.url{{position:absolute;right:190px;bottom:54px;font:500 20px JB;color:#8FD3EE}}
</style></head><body><div class="grid"></div><div class="strip"></div>
<div class="brand"><i></i><b>SubZer0</b><span>CVE RADAR</span></div>
<div class="wk">WEEKLY \u00b7 {html.escape(_span(d).upper())}</div>
<h1>This <em>week</em></h1>
<div class="stats">
<div><small>NEW CVES</small><b>{d['total']:,}</b></div>
<div><small>CRITICAL</small><b style="color:#E5323F">{d['critical']}</b></div>
<div><small>CISA KEV</small><b style="color:#F08A24">{len(d['kev'])}</b></div>
<div><small>PUBLIC POC</small><b style="color:#E9C548">{d['pocs']}</b></div>
<div><small>HIGH</small><b style="color:#8FD3EE">{d['high']}</b></div>
</div>
<div class="list"><h2>TOP TO PATCH</h2>{rows}</div>
<div class="ew"><span>EARLY WARNING</span>{ew}</div>
<div class="url">iliya-bashrc.github.io/SubZer0 \u00b7 @SubZer0Robot</div>
</body></html>"""


def render_card(markup: str, out: Path) -> bool:
    browser = next((shutil.which(b) for b in ("google-chrome", "chromium", "chromium-browser") if shutil.which(b)), None)
    if not browser:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "card.html"
        page.write_text(markup, encoding="utf-8")
        try:
            subprocess.run([browser, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                            "--force-device-scale-factor=1", "--window-size=1600,900", "--virtual-time-budget=4000",
                            f"--screenshot={out}", page.as_uri()], check=True, timeout=90,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            return False
    return out.exists() and out.stat().st_size > 10_000


# ------------------------------------------------------------------ telegram
def tg_call(method: str, token: str, fields: dict, photo: Path | None = None) -> bool:
    url = f"https://api.telegram.org/bot{token}/{method}"
    if photo is None:
        body = json.dumps(fields).encode()
        headers = {"Content-Type": "application/json"}
    else:
        b = uuid.uuid4().hex
        chunks = []
        for k, v in fields.items():
            chunks.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        chunks.append(f'--{b}\r\nContent-Disposition: form-data; name="photo"; filename="weekly.png"\r\n'
                      f"Content-Type: image/png\r\n\r\n".encode() + photo.read_bytes() + b"\r\n")
        chunks.append(f"--{b}--\r\n".encode())
        body = b"".join(chunks)
        headers = {"Content-Type": f"multipart/form-data; boundary={b}"}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method="POST"), timeout=60) as r:
            return bool(json.load(r).get("ok"))
    except urllib.error.HTTPError as exc:
        try:
            print("digest: telegram error:", json.load(exc).get("description"), file=sys.stderr)
        except Exception:
            print(f"digest: telegram HTTP {exc.code}", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"digest: telegram failed ({type(exc).__name__})", file=sys.stderr)
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--snapshot", type=Path, default=ROOT / "public" / "snapshot")
    ap.add_argument("--mode", choices=["auto", "daily", "weekly"], default="auto")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--card-out", type=Path, default=None, help="where to keep the rendered weekly card")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    mode = args.mode if args.mode != "auto" else ("weekly" if now.weekday() == 5 else "daily")
    manifest, rows, ctx = bs.load_index(args.snapshot)
    # Anchor the period on the snapshot time so a late cron run never shifts onto an empty "today".
    try:
        anchor = datetime.fromisoformat(str(manifest["generated_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        anchor = now
    d = build_digest(rows, ctx, mode, anchor)
    edoc = early_doc()
    kev_map, ctx["titles"] = shard_facts(args.snapshot, manifest, d["dates"])
    ctx["names"] = {**early_cve_names(edoc), **kev_map}
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(), os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    dry = args.dry_run or not token or not chat

    if mode == "daily":
        text = daily_text(d, ctx)
        if text is None:
            print("digest: quiet day, nothing to post")
            return 0
        if dry:
            print(text)
            return 0
        ok = tg_call("sendMessage", token, {"chat_id": chat, "text": text, "parse_mode": "HTML",
                                            "disable_web_page_preview": True})
        print("digest: daily posted" if ok else "digest: daily FAILED")
        return 0 if ok else 1

    early = early_names(edoc)
    caption = weekly_caption(d, ctx, early)
    card = args.card_out or Path(tempfile.gettempdir()) / "subzer0-weekly.png"
    have_card = render_card(card_html(d, ctx, early), card)
    if dry:
        print(caption)
        print(f"digest: card {'rendered at ' + str(card) if have_card else 'not rendered'}")
        return 0
    if have_card:
        ok = tg_call("sendPhoto", token, {"chat_id": chat, "caption": caption, "parse_mode": "HTML"}, photo=card)
    else:
        ok = tg_call("sendMessage", token, {"chat_id": chat, "text": caption, "parse_mode": "HTML",
                                            "disable_web_page_preview": True})
    print("digest: weekly posted" if ok else "digest: weekly FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
