"""Deploy worker/bot.js to Cloudflare Workers and register it as @SubZer0Robot's webhook.

Standard library only. Never prints secrets. Env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, TELEGRAM_BOT_TOKEN.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CF = "https://api.cloudflare.com/client/v4"
SCRIPT = "subzer0"
KV_TITLE = "subzer0-bot"
SITE = "https://iliya-bashrc.github.io/SubZer0/"
COMMANDS = [
    ("cve", "Summary of one CVE, e.g. /cve CVE-2026-110447"),
    ("top", "What to patch right now"),
    ("week", "This week's recap: the CVEs that mattered"),
    ("watch", "Get a DM when a product gets a patch-now CVE"),
    ("unwatch", "Remove a name from your watchlist"),
    ("list", "Show your watchlist"),
    ("help", "How to use SubZer0 Sentinel"),
]


def webhook_secret(bot_token: str) -> str:
    """Stable, non-reversible secret derived from the bot token (Telegram allows A-Z a-z 0-9 _ -)."""
    return hashlib.sha256((bot_token + "webhook").encode()).hexdigest()[:48]


def multipart(parts: list[tuple[str, str, str, bytes]]) -> tuple[bytes, str]:
    """parts: (field name, filename, content type, body)."""
    b = uuid.uuid4().hex
    out = bytearray()
    for name, filename, ctype, body in parts:
        out += f'--{b}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n'.encode()
        out += body + b"\r\n"
    out += f"--{b}--\r\n".encode()
    return bytes(out), f"multipart/form-data; boundary={b}"


def metadata(kv_id: str, bot_token: str) -> dict:
    return {
        "main_module": "bot.js",
        "compatibility_date": "2025-01-01",
        "bindings": [
            {"type": "kv_namespace", "name": "KV", "namespace_id": kv_id},
            {"type": "secret_text", "name": "BOT_TOKEN", "text": bot_token},
            {"type": "secret_text", "name": "WEBHOOK_SECRET", "text": webhook_secret(bot_token)},
            {"type": "plain_text", "name": "SITE", "text": SITE},
        ],
    }


def call(url: str, token: str | None = None, method: str = "GET", data: bytes | None = None, ctype: str = "application/json") -> dict:
    headers = {"Content-Type": ctype, "User-Agent": "SubZer0-deploy"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
        except Exception:
            body = {}
        errs = body.get("errors") or body.get("description") or ""
        where = url.split("?")[0].replace(CF, "") if url.startswith(CF) else "telegram " + url.rsplit("/", 1)[-1]
        raise SystemExit(f"{method} {where} failed: HTTP {e.code} {json.dumps(errs)[:400]}")


def main() -> int:
    tok = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    acc = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    bot = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not tok or not bot:
        sys.exit("CLOUDFLARE_API_TOKEN or TELEGRAM_BOT_TOKEN secret is missing")
    if not re.fullmatch(r"[0-9a-f]{32}", acc):
        sys.exit("CLOUDFLARE_ACCOUNT_ID must be the 32-character account id (Workers & Pages -> right sidebar)")

    v = call(f"{CF}/user/tokens/verify", tok)
    print("Cloudflare token:", (v.get("result") or {}).get("status"))

    a = f"{CF}/accounts/{acc}"
    ns = call(f"{a}/storage/kv/namespaces?per_page=100", tok).get("result") or []
    kv = next((n["id"] for n in ns if n.get("title") == KV_TITLE), None)
    if not kv:
        kv = call(f"{a}/storage/kv/namespaces", tok, "POST", json.dumps({"title": KV_TITLE}).encode())["result"]["id"]
        print("Created KV namespace", KV_TITLE)
    else:
        print("Using KV namespace", KV_TITLE)

    js = (ROOT / "worker/bot.js").read_bytes()
    body, ctype = multipart([
        ("metadata", "metadata.json", "application/json", json.dumps(metadata(kv, bot)).encode()),
        ("bot.js", "bot.js", "application/javascript+module", js),
    ])
    call(f"{a}/workers/scripts/{SCRIPT}", tok, "PUT", body, ctype)
    print("Uploaded worker", SCRIPT, f"({len(js)} bytes)")

    call(f"{a}/workers/scripts/{SCRIPT}/subdomain", tok, "POST", json.dumps({"enabled": True}).encode())
    sub = (call(f"{a}/workers/subdomain", tok).get("result") or {}).get("subdomain")
    if not sub:
        sys.exit("No workers.dev subdomain on this account: open Workers & Pages once in the dashboard to create it")
    url = f"https://{SCRIPT}.{sub}.workers.dev"
    print("Worker URL:", url)

    tg = f"https://api.telegram.org/bot{bot}"
    hook = {"url": url + "/tg", "secret_token": webhook_secret(bot), "allowed_updates": ["message"],
            "drop_pending_updates": True, "max_connections": 20}
    r = call(f"{tg}/setWebhook", None, "POST", json.dumps(hook).encode())
    print("setWebhook:", r.get("description") or r.get("ok"))
    cmds = {"commands": [{"command": c, "description": d} for c, d in COMMANDS]}
    r = call(f"{tg}/setMyCommands", None, "POST", json.dumps(cmds).encode())
    print("setMyCommands:", r.get("ok"))
    info = call(f"{tg}/getWebhookInfo").get("result") or {}
    print("Webhook pending updates:", info.get("pending_update_count"), "| last error:", info.get("last_error_message") or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
