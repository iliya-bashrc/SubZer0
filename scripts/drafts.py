"""Channel posts are drafts now: automation never posts to @RootAccessClub by itself.

Each would-be channel post goes to the owner's DM (TELEGRAM_ADMIN_ID) with two extra buttons:
"📤 Post to channel" and "✕ Skip". The bot (worker/bot.js) copies the draft to the channel only when
the owner taps Post, or when the owner replies to the draft with a note (posted on top of the draft).
Without TELEGRAM_ADMIN_ID nothing is sent anywhere.
"""
from __future__ import annotations

import os
import re

POST, SKIP = "P", "X"  # callback_data handled by worker/bot.js (owner only)


def admin_chat() -> str:
    """The owner's chat id, or "" when TELEGRAM_ADMIN_ID is not set (then drafts are skipped)."""
    v = os.environ.get("TELEGRAM_ADMIN_ID", "").strip()
    return v if re.fullmatch(r"\d{1,20}", v) else ""


def draft_markup(markup: dict | None) -> dict:
    """The channel buttons (kept as-is for the real post) plus the owner-only Post / Skip row."""
    rows = [list(r) for r in (markup or {}).get("inline_keyboard") or [] if r]
    rows.append([{"text": "\U0001F4E4 Post to channel", "callback_data": POST, "style": "success"},
                 {"text": "\u2715 Skip", "callback_data": SKIP}])
    return {"inline_keyboard": rows}
