"""Per-page share cards (og:image) for SubZer0: 1200x630 JPEGs in og/<key>.jpg.

Optional by design: needs Pillow (requirements-cards.txt). If Pillow or a font is missing the
build carries on and pages keep the default og.png. Cards are drawn for every P1 CVE, the most
urgent P2 CVEs (by EPSS, then CVSS) up to CARD_LIMIT, and every weekly recap.
"""
from __future__ import annotations

from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - exercised when Pillow is absent
    Image = None

FONTS = Path(__file__).resolve().parent.parent / "site" / "fonts"
W, H = 1200, 630
CARD_LIMIT = 500
VOID, PANEL, INK, INK2, INK3, LINE = "#07080A", "#0E1115", "#F2EEE6", "#BDB6AA", "#6F737A", "#22262C"
SEV = {"critical": "#E5323F", "high": "#F08A24", "medium": "#E9C548", "low": "#2FA37E", "unscored": "#8ED3E8"}
P_TEXT = {1: "P1 · PATCH NOW", 2: "P2 · THIS WEEK", 3: "P3 · PLANNED", 4: "P4 · TRACK"}
FOOT = "iliya-bashrc.github.io/SubZer0   ·   t.me/RootAccessClub"


class Fonts:
    def __init__(self) -> None:
        self.cache: dict = {}

    def get(self, name: str, size: int, weight: int | None = None):
        key = (name, size, weight)
        if key not in self.cache:
            font = ImageFont.truetype(str(FONTS / name), size)
            if weight:
                try:
                    font.set_variation_by_axes([weight])
                except (OSError, ValueError):
                    pass
            self.cache[key] = font
        return self.cache[key]

    def display(self, size: int):
        return self.get("ChakraPetch-700.woff2", size)

    def text(self, size: int, weight: int = 400):
        return self.get("Inter.woff2", size, weight)

    def mono(self, size: int):
        return self.get("JetBrainsMono.woff2", size, 500)


def wrap(draw, text: str, font, width: int, lines: int) -> list[str]:
    words, out, cur = str(text or "").split(), [], ""
    for word in words:
        trial = f"{cur} {word}".strip()
        if draw.textlength(trial, font=font) <= width:
            cur = trial
            continue
        if cur:
            out.append(cur)
        cur = word
        if len(out) == lines:
            break
    if cur and len(out) < lines:
        out.append(cur)
    if len(out) == lines and " ".join(out) != " ".join(words):
        last = out[-1]
        while last and draw.textlength(last + "…", font=font) > width:
            last = last[:-1]
        out[-1] = last.rstrip(" ,.;:-") + "…"
    return out


def base(f: Fonts, accent: str):
    img = Image.new("RGB", (W, H), VOID)
    d = ImageDraw.Draw(img)
    for x in range(700, W):  # soft ice glow on the right, like og.png
        t = (x - 700) / (W - 700)
        d.line([(x, 0), (x, H)], fill=(int(7 + 11 * t), int(8 + 22 * t), int(10 + 30 * t)))
    d.rectangle([64, 64, 74, H - 64], fill=accent)
    d.text((110, 58), "SUBZER", font=f.display(40), fill=INK)
    d.text((110 + d.textlength("SUBZER", font=f.display(40)), 58), "0", font=f.display(40), fill="#E5323F")
    d.text((110, H - 92), FOOT, font=f.mono(22), fill=INK3)
    return img, d


def badge(d, f: Fonts, text: str, color: str, right: int = W - 64, top: int = 60) -> None:
    font = f.mono(24)
    w = d.textlength(text, font=font)
    d.rounded_rectangle([right - w - 36, top, right, top + 46], radius=8, outline=color, width=2, fill=PANEL)
    d.text((right - w - 18, top + 9), text, font=font, fill=color)


def stats(d, f: Fonts, cells: list[tuple[str, str, str]], y: int) -> None:
    x = 110
    for label, value, color in cells:
        vf, lf = f.display(44), f.mono(18)
        w = max(d.textlength(value, font=vf), d.textlength(label, font=lf)) + 44
        d.rounded_rectangle([x, y, x + w, y + 104], radius=10, fill=PANEL, outline=LINE, width=2)
        d.text((x + 22, y + 12), value, font=vf, fill=color)
        d.text((x + 22, y + 70), label, font=lf, fill=INK3)
        x += w + 16


def cve_card(f: Fonts, item: dict):
    sev = item.get("sev") if item.get("sev") in SEV else "unscored"
    accent = SEV[sev]
    img, d = base(f, accent)
    if item.get("p") in P_TEXT:
        badge(d, f, P_TEXT[item["p"]], "#E5323F" if item["p"] == 1 else accent)
    d.text((106, 140), item["id"], font=f.display(92), fill=INK)
    y = 262
    for line in wrap(d, item.get("title") or "", f.text(36, 500), W - 220, 2):
        d.text((110, y), line, font=f.text(36, 500), fill=INK2)
        y += 48
    cells = [("SEVERITY", sev.upper() if sev != "unscored" else "N/A", accent)]
    if item.get("score"):
        cells.append(("CVSS", f"{float(item['score']):.1f}", INK))
    if isinstance(item.get("epss"), (int, float)):
        cells.append(("EPSS", f"{item['epss'] * 100:.1f}%", INK))
    if item.get("kev"):
        cells.append(("CISA KEV", "EXPLOITED", "#E5323F"))
    elif item.get("weap"):
        cells.append(("EXPLOIT", "WEAPONIZED", "#F08A24"))
    elif item.get("poc"):
        cells.append(("EXPLOIT", "PUBLIC", "#F08A24"))
    stats(d, f, cells[:4], 380)
    return img


def week_card(f: Fonts, key: str, label: str, items: list[dict], rank):
    img, d = base(f, "#8ED3E8")
    badge(d, f, "WEEKLY RECAP", "#8ED3E8")
    head, span = label.split(" (")[0], label.split("(")[1].rstrip(")")
    d.text((106, 136), head.upper(), font=f.display(84), fill=INK)
    d.text((110, 240), span, font=f.text(34, 500), fill=INK2)
    p1 = sum(1 for i in items if i.get("p") == 1)
    kev = sum(1 for i in items if i.get("kev"))
    crit = sum(1 for i in items if i.get("sev") == "critical")
    stats(d, f, [("CVES", f"{len(items):,}", INK), ("PATCH NOW", str(p1), "#E5323F"), ("ON KEV", str(kev), "#F08A24"),
                 ("CRITICAL", str(crit), "#E9C548")], 300)
    top = [i["id"] for i in sorted(items, key=rank)[:3]]
    if top:
        d.text((110, 438), "TOP  " + "  ·  ".join(top), font=f.mono(24), fill="#8ED3E8")
    return img


def pick(items: list[dict]) -> list[dict]:
    p1 = [i for i in items if i.get("p") == 1]
    p2 = sorted((i for i in items if i.get("p") == 2), key=lambda i: (-(i.get("epss") or 0), -(i.get("score") or 0), i["id"]))
    return (p1 + p2)[:CARD_LIMIT] if len(p1) < CARD_LIMIT else p1


def render_all(out: Path, items: list[dict], hubs: dict) -> set[str]:
    """Write og/<key>.jpg and return the keys that have a card ("CVE-…" or "week/2026-w43")."""
    if Image is None:
        return set()
    try:
        f = Fonts()
        f.display(40), f.text(36, 500), f.mono(22)
    except OSError as exc:
        print(f"share cards skipped: {exc}")
        return set()
    import hub_pages as hub
    made: set[str] = set()
    (out / "og" / "week").mkdir(parents=True, exist_ok=True)
    for item in pick(items):
        cve_card(f, item).save(out / "og" / f"{item['id']}.jpg", "JPEG", quality=80, optimize=True, progressive=True)
        made.add(item["id"])
    for key, week_items in (hubs.get("weeks") or {}).items():
        week_card(f, key, hub.week_label(key), week_items, hub.rank).save(out / "og" / "week" / f"{key}.jpg", "JPEG", quality=84, optimize=True)
        made.add(f"week/{key}")
    return made
