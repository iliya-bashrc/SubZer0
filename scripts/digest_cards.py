"""Rotating weekly banner themes for the SubZer0 Telegram digest.

Every theme renders the same small data set (week label, a hero metric, three stats, at most three CVEs)
into a clean 1600x900 card; the caption carries the details. pick_theme() rotates themes by ISO week so two
weeks in a row never look the same, and seeds the procedural art with the week so repeats are not identical.
A named exploitation wave (PHP2Shell, ...) always gets the Spotlight theme.
"""
from __future__ import annotations

import html
import math
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
W, H = 1600, 900
ROTATION = ["bignumber", "terminal", "radar", "heatmap", "frost"]
THEMES = ["spotlight"] + ROTATION
INK, DIM, MUTE, LINE = "#EDE6DA", "#A7AFB6", "#6B747C", "#23292F"
CYAN, CRIT, HIGH, MED, LOW, STRIP = "#8FD3EE", "#E5323F", "#F08A24", "#E9C548", "#2FA37E", "#F29A2E"
MOSAIC = ["#1E3A4C", "#2E5A70", "#3E6F86", "#6B3A2A", "#A0522D", "#C8B79E", "#D9A441", "#0D1114", "#14232E", "#8A929A"]


def esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def pick_theme(week: int, spotlight: str | None) -> str:
    return "spotlight" if spotlight else ROTATION[week % len(ROTATION)]


def _base_css() -> str:
    f = (ROOT / "site" / "fonts").as_uri()
    return f"""
@font-face{{font-family:CP;src:url({f}/ChakraPetch-700.woff2);font-weight:700}}
@font-face{{font-family:CP;src:url({f}/ChakraPetch-600.woff2);font-weight:600}}
@font-face{{font-family:IN;src:url({f}/Inter.woff2);font-weight:100 900}}
@font-face{{font-family:JB;src:url({f}/JetBrainsMono.woff2);font-weight:100 900}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{width:{W}px;height:{H}px;overflow:hidden;position:relative;background:#07080A;color:{INK};font-family:IN}}
.abs{{position:absolute}}
.brand{{position:absolute;left:72px;top:58px;display:flex;align-items:center;gap:18px;z-index:5}}
.brand i{{width:7px;height:34px;background:{STRIP}}}.brand b{{font:700 32px CP}}
.brand span{{font:500 15px JB;letter-spacing:.3em;color:#8A929A}}
.wk{{position:absolute;right:72px;top:56px;z-index:5;padding:11px 18px;border:1px solid {LINE};background:#07080Ad9;
font:500 16px JB;letter-spacing:.24em;color:#C9C2B6;display:flex;gap:12px;align-items:center}}
.wk i{{width:10px;height:10px;background:{LOW};box-shadow:0 0 10px {LOW}}}
.foot{{position:absolute;left:72px;right:72px;bottom:46px;z-index:5;display:flex;justify-content:space-between;
font:500 17px JB;color:{MUTE};letter-spacing:.06em}}.foot b{{color:{CYAN};font-weight:500}}
.stats{{display:flex;gap:0;border:1px solid {LINE};background:#0A0C0Ee6}}
.stats div{{padding:18px 24px;min-width:200px}}.stats div+div{{border-left:1px solid {LINE}}}
.stats small{{display:block;font:500 13px JB;letter-spacing:.22em;color:{MUTE}}}
.stats b{{display:block;font:700 46px/1.15 CP;margin-top:6px}}
.cves{{font:500 21px/1.75 JB;color:{DIM}}}.cves b{{color:{INK};font-weight:600;margin-right:14px}}
.cves em{{font-style:normal;margin-right:14px}}
"""


def _chrome(d: dict) -> str:
    return (f'<div class="brand"><i></i><b>SubZer0</b><span>WEEKLY</span></div>'
            f'<div class="wk"><i></i>WEEK {d["week"]} \u00b7 {esc(d["span"]).upper()}</div>'
            f'<div class="foot"><span>for defenders, patch first</span>'
            f'<span><b>iliya-bashrc.github.io/SubZer0</b> \u00b7 @SubZer0Robot</span></div>')


def _stats(items: list[tuple[str, str, str]]) -> str:
    return '<div class="stats">' + "".join(
        f'<div><small>{esc(k)}</small><b style="color:{c}">{esc(v)}</b></div>' for k, v, c in items) + "</div>"


def _cves(top: list[dict], n: int = 3) -> str:
    rows = []
    for c in top[:n]:
        sc = f'{c["score"]:.1f}' if c.get("score") else "\u2014"
        col = CRIT if (c.get("score") or 0) >= 9 else HIGH if (c.get("score") or 0) >= 7 else MED
        rows.append(f'<div><b>{esc(c["id"])}</b><em style="color:{col}">{sc}</em>{esc(c["name"])}</div>')
    return '<div class="cves">' + "".join(rows) + "</div>"


def _fmt(n: int) -> str:
    return f"{n:,}"


def _page(css: str, body: str) -> str:
    return f'<!doctype html><html><head><meta charset="utf-8"><style>{_base_css()}{css}</style></head><body>{body}</body></html>'


def split_name(name: str) -> tuple[str, str]:
    """Two-tone title like the PHP2Shell banner: split after a digit (PHP2|Shell), else at the last space,
    else at a lower->Upper camel-case boundary; otherwise the whole name stays one colour."""
    for i, ch in enumerate(name):
        if ch.isdigit() and 0 < i < len(name) - 1 and not name[i + 1].isdigit():
            return name[: i + 1], name[i + 1:]
    if " " in name.strip():
        a, b = name.rsplit(" ", 1)
        return a + " ", b
    for i in range(1, len(name)):
        if name[i - 1].islower() and name[i].isupper():
            return name[:i], name[i:]
    return name, ""


# ---------------------------------------------------------------- themes
def spotlight(d: dict, rng: random.Random) -> str:
    name = d["spotlight"] or "This week"
    size = int(min(230, 1180 / max(4, len(name) * 0.6)))
    cols, rects, x = [], [], 820
    while x < W:
        w = rng.choice([14, 18, 22, 28, 36])
        y = 0
        while y < H:
            h = rng.choice([10, 14, 20, 30, 46, 70, 110])
            col = rng.choice(MOSAIC)
            op = 0.35 + 0.65 * (x - 820) / (W - 820)
            rects.append(f'<rect x="{x}" y="{y}" width="{w - 2}" height="{h - 2}" fill="{col}" opacity="{op:.2f}"/>')
            y += h
        x += w
    first, second = split_name(name)
    ids = " + ".join(esc(c) for c in d["spotlight_cves"][:2]) or "named exploitation wave"
    css = f"""
.mos{{position:absolute;inset:0}}
.fade{{position:absolute;inset:0;background:linear-gradient(90deg,#07080A 0,#07080A 46%,rgba(7,8,10,.75) 62%,rgba(7,8,10,.15) 88%)}}
.strip{{position:absolute;top:0;bottom:0;right:9%;width:18px;background:{STRIP};opacity:.95}}
.tag{{left:72px;top:190px;display:flex;gap:12px}}.tag b{{font:700 18px CP;letter-spacing:.14em;padding:11px 15px}}
h1{{position:absolute;left:66px;top:268px;font:700 {size}px/1 CP;letter-spacing:-.01em;white-space:nowrap;text-shadow:0 0 70px rgba(143,211,238,.18)}}
h1 em{{font-style:normal;color:{CYAN}}}
.ids{{left:74px;top:{268 + size + 34}px;font:600 34px JB}}
.st{{left:72px;bottom:120px}}
"""
    body = (f'<svg class="mos" viewBox="0 0 {W} {H}">{"".join(rects)}</svg><div class="fade"></div><div class="strip"></div>'
            + _chrome(d)
            + f'<div class="abs tag"><b style="background:{CRIT}">WAVE OF THE WEEK</b><b style="border:1.5px solid #2E4A57;color:{CYAN}">EARLY WARNING</b></div>'
            + f'<h1>{esc(first)}<em>{esc(second)}</em></h1><div class="abs ids">{ids}</div>'
            + '<div class="abs st">' + _stats([("CRITICAL", _fmt(d["critical"]), CRIT), ("CISA KEV", _fmt(d["kev"]), HIGH),
                                             ("PUBLIC POC", _fmt(d["pocs"]), MED)]) + "</div>")
    return _page(css, body)


def bignumber(d: dict, rng: random.Random) -> str:
    choices = [("CRITICAL CVES THIS WEEK", d["critical"], CRIT), ("NEW CVES IN 7 DAYS", d["total"], CYAN),
               ("CVES WITH PUBLIC EXPLOITS", d["pocs"], MED)]
    label, value, color = choices[rng.randrange(len(choices))]
    txt = _fmt(value)
    size = int(min(420, 1250 / max(2, len(txt) * 0.62)))
    slices = "".join(
        f'<div class="sl" style="top:{t}px;height:{h}px;transform:translateX({dx}px)"><span style="top:-{t}px">{txt}</span></div>'
        for t, h, dx in [(rng.randint(30, 120), rng.randint(8, 22), rng.choice([-26, -14, 18, 30])),
                         (rng.randint(170, 260), rng.randint(6, 16), rng.choice([-30, 22, 34]))])
    css = f"""
.grid{{position:absolute;inset:0;background-image:linear-gradient(#ffffff07 1px,transparent 1px),linear-gradient(90deg,#ffffff07 1px,transparent 1px);background-size:48px 48px}}
.glow{{position:absolute;left:-200px;top:80px;width:1300px;height:800px;background:radial-gradient(circle,{color}22 0,transparent 60%)}}
.num{{position:absolute;left:58px;top:170px;height:{size}px;font:700 {size}px/1 CP;letter-spacing:-.02em}}
.num>span,.sl span{{position:absolute;left:0;white-space:nowrap}}
.num .a{{color:{CRIT};transform:translate(-7px,3px);opacity:.75}}.num .b{{color:{CYAN};transform:translate(7px,-3px);opacity:.6}}
.num .m{{color:{INK}}}
.sl{{position:absolute;left:0;width:1400px;overflow:hidden}}.sl span{{color:{color}}}
.lab{{left:74px;top:{170 + size + 26}px;font:600 30px JB;letter-spacing:.2em;color:{color}}}
.st{{left:72px;bottom:120px}}
"""
    body = ('<div class="grid"></div><div class="glow"></div>' + _chrome(d)
            + f'<div class="num"><span class="a">{txt}</span><span class="b">{txt}</span><span class="m">{txt}</span>{slices}</div>'
            + f'<div class="abs lab">{esc(label)}</div>'
            + '<div class="abs st">' + _stats([("CISA KEV", _fmt(d["kev"]), HIGH), ("HIGH", _fmt(d["high"]), CYAN),
                                             ("PATCH NOW", _fmt(d["p1"]), CRIT)]) + "</div>")
    return _page(css, body)


def terminal(d: dict, rng: random.Random) -> str:
    top = d["top"][:3]
    lines = [f'<div><span class="p">$</span> sz weekly --week {d["week"]}</div>',
             f'<div><span class="ok">[  OK  ]</span> {_fmt(d["total"])} new CVEs indexed</div>',
             f'<div><span class="wa">[ WARN ]</span> {_fmt(d["critical"])} critical</div>',
             f'<div><span class="cr">[ CRIT ]</span> {_fmt(d["kev"])} added to CISA KEV</div>',
             f'<div><span class="ok">[  OK  ]</span> {_fmt(d["pocs"])} with public exploits</div>',
             '<div class="gap"></div>',
             f'<div><span class="p">$</span> sz top --limit {len(top) or 3}</div>']
    for c in top:
        sc = f'{c["score"]:.1f}' if c.get("score") else " \u2014 "
        lines.append(f'<div class="row">  <b>{esc(c["id"])}</b>  <span class="cr">{sc}</span>  {esc(c["name"][:40])}</div>')
    lines.append('<div><span class="p">$</span> <span class="cur"></span></div>')
    css = f"""
.bgx{{position:absolute;inset:0;background:radial-gradient(circle at 70% 20%,#10202A 0,#07080A 60%)}}
.win{{position:absolute;left:150px;top:150px;width:1300px;height:620px;border:1px solid #2B3238;background:#050607f2;box-shadow:0 40px 120px #000}}
.bar{{height:46px;border-bottom:1px solid #1C2126;display:flex;align-items:center;gap:10px;padding:0 18px;font:500 16px JB;color:{MUTE}}}
.bar i{{width:13px;height:13px;border-radius:50%}}.bar span{{margin-left:16px}}
.term{{padding:26px 34px;font:500 27px/1.55 JB;color:#C9C2B6;white-space:pre}}
.p{{color:{LOW}}}.ok{{color:{LOW}}}.wa{{color:{MED}}}.cr{{color:{CRIT}}}.row b{{color:{INK};font-weight:600}}
.gap{{height:14px}}.cur{{display:inline-block;width:15px;height:30px;background:{INK};vertical-align:-5px}}
"""
    body = ('<div class="bgx"></div>' + _chrome(d)
            + f'<div class="win"><div class="bar"><i style="background:{CRIT}"></i><i style="background:{MED}"></i><i style="background:{LOW}"></i>'
            + f'<span>sz@subzer0: ~/weekly</span></div><div class="term">{"".join(lines)}</div></div>')
    return _page(css, body)


def radar(d: dict, rng: random.Random) -> str:
    cx, cy, R = 1130, 470, 330
    dots = []
    for i in range(min(40, d["pocs"])):
        a, r = rng.random() * 2 * math.pi, R * (0.25 + 0.72 * rng.random())
        dots.append(f'<circle cx="{cx + r * math.cos(a):.0f}" cy="{cy + r * math.sin(a):.0f}" r="4" fill="{MED}" opacity=".7"/>')
    for i in range(min(16, d["kev"])):
        a, r = rng.random() * 2 * math.pi, R * (0.15 + 0.6 * rng.random())
        x, y = cx + r * math.cos(a), cy + r * math.sin(a)
        dots.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="18" fill="{CRIT}" opacity=".18"/>'
                    f'<circle cx="{x:.0f}" cy="{y:.0f}" r="7" fill="{CRIT}"/>')
    rings = "".join(f'<circle cx="{cx}" cy="{cy}" r="{R * k:.0f}" fill="none" stroke="#2E5A70" stroke-opacity=".55" stroke-width="1.5"/>'
                    for k in (0.25, 0.5, 0.75, 1))
    cross = (f'<line x1="{cx - R}" y1="{cy}" x2="{cx + R}" y2="{cy}" stroke="#2E5A70" stroke-opacity=".5"/>'
             f'<line x1="{cx}" y1="{cy - R}" x2="{cx}" y2="{cy + R}" stroke="#2E5A70" stroke-opacity=".5"/>')
    start = rng.randint(0, 359)
    css = f"""
.bgx{{position:absolute;inset:0;background:radial-gradient(circle at {cx}px {cy}px,#0E1A22 0,#07080A 55%)}}
.sweep{{position:absolute;left:{cx - R}px;top:{cy - R}px;width:{2 * R}px;height:{2 * R}px;border-radius:50%;
background:conic-gradient(from {start}deg,rgba(143,211,238,.28),rgba(143,211,238,0) 70deg,transparent 360deg)}}
svg{{position:absolute;inset:0}}
.k{{left:72px;top:200px;font:600 22px JB;letter-spacing:.24em;color:{CRIT}}}
.big{{left:66px;top:236px;font:700 250px/1 CP;color:{INK}}}
.sub{{left:74px;top:500px;font:500 34px IN;color:{DIM}}}.sub b{{color:{INK};font-weight:600}}
.cv{{left:74px;top:575px;width:640px}}
"""
    names = [c for c in d["kev_list"][:2]] or d["top"][:2]
    body = ('<div class="bgx"></div><div class="sweep"></div>'
            + f'<svg viewBox="0 0 {W} {H}">{rings}{cross}{"".join(dots)}</svg>' + _chrome(d)
            + '<div class="abs k">UNDER ACTIVE ATTACK</div>'
            + f'<div class="abs big">{_fmt(d["kev"])}</div>'
            + f'<div class="abs sub">CVEs added to <b>CISA KEV</b> this week</div>'
            + f'<div class="abs cv">{_cves(names, 2)}</div>')
    return _page(css, body)


def heatmap(d: dict, rng: random.Random) -> str:
    days = d["days"] or [{"date": "", "count": 0, "critical": 0}]
    mx = max(1, max(x["count"] for x in days))
    cols = []
    for x in days:
        n = max(1, round(14 * x["count"] / mx))
        crit_cells = min(n, round(n * (x["critical"] / max(1, x["count"])) * 2.5))
        cells = "".join(
            f'<i style="background:{CRIT if j < crit_cells else (CYAN if j < n * 0.55 else "#2E5A70")};opacity:{0.45 + 0.55 * (j + 1) / 14:.2f}"></i>'
            for j in range(n))
        cols.append(f'<div class="col"><div class="cells">{cells}</div><b>{_fmt(x["count"])}</b><span>{esc(x["label"])}</span></div>')
    css = f"""
.bgx{{position:absolute;inset:0;background:linear-gradient(180deg,#07080A 0,#0B1218 100%)}}
.t{{left:72px;top:176px;font:700 92px/1 CP}}.t em{{font-style:normal;color:{CYAN}}}
.s{{left:76px;top:282px;font:500 26px IN;color:{DIM}}}.s b{{color:{CRIT};font-weight:600}}
.chart{{position:absolute;left:72px;right:72px;top:350px;height:430px;display:flex;gap:26px;align-items:flex-end}}
.col{{flex:1;display:flex;flex-direction:column;align-items:center;gap:10px}}
.cells{{width:100%;display:flex;flex-direction:column-reverse;gap:5px}}
.cells i{{display:block;height:19px}}
.col b{{font:700 30px CP}}.col span{{font:500 15px JB;letter-spacing:.2em;color:{MUTE}}}
"""
    body = ('<div class="bgx"></div>' + _chrome(d)
            + f'<div class="abs t">{_fmt(d["total"])} <em>CVEs</em> in 7 days</div>'
            + f'<div class="abs s"><b>{_fmt(d["critical"])} critical</b> \u00b7 {_fmt(d["kev"])} exploited \u00b7 {_fmt(d["pocs"])} with public exploits</div>'
            + f'<div class="chart">{"".join(cols)}</div>')
    return _page(css, body)


def frost(d: dict, rng: random.Random) -> str:
    polys = []
    for _ in range(70):
        x, y, s = rng.randint(600, W + 100), rng.randint(-80, H + 80), rng.randint(40, 220)
        pts = " ".join(f"{x + s * math.cos(a):.0f},{y + s * math.sin(a):.0f}"
                       for a in sorted(rng.random() * 2 * math.pi for _ in range(3)))
        polys.append(f'<polygon points="{pts}" fill="#8FD3EE" fill-opacity="{rng.uniform(.02, .09):.3f}" '
                     f'stroke="#BFE7F7" stroke-opacity="{rng.uniform(.08, .3):.2f}" stroke-width="1.2"/>')
    css = f"""
.bgx{{position:absolute;inset:0;background:radial-gradient(circle at 75% 45%,#12303D 0,#07080A 62%)}}
svg{{position:absolute;inset:0}}
.k{{left:74px;top:196px;font:600 22px JB;letter-spacing:.3em;color:{CYAN}}}
.big{{left:62px;top:228px;font:700 230px/1 CP;background:linear-gradient(180deg,#FFFFFF 0,#BFE7F7 45%,#3E6F86 100%);
-webkit-background-clip:text;background-clip:text;color:transparent}}
.facts{{left:74px;top:500px;font:500 34px/1.75 IN;color:{DIM}}}.facts b{{font:700 40px CP;margin-right:14px}}
"""
    body = ('<div class="bgx"></div>' + f'<svg viewBox="0 0 {W} {H}">{"".join(polys)}</svg>' + _chrome(d)
            + '<div class="abs k">COLD FACTS</div>'
            + f'<div class="abs big">WEEK {d["week"]}</div>'
            + '<div class="abs facts">'
            + f'<div><b style="color:{CRIT}">{_fmt(d["critical"])}</b>critical CVEs</div>'
            + f'<div><b style="color:{HIGH}">{_fmt(d["kev"])}</b>exploited in the wild</div>'
            + f'<div><b style="color:{MED}">{_fmt(d["pocs"])}</b>with public exploit code</div></div>')
    return _page(css, body)


RENDERERS = {"spotlight": spotlight, "bignumber": bignumber, "terminal": terminal,
             "radar": radar, "heatmap": heatmap, "frost": frost}


def render(theme: str, d: dict) -> str:
    rng = random.Random(d["week"] * 7919 + THEMES.index(theme))
    return RENDERERS[theme](d, rng)
