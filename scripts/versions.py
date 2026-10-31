"""Version-aware lookups: "is nginx 1.24.0 affected?".

Turns the affected-version strings already in each record ("< 1.25.3", ">= 2.1.0, <= 2.11.0",
">= 11.0.0-preview.1, <= 11.0.0-rc.1; first patched: 11.0.0-rc.2", or one exact version) into small
pre-parsed shards under api/versions/<shard>.json. The site and the Telegram bot both read them and
compare with the same algorithm (cmp() here, vcmp() in site/app.js and worker/bot.js). Keep the three in sync;
tests/test_versions.py runs the JS copies against the same cases.

Shard key: first character of the product name, so a query only fetches the shards its words start with.
Each shard: {"v":1,"c":[[id,sev,priority,kev,cvss,title],...],"p":{"vendor|product":[[ci,lo,loInc,hi,hiInc,fix],...]}}
An entry with lo == hi == "" and hiInc == -1 means the source names the product but gives no version.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

PRE = {"dev": 0, "snapshot": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "preview": 3, "pre": 3, "rc": 4, "cr": 4}
TOK = re.compile(r"\d+|[a-z]+")
VER_OK = re.compile(r"^[0-9][0-9a-z.\-_+~]*$")
MAX_PER_PRODUCT = 5000


def tokens(v: str) -> list:
    v = re.sub(r"^v(?=\d)", "", str(v).strip().lower())
    return [int(t) if t.isdigit() else t for t in TOK.findall(v)]


def cmp(a: str, b: str) -> int:
    """-1/0/1. Numeric parts numerically; 1.0 == 1.0.0; 1.0rc1 < 1.0 < 1.0.1; 1.0.1 > 1.0rc1."""
    x, y = tokens(a), tokens(b)
    i = 0
    while i < len(x) and i < len(y):
        p, q = x[i], y[i]
        if p != q:
            if isinstance(p, int) and isinstance(q, int):
                return -1 if p < q else 1
            if isinstance(p, int):
                return 1 if q in PRE else -1
            if isinstance(q, int):
                return -1 if p in PRE else 1
            rp, rq = PRE.get(p, 9), PRE.get(q, 9)
            if rp != rq:
                return -1 if rp < rq else 1
            return -1 if p < q else 1
        i += 1
    rest, sign = (x[i:], 1) if len(x) > len(y) else (y[i:], -1)
    if not rest:
        return 0
    head = rest[0]
    if isinstance(head, str):
        return -sign if head in PRE else sign
    return sign if any(t != 0 for t in rest if isinstance(t, int)) or any(isinstance(t, str) for t in rest) else 0


def parse(versions: str):
    """Return (lo, loInc, hi, hiInc, fix) or None when the string carries no usable version."""
    s = str(versions or "").strip()
    if not s or "not specified" in s.lower():
        return None
    fix = ""
    m = re.search(r"first patched:\s*([^\s;,]+)", s, re.I)
    if m:
        fix = m.group(1)
        s = s[:m.start()].rstrip(" ;,")
    lo = hi = ""
    lo_inc, hi_inc = 1, 1
    exact = []
    for part in [p.strip() for p in re.split(r"[;,]", s) if p.strip()]:
        m = re.fullmatch(r"(>=|>|<=|<|=)?\s*(\S+)", part)
        if not m or not VER_OK.match(m.group(2).lower()):
            return None
        op, v = m.group(1) or "=", m.group(2)
        if op == ">=":
            lo, lo_inc = v, 1
        elif op == ">":
            lo, lo_inc = v, 0
        elif op == "<=":
            hi, hi_inc = v, 1
        elif op == "<":
            hi, hi_inc = v, 0
        else:
            exact.append(v)
    if exact and not (lo or hi):
        lo = hi = exact[0]
        lo_inc = hi_inc = 1
    elif exact and not lo:  # "4.0.0, < 4.0.5" style: exact is the floor
        lo, lo_inc = exact[0], 1
    if not (lo or hi):
        return None
    if not fix and hi and not hi_inc:
        fix = hi
    return lo, lo_inc, hi, hi_inc, fix


def hit(v: str, rng) -> bool:
    lo, lo_inc, hi, hi_inc, _ = rng
    if lo:
        c = cmp(v, lo)
        if c < 0 or (c == 0 and not lo_inc):
            return False
    if hi:
        c = cmp(v, hi)
        if c > 0 or (c == 0 and not hi_inc):
            return False
    return True


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9.+ ]", " ", str(s or "").lower().replace("_", " "))).strip()


def shard_of(product: str) -> str:
    p = norm(product)
    c = p[:1]
    return c if c.isalpha() else "0"


class Builder:
    def __init__(self) -> None:
        self.cves: dict[str, list] = {}
        self.products: dict[str, dict[str, list]] = {}

    def add(self, rec: dict, row: list | None, prio, fx: dict | None) -> None:
        cid = rec.get("id")
        aff = [a for a in rec.get("affected") or [] if isinstance(a, dict) and (a.get("product") or "").strip()]
        if not cid or not aff:
            return
        seen = set()
        for a in aff:
            vendor, product = norm(a.get("vendor")), norm(a.get("product"))
            if not product or product in {"*", "-"}:
                continue
            key = f"{vendor}|{product}"
            rng = parse(a.get("versions"))
            ident = (key, rng)
            if ident in seen:
                continue
            seen.add(ident)
            if cid not in self.cves:
                fx = fx or {}
                sev = (row[2] if row else rec.get("sev")) or "unknown"
                score = float(fx.get("c") or rec.get("score") or 0)
                self.cves[cid] = [cid, sev, (prio[0] if prio else 4), 1 if (row and row[4]) or rec.get("kev") else 0,
                                  round(score, 1) if score else 0, str(rec.get("title") or "")[:90]]
            if rng:
                lo, lo_inc, hi, hi_inc, fix = rng
                if fix == hi and not hi_inc:
                    fix = ""  # implied: the exclusive upper bound is the fix (vfix() in JS)
                entry = [cid, lo, lo_inc, hi, hi_inc, fix]
            else:
                entry = [cid, "", 1, "", -1, ""]
            self.products.setdefault(shard_of(product), {}).setdefault(key, []).append(entry)

    def examples(self, n: int = 5) -> list:
        """A few real queries for the UI: popular products with a version one step below a common fix."""
        from collections import Counter
        ranked = []
        for prods in self.products.values():
            for key, entries in prods.items():
                his = Counter(e[3] for e in entries if e[4] == 0 and e[3])
                if his:
                    ranked.append((len({e[0] for e in entries}), key, his.most_common(1)[0][0]))
        out, vendors = [], set()
        for _, key, hi in sorted(ranked, reverse=True):
            vendor, product = key.split("|")
            if vendor in vendors:
                continue
            parts = re.split(r"([0-9]+)", hi)
            nums = [i for i, p in enumerate(parts) if p.isdigit()]
            if not nums or int(parts[nums[-1]]) == 0:
                continue
            parts[nums[-1]] = str(int(parts[nums[-1]]) - 1)
            out.append(f"{product} {''.join(parts)}")
            vendors.add(vendor)
            if len(out) >= n:
                break
        return out

    def write(self, out: Path) -> int:
        d = out / "api" / "versions"
        d.mkdir(parents=True, exist_ok=True)
        total = 0
        names = []
        for shard, prods in sorted(self.products.items()):
            ids: dict[str, int] = {}
            table: list = []
            p_out: dict[str, list] = {}
            for key, entries in sorted(prods.items()):
                # live CVEs with real ranges first, capped so one giant product cannot bloat a shard
                entries = sorted(entries, key=lambda e: (e[4] == -1, self.cves[e[0]][2], -self.cves[e[0]][4]))[:MAX_PER_PRODUCT]
                rows = []
                for e in entries:
                    if e[0] not in ids:
                        ids[e[0]] = len(table)
                        table.append(self.cves[e[0]])
                    rows.append([ids[e[0]], *e[1:]])
                p_out[key] = rows
            raw = json.dumps({"v": 1, "c": table, "p": p_out}, separators=(",", ":"), ensure_ascii=False)
            (d / f"{shard}.json").write_text(raw, encoding="utf-8")
            total += len(raw)
            names.append(shard)
        (d / "index.json").write_text(json.dumps({"v": 1, "shards": names, "ex": self.examples(),
                                                  "products": sum(len(p) for p in self.products.values()),
                                                  "cves": len(self.cves)}, separators=(",", ":")), encoding="utf-8")
        return total
