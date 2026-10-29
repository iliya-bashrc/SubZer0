#!/usr/bin/env python3
"""Fail the build when what a first visit downloads grows past its budget.

  python3 scripts/check_budgets.py --site _site

Sizes are gzip -9 (what GitHub Pages actually sends) unless marked raw. A table is written
to $GITHUB_STEP_SUMMARY when it is set. Raise a budget on purpose, never by accident.
"""
from __future__ import annotations

import argparse
import gzip
import os
import sys
from pathlib import Path

KB = 1024
# path, budget in bytes, gzip?
FILES = [
    ("app.js", 55 * KB, True),
    ("app.css", 18 * KB, True),
    ("index.html", 9 * KB, True),
    ("sw.js", 3 * KB, True),
    ("snapshot/manifest.json", 8 * KB, True),
    ("brief/briefing.json", 40 * KB, True),
    ("brief/briefing.json", 400 * KB, False),
]
FONTS_RAW = 140 * KB
# everything the Briefing needs before it can paint (shell + preloaded fonts + manifest + briefing)
FIRST_PAINT = ["index.html", "app.css", "app.js", "snapshot/manifest.json", "brief/briefing.json",
               "fonts/ChakraPetch-700.woff2", "fonts/Inter.woff2"]
FIRST_PAINT_BUDGET = 180 * KB


def size(path: Path, gz: bool) -> int:
    data = path.read_bytes()
    return len(gzip.compress(data, 9)) if gz and path.suffix not in (".woff2", ".png") else len(data)


def check(site: Path) -> tuple[list[tuple[str, int, int, bool]], list[str]]:
    rows, errors = [], []
    for rel, budget, gz in FILES:
        p = site / rel
        if not p.is_file():
            errors.append(f"{rel} is missing")
            continue
        n = size(p, gz)
        rows.append((rel + ("" if gz else " (raw)"), n, budget, n <= budget))
    fonts = sum(f.stat().st_size for f in (site / "fonts").glob("*.woff2")) if (site / "fonts").is_dir() else 0
    rows.append(("fonts/*.woff2 (raw)", fonts, FONTS_RAW, fonts <= FONTS_RAW))
    fp = sum(size(site / rel, True) for rel in FIRST_PAINT if (site / rel).is_file())
    rows.append(("first paint total", fp, FIRST_PAINT_BUDGET, fp <= FIRST_PAINT_BUDGET))
    errors += [f"{name}: {n / KB:.1f} KB is over its {b / KB:.0f} KB budget" for name, n, b, ok in rows if not ok]
    return rows, errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--site", type=Path, required=True)
    args = ap.parse_args(argv)
    rows, errors = check(args.site)
    table = ["| file | size | budget | |", "|---|---:|---:|---|"] + [
        f"| `{name}` | {n / KB:.1f} KB | {b / KB:.0f} KB | {'✅' if ok else '❌'} |" for name, n, b, ok in rows]
    print("\n".join(table))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("### Size budgets\n\n" + "\n".join(table) + "\n\n")
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
