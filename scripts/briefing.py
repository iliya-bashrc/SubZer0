#!/usr/bin/env python3
"""Small first-paint file for the Briefing tab (brief/briefing.json).

The full search index is ~3.5 MB (≈550 KB gzipped). On a slow phone that is several seconds of
download + SHA-256 before anything shows. The Briefing only needs a few hundred rows, so the
deploy writes this subset and the app paints from it first, then loads and verifies the full
index in the background.

Trust: the file pins the exact sha256 of the snapshot manifest it was cut from, is signed with
the same Ed25519 key as the manifest (brief/briefing.sig, see sign_manifest.py), and once the
full index has been verified the browser cross-checks every briefing row against it.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA = 1
MAX_BYTES = 400_000  # budget (raw); checks.yml fails the build above this

# how many rows of each Briefing list to carry (the UI shows 5–7 of each)
QUEUE_P2 = 60
FEED = 40
TREND = 30
NOPATCH = 40
RECENT_KEV = 40


def _num(cve_id: str) -> int:
    try:
        _, year, seq = cve_id.split("-")
        return int(year) * 1_000_000_000 + int(seq)
    except ValueError:
        return 0


def build(manifest_bytes: bytes, manifest: dict, rows: list[list], ctx: dict, intel_doc: dict | None,
          facts, priority) -> bytes:
    intel = ctx.get("intel") or {}
    F = {r[0]: facts(r, ctx) for r in rows}
    P = {r[0]: priority(r, ctx) for r in rows}
    pick: set[str] = set()

    def add(seq, n=None):
        for i, r in enumerate(seq):
            if n is not None and i >= n:
                break
            pick.add(r[0])

    # Patch queue: every P1 (also gives an exact "Patch now" count) + the strongest P2s
    add([r for r in rows if P[r[0]] == 1])
    add(sorted((r for r in rows if P[r[0]] == 2), key=lambda r: -(F[r[0]]["e"] or 0)), QUEUE_P2)
    # Live feed: newest scored records
    newest = sorted(rows, key=lambda r: (str(r[7] or r[6] or ""), _num(r[0])), reverse=True)
    add([r for r in newest if F[r[0]]["c"] > 0], FEED)
    # Just weaponized: all of them (exact count on the hero + stats)
    add([r for r in rows if F[r[0]]["weap"]])
    # Trending
    def buzz(r):
        b = (intel.get(r[0]) or {}).get("b") or [0]
        return b[0] if isinstance(b, list) and b and isinstance(b[0], (int, float)) else 0
    add(sorted((r for r in rows if buzz(r) > 0), key=lambda r: -buzz(r)), TREND)
    # No patch yet (urgent, no fix in the refs, some exploitation signal)
    add(sorted((r for r in rows if P[r[0]] <= 2 and not F[r[0]]["patch"]
                and (F[r[0]]["kev"] or F[r[0]]["active"] or F[r[0]]["weap"] or F[r[0]]["poc"])),
               key=lambda r: (P[r[0]], -(F[r[0]]["e"] or 0))), NOPATCH)
    add([r for r in newest if r[4]], RECENT_KEV)

    sub = [r for r in rows if r[0] in pick]
    doc = {
        "schema": SCHEMA,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "generated_at": manifest.get("generated_at"),
        "counts": {
            "cves": len(rows),
            "poc": sum(1 for r in rows if F[r[0]]["poc"]),
            "weap": sum(1 for r in rows if F[r[0]]["weap"]),
            "p1": sum(1 for r in rows if P[r[0]] == 1),
        },
        "rows": sub,
        "poc": sorted(i for i in (ctx.get("poc") or set()) if i in pick),
        "intel": {
            "cves": {k: v for k, v in intel.items() if k in pick},
            "sources": (intel_doc or {}).get("sources") or [],
        } if intel_doc else None,
    }
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write(out: Path, manifest: dict, rows: list[list], ctx: dict, intel_doc: dict | None, facts, priority) -> int:
    manifest_bytes = (out / "snapshot" / "manifest.json").read_bytes()
    data = build(manifest_bytes, manifest, rows, ctx, intel_doc, facts, priority)
    (out / "brief").mkdir(exist_ok=True)
    (out / "brief" / "briefing.json").write_bytes(data)
    return len(data)
