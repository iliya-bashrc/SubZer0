#!/usr/bin/env python3
"""Permanent archive of notable CVEs, so their pages keep working after they leave the 30-day window.

A CVE is notable when SubZer0 ranked it P1 or P2 (exploited, weaponized, public exploit with real EPSS,
critical, or automatable). Each refresh upserts the notable CVEs of the validated snapshot into
month files keyed by publication month; nothing is ever dropped. Layout:

  archive/index.json        {"schema_version":1,"updated_at":…,"count":…,"months":[{"month","path","count","bytes","sha256"}]}
  archive/YYYY-MM.json      [compact record, …] sorted by CVE id

Usage:
  archive.py --snapshot snapshot --previous public/archive --out bundle/archive   # build next archive
  archive.py --verify public/archive                                             # fail-closed check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_site  # noqa: E402

SCHEMA = 1
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")
MAX_MONTH_BYTES = 40 * 1024 * 1024
MAX_FILES = 600
NOTABLE = (1, 2)


class ArchiveError(RuntimeError):
    pass


def _clip(text, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def compact(rec: dict, row: list, ctx: dict, seen_at: str) -> dict:
    fx = build_site.facts(row, ctx)
    p, why = build_site.priority_reason(row, ctx)
    kev = rec.get("kev") if isinstance(rec.get("kev"), dict) else None
    return {
        "id": rec["id"],
        "title": _clip(rec.get("title"), 300),
        "desc": _clip(rec.get("desc"), 1500),
        "sev": rec.get("sev"),
        "score": rec.get("score") or (fx["c"] or None),
        "published": rec.get("published"),
        "modified": rec.get("modified"),
        "window_date": rec.get("window_date"),
        "kev": {k: kev.get(k) for k in ("date_added", "due_date", "ransomware", "vendor", "product")} if kev else None,
        "affected": [{k: a.get(k) for k in ("vendor", "product", "versions")} for a in (rec.get("affected") or [])[:10] if isinstance(a, dict)],
        "cwe": [c for c in rec.get("cwe") or [] if isinstance(c, str)][:6],
        "cvss_vector": rec.get("cvss_vector") if isinstance(rec.get("cvss_vector"), str) else None,
        "refs": [{k: r.get(k) for k in ("label", "url", "source")} for r in (rec.get("refs") or [])
                 if isinstance(r, dict) and str(r.get("url", "")).startswith("https://")][:12],
        "related_cves": [c for c in rec.get("related_cves") or [] if isinstance(c, str)][:12],
        "sources": [s for s in rec.get("sources") or [] if isinstance(s, str)][:8],
        "signals": {"epss": row[5] if isinstance(row[5], (int, float)) else None, "poc": fx["poc"], "weap": fx["weap"],
                    "p": p, "why": why},
        "last_seen": seen_at,
    }


def month_of(rec: dict) -> str:
    for key in ("published", "window_date"):
        value = str(rec.get(key) or "")[:7]
        if MONTH_RE.match(value):
            return value
    return str(rec.get("last_seen") or "")[:7]


def load(archive: Path) -> dict[str, dict]:
    """Verified records keyed by CVE id. A missing archive is empty; a corrupt one raises."""
    if not (archive / "index.json").exists():
        return {}
    index = verify(archive)
    out: dict[str, dict] = {}
    for month in index["months"]:
        for rec in json.loads((archive / month["path"]).read_bytes()):
            out[rec["id"]] = rec
    return out


def verify(archive: Path) -> dict:
    index_path = archive / "index.json"
    if index_path.is_symlink() or not index_path.is_file():
        raise ArchiveError("archive/index.json is missing")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if index.get("schema_version") != SCHEMA or not isinstance(index.get("months"), list):
        raise ArchiveError("archive index has an unexpected shape")
    expected = {"index.json"}
    total = 0
    for month in index["months"]:
        name = month.get("month")
        if not isinstance(name, str) or not MONTH_RE.match(name) or month.get("path") != f"{name}.json":
            raise ArchiveError(f"bad archive month entry: {month!r}")
        path = archive / month["path"]
        if path.is_symlink() or not path.is_file():
            raise ArchiveError(f"archive month file missing: {month['path']}")
        raw = path.read_bytes()
        if len(raw) != month.get("bytes") or len(raw) > MAX_MONTH_BYTES:
            raise ArchiveError(f"archive byte count differs for {month['path']}")
        if hashlib.sha256(raw).hexdigest() != month.get("sha256"):
            raise ArchiveError(f"archive SHA-256 differs for {month['path']}")
        records = json.loads(raw)
        if not isinstance(records, list) or len(records) != month.get("count"):
            raise ArchiveError(f"archive record count differs for {month['path']}")
        for rec in records:
            if not isinstance(rec, dict) or not CVE_RE.match(str(rec.get("id"))):
                raise ArchiveError(f"bad archive record in {month['path']}")
        total += len(records)
        expected.add(month["path"])
    actual = {p.name for p in archive.iterdir()}
    if actual != expected or len(actual) > MAX_FILES:
        raise ArchiveError(f"unexpected files in archive: {sorted(actual - expected)}")
    if index.get("count") != total:
        raise ArchiveError("archive total count differs")
    return index


def update(snapshot: Path, previous: Path, out: Path) -> dict:
    manifest, rows, ctx = build_site.load_index(snapshot)
    seen_at = str(manifest.get("generated_at") or "")
    records = load(previous)
    by_id = {r[0]: r for r in rows}
    for day in manifest.get("days") or []:
        shard = build_site._read_verified(snapshot, day)
        for rec in shard if isinstance(shard, list) else []:
            row = by_id.get(rec.get("id")) if isinstance(rec, dict) else None
            if row and CVE_RE.match(rec["id"]) and build_site.priority(row, ctx) in NOTABLE:
                records[rec["id"]] = compact(rec, row, ctx, seen_at)
    months: dict[str, list[dict]] = {}
    for rec in records.values():
        months.setdefault(month_of(rec), []).append(rec)
    out.mkdir(parents=True, exist_ok=True)
    for stale in out.iterdir():
        stale.unlink()
    entries = []
    for name in sorted(m for m in months if MONTH_RE.match(m)):
        items = sorted(months[name], key=lambda r: r["id"])
        raw = json.dumps(items, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        (out / f"{name}.json").write_bytes(raw)
        entries.append({"month": name, "path": f"{name}.json", "count": len(items), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    index = {"schema_version": SCHEMA, "updated_at": seen_at, "count": sum(e["count"] for e in entries), "months": entries}
    (out / "index.json").write_text(json.dumps(index, indent=1) + "\n", encoding="utf-8")
    verify(out)
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        index = verify(args.verify)
        print(f"Archive OK: {index['count']} CVEs across {len(index['months'])} months")
        return 0
    if not (args.snapshot and args.previous and args.out):
        parser.error("--snapshot, --previous and --out are required to build the archive")
    index = update(args.snapshot, args.previous, args.out)
    print(f"Archive built: {index['count']} notable CVEs across {len(index['months'])} months")
    return 0


if __name__ == "__main__":
    sys.exit(main())
