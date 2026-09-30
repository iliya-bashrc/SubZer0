#!/usr/bin/env python3
"""Backfill rolling snapshot history from committed, complete feed snapshots.

Run from the repository root after `data/history.json` is added to the updater.
The script reads immutable Git blobs, records only 30 days of complete snapshots,
and compares only changed UTC shards; it never invents changes from client state.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import update_data as feed  # noqa: E402


class GitHistoryReader:
    def __init__(self, root: Path):
        self.root = root
        self.blob_cache: dict[str, Any] = {}

    def run(self, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=self.root, text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
        return result.stdout

    def blob_oid(self, revision: str, path: str) -> str | None:
        result = subprocess.run(["git", "rev-parse", f"{revision}:{path}"], cwd=self.root, text=True, capture_output=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def json_blob(self, revision: str, path: str, default: Any = None) -> Any:
        oid = self.blob_oid(revision, path)
        if not oid:
            return default
        if oid not in self.blob_cache:
            content = self.run("cat-file", "-p", oid)
            self.blob_cache[oid] = json.loads(content)
        return self.blob_cache[oid]

    def snapshots(self) -> list[dict[str, Any]]:
        commits = self.run("log", "--all", "--reverse", "--format=%H", "--", "data/manifest.json").splitlines()
        result = []
        for commit in commits:
            manifest = self.json_blob(commit, "data/manifest.json")
            if not isinstance(manifest, dict) or manifest.get("complete") is not True or not isinstance(manifest.get("days"), list):
                continue
            generated = feed.parse_datetime(str(manifest.get("generated_at") or ""))
            epss = manifest.get("epss") or {}
            epss_updated = feed.parse_datetime(str(epss.get("updated_at") or ""))
            observed = max(item for item in (generated, epss_updated) if item is not None) if generated or epss_updated else None
            if observed is None:
                continue
            result.append({"commit": commit, "manifest": manifest, "observed": observed})
        return result

    def records_in_changed_days(self, revision: str, days: set[str]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for day in sorted(days):
            if len(day) != 10 or day[4] != "-" or day[7] != "-":
                continue
            payload = self.json_blob(revision, f"data/{day}.json", [])
            if not isinstance(payload, list):
                raise RuntimeError(f"Invalid historical shard {day} at {revision[:12]}")
            records.extend(item for item in payload if isinstance(item, dict) and feed._cve_id(item.get("id")))
        return records

    def records_in_manifest(self, revision: str, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        days = {str(item.get("date") or "") for item in manifest.get("days") or []}
        return self.records_in_changed_days(revision, days)

    def sidecar(self, revision: str) -> dict[str, Any]:
        value = self.json_blob(revision, "data/epss.json", {})
        return value if isinstance(value, dict) else {}


def day_fingerprints(manifest: dict[str, Any]) -> dict[str, str]:
    result = {}
    for item in manifest.get("days") or []:
        day = str(item.get("date") or "")
        if day:
            result[day] = str(item.get("sha256") or "")
    return result


def backfill(root: Path, output: Path | None = None, retention_days: int = 30) -> dict[str, Any]:
    reader = GitHistoryReader(root)
    snapshots = reader.snapshots()
    if not snapshots:
        raise RuntimeError("No complete committed data/manifest.json snapshots were found")
    latest = max(item["observed"] for item in snapshots)
    cutoff = latest - timedelta(days=retention_days)
    first_kept = next((index for index, item in enumerate(snapshots) if item["observed"] >= cutoff), len(snapshots) - 1)
    selected = snapshots[max(0, first_kept - 1):]
    retained = [item for item in selected if item["observed"] >= cutoff]
    events: list[dict[str, Any]] = []

    previous = None
    previous_epss: dict[str, Any] = {}
    for item in selected:
        manifest = item["manifest"]
        epss = reader.sidecar(item["commit"])
        if previous is not None:
            before, after = previous["manifest"], manifest
            old_days, new_days = day_fingerprints(before), day_fingerprints(after)
            changed = {day for day in old_days.keys() | new_days.keys() if old_days.get(day) != new_days.get(day)}
            epss_changed = reader.blob_oid(previous["commit"], "data/epss.json") != reader.blob_oid(item["commit"], "data/epss.json")
            if epss_changed:
                old_records = reader.records_in_manifest(previous["commit"], before)
                new_records = reader.records_in_manifest(item["commit"], after)
            else:
                old_records = reader.records_in_changed_days(previous["commit"], changed)
                new_records = reader.records_in_changed_days(item["commit"], changed)
            diff = feed.material_change_events(old_records, new_records, previous_epss, epss, item["observed"])
            for event in diff:
                event["commit"] = item["commit"][:12]
            events.extend(diff)
        previous = item
        previous_epss = epss

    history_snapshots = []
    for item in retained:
        manifest = item["manifest"]
        epss = manifest.get("epss") or {}
        history_snapshots.append({
            "observed_at": feed.iso_z(item["observed"]),
            "core_snapshot_at": str(manifest.get("generated_at") or ""),
            "epss_score_date": str(epss.get("score_date") or ""),
            "record_count": int((manifest.get("totals") or {}).get("cves") or 0),
            "complete": True,
            "commit": item["commit"][:12],
        })
    history = {
        "schema_version": 1,
        "retention_days": retention_days,
        "basis": "Complete committed feed snapshots; comparisons use changed UTC shards and dated EPSS sidecars.",
        "snapshots": history_snapshots[-800:],
        "events": [event for event in events if (feed.parse_datetime(event.get("observed_at")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff][-10_000:],
    }
    target = output or root / "data" / "history.json"
    feed._write_json(target, history)
    return history


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="repository checkout (default: current directory)")
    parser.add_argument("--output", type=Path, help="output path (default: <root>/data/history.json)")
    parser.add_argument("--retention-days", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.retention_days <= 90:
        parser.error("--retention-days must be between 1 and 90")
    try:
        history = backfill(args.root.resolve(), args.output.resolve() if args.output else None, args.retention_days)
    except Exception as exc:
        print(f"History backfill failed: {exc}", file=sys.stderr)
        return 1
    print(f"Backfilled {len(history['snapshots'])} actual complete snapshots and {len(history['events'])} material events over {args.retention_days} days.")
    if history["snapshots"]:
        print(f"Observed range: {history['snapshots'][0]['observed_at']} to {history['snapshots'][-1]['observed_at']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
