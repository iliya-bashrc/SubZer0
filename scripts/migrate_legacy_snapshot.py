#!/usr/bin/env python3
"""Upgrade checked-in snapshot metadata without refreshing its sources.

This migration preserves every original daily shard and the EPSS sidecar byte for
byte. It creates or upgrades the bounded Overview sidecar and exact byte/hash
metadata required by the current app, removes stale pointers to unbundled legacy
outputs, validates the complete staged snapshot, then swaps it into place
atomically. It never changes generated_at or fetches/refreshes upstream data.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import update_data as producer  # noqa: E402
import verify_data_snapshot as verifier  # noqa: E402


def migrate_snapshot(snapshot_root: Path = ROOT / "snapshot") -> dict[str, Any]:
    root = Path(snapshot_root).expanduser().absolute()
    if root.is_symlink() or not root.is_dir():
        raise producer.FeedError("Legacy snapshot root must be a real directory")
    data_root = root / "data"
    if data_root.is_symlink() or not data_root.is_dir():
        raise producer.FeedError("Legacy snapshot data must be a real directory")

    manifest_raw = verifier._contained_bytes(root, "manifest.json", verifier.MAX_MANIFEST_BYTES)
    manifest = verifier._loads(manifest_raw, "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2 or manifest.get("complete") is not True:
        raise producer.FeedError("Only complete schema-v2 snapshots can be migrated")
    upgrade_existing_overview = False
    overview_meta = manifest.get("overview")
    if overview_meta is not None:
        if not isinstance(overview_meta, dict) or overview_meta.get("path") != "data/overview.json":
            raise producer.FeedError("Existing Overview metadata has an unexpected path or shape")
        old_overview_raw = verifier._contained_bytes(root, "data/overview.json", verifier.MAX_OVERVIEW_BYTES)
        if "bytes" in overview_meta and overview_meta["bytes"] != len(old_overview_raw):
            raise producer.FeedError("Existing Overview sidecar byte-count mismatch")
        if overview_meta.get("sha256") and hashlib.sha256(old_overview_raw).hexdigest().lower() != str(overview_meta["sha256"]).lower():
            raise producer.FeedError("Existing Overview sidecar SHA-256 mismatch")
        old_overview = verifier._loads(old_overview_raw, "data/overview.json")
        old_schema = old_overview.get("schema_version") if isinstance(old_overview, dict) else None
        if old_schema == producer.OVERVIEW_SCHEMA_VERSION and overview_meta.get("schema_version") == producer.OVERVIEW_SCHEMA_VERSION:
            try:
                return verifier.validate_snapshot(root)
            except verifier.SnapshotValidationError as exc:
                raise producer.FeedError(f"Snapshot already advertises a current Overview sidecar but fails validation: {exc}") from exc
        if old_schema not in {1, 2} or overview_meta.get("schema_version") not in (None, 1, 2):
            raise producer.FeedError("Existing Overview sidecar is neither the supported legacy schema nor the current schema")
        upgrade_existing_overview = True

    days = manifest.get("days")
    epss_meta = manifest.get("epss")
    if not isinstance(days, list) or not days or not isinstance(epss_meta, dict) or epss_meta.get("path") != "data/epss.json":
        raise producer.FeedError("Legacy manifest must declare daily shards and the standard EPSS sidecar")

    expected_paths: set[str] = {"data/epss.json"}
    if upgrade_existing_overview:
        expected_paths.add("data/overview.json")
    legacy_index_path = next((name for name in ("search-index.json", "search-index.json.gz") if (data_root / name).is_file()), None)
    has_search_index = legacy_index_path is not None
    has_history = (data_root / "history.json").is_file()
    if has_search_index:
        expected_paths.add(f"data/{legacy_index_path}")
    if has_history:
        expected_paths.add("data/history.json")
    for summary in days:
        if not isinstance(summary, dict):
            raise producer.FeedError("Legacy manifest contains a malformed day entry")
        day = summary.get("date")
        if not isinstance(day, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day) or summary.get("path") != f"data/{day}.json":
            raise producer.FeedError("Legacy manifest contains an unexpected day-shard path")
        expected_paths.add(summary["path"])
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in data_root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_paths != expected_paths:
        raise producer.FeedError("Legacy snapshot contains missing or undeclared data files; refusing to discard any files")

    records: list[dict[str, Any]] = []
    record_ids: set[str] = set()
    shard_payloads: list[tuple[dict[str, Any], bytes]] = []
    for summary in days:
        day = summary["date"]
        raw = verifier._contained_bytes(root, summary["path"], verifier.MAX_SHARD_BYTES)
        if hashlib.sha256(raw).hexdigest().lower() != str(summary.get("sha256", "")).lower():
            raise producer.FeedError(f"Legacy shard SHA-256 mismatch: {summary['path']}")
        payload = verifier._loads(raw, summary["path"])
        if not isinstance(payload, list) or len(payload) != summary.get("count"):
            raise producer.FeedError(f"Legacy shard count mismatch: {summary['path']}")
        for index, candidate in enumerate(payload):
            record = verifier._validate_record(candidate, day, f"{day}[{index}]")
            if record["id"] in record_ids:
                raise producer.FeedError(f"Duplicate CVE ID across legacy shards: {record['id']}")
            record_ids.add(record["id"])
            records.append(record)
        summary["bytes"] = len(raw)
        shard_payloads.append((summary, raw))

    epss_raw = verifier._contained_bytes(root, "data/epss.json", verifier.MAX_EPSS_BYTES)
    if epss_meta.get("sha256") and hashlib.sha256(epss_raw).hexdigest().lower() != str(epss_meta["sha256"]).lower():
        raise producer.FeedError("Legacy EPSS sidecar SHA-256 mismatch")
    if "bytes" in epss_meta and epss_meta["bytes"] != len(epss_raw):
        raise producer.FeedError("Legacy EPSS sidecar byte-count mismatch")
    epss_payload = verifier._loads(epss_raw, "data/epss.json")
    if not isinstance(epss_payload, dict) or not isinstance(epss_payload.get("scores"), dict):
        raise producer.FeedError("Legacy EPSS sidecar has an invalid structure")
    epss_meta["bytes"] = len(epss_raw)
    epss_meta["sha256"] = hashlib.sha256(epss_raw).hexdigest()

    generated_at = producer.parse_datetime(manifest.get("generated_at"))
    if generated_at is None:
        raise producer.FeedError("Legacy manifest generated_at is invalid")
    if has_history:
        history_raw = verifier._contained_bytes(root, "data/history.json", verifier.MAX_HISTORY_BYTES)
        old_history_meta = manifest.get("history")
        if isinstance(old_history_meta, dict) and old_history_meta.get("sha256") and hashlib.sha256(history_raw).hexdigest().lower() != str(old_history_meta["sha256"]).lower():
            raise producer.FeedError("Existing history sidecar SHA-256 mismatch")
        history = verifier._loads(history_raw, "data/history.json")
        if not isinstance(history, dict) or history.get("schema_version") != 1 or history.get("retention_days") != 30 or not isinstance(history.get("snapshots"), list) or not isinstance(history.get("events"), list):
            raise producer.FeedError("Existing change history has an unsupported schema; refusing to discard it")
    else:
        history = {"schema_version": 1, "retention_days": 30,
                   "baseline": {"core_snapshot_at": manifest["generated_at"],
                                "epss_score_date": str(epss_payload.get("score_date") or ""),
                                "record_count": len(records), "complete": True},
                   "snapshots": [], "events": []}
    history.setdefault("baseline", None)
    history_raw = producer._json_bytes(history)

    if has_search_index:
        old_index_meta = manifest.get("search_index")
        expected_index_path = f"data/{legacy_index_path}"
        old_index_limit = verifier.MAX_INDEX_BYTES if legacy_index_path.endswith(".gz") else 20 * 1024 * 1024
        old_index_raw = verifier._contained_bytes(root, expected_index_path, old_index_limit)
        if legacy_index_path.endswith(".gz"):
            _, _, _ = verifier._verify_gzip_blob(root, old_index_meta, expected_index_path,
                                                  verifier.MAX_INDEX_BYTES, verifier.MAX_INDEX_UNCOMPRESSED_BYTES,
                                                  "legacy search_index")
        elif isinstance(old_index_meta, dict):
            if old_index_meta.get("bytes") is not None and old_index_meta["bytes"] != len(old_index_raw):
                raise producer.FeedError("Existing search-index sidecar byte-count mismatch")
            if old_index_meta.get("sha256") and hashlib.sha256(old_index_raw).hexdigest().lower() != str(old_index_meta["sha256"]).lower():
                raise producer.FeedError("Existing search-index sidecar SHA-256 mismatch")

    overview = producer.build_overview(records, generated_at, epss_payload, history)
    overview_raw = producer._json_bytes(overview)
    manifest["overview"] = {
        "schema_version": producer.OVERVIEW_SCHEMA_VERSION,
        "path": "data/overview.json",
        "bytes": len(overview_raw),
        "sha256": hashlib.sha256(overview_raw).hexdigest(),
        "count": len(overview["records"]),
        "recent_change_count": len(overview["recent_changes"]),
    }
    index = producer.build_search_index(records, epss_payload)
    index["generated_at"] = producer.iso_z(generated_at)
    index_raw = producer._json_bytes(index)
    compressed_index_raw = producer._gzip_bytes(index_raw)

    manifest.pop("facets", None)
    manifest.pop("search_index", None)
    manifest.pop("history", None)
    manifest["search_index"] = {"schema_version": producer.SEARCH_INDEX_SCHEMA_VERSION, "path": "data/search-index.json.gz",
                                "compression": "gzip", "bytes": len(compressed_index_raw),
                                "sha256": hashlib.sha256(compressed_index_raw).hexdigest(),
                                "uncompressed_bytes": len(index_raw), "uncompressed_sha256": hashlib.sha256(index_raw).hexdigest(),
                                "count": len(index["records"])}
    manifest["history"] = {"schema_version": 1, "path": "data/history.json", "bytes": len(history_raw),
                           "sha256": hashlib.sha256(history_raw).hexdigest(), "retention_days": 30,
                           "event_count": len(history["events"]), "snapshot_count": len(history["snapshots"]),
                           "kev_catalog_count": len(history.get("kev_catalog", []))}

    stage_root = Path(tempfile.mkdtemp(prefix=f".{root.name}.migration-", dir=root.parent))
    try:
        stage_data = stage_root / "data"
        stage_data.mkdir()
        for summary, raw in shard_payloads:
            (stage_data / f"{summary['date']}.json").write_bytes(raw)
        (stage_data / "epss.json").write_bytes(epss_raw)
        (stage_data / "overview.json").write_bytes(overview_raw)
        (stage_data / "search-index.json.gz").write_bytes(compressed_index_raw)
        (stage_data / "history.json").write_bytes(history_raw)
        (stage_root / "manifest.json").write_bytes(producer._json_bytes(manifest))
        try:
            report = verifier.validate_snapshot(stage_root, write_report=True)
        except Exception as exc:
            raise producer.FeedError(f"Migrated snapshot failed full offline validation: {exc}") from exc
        producer._commit_snapshot(stage_root, root)
        return report
    finally:
        if stage_root.exists():
            shutil.rmtree(stage_root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-root", type=Path, default=ROOT / "snapshot")
    args = parser.parse_args()
    try:
        report = migrate_snapshot(args.snapshot_root)
    except (producer.FeedError, verifier.SnapshotValidationError, OSError, ValueError) as exc:
        print(f"Snapshot migration aborted; the previous snapshot was preserved: {exc}", file=sys.stderr)
        return 1
    print(
        f"Metadata migration complete without upstream requests: {report['records']:,} records, "
        f"{report['shards']} shards, source timestamp {report['generated_at']}; source records were byte-preserved."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
