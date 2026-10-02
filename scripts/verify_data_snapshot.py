#!/usr/bin/env python3
"""Validate the complete, committed static CVE snapshot before release/publication."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from typing import Any

CVE_ID = re.compile(r"^CVE-\d{4,}-\d+$", re.I)
CORE_SOURCES = {"NVD CVE API 2.0", "GitHub Security Advisory Database", "CISA KEV"}
SEVERITIES = ("critical", "high", "medium", "low", "none", "unknown")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read valid JSON from {path}: {exc}") from exc


def contained_file(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"Unsafe or missing snapshot file: {relative}")
    return path


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not an ISO timestamp: {value}") from exc
    if result.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return result.astimezone(timezone.utc)


def severity_for(record: dict[str, Any]) -> str:
    value = record.get("score")
    if value is None or value == "":
        return "unknown"
    if isinstance(value, bool):
        raise ValueError(f"Boolean CVSS score is invalid for {record.get('id')}")
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Non-numeric CVSS score for {record.get('id')}") from exc
    if not 0 <= score <= 10:
        raise ValueError(f"CVSS score outside 0–10 for {record.get('id')}")
    if score == 0:
        return "none"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def validate_snapshot(root: Path) -> dict[str, int | str]:
    root = root.resolve()
    manifest_path = contained_file(root, "data/manifest.json")
    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != 2:
        raise ValueError("Unsupported data/manifest.json schema_version")
    generated = parse_timestamp(manifest.get("generated_at"), "manifest.generated_at")
    start = parse_timestamp(manifest.get("window", {}).get("start"), "manifest.window.start")
    end = parse_timestamp(manifest.get("window", {}).get("end"), "manifest.window.end")
    if start > end or generated < start:
        raise ValueError("Manifest window timestamps are inconsistent")
    if manifest.get("complete") is not True or manifest.get("coverage", {}).get("sources_complete") is not True:
        raise ValueError("Manifest does not declare complete core-source coverage")

    statuses = {item.get("name"): item for item in manifest.get("source_status", []) if isinstance(item, dict)}
    for source in CORE_SOURCES:
        if statuses.get(source, {}).get("ok") is not True:
            raise ValueError(f"Core source is not complete: {source}")

    days = manifest.get("days")
    if not isinstance(days, list) or not days:
        raise ValueError("Manifest contains no date shards")
    if days != sorted(days, key=lambda item: item.get("date", "")):
        raise ValueError("Manifest date shards are not in ascending chronological order")

    all_ids: dict[str, str] = {}
    totals = {key: 0 for key in (*SEVERITIES, "exploited")}
    seen_dates: set[str] = set()
    for item in days:
        if not isinstance(item, dict):
            raise ValueError("Manifest contains a malformed date shard entry")
        day = item.get("date")
        if not isinstance(day, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day) or day in seen_dates:
            raise ValueError(f"Manifest contains an invalid or duplicate shard date: {day!r}")
        seen_dates.add(day)
        expected_path = f"data/{day}.json"
        if item.get("path") != expected_path:
            raise ValueError(f"Unexpected shard path for {day}: {item.get('path')!r}")
        expected_hash = item.get("sha256")
        if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash, re.I):
            raise ValueError(f"Missing or invalid SHA-256 fingerprint for {day}")
        shard_path = contained_file(root, expected_path)
        raw = shard_path.read_bytes()
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise ValueError(f"SHA-256 mismatch for {day}: expected {expected_hash}, got {actual_hash}")
        try:
            records = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid UTF-8 JSON shard for {day}: {exc}") from exc
        if not isinstance(records, list):
            raise ValueError(f"Shard is not a JSON array: {day}")
        if len(records) != int(item.get("count", -1)):
            raise ValueError(f"Declared row count mismatch for {day}: manifest {item.get('count')}, actual {len(records)}")

        daily = {key: 0 for key in (*SEVERITIES, "exploited")}
        daily_ids: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError(f"Non-object record in {day}")
            raw_id = record.get("id")
            if not isinstance(raw_id, str) or not CVE_ID.fullmatch(raw_id):
                raise ValueError(f"Invalid CVE ID in {day}: {raw_id!r}")
            cve_id = raw_id.upper()
            if cve_id in daily_ids:
                raise ValueError(f"Duplicate CVE ID inside {day}: {cve_id}")
            daily_ids.add(cve_id)
            if cve_id in all_ids:
                raise ValueError(f"Duplicate CVE ID across shards: {cve_id} in {all_ids[cve_id]} and {day}")
            all_ids[cve_id] = day
            daily[severity_for(record)] += 1
            if record.get("kev"):
                daily["exploited"] += 1
        for key, actual in daily.items():
            if key == "exploited" and key not in item:
                continue
            if item.get(key) is None or int(item[key]) != actual:
                raise ValueError(f"Declared {key} total mismatch for {day}: manifest {item.get(key)}, actual {actual}")
            totals[key] += actual

    expected_total = manifest.get("totals", {})
    if int(expected_total.get("cves", -1)) != len(all_ids):
        raise ValueError(f"Manifest CVE total mismatch: expected {expected_total.get('cves')}, shards contain {len(all_ids)}")
    for key in SEVERITIES:
        if int(expected_total.get(key, -1)) != totals[key]:
            raise ValueError(f"Manifest {key} total mismatch: expected {expected_total.get(key)}, shards contain {totals[key]}")
    if int(expected_total.get("known_exploited", -1)) != totals["exploited"]:
        raise ValueError(f"Manifest KEV total mismatch: expected {expected_total.get('known_exploited')}, shards contain {totals['exploited']}")
    coverage = manifest.get("coverage", {})
    if int(coverage.get("utc_days_sharded", -1)) != len(days):
        raise ValueError("Manifest UTC-shard coverage does not match its date list")
    if int(coverage.get("distinct_cve_records", -1)) != len(all_ids):
        raise ValueError("Manifest distinct-CVE coverage does not match the shards")

    api_manifest = load_json(contained_file(root, "api/v1/manifest.json"))
    if api_manifest.get("generated_at") != manifest.get("generated_at") or api_manifest.get("days") != days or api_manifest.get("totals") != expected_total:
        raise ValueError("Static API manifest is not synchronized with data/manifest.json")

    facets_config = manifest.get("facets", {})
    facets = load_json(contained_file(root, facets_config.get("path", "")))
    if facets.get("schema_version") != 1 or not all(isinstance(facets.get(key), list) for key in ("vendors", "products", "product_pairs")):
        raise ValueError("Facet sidecar has an unsupported schema or malformed lists")

    history_config = manifest.get("history", {})
    history = load_json(contained_file(root, history_config.get("path", "")))
    if history.get("schema_version") != 1 or not isinstance(history.get("snapshots"), list) or not isinstance(history.get("events"), list):
        raise ValueError("Retained history sidecar has an unsupported schema")

    epss_config = manifest.get("epss", {})
    epss = load_json(contained_file(root, epss_config.get("path", "")))
    scores = epss.get("scores")
    if epss.get("schema_version") != 1 or not isinstance(scores, dict):
        raise ValueError("FIRST EPSS sidecar has an unsupported schema")
    if epss.get("score_date") != epss_config.get("score_date"):
        raise ValueError("EPSS score-set date does not match the manifest")
    for cve_id, value in scores.items():
        if not CVE_ID.fullmatch(str(cve_id)) or not isinstance(value, dict):
            raise ValueError(f"Malformed EPSS score entry: {cve_id}")
        try:
            score = float(value.get("score"))
            percentile = float(value.get("percentile"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Malformed EPSS values for {cve_id}") from exc
        if not 0 <= score <= 1 or not 0 <= percentile <= 1:
            raise ValueError(f"EPSS value outside 0–1 for {cve_id}")
    epss_status = statuses.get("FIRST EPSS", {})
    if epss_status.get("ok") is True:
        source_time = parse_timestamp(epss_config.get("source_updated_at"), "manifest.epss.source_updated_at")
        if abs((generated - source_time).total_seconds()) > 36 * 60 * 60:
            raise ValueError("EPSS is marked current despite a stale or future-dated score set")

    return {
        "generated_at": str(manifest["generated_at"]),
        "shards": len(days),
        "records": len(all_ids),
        "epss_scores": len(scores),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="Repository root (defaults to this script's repository)")
    args = parser.parse_args()
    try:
        result = validate_snapshot(args.root)
    except (ValueError, OSError, TypeError) as exc:
        print(f"SNAPSHOT VALIDATION FAILED: {exc}")
        return 1
    print(
        "SNAPSHOT VALIDATION PASSED: "
        f"{result['records']:,} unique CVEs across {result['shards']} UTC date shards; "
        f"{result['epss_scores']:,} optional EPSS values; generated {result['generated_at']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
