#!/usr/bin/env python3
"""Fail-closed validation for SubZer0's static Pages snapshot (schema v2)."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = REPO_ROOT / "snapshot"
CVE_RE = re.compile(r"^CVE-\d{4,}-\d+$", re.I)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.I)
NAIVE_SOURCE_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$")
SEVERITIES = ("critical", "high", "medium", "low", "none", "unknown")
CORE_SOURCES = (
    "NVD CVE API 2.0",
    "GitHub Security Advisory Database",
    "CISA KEV",
)
SOURCE_LABELS = {"NVD", "GitHub Advisory Database", "CISA KEV"}

# Derived from the checked-in 2026-10-02 snapshot (34,732,431 bytes total;
# largest shard 5,500,923; 15,318 records; longest description 22,499 chars;
# largest affected list 61; 14 references; longest URL 289 chars).
MAX_MANIFEST_BYTES = 512 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_SHARD_BYTES = 16 * 1024 * 1024
MAX_OVERVIEW_BYTES = 64 * 1024
MAX_OVERVIEW_RECORDS = 50
MAX_EPSS_BYTES = 4 * 1024 * 1024
MAX_SHARDS = 31
MAX_RECORDS = 50_000
MAX_TITLE_CHARS = 512
MAX_DESCRIPTION_CHARS = 65_536
MAX_TEXT_CHARS = 4_096
MAX_URL_CHARS = 2_048
MAX_SOURCES = 8
MAX_AFFECTED = 128
MAX_REFERENCES = 64
MAX_RELATED = 100
MAX_ADVISORIES = 32
MAX_TAGS = 40


class SnapshotValidationError(ValueError):
    """Raised when a snapshot is malformed, incomplete, unsafe, or too large."""


def _reject_constant(value: str) -> None:
    raise SnapshotValidationError(f"Non-finite JSON number is not permitted: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotValidationError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _loads(raw: bytes, label: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except SnapshotValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SnapshotValidationError(f"{label} is not strict UTF-8 JSON: {exc}") from exc


def _contained_bytes(root: Path, relative: str, limit: int) -> bytes:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise SnapshotValidationError(f"Invalid snapshot path: {relative!r}")
    posix = PurePosixPath(relative)
    if posix.is_absolute() or posix.as_posix() != relative or any(part in {"", ".", ".."} for part in posix.parts):
        raise SnapshotValidationError(f"Unsafe snapshot path: {relative!r}")
    path = root.joinpath(*posix.parts)
    if path.is_symlink():
        raise SnapshotValidationError(f"Snapshot file must not be a symlink: {relative}")
    try:
        resolved = path.resolve(strict=True)
        size = path.stat().st_size
    except OSError as exc:
        raise SnapshotValidationError(f"Missing snapshot file: {relative}") from exc
    if not resolved.is_relative_to(root) or not path.is_file():
        raise SnapshotValidationError(f"Unsafe or non-file snapshot path: {relative}")
    if size > limit:
        raise SnapshotValidationError(f"Snapshot file exceeds its {limit}-byte limit: {relative} ({size} bytes)")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SnapshotValidationError(f"Cannot read snapshot file: {relative}") from exc
    if len(raw) != size:
        raise SnapshotValidationError(f"Snapshot file changed while being read: {relative}")
    return raw


def _text(value: Any, label: str, limit: int, *, allow_empty: bool = False, multiline: bool = False) -> str:
    if not isinstance(value, str):
        raise SnapshotValidationError(f"{label} must be text")
    if len(value) > limit:
        raise SnapshotValidationError(f"{label} exceeds its {limit}-character limit")
    if not allow_empty and not value.strip():
        raise SnapshotValidationError(f"{label} must not be empty")
    for char in value:
        code = ord(char)
        if (code < 32 and not (multiline and char in "\t\n\r")) or 0xD800 <= code <= 0xDFFF:
            raise SnapshotValidationError(f"{label} contains an invalid control or surrogate character")
    return value


def _date(value: Any, label: str) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise SnapshotValidationError(f"{label} must be a YYYY-MM-DD date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise SnapshotValidationError(f"{label} is not a real calendar date: {value}") from exc
    if parsed.isoformat() != value:
        raise SnapshotValidationError(f"{label} is not canonical: {value}")
    return parsed


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise SnapshotValidationError(f"{label} must be a short ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotValidationError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SnapshotValidationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _source_timestamp(value: Any, label: str) -> datetime:
    """Accept legacy no-zone source timestamps using the producer's UTC rule.

    Historical feed normalization treated ISO timestamps without an offset as
    UTC. Only the raw published/modified source fields use this compatibility
    path; manifests and activity timestamps still require an explicit zone.
    """
    try:
        return _timestamp(value, label)
    except SnapshotValidationError as original:
        if not isinstance(value, str) or not NAIVE_SOURCE_TIMESTAMP_RE.fullmatch(value):
            raise
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise original
        if parsed.tzinfo is not None:
            raise original
        return parsed.replace(tzinfo=timezone.utc)


def _safe_url(value: Any, label: str) -> str:
    url = _text(value, label, MAX_URL_CHARS)
    if any(char.isspace() for char in url):
        raise SnapshotValidationError(f"{label} contains unescaped whitespace")
    try:
        parsed = urlsplit(url)
        # Accessing port also validates malformed numeric ports and brackets.
        _ = parsed.port
    except ValueError as exc:
        raise SnapshotValidationError(f"{label} is malformed") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise SnapshotValidationError(f"{label} must use an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise SnapshotValidationError(f"{label} must not contain URL credentials")
    return url


def _count(value: Any, label: str, maximum: int = MAX_RECORDS) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise SnapshotValidationError(f"{label} must be an integer between 0 and {maximum}")
    return value


def _score(value: Any, label: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SnapshotValidationError(f"{label} must be a JSON number")
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > maximum:
        raise SnapshotValidationError(f"{label} must be finite and between 0 and {maximum}")
    return number


def _severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score >= 0.1 else "none"


def _validate_record(record: Any, expected_day: str, label: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise SnapshotValidationError(f"{label} must be an object")
    required = {
        "id", "title", "desc", "score", "sev", "published", "modified",
        "window_date", "activity_at", "date_basis", "affected", "refs",
        "related_cves", "advisories", "sources", "kev", "primary_url",
    }
    missing = required - record.keys()
    if missing:
        raise SnapshotValidationError(f"{label} is missing required fields: {', '.join(sorted(missing))}")

    cve_id = _text(record["id"], f"{label}.id", 32)
    if not CVE_RE.fullmatch(cve_id) or cve_id != cve_id.upper():
        raise SnapshotValidationError(f"{label}.id is not a canonical CVE identifier")
    _text(record["title"], f"{label}.title", MAX_TITLE_CHARS)
    _text(record["desc"], f"{label}.desc", MAX_DESCRIPTION_CHARS, multiline=True)
    raw_score = record["score"]
    score = None if raw_score is None else _score(raw_score, f"{label}.score", 10)
    severity = _text(record["sev"], f"{label}.sev", 16).lower()
    if severity not in SEVERITIES or severity != _severity(score):
        raise SnapshotValidationError(f"{label}.sev is inconsistent with its CVSS score")

    for field in ("published", "modified"):
        value = record[field]
        if value is not None:
            _source_timestamp(value, f"{label}.{field}")
    window_day = _date(record["window_date"], f"{label}.window_date")
    activity = _source_timestamp(record["activity_at"], f"{label}.activity_at")
    if window_day.isoformat() != expected_day or activity.date() != window_day:
        raise SnapshotValidationError(f"{label} activity date does not match shard {expected_day}")
    _text(record["date_basis"], f"{label}.date_basis", 128)
    _safe_url(record["primary_url"], f"{label}.primary_url")

    sources = record["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise SnapshotValidationError(f"{label}.sources must contain 1–{MAX_SOURCES} labels")
    clean_sources = [_text(item, f"{label}.sources[]", 64) for item in sources]
    if len(set(clean_sources)) != len(clean_sources) or not set(clean_sources) <= SOURCE_LABELS:
        raise SnapshotValidationError(f"{label}.sources contains duplicate or unknown labels")

    affected = record["affected"]
    if not isinstance(affected, list) or len(affected) > MAX_AFFECTED:
        raise SnapshotValidationError(f"{label}.affected must be an array of at most {MAX_AFFECTED} items")
    for index, item in enumerate(affected):
        item_label = f"{label}.affected[{index}]"
        if not isinstance(item, dict):
            raise SnapshotValidationError(f"{item_label} must be an object")
        for field in ("vendor", "product", "versions"):
            _text(item.get(field), f"{item_label}.{field}", MAX_TEXT_CHARS, allow_empty=True, multiline=True)
        if item.get("source") not in SOURCE_LABELS:
            raise SnapshotValidationError(f"{item_label}.source is unknown")
        if "cpe" in item:
            _text(item["cpe"], f"{item_label}.cpe", MAX_URL_CHARS, allow_empty=True)

    refs = record["refs"]
    if not isinstance(refs, list) or len(refs) > MAX_REFERENCES:
        raise SnapshotValidationError(f"{label}.refs must be an array of at most {MAX_REFERENCES} items")
    for index, item in enumerate(refs):
        item_label = f"{label}.refs[{index}]"
        if not isinstance(item, dict):
            raise SnapshotValidationError(f"{item_label} must be an object")
        _text(item.get("label"), f"{item_label}.label", 256)
        _safe_url(item.get("url"), f"{item_label}.url")
        _text(item.get("source"), f"{item_label}.source", 128)
        tags = item.get("tags", [])
        if not isinstance(tags, list) or len(tags) > 16:
            raise SnapshotValidationError(f"{item_label}.tags must contain at most 16 items")
        for tag in tags:
            _text(tag, f"{item_label}.tags[]", MAX_TAGS)

    related = record["related_cves"]
    if not isinstance(related, list) or len(related) > MAX_RELATED:
        raise SnapshotValidationError(f"{label}.related_cves must be an array of at most {MAX_RELATED} items")
    related_ids: set[str] = set()
    for index, item in enumerate(related):
        item_label = f"{label}.related_cves[{index}]"
        if not isinstance(item, dict):
            raise SnapshotValidationError(f"{item_label} must be an object")
        other_id = _text(item.get("id"), f"{item_label}.id", 32)
        if not CVE_RE.fullmatch(other_id) or other_id != other_id.upper() or other_id == cve_id or other_id in related_ids:
            raise SnapshotValidationError(f"{item_label}.id is invalid or duplicated")
        related_ids.add(other_id)
        _safe_url(item.get("url"), f"{item_label}.url")
        _text(item.get("source"), f"{item_label}.source", 128)

    advisories = record["advisories"]
    if not isinstance(advisories, list) or len(advisories) > MAX_ADVISORIES:
        raise SnapshotValidationError(f"{label}.advisories must be an array of at most {MAX_ADVISORIES} items")
    for index, item in enumerate(advisories):
        item_label = f"{label}.advisories[{index}]"
        if not isinstance(item, dict):
            raise SnapshotValidationError(f"{item_label} must be an object")
        _text(item.get("label"), f"{item_label}.label", 256)
        _safe_url(item.get("url"), f"{item_label}.url")

    kev = record["kev"]
    if kev is not None:
        if not isinstance(kev, dict):
            raise SnapshotValidationError(f"{label}.kev must be null or an object")
        _date(kev.get("date_added"), f"{label}.kev.date_added")
        for field in ("vendor", "product"):
            _text(kev.get(field), f"{label}.kev.{field}", 256, allow_empty=True)
        if kev.get("due_date"):
            _date(kev["due_date"], f"{label}.kev.due_date")
        else:
            _text(kev.get("due_date"), f"{label}.kev.due_date", 10, allow_empty=True)
        _text(kev.get("required_action"), f"{label}.kev.required_action", MAX_TEXT_CHARS, allow_empty=True, multiline=True)
        _text(kev.get("ransomware"), f"{label}.kev.ransomware", 64, allow_empty=True)
    return record


def _manifest_count(mapping: Any, key: str, maximum: int = MAX_RECORDS) -> int:
    if not isinstance(mapping, dict) or key not in mapping:
        raise SnapshotValidationError(f"Manifest is missing count {key}")
    return _count(mapping[key], f"manifest.{key}", maximum)


def _verify_blob(root: Path, config: Any, expected_path: str, limit: int, label: str) -> tuple[bytes, Any]:
    if not isinstance(config, dict) or config.get("path") != expected_path:
        raise SnapshotValidationError(f"{label} path must be {expected_path}")
    declared = _count(config.get("bytes"), f"manifest.{label}.bytes", limit)
    if declared == 0:
        raise SnapshotValidationError(f"manifest.{label}.bytes must be greater than zero")
    digest = config.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise SnapshotValidationError(f"manifest.{label}.sha256 is invalid")
    raw = _contained_bytes(root, expected_path, limit)
    if len(raw) != declared:
        raise SnapshotValidationError(f"Declared byte count mismatch for {expected_path}: {declared} vs {len(raw)}")
    actual = hashlib.sha256(raw).hexdigest()
    if actual.lower() != digest.lower():
        raise SnapshotValidationError(f"SHA-256 mismatch for {expected_path}")
    return raw, _loads(raw, expected_path)


def _activity_key(record: dict[str, Any]) -> tuple[datetime, str]:
    return _source_timestamp(record["activity_at"], "record.activity_at"), record["id"]


def validate_snapshot(root: Path = DEFAULT_ROOT, *, max_age_hours: float | None = None, write_report: bool = False) -> dict[str, Any]:
    root = Path(root).expanduser()
    if root.is_symlink():
        raise SnapshotValidationError("Snapshot root must not be a symlink")
    root = root.resolve()
    if not root.is_dir():
        raise SnapshotValidationError(f"Snapshot root is not a directory: {root}")
    manifest_raw = _contained_bytes(root, "manifest.json", MAX_MANIFEST_BYTES)
    manifest = _loads(manifest_raw, "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2 or manifest.get("complete") is not True:
        raise SnapshotValidationError("manifest.json must be a complete schema-v2 snapshot")
    if {"history", "facets"} & manifest.keys():
        raise SnapshotValidationError("Manifest contains obsolete history/facets output not consumed by this application")

    generated = _timestamp(manifest.get("generated_at"), "manifest.generated_at")
    last_success = _timestamp(manifest.get("last_successful_update"), "manifest.last_successful_update")
    if last_success != generated:
        raise SnapshotValidationError("manifest last_successful_update must match generated_at")
    now = datetime.now(timezone.utc)
    if generated > now + timedelta(minutes=5):
        raise SnapshotValidationError("manifest.generated_at is implausibly in the future")
    if max_age_hours is not None:
        if max_age_hours <= 0:
            raise SnapshotValidationError("max-age-hours must be positive")
        if now - generated > timedelta(hours=max_age_hours):
            raise SnapshotValidationError(f"Snapshot is older than the {max_age_hours:g}-hour freshness gate")

    window = manifest.get("window")
    if not isinstance(window, dict) or window.get("days") != 30 or window.get("timezone") != "UTC":
        raise SnapshotValidationError("manifest.window must describe the 30-day UTC feed contract")
    start = _timestamp(window.get("start"), "manifest.window.start")
    end = _timestamp(window.get("end"), "manifest.window.end")
    if start >= end or end - start != timedelta(days=30) or generated != end:
        raise SnapshotValidationError("Manifest window is inconsistent with its 30-day generated snapshot")
    first_day, last_day = start.date(), end.date()
    expected_dates = [(first_day + timedelta(days=index)).isoformat() for index in range((last_day - first_day).days + 1)]
    if not expected_dates or len(expected_dates) > MAX_SHARDS:
        raise SnapshotValidationError(f"Manifest window requires more than {MAX_SHARDS} UTC shards")

    coverage = manifest.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("sources_complete") is not True:
        raise SnapshotValidationError("Manifest does not declare complete core-source coverage")
    for key in ("nvd_records_returned", "github_advisories_returned", "cisa_kev_catalog_records"):
        if _manifest_count(coverage, key) == 0:
            raise SnapshotValidationError(f"Core source {key} is empty")
    statuses = manifest.get("source_status")
    if not isinstance(statuses, list):
        raise SnapshotValidationError("manifest.source_status must be an array")
    status_by_name: dict[str, dict[str, Any]] = {}
    for item in statuses:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or type(item.get("ok")) is not bool:
            raise SnapshotValidationError("manifest.source_status contains a malformed entry")
        if item["name"] in status_by_name:
            raise SnapshotValidationError(f"Duplicate source-status entry: {item['name']}")
        status_by_name[item["name"]] = item
        if "checked_at" in item and _timestamp(item["checked_at"], f"source_status.{item['name']}.checked_at") != generated:
            raise SnapshotValidationError(f"Source check time does not match the complete snapshot for {item['name']}")
        if "note" in item:
            _text(item["note"], f"source_status.{item['name']}.note", 2_048, allow_empty=True, multiline=True)
    expected_status_names = set(CORE_SOURCES) | {"FIRST EPSS"}
    if set(status_by_name) != expected_status_names:
        raise SnapshotValidationError("Manifest source status names do not match the required source set")
    for source in CORE_SOURCES:
        if status_by_name.get(source, {}).get("ok") is not True:
            raise SnapshotValidationError(f"Core source is not complete: {source}")
    nvd_status = status_by_name[CORE_SOURCES[0]]
    github_status = status_by_name[CORE_SOURCES[1]]
    cisa_status = status_by_name[CORE_SOURCES[2]]
    if _count(nvd_status.get("records"), "NVD source records") != _manifest_count(coverage, "nvd_records_returned"):
        raise SnapshotValidationError("NVD status count does not match source coverage")
    if _count(nvd_status.get("pages"), "NVD source pages", 1_000) == 0:
        raise SnapshotValidationError("NVD source status has no completed pages")
    if _count(github_status.get("advisories"), "GitHub source advisories", MAX_RECORDS) != _manifest_count(coverage, "github_advisories_returned"):
        raise SnapshotValidationError("GitHub status count does not match source coverage")
    if _count(github_status.get("pages"), "GitHub source pages", 250) == 0:
        raise SnapshotValidationError("GitHub source status has no completed pages")
    if _count(cisa_status.get("catalog_records"), "CISA source records", 10_000) != _manifest_count(coverage, "cisa_kev_catalog_records"):
        raise SnapshotValidationError("CISA status count does not match source coverage")

    sources = manifest.get("sources")
    expected_source_names = {
        "NVD CVE API 2.0",
        "GitHub Security Advisory Database",
        "CISA Known Exploited Vulnerabilities catalog",
        "FIRST EPSS",
    }
    if not isinstance(sources, list) or len(sources) != len(expected_source_names):
        raise SnapshotValidationError("manifest.sources must contain the four expected source references")
    source_by_name: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("name"), str) or source["name"] in source_by_name:
            raise SnapshotValidationError("manifest.sources contains a malformed or duplicate source")
        url = _safe_url(source.get("url"), f"source {source['name']} URL")
        if urlsplit(url).scheme.lower() != "https":
            raise SnapshotValidationError(f"Source reference must use HTTPS: {source['name']}")
        source_by_name[source["name"]] = source
    if set(source_by_name) != expected_source_names:
        raise SnapshotValidationError("manifest.sources names do not match the expected source set")

    days = manifest.get("days")
    if not isinstance(days, list) or days != sorted(days, key=lambda item: item.get("date", "") if isinstance(item, dict) else ""):
        raise SnapshotValidationError("manifest.days must be an ascending array of date shards")
    if [item.get("date") if isinstance(item, dict) else None for item in days] != expected_dates:
        raise SnapshotValidationError("Manifest shard dates must cover every UTC day in the 30-day window exactly once")
    if len(days) > MAX_SHARDS:
        raise SnapshotValidationError(f"Manifest lists more than {MAX_SHARDS} shards")

    totals = manifest.get("totals")
    if not isinstance(totals, dict):
        raise SnapshotValidationError("manifest.totals must be an object")
    expected_totals = {severity: _manifest_count(totals, severity) for severity in SEVERITIES}
    expected_cves = _manifest_count(totals, "cves")
    expected_kev = _manifest_count(totals, "known_exploited")
    if expected_cves == 0:
        raise SnapshotValidationError("Snapshot contains no CVE records")
    if expected_cves != coverage.get("distinct_cve_records"):
        raise SnapshotValidationError("Manifest coverage distinct-CVE count does not match totals")
    if coverage.get("utc_days_sharded") != len(days):
        raise SnapshotValidationError("Manifest UTC day-shard count does not match days")

    all_records: list[dict[str, Any]] = []
    all_ids: set[str] = set()
    calculated = {severity: 0 for severity in SEVERITIES}
    calculated_kev = 0
    declared_files: set[str] = {"manifest.json"}
    snapshot_bytes = len(manifest_raw)
    shard_bytes: list[int] = []
    for summary, expected_day in zip(days, expected_dates, strict=True):
        if not isinstance(summary, dict) or summary.get("date") != expected_day:
            raise SnapshotValidationError("Malformed manifest day entry")
        if summary.get("path") != f"data/{expected_day}.json":
            raise SnapshotValidationError(f"Unexpected path for shard {expected_day}")
        count = _count(summary.get("count"), f"manifest.days[{expected_day}].count")
        byte_count = _count(summary.get("bytes"), f"manifest.days[{expected_day}].bytes", MAX_SHARD_BYTES)
        if not isinstance(summary.get("sha256"), str) or not SHA256_RE.fullmatch(summary["sha256"]):
            raise SnapshotValidationError(f"Invalid shard SHA-256 for {expected_day}")
        raw = _contained_bytes(root, summary["path"], MAX_SHARD_BYTES)
        if len(raw) != byte_count:
            raise SnapshotValidationError(f"Declared byte count mismatch for {summary['path']}")
        if hashlib.sha256(raw).hexdigest().lower() != summary["sha256"].lower():
            raise SnapshotValidationError(f"SHA-256 mismatch for {summary['path']}")
        payload = _loads(raw, summary["path"])
        if not isinstance(payload, list) or len(payload) != count:
            raise SnapshotValidationError(f"Declared record count mismatch for {summary['path']}")
        daily = {severity: 0 for severity in SEVERITIES}
        daily_kev = 0
        for index, candidate in enumerate(payload):
            record = _validate_record(candidate, expected_day, f"{expected_day}[{index}]")
            cve_id = record["id"]
            if cve_id in all_ids:
                raise SnapshotValidationError(f"Duplicate CVE ID across shards: {cve_id}")
            all_ids.add(cve_id)
            all_records.append(record)
            daily[record["sev"]] += 1
            calculated[record["sev"]] += 1
            if record["kev"] is not None:
                daily_kev += 1
                calculated_kev += 1
        for severity in SEVERITIES:
            if _count(summary.get(severity), f"manifest.days[{expected_day}].{severity}") != daily[severity]:
                raise SnapshotValidationError(f"Severity count mismatch in {expected_day}: {severity}")
        if _count(summary.get("exploited"), f"manifest.days[{expected_day}].exploited") != daily_kev:
            raise SnapshotValidationError(f"KEV count mismatch in {expected_day}")
        declared_files.add(summary["path"])
        snapshot_bytes += len(raw)
        shard_bytes.append(len(raw))

    if len(all_ids) != expected_cves or len(all_ids) > MAX_RECORDS:
        raise SnapshotValidationError(f"Manifest record total mismatch or limit exceeded: {len(all_ids)}")
    if calculated != expected_totals or calculated_kev != expected_kev:
        raise SnapshotValidationError("Manifest severity or known-exploited totals do not match the shards")

    overview_config = manifest.get("overview")
    overview_raw, overview = _verify_blob(root, overview_config, "data/overview.json", MAX_OVERVIEW_BYTES, "overview")
    overview_records = overview.get("records") if isinstance(overview, dict) else None
    overview_count = _count(overview_config.get("count"), "manifest.overview.count", MAX_OVERVIEW_RECORDS)
    if (not isinstance(overview, dict) or overview.get("schema_version") != 2 or
            set(overview) != {"schema_version", "generated_at", "records"} or
            overview.get("generated_at") != manifest["generated_at"] or overview_config.get("schema_version") != 2):
        raise SnapshotValidationError("overview.json schema or generated_at does not match the manifest")
    if not isinstance(overview_records, list) or len(overview_records) != overview_count or overview_count != min(MAX_OVERVIEW_RECORDS, len(all_records)):
        raise SnapshotValidationError("overview.json record count is inconsistent")
    overview_keys = ("id", "title", "sev", "score", "window_date", "activity_at", "date_basis", "sources", "kev_date_added", "epss")
    overview_ids: set[str] = set()
    for index, summary_record in enumerate(overview_records):
        label = f"overview.records[{index}]"
        if not isinstance(summary_record, dict) or set(summary_record) != set(overview_keys):
            raise SnapshotValidationError(f"{label} has an invalid shape")
        cve_id = summary_record.get("id")
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id) or cve_id in overview_ids:
            raise SnapshotValidationError(f"{label}.id is invalid or duplicated")
        overview_ids.add(cve_id)
        if summary_record.get("kev_date_added") is not None:
            _date(summary_record["kev_date_added"], f"{label}.kev_date_added")
        epss_value = summary_record.get("epss")
        if epss_value is not None:
            if not isinstance(epss_value, dict) or set(epss_value) != {"score", "percentile"}:
                raise SnapshotValidationError(f"{label}.epss must be null or a score/percentile object")
            _score(epss_value["score"], f"{label}.epss.score", 1)
            _score(epss_value["percentile"], f"{label}.epss.percentile", 1)
    declared_files.add("data/overview.json")
    snapshot_bytes += len(overview_raw)

    epss_config = manifest.get("epss")
    epss_raw, epss = _verify_blob(root, epss_config, "data/epss.json", MAX_EPSS_BYTES, "epss")
    if not isinstance(epss_config, dict) or not isinstance(epss, dict) or epss.get("schema_version") != 1:
        raise SnapshotValidationError("EPSS sidecar schema is unsupported")
    if not isinstance(epss.get("scores"), dict):
        raise SnapshotValidationError("EPSS scores must be an object")
    score_date = epss_config.get("score_date")
    if score_date:
        _date(score_date, "manifest.epss.score_date")
    if epss.get("score_date") != score_date or epss.get("source_updated_at") != epss_config.get("source_updated_at"):
        raise SnapshotValidationError("EPSS dates do not match the manifest")
    if epss.get("updated_at") != epss_config.get("updated_at"):
        raise SnapshotValidationError("EPSS updated_at does not match the manifest")
    _timestamp(epss.get("checked_at"), "epss.checked_at")
    if epss.get("updated_at"):
        _timestamp(epss["updated_at"], "epss.updated_at")
    if epss.get("error") is not None:
        _text(epss["error"], "epss.error", 2_048, allow_empty=True, multiline=True)
    scores = epss["scores"]
    if len(scores) != _count(epss_config.get("scored_cves"), "manifest.epss.scored_cves", MAX_RECORDS):
        raise SnapshotValidationError("EPSS score count does not match the manifest")
    if _count(epss_config.get("records"), "manifest.epss.records") != expected_cves:
        raise SnapshotValidationError("EPSS record coverage does not match the CVE total")
    for cve_id, value in scores.items():
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id) or cve_id != cve_id.upper() or cve_id not in all_ids:
            raise SnapshotValidationError(f"EPSS score has an invalid or unknown CVE key: {cve_id!r}")
        if not isinstance(value, dict) or set(value) != {"score", "percentile"}:
            raise SnapshotValidationError(f"EPSS value for {cve_id} must contain score and percentile")
        _score(value["score"], f"EPSS {cve_id}.score", 1)
        _score(value["percentile"], f"EPSS {cve_id}.percentile", 1)
    latest_records = sorted(all_records, key=_activity_key, reverse=True)[:overview_count]
    for index, (summary_record, expected_record) in enumerate(zip(overview_records, latest_records, strict=True)):
        expected_summary = {key: expected_record[key] for key in overview_keys[:8]}
        expected_kev = expected_record.get("kev")
        expected_summary["kev_date_added"] = expected_kev.get("date_added") if isinstance(expected_kev, dict) else None
        expected_summary["epss"] = scores.get(expected_record["id"])
        if summary_record != expected_summary:
            raise SnapshotValidationError(f"overview.records[{index}] does not match the newest full-feed record and EPSS sidecar")
    epss_status = status_by_name.get("FIRST EPSS")
    if epss_status is None:
        raise SnapshotValidationError("Manifest is missing FIRST EPSS status")
    if epss_status["ok"] is True:
        source_updated = _timestamp(epss_config.get("source_updated_at"), "manifest.epss.source_updated_at")
        age = generated - source_updated
        if age < timedelta(0) or age > timedelta(hours=36):
            raise SnapshotValidationError("EPSS is marked current despite a stale or future-dated score set")
    declared_files.add("data/epss.json")
    snapshot_bytes += len(epss_raw)

    if snapshot_bytes > MAX_SNAPSHOT_BYTES:
        raise SnapshotValidationError(f"Static snapshot exceeds its {MAX_SNAPSHOT_BYTES}-byte total limit")
    data_root = root / "data"
    if data_root.is_symlink() or not data_root.is_dir():
        raise SnapshotValidationError("snapshot/data must be a real directory")
    actual_files = {path.relative_to(root).as_posix() for path in data_root.rglob("*") if path.is_file()}
    if actual_files != declared_files - {"manifest.json"}:
        missing = sorted((declared_files - {"manifest.json"}) - actual_files)
        unexpected = sorted(actual_files - (declared_files - {"manifest.json"}))
        raise SnapshotValidationError(f"snapshot/data file set mismatch; missing={missing[:3]}, unexpected={unexpected[:3]}")

    report = {
        "schema_version": 1,
        "generated_at": manifest["generated_at"],
        "checked_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "static_json_bytes": snapshot_bytes,
        "largest_shard_bytes": max(shard_bytes, default=0),
        "shards": len(days),
        "records": len(all_ids),
        "totals": {**expected_totals, "cves": expected_cves, "known_exploited": expected_kev},
        "epss_scores": len(scores),
        "epss_status": "current" if epss_status["ok"] else "stale-or-unavailable",
        "integrity": "Manifest-declared SHA-256 values and all counts were recomputed against exact UTF-8 JSON bytes.",
        "authenticity": "Not cryptographically authenticated; the manifest and its hashes are served from the same GitHub Pages origin.",
        "provenance": "Source names, response counts, timestamps, and update status are recorded in the manifest; source records remain attributed in each CVE record.",
        "limits": {
            "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
            "max_shard_bytes": MAX_SHARD_BYTES,
            "max_records": MAX_RECORDS,
            "max_description_chars": MAX_DESCRIPTION_CHARS,
            "max_url_chars": MAX_URL_CHARS,
            "max_affected_items": MAX_AFFECTED,
            "max_reference_items": MAX_REFERENCES,
        },
    }
    if write_report:
        _write_report(root / "VALIDATION.json", report)
    return report


def _write_report(path: Path, report: dict[str, Any]) -> None:
    staged: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=".validation-", delete=False) as stream:
            json.dump(report, stream, ensure_ascii=False, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            staged = Path(stream.name)
        os.replace(staged, path)
    except OSError as exc:
        if staged is not None:
            staged.unlink(missing_ok=True)
        raise SnapshotValidationError(f"Could not atomically write {path.name}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Snapshot root (default: repository snapshot/)")
    parser.add_argument("--max-age-hours", type=float, default=None, help="Optional freshness gate; omitted by offline/PR validation")
    parser.add_argument("--write-report", action="store_true", help="Atomically refresh snapshot/VALIDATION.json after successful validation")
    args = parser.parse_args()
    try:
        result = validate_snapshot(args.root, max_age_hours=args.max_age_hours, write_report=args.write_report)
    except (SnapshotValidationError, OSError, TypeError, ValueError) as exc:
        print(f"SNAPSHOT VALIDATION FAILED: {exc}")
        return 1
    print(
        "SNAPSHOT VALIDATION PASSED: "
        f"{result['records']:,} unique CVEs across {result['shards']} UTC shards; "
        f"{result['epss_scores']:,} EPSS values; {result['static_json_bytes']:,} JSON bytes; "
        f"generated {result['generated_at']} (EPSS {result['epss_status']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
