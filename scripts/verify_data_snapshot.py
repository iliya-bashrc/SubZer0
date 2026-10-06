#!/usr/bin/env python3
"""Fail-closed validation for SubZer0's static Pages snapshot (schema v2)."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import gzip
import hashlib
import io
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
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$", re.I)
CWE_RE = re.compile(r"^CWE-\d{1,5}$", re.I)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.I)
CVSS_VECTOR_RE = re.compile(r"^CVSS:(?:3\.0|3\.1|4\.0)/[A-Za-z0-9:._/-]+$")
CVSS2_VECTOR_RE = re.compile(
    r"^(?:CVSS:2\.0/)?AV:[NAL]/AC:[LMH]/Au:[NSM]/C:[NPC]/I:[NPC]/A:[NPC]"
    r"(?:/E:(?:ND|U|POC|F|H))?(?:/RL:(?:ND|OF|TF|W|U))?(?:/RC:(?:ND|UC|UR|C))?"
    r"(?:/CDP:(?:ND|N|L|LM|MH|H))?(?:/TD:(?:ND|N|L|M|H))?"
    r"(?:/CR:(?:ND|L|M|H))?(?:/IR:(?:ND|L|M|H))?(?:/AR:(?:ND|L|M|H))?$"
)
MAX_CVSS_VECTOR_CHARS = 512
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
MAX_INDEX_BYTES = 3 * 1024 * 1024
MAX_INDEX_UNCOMPRESSED_BYTES = 12 * 1024 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_HISTORY_EVENTS = 10_000
MAX_HISTORY_SNAPSHOTS = 800
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
MAX_CWES = 32
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
    for field, limit in (("cvss_version", 8), ("cvss_vector", MAX_CVSS_VECTOR_CHARS), ("cvss_source", 64)):
        if field in record:
            _text(record[field], f"{label}.{field}", limit, allow_empty=True)
    if "cwes" in record:
        cwes = record["cwes"]
        if not isinstance(cwes, list) or len(cwes) > MAX_CWES:
            raise SnapshotValidationError(f"{label}.cwes must be an array of at most {MAX_CWES} identifiers")
        clean_cwes = [_text(value, f"{label}.cwes[]", 12) for value in cwes]
        if clean_cwes != sorted(set(clean_cwes)) or any(not CWE_RE.fullmatch(value) or value != value.upper() for value in clean_cwes):
            raise SnapshotValidationError(f"{label}.cwes contains invalid, duplicate, or non-canonical identifiers")
    version = record.get("cvss_version", "")
    if version and version not in {"2.0", "3.0", "3.1", "4.0"}:
        raise SnapshotValidationError(f"{label}.cvss_version is unsupported")
    vector = record.get("cvss_vector", "")
    if vector:
        if version == "2.0":
            if not CVSS2_VECTOR_RE.fullmatch(vector):
                raise SnapshotValidationError(f"{label}.cvss_vector is not a supported CVSS 2.0 vector")
        elif not version or not CVSS_VECTOR_RE.fullmatch(vector):
            raise SnapshotValidationError(f"{label}.cvss_vector is not a supported CVSS vector")
        elif vector.split("/", 1)[0] != f"CVSS:{version}":
            raise SnapshotValidationError(f"{label}.cvss_vector version differs from its scoring evidence")
    if record.get("cvss_source") and record["cvss_source"] not in {"NVD", "GitHub Advisory Database"}:
        raise SnapshotValidationError(f"{label}.cvss_source is not a recognized scoring source")
    if record.get("cvss_source") and score is None:
        raise SnapshotValidationError(f"{label}.cvss_source is present without a numeric CVSS score")

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


def _verify_gzip_blob(
    root: Path, config: Any, expected_path: str, compressed_limit: int,
    uncompressed_limit: int, label: str,
) -> tuple[bytes, Any, int]:
    if not isinstance(config, dict) or config.get("path") != expected_path or config.get("compression") != "gzip":
        raise SnapshotValidationError(f"{label} must declare its expected gzip path and encoding")
    declared = _count(config.get("bytes"), f"manifest.{label}.bytes", compressed_limit)
    uncompressed_declared = _count(config.get("uncompressed_bytes"), f"manifest.{label}.uncompressed_bytes", uncompressed_limit)
    digest = config.get("sha256")
    uncompressed_digest = config.get("uncompressed_sha256")
    if not declared or not uncompressed_declared or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or \
            not isinstance(uncompressed_digest, str) or not SHA256_RE.fullmatch(uncompressed_digest):
        raise SnapshotValidationError(f"{label} gzip integrity metadata is invalid")
    compressed = _contained_bytes(root, expected_path, compressed_limit)
    if len(compressed) != declared or hashlib.sha256(compressed).hexdigest().lower() != digest.lower():
        raise SnapshotValidationError(f"Compressed byte count or SHA-256 mismatch for {expected_path}")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as source:
            raw = source.read(uncompressed_limit + 1)
    except (OSError, EOFError) as exc:
        raise SnapshotValidationError(f"{expected_path} is not a valid gzip stream") from exc
    if len(raw) > uncompressed_limit or len(raw) != uncompressed_declared:
        raise SnapshotValidationError(f"Uncompressed byte count exceeds its declared bound for {expected_path}")
    if hashlib.sha256(raw).hexdigest().lower() != uncompressed_digest.lower():
        raise SnapshotValidationError(f"Uncompressed SHA-256 mismatch for {expected_path}")
    return compressed, _loads(raw, expected_path), len(raw)


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
    if "facets" in manifest:
        raise SnapshotValidationError("Manifest contains obsolete facets output not consumed by this application")

    generated = _timestamp(manifest.get("generated_at"), "manifest.generated_at")
    last_success = _timestamp(manifest.get("last_successful_update"), "manifest.last_successful_update")
    if last_success != generated:
        raise SnapshotValidationError("manifest last_successful_update must match generated_at")
    capture_at = _timestamp(manifest.get("capture_generated_at", manifest.get("generated_at")), "manifest.capture_generated_at")
    created_at = _timestamp(manifest.get("dataset_created_at", manifest.get("generated_at")), "manifest.dataset_created_at")
    modified_at = _timestamp(manifest.get("dataset_modified_at", manifest.get("generated_at")), "manifest.dataset_modified_at")
    if capture_at != generated or created_at > modified_at or modified_at > generated:
        raise SnapshotValidationError("Manifest capture and dataset timestamps are inconsistent")
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
        _manifest_count(coverage, key)
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
    nvd_records_returned = _count(nvd_status.get("records"), "NVD source records")
    if nvd_records_returned != _manifest_count(coverage, "nvd_records_returned"):
        raise SnapshotValidationError("NVD status count does not match source coverage")
    if _count(nvd_status.get("pages"), "NVD source pages", 1_000) == 0:
        raise SnapshotValidationError("NVD source status has no completed pages")
    if "full_baseline" in nvd_status:
        if type(nvd_status["full_baseline"]) is not bool:
            raise SnapshotValidationError("NVD full_baseline must be a boolean")
        cursor_start = _timestamp(nvd_status.get("cursor_start"), "NVD cursor_start")
        cursor_end = _timestamp(nvd_status.get("cursor_end"), "NVD cursor_end")
        overlap = _count(nvd_status.get("overlap_seconds"), "NVD overlap_seconds", 86_400)
        if cursor_start >= cursor_end or cursor_end != generated or overlap != 7_200 or generated - cursor_start > timedelta(days=92):
            raise SnapshotValidationError("NVD incremental cursor metadata is inconsistent")
        if nvd_status["full_baseline"] and nvd_records_returned == 0:
            raise SnapshotValidationError("The initial NVD baseline cannot be empty")
        if nvd_status["full_baseline"] and cursor_start != start:
            raise SnapshotValidationError("The initial NVD baseline does not span the complete rolling window")
    elif nvd_records_returned == 0:
        raise SnapshotValidationError("Legacy full-window NVD source coverage cannot be empty")
    if _count(github_status.get("advisories"), "GitHub source advisories", MAX_RECORDS) != _manifest_count(coverage, "github_advisories_returned"):
        raise SnapshotValidationError("GitHub status count does not match source coverage")
    if _count(github_status.get("pages"), "GitHub source pages", 250) == 0:
        raise SnapshotValidationError("GitHub source status has no completed pages")
    cisa_count = _count(cisa_status.get("catalog_records"), "CISA source records", 10_000)
    if cisa_count == 0:
        raise SnapshotValidationError("CISA KEV full-catalog coverage cannot be empty")
    if cisa_count != _manifest_count(coverage, "cisa_kev_catalog_records"):
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
    if "nvd_records_in_window" in coverage:
        declared_nvd_window = _count(coverage["nvd_records_in_window"], "manifest.coverage.nvd_records_in_window")
        actual_nvd_window = sum("NVD" in (record.get("sources") or []) for record in all_records)
        if declared_nvd_window != actual_nvd_window:
            raise SnapshotValidationError("Manifest retained NVD-record count does not match the validated shards")

    overview_config = manifest.get("overview")
    overview_raw, overview = _verify_blob(root, overview_config, "data/overview.json", MAX_OVERVIEW_BYTES, "overview")
    overview_records = overview.get("records") if isinstance(overview, dict) else None
    recent_changes = overview.get("recent_changes") if isinstance(overview, dict) else None
    overview_count = _count(overview_config.get("count"), "manifest.overview.count", MAX_OVERVIEW_RECORDS)
    recent_count = _count(overview_config.get("recent_change_count"), "manifest.overview.recent_change_count", 5)
    if (not isinstance(overview, dict) or overview.get("schema_version") != 3 or
            set(overview) != {"schema_version", "generated_at", "records", "recent_changes"} or
            overview.get("generated_at") != manifest["generated_at"] or overview_config.get("schema_version") != 3):
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
    if not isinstance(recent_changes, list) or len(recent_changes) != recent_count or len(recent_changes) > 5:
        raise SnapshotValidationError("overview.recent_changes count is invalid")
    preview_ids: set[str] = set()
    preview_types = {"NEW_CVE", "CVE_REOBSERVED", "CWE_CHANGED", "KEV_ADDED", "KEV_CHANGED", "KEV_REMOVED",
                     "CVSS_CHANGED", "EPSS_CHANGED", "AFFECTED_PRODUCTS_CHANGED", "VERSION_RANGE_CHANGED",
                     "DESCRIPTION_CHANGED", "TITLE_CHANGED", "ADVISORY_ADDED", "REFERENCE_ADDED"}
    full_by_id = {record["id"]: record for record in all_records}
    for index, item in enumerate(recent_changes):
        label = f"overview.recent_changes[{index}]"
        if not isinstance(item, dict) or set(item) != {"id", "title", "type", "observed_at", "source_time", "source"}:
            raise SnapshotValidationError(f"{label} has an invalid shape")
        cve_id = _text(item["id"], f"{label}.id", 32)
        if cve_id not in full_by_id or cve_id in preview_ids or item["type"] not in preview_types:
            raise SnapshotValidationError(f"{label} does not refer to a unique current CVE and supported event")
        preview_ids.add(cve_id)
        if item["title"] != full_by_id[cve_id]["title"]:
            raise SnapshotValidationError(f"{label}.title differs from the current full record")
        observed_at = _timestamp(item["observed_at"], f"{label}.observed_at")
        if observed_at > generated:
            raise SnapshotValidationError(f"{label}.observed_at is ahead of capture time")
        if item["source_time"] is not None:
            if isinstance(item["source_time"], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["source_time"]):
                _date(item["source_time"], f"{label}.source_time")
            else:
                _timestamp(item["source_time"], f"{label}.source_time")
        _text(item["source"], f"{label}.source", 128)
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
    if "coverage_kind" in epss_status:
        expected_scores_hash = hashlib.sha256((json.dumps(scores, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")).hexdigest()
        if (epss_status.get("coverage_kind") != "current-record-intersection" or
                epss_status.get("cursor") != score_date or epss_status.get("scores_sha256") != expected_scores_hash or
                not isinstance(epss_status.get("scores_sha256"), str) or not SHA256_RE.fullmatch(epss_status["scores_sha256"])):
            raise SnapshotValidationError("EPSS coverage cursor or score fingerprint does not match its sidecar")
    declared_files.add("data/epss.json")
    snapshot_bytes += len(epss_raw)

    index_config = manifest.get("search_index")
    index_raw, search_index, index_uncompressed_bytes = _verify_gzip_blob(
        root, index_config, "data/search-index.json.gz", MAX_INDEX_BYTES,
        MAX_INDEX_UNCOMPRESSED_BYTES, "search_index")
    if (not isinstance(index_config, dict) or index_config.get("schema_version") != 3 or
            not isinstance(search_index, dict) or search_index.get("schema_version") != 3 or
            search_index.get("generated_at") != manifest["generated_at"] or
            set(search_index) != {"schema_version", "generated_at", "records"}):
        raise SnapshotValidationError("Search-index schema or capture time is invalid")
    index_records = search_index.get("records")
    if not isinstance(index_records, list) or len(index_records) != expected_cves or _count(index_config.get("count"), "manifest.search_index.count") != expected_cves:
        raise SnapshotValidationError("Search-index record count does not match the full snapshot")
    indexed_ids: set[str] = set()
    index_severities = ("critical", "high", "medium", "low", "none", "unknown")
    index_date_bases = ("CVE publication", "GitHub advisory publication", "NVD last modified",
                        "GitHub advisory updated", "CISA KEV date added")
    source_bits = {"NVD": 1, "GitHub Advisory Database": 2, "CISA KEV": 4}
    for index, row in enumerate(index_records):
        label = f"search_index.records[{index}]"
        if not isinstance(row, list) or len(row) != 11:
            raise SnapshotValidationError(f"{label} has an invalid shape")
        cve_id, title, summary, score, severity_code, has_kev, activity_at, date_basis_code, sources_mask, affected, advisory_ids = row
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id) or cve_id != cve_id.upper() or cve_id in indexed_ids or cve_id not in full_by_id:
            raise SnapshotValidationError(f"{label}.id is invalid, duplicated, or absent from detail shards")
        indexed_ids.add(cve_id)
        full = full_by_id[cve_id]
        if (title != full["title"] or not isinstance(severity_code, int) or isinstance(severity_code, bool) or
                severity_code != index_severities.index(full["sev"]) or score != full["score"]):
            raise SnapshotValidationError(f"{label} identity or severity differs from its detail record")
        _text(summary, f"{label}.summary", 320, allow_empty=True)
        if summary != " ".join(str(full.get("desc") or "").split())[:320]:
            raise SnapshotValidationError(f"{label}.summary differs from its detail description")
        if (not isinstance(activity_at, str) or activity_at != full["activity_at"] or
                not isinstance(date_basis_code, int) or isinstance(date_basis_code, bool) or
                not 0 <= date_basis_code < len(index_date_bases) or index_date_bases[date_basis_code] != full["date_basis"]):
            raise SnapshotValidationError(f"{label} activity fields differ from its detail record")
        if not isinstance(sources_mask, int) or isinstance(sources_mask, bool) or not 1 <= sources_mask <= 7 or \
                sources_mask != sum(bit for source, bit in source_bits.items() if source in full["sources"]):
            raise SnapshotValidationError(f"{label} provenance differs from its detail record")
        if not isinstance(has_kev, bool) or has_kev != isinstance(full.get("kev"), dict):
            raise SnapshotValidationError(f"{label} KEV marker differs from its detail record")
        if not isinstance(affected, list) or len(affected) > 8:
            raise SnapshotValidationError(f"{label}.affected must be a compact list of at most eight entries")
        for item in affected:
            if not isinstance(item, list) or len(item) != 3 or any(not isinstance(value, str) for value in item):
                raise SnapshotValidationError(f"{label}.affected contains invalid compact product data")
            if len(item[2]) > 160:
                raise SnapshotValidationError(f"{label}.affected version hint exceeds its compact bound")
        source_affected = full.get("affected") if isinstance(full.get("affected"), list) else []
        expected_affected = []
        for source_index, source_item in enumerate(source_affected[:8]):
            if not isinstance(source_item, dict):
                continue
            vendor = source_item.get("vendor", "") if isinstance(source_item.get("vendor", ""), str) else ""
            product = source_item.get("product", "") if isinstance(source_item.get("product", ""), str) else ""
            version_hint = ""
            if source_index < 3 and isinstance(source_item.get("versions"), str):
                version_hint = " ".join(source_item["versions"].split())[:160]
            if vendor or product:
                expected_affected.append([vendor, product, version_hint])
        if affected != expected_affected:
            raise SnapshotValidationError(f"{label}.affected differs from the source details or version hints")
        if not isinstance(advisory_ids, list) or len(advisory_ids) > 8 or any(not isinstance(value, str) or not GHSA_RE.fullmatch(value) for value in advisory_ids):
            raise SnapshotValidationError(f"{label}.advisory_ids is invalid")
        expected_advisory_ids = []
        for advisory in full.get("advisories") or []:
            if not isinstance(advisory, dict) or not isinstance(advisory.get("url"), str):
                continue
            parsed = urlsplit(advisory["url"])
            candidate = parsed.path.rstrip("/").rsplit("/", 1)[-1]
            if parsed.scheme == "https" and parsed.netloc.lower() == "github.com" and GHSA_RE.fullmatch(candidate):
                expected_advisory_ids.append(candidate.upper())
        if advisory_ids != list(dict.fromkeys(expected_advisory_ids))[:8]:
            raise SnapshotValidationError(f"{label}.advisory_ids differ from source advisory URLs")
    if indexed_ids != all_ids:
        raise SnapshotValidationError("Search index must contain each detail record exactly once")
    declared_files.add("data/search-index.json.gz")
    snapshot_bytes += len(index_raw)

    history_config = manifest.get("history")
    history_raw, history = _verify_blob(root, history_config, "data/history.json", MAX_HISTORY_BYTES, "history")
    if (not isinstance(history_config, dict) or history_config.get("schema_version") != 1 or
            not isinstance(history, dict) or set(history) - {"schema_version", "retention_days", "baseline", "snapshots", "events", "kev_catalog"} or
            not {"schema_version", "retention_days", "baseline", "snapshots", "events"}.issubset(history) or
            history.get("schema_version") != 1 or history.get("retention_days") != 30 or history_config.get("retention_days") != 30):
        raise SnapshotValidationError("Change-history schema or retention policy is invalid")
    baseline = history.get("baseline")
    if baseline is not None:
        if not isinstance(baseline, dict) or set(baseline) != {"core_snapshot_at", "epss_score_date", "record_count", "complete"} or baseline.get("complete") is not True:
            raise SnapshotValidationError("Change-history baseline metadata is invalid")
        _timestamp(baseline["core_snapshot_at"], "history.baseline.core_snapshot_at")
        if baseline["epss_score_date"]:
            _date(baseline["epss_score_date"], "history.baseline.epss_score_date")
        _count(baseline["record_count"], "history.baseline.record_count")
    snapshots = history.get("snapshots")
    events = history.get("events")
    if not isinstance(snapshots, list) or len(snapshots) > MAX_HISTORY_SNAPSHOTS or _count(history_config.get("snapshot_count"), "manifest.history.snapshot_count", MAX_HISTORY_SNAPSHOTS) != len(snapshots):
        raise SnapshotValidationError("Change-history snapshot list exceeds its declared bound")
    if not isinstance(events, list) or len(events) > MAX_HISTORY_EVENTS or _count(history_config.get("event_count"), "manifest.history.event_count", MAX_HISTORY_EVENTS) != len(events):
        raise SnapshotValidationError("Change-history event list exceeds its declared bound")
    retention_start = generated - timedelta(days=30)
    for index, item in enumerate(snapshots):
        label = f"history.snapshots[{index}]"
        if not isinstance(item, dict) or set(item) != {"observed_at", "core_snapshot_at", "epss_score_date", "record_count", "complete"}:
            raise SnapshotValidationError(f"{label} has an invalid shape")
        observed = _timestamp(item["observed_at"], f"{label}.observed_at")
        _timestamp(item["core_snapshot_at"], f"{label}.core_snapshot_at")
        if observed > generated or observed < retention_start or item["complete"] is not True:
            raise SnapshotValidationError(f"{label} is outside the retained complete-capture window")
        if item["epss_score_date"]:
            _date(item["epss_score_date"], f"{label}.epss_score_date")
        _count(item["record_count"], f"{label}.record_count")
    event_types = {"NEW_CVE", "CVE_UPDATED", "CVE_REOBSERVED", "CVE_REJECTED", "CWE_CHANGED", "CVSS_CHANGED", "TITLE_CHANGED", "DESCRIPTION_CHANGED",
                   "KEV_ADDED", "KEV_CHANGED", "KEV_REMOVED", "EPSS_CHANGED", "AFFECTED_PRODUCTS_CHANGED",
                   "REFERENCE_CHANGED", "REFERENCE_ADDED", "REFERENCE_REMOVED", "ADVISORY_CHANGED",
                   "ADVISORY_ADDED", "ADVISORY_REMOVED", "VERSION_RANGE_CHANGED", "SOURCE_METADATA_CHANGED"}
    for index, item in enumerate(events):
        label = f"history.events[{index}]"
        if not isinstance(item, dict) or set(item) != {"id", "type", "observed_at", "source_time", "source", "from", "to"}:
            raise SnapshotValidationError(f"{label} has an invalid shape")
        cve_id = _text(item["id"], f"{label}.id", 32)
        if not CVE_RE.fullmatch(cve_id) or cve_id != cve_id.upper() or not isinstance(item["type"], str) or item["type"] not in event_types:
            raise SnapshotValidationError(f"{label} identity or change type is invalid")
        observed = _timestamp(item["observed_at"], f"{label}.observed_at")
        if observed > generated or observed < retention_start:
            raise SnapshotValidationError(f"{label} is outside the retained observation window")
        if item["source_time"] is not None:
            if isinstance(item["source_time"], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["source_time"]):
                _date(item["source_time"], f"{label}.source_time")
            else:
                _timestamp(item["source_time"], f"{label}.source_time")
        _text(item["source"], f"{label}.source", 128)
        for field in ("from", "to"):
            value_size = len(json.dumps(item[field], ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            if value_size > 2_300:
                raise SnapshotValidationError(f"{label}.{field} exceeds the bounded change-value size")

    preview_priority = {"NEW_CVE": 0, "CVE_REOBSERVED": 1, "KEV_ADDED": 2, "KEV_CHANGED": 2,
                        "KEV_REMOVED": 2, "CVSS_CHANGED": 3, "EPSS_CHANGED": 4,
                        "AFFECTED_PRODUCTS_CHANGED": 5, "VERSION_RANGE_CHANGED": 5, "CWE_CHANGED": 5,
                        "DESCRIPTION_CHANGED": 6, "TITLE_CHANGED": 6, "ADVISORY_ADDED": 7,
                        "REFERENCE_ADDED": 8}
    preview_candidates = [item for item in events if item["id"] in full_by_id and item["type"] in preview_priority]
    preview_candidates.sort(key=lambda item: (_timestamp(item["observed_at"], "history event observed_at"),
                                              -preview_priority[item["type"]], item["id"]), reverse=True)
    expected_recent: list[dict[str, Any]] = []
    retained_ids: set[str] = set()
    for event in preview_candidates:
        if event["id"] in retained_ids:
            continue
        current_record = full_by_id[event["id"]]
        expected_recent.append({"id": event["id"], "title": current_record["title"], "type": event["type"],
                                "observed_at": event["observed_at"], "source_time": event["source_time"],
                                "source": event["source"] or "Verified source comparison"})
        retained_ids.add(event["id"])
        if len(expected_recent) == 5:
            break
    if recent_changes != expected_recent:
        raise SnapshotValidationError("Overview recent changes do not match the newest source-verified retained events")

    kev_catalog = history.get("kev_catalog", [])
    if not isinstance(kev_catalog, list) or len(kev_catalog) > 5_000 or _count(history_config.get("kev_catalog_count"), "manifest.history.kev_catalog_count", 5_000) != len(kev_catalog):
        raise SnapshotValidationError("Change-history CISA baseline exceeds its declared entry bound")
    kev_keys = {"cveID", "dateAdded", "vendorProject", "product", "vulnerabilityName", "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes"}
    kev_ids: set[str] = set()
    for index, item in enumerate(kev_catalog):
        label = f"history.kev_catalog[{index}]"
        if not isinstance(item, dict) or set(item) != kev_keys:
            raise SnapshotValidationError(f"{label} has an invalid CISA catalog shape")
        cve_id = _text(item["cveID"], f"{label}.cveID", 32)
        if not CVE_RE.fullmatch(cve_id) or cve_id != cve_id.upper() or cve_id in kev_ids:
            raise SnapshotValidationError(f"{label}.cveID is invalid or duplicated")
        kev_ids.add(cve_id)
        _date(item["dateAdded"], f"{label}.dateAdded")
        for key, limit in (("vendorProject", 256), ("product", 256), ("vulnerabilityName", 512),
                           ("shortDescription", 4_096), ("requiredAction", 2_048), ("dueDate", 10),
                           ("knownRansomwareCampaignUse", 64), ("notes", 1_024)):
            _text(item[key], f"{label}.{key}", limit, allow_empty=True, multiline=True)
    if len(json.dumps(kev_catalog, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > 4 * 1024 * 1024:
        raise SnapshotValidationError("Change-history CISA catalog baseline exceeds 4 MiB")
    cisa_status = status_by_name[CORE_SOURCES[2]]
    if "coverage_kind" in cisa_status:
        catalog_hash = hashlib.sha256((json.dumps(kev_catalog, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")).hexdigest()
        catalog_cursor = max((item["dateAdded"] for item in kev_catalog), default="")
        if (cisa_status.get("coverage_kind") != "complete-catalog" or cisa_status.get("cursor") != catalog_cursor or
                cisa_status.get("catalog_sha256") != catalog_hash or
                not isinstance(cisa_status.get("catalog_sha256"), str) or not SHA256_RE.fullmatch(cisa_status["catalog_sha256"])):
            raise SnapshotValidationError("CISA KEV cursor or catalog fingerprint does not match its complete history sidecar")
    github_status = status_by_name[CORE_SOURCES[1]]
    if "coverage_kind" in github_status and github_status.get("coverage_kind") != "complete-rolling-window":
        raise SnapshotValidationError("GitHub advisory coverage is not a complete rolling-window query")

    declared_files.add("data/history.json")
    snapshot_bytes += len(history_raw)

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
        "search_index_compressed_bytes": len(index_raw),
        "search_index_uncompressed_bytes": index_uncompressed_bytes,
        "search_index_compression_ratio": round(len(index_raw) / index_uncompressed_bytes, 4),
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
        f"{result['epss_scores']:,} EPSS values; {result['static_json_bytes']:,} static bytes; "
        f"search index {result['search_index_compressed_bytes']:,} compressed / {result['search_index_uncompressed_bytes']:,} uncompressed bytes; "
        f"generated {result['generated_at']} (EPSS {result['epss_status']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
