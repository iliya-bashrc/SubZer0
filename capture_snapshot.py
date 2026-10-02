#!/usr/bin/env python3
"""Capture SubZer0's published rolling feed and verify its manifest-listed bytes."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
SNAPSHOT = ROOT / "snapshot"
MANIFEST_URL = "https://iliya-bashrc.github.io/SubZer0/api/v1/manifest.json"
SITE_ROOT = "https://iliya-bashrc.github.io/SubZer0/"
CVE_RE = re.compile(r"^CVE-\d{4,}-\d+$", re.I)


def get_bytes(url: str) -> bytes:
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "SubZer0 local preview snapshot capture", "Accept": "application/json"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError) as error:
            last_error = error
            if isinstance(error, urllib.error.HTTPError) and error.code not in {408, 425, 429, 500, 502, 503, 504}:
                raise
            if attempt == 3:
                break
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"Could not download {url}: {last_error}")


def json_bytes(data: bytes, label: str):
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Invalid JSON at {label}: {error}") from error


def safe_manifest_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "data":
        raise RuntimeError(f"Unsafe or unexpected manifest path: {value!r}")
    return path


def main() -> None:
    SNAPSHOT.mkdir(parents=True, exist_ok=True)
    manifest_bytes = get_bytes(MANIFEST_URL)
    manifest = json_bytes(manifest_bytes, MANIFEST_URL)
    (SNAPSHOT / "manifest.json").write_bytes(manifest_bytes)

    if manifest.get("schema_version") != 2 or manifest.get("complete") is not True:
        raise RuntimeError("Published manifest is incomplete or has an unsupported schema")
    days = manifest.get("days")
    if not isinstance(days, list) or not days:
        raise RuntimeError("Published manifest does not contain daily shards")

    jobs: list[tuple[str, str, str | None]] = []
    for item in days:
        if not isinstance(item, dict):
            raise RuntimeError("Malformed manifest day entry")
        relative = safe_manifest_path(item["path"])
        if relative.name != f"{item['date']}.json":
            raise RuntimeError(f"Unexpected shard date/path pair: {item.get('date')} / {item.get('path')}")
        jobs.append((item["path"], item["sha256"], item["date"]))

    epss = manifest.get("epss", {})
    if isinstance(epss, dict) and epss.get("path"):
        epss_path = safe_manifest_path(epss["path"])
        jobs.append((epss["path"], "", None))

    results: dict[str, bytes] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        future_map = {
            pool.submit(get_bytes, urllib.parse.urljoin(SITE_ROOT, path)): path
            for path, _, _ in jobs
        }
        for future in concurrent.futures.as_completed(future_map):
            path = future_map[future]
            results[path] = future.result()

    seen_ids: set[str] = set()
    severity_counts = {key: 0 for key in ("critical", "high", "medium", "low", "none", "unknown")}
    day_audits = []
    for item in days:
        path = item["path"]
        body = results[path]
        actual_hash = hashlib.sha256(body).hexdigest()
        if actual_hash != item["sha256"]:
            raise RuntimeError(f"SHA-256 mismatch for {path}: expected {item['sha256']}, got {actual_hash}")
        payload = json_bytes(body, path)
        if not isinstance(payload, list) or len(payload) != item["count"]:
            actual_count = len(payload) if isinstance(payload, list) else "not an array"
            raise RuntimeError(f"Count mismatch for {path}: expected {item['count']}, got {actual_count}")
        day_counts = {key: 0 for key in severity_counts}
        exploited = 0
        for record in payload:
            if not isinstance(record, dict) or not CVE_RE.fullmatch(str(record.get("id", ""))):
                raise RuntimeError(f"Invalid CVE record in {path}")
            if record["id"] in seen_ids:
                raise RuntimeError(f"Duplicate CVE ID across published daily shards: {record['id']}")
            seen_ids.add(record["id"])
            severity = record.get("sev")
            if severity not in day_counts:
                raise RuntimeError(f"Unexpected severity in {path}: {severity!r}")
            day_counts[severity] += 1
            severity_counts[severity] += 1
            exploited += int(isinstance(record.get("kev"), dict))
        for severity, expected in (("critical", "critical"), ("high", "high"), ("medium", "medium"), ("low", "low"), ("none", "none"), ("unknown", "unknown")):
            if day_counts[severity] != item.get(expected, 0):
                raise RuntimeError(f"Manifest severity count mismatch for {path}: {severity}={day_counts[severity]}, expected {item.get(expected, 0)}")
        if exploited != item.get("exploited", 0):
            raise RuntimeError(f"Manifest KEV count mismatch for {path}: {exploited}, expected {item.get('exploited', 0)}")
        out = SNAPSHOT / path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(body)
        day_audits.append({"date": item["date"], "path": path, "count": len(payload), "sha256": actual_hash})

    totals = manifest["totals"]
    if len(seen_ids) != totals.get("cves"):
        raise RuntimeError(f"Unique ID count mismatch: {len(seen_ids)} vs manifest {totals.get('cves')}")
    if severity_counts != {key: totals.get(key, 0) for key in severity_counts}:
        raise RuntimeError(f"Severity totals mismatch: {severity_counts} vs {totals}")
    kev_total = sum(int(isinstance(record.get("kev"), dict)) for item in days for record in json_bytes(results[item["path"]], item["path"]))
    if kev_total != totals.get("known_exploited"):
        raise RuntimeError(f"KEV total mismatch: {kev_total} vs manifest {totals.get('known_exploited')}")

    epss_audit = None
    if isinstance(epss, dict) and epss.get("path"):
        epss_path = epss["path"]
        epss_bytes = results[epss_path]
        epss_payload = json_bytes(epss_bytes, epss_path)
        scores = epss_payload.get("scores", {}) if isinstance(epss_payload, dict) else {}
        if not isinstance(scores, dict):
            raise RuntimeError("EPSS scores are not a mapping")
        if len(scores) != epss.get("scored_cves"):
            raise RuntimeError(f"EPSS score count mismatch: {len(scores)} vs manifest {epss.get('scored_cves')}")
        out = SNAPSHOT / epss_path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(epss_bytes)
        epss_audit = {
            "path": epss_path,
            "sha256": hashlib.sha256(epss_bytes).hexdigest(),
            "scored_cves": len(scores),
            "score_date": epss.get("score_date"),
            "source_updated_at": epss.get("source_updated_at"),
            "manifest_marks_stale": next((source.get("ok") is False for source in manifest.get("source_status", []) if source.get("name") == "FIRST EPSS"), None),
        }

    audit = {
        "source_manifest_url": MANIFEST_URL,
        "source_shard_base_url": SITE_ROOT,
        "generated_at": manifest["generated_at"],
        "window": manifest["window"],
        "complete": manifest["complete"],
        "record_count": len(seen_ids),
        "severity_counts": severity_counts,
        "known_exploited_count": kev_total,
        "shard_count": len(day_audits),
        "shards": day_audits,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "epss": epss_audit,
        "validation": "all manifest-listed date-shard byte hashes, row counts, daily severity counts, daily KEV counts, global unique CVE IDs, severity totals, global KEV count, and EPSS score count matched",
    }
    (SNAPSHOT / "VALIDATION.json").write_text(json.dumps(audit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({k: audit[k] for k in ("generated_at", "record_count", "severity_counts", "known_exploited_count", "shard_count", "manifest_sha256", "epss", "validation")}, indent=2))
    print(f"Captured snapshot: {SNAPSHOT}")


if __name__ == "__main__":
    main()
