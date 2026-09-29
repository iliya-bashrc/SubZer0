#!/usr/bin/env python3
"""Build SubZer0's rolling 30-day, deduplicated static CVE feed.

Sources: NVD CVE API 2.0, GitHub's Global Security Advisories API, and CISA's
Known Exploited Vulnerabilities catalog. The output is sharded by UTC activity
day so the browser can load recent records first on slower devices.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import date, datetime, time as dt_time, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "data"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com/advisories"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4,}-\d+$", re.I)
MAX_NVD_PAGE = 2000
NVD_PAGE_PAUSE_SECONDS = 6
USER_AGENT = "SubZer0-Radar/2.0 (+https://github.com/iliya-bashrc/SubZer0)"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
SOURCE_CREDITS = [
    {"name": "NVD CVE API 2.0", "url": "https://nvd.nist.gov/developers/vulnerabilities"},
    {"name": "GitHub Security Advisory Database", "url": "https://github.com/advisories"},
    {"name": "CISA Known Exploited Vulnerabilities catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
]


class FeedError(RuntimeError):
    """Raised when a complete trustworthy snapshot could not be assembled."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def nvd_time(value: datetime) -> str:
    value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}"


def _header(headers: Any, key: str, default: str = "") -> str:
    if not headers:
        return default
    for name, value in headers.items():
        if str(name).lower() == key.lower():
            return str(value)
    return default


def request_json(url: str, headers: dict[str, str] | None = None, timeout: int = 60) -> tuple[Any, Any]:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    for attempt in range(5):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8")), response.headers
        except urllib.error.HTTPError as exc:
            retry_after = _header(exc.headers, "Retry-After")
            retryable = exc.code in {408, 425, 429, 500, 502, 503, 504}
            if not retryable or attempt == 4:
                raise FeedError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
            try:
                delay = min(90, max(1, int(retry_after))) if retry_after else min(30, 2 ** attempt)
            except ValueError:
                delay = min(30, 2 ** attempt)
            print(f"Temporary HTTP {exc.code}; retrying in {delay}s", file=sys.stderr)
            time.sleep(delay)
        except (TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
            if attempt == 4:
                raise FeedError(f"Could not read {urllib.parse.urlsplit(url).netloc}: {exc}") from exc
            delay = min(30, 2 ** attempt)
            print(f"Temporary source error; retrying in {delay}s", file=sys.stderr)
            time.sleep(delay)
    raise FeedError(f"Could not fetch {url}")


def iter_nvd(
    start: datetime,
    end: datetime,
    request_fn: Callable[..., tuple[Any, Any]] = request_json,
    sleep_fn: Callable[[float], None] = time.sleep,
    page_size: int = MAX_NVD_PAGE,
    api_key: str | None = None,
) -> tuple[list[dict[str, Any]], int, int]:
    """Fetch every offset page in the requested publication window."""
    if start >= end:
        raise ValueError("NVD window start must be earlier than end")
    if not 1 <= page_size <= MAX_NVD_PAGE:
        raise ValueError(f"NVD page size must be between 1 and {MAX_NVD_PAGE}")
    params = {
        "pubStartDate": nvd_time(start),
        "pubEndDate": nvd_time(end),
        "resultsPerPage": page_size,
    }
    headers = {"apiKey": api_key} if api_key else {}
    records: list[dict[str, Any]] = []
    start_index = 0
    total_results: int | None = None
    pages = 0
    while total_results is None or start_index < total_results:
        if pages:
            # NVD's unauthenticated cap is five calls per rolling 30 seconds.
            sleep_fn(NVD_PAGE_PAUSE_SECONDS)
        query = urllib.parse.urlencode({**params, "startIndex": start_index})
        payload, _ = request_fn(f"{NVD_API}?{query}", headers=headers)
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise FeedError("NVD returned an unexpected response shape")
        if total_results is None:
            total_results = int(payload.get("totalResults", 0))
        page = payload["vulnerabilities"]
        if not page and start_index < total_results:
            raise FeedError("NVD returned an empty page before the reported end of the result set")
        records.extend(page)
        pages += 1
        start_index += len(page)
        if pages > 1000:
            raise FeedError("NVD pagination safety limit reached")
    return records, int(total_results or 0), pages


def _next_link(link_header: str) -> str | None:
    for match in re.finditer(r'<([^>]+)>\s*;\s*rel="?([^";,]+)', link_header, re.I):
        if match.group(2).strip().lower() == "next":
            url = match.group(1).strip()
            if url.startswith("https://api.github.com/advisories?"):
                return url
            raise FeedError("GitHub returned an unexpected pagination URL")
    return None


def iter_github_advisories(
    start: datetime,
    end: datetime,
    request_fn: Callable[..., tuple[Any, Any]] = request_json,
    token: str | None = None,
    max_pages: int = 500,
) -> tuple[list[dict[str, Any]], int]:
    """Traverse GitHub's date-filtered advisory pages using its Link cursor."""
    if start >= end:
        raise ValueError("GitHub advisory window start must be earlier than end")
    date_range = f"{start.date().isoformat()}..{end.date().isoformat()}"
    query = urllib.parse.urlencode({
        "per_page": 100,
        "published": date_range,
        "sort": "published",
        "direction": "desc",
    })
    url = f"{GITHUB_API}?{query}"
    headers = {"X-GitHub-Api-Version": "2026-03-10"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    items: list[dict[str, Any]] = []
    seen_ghsa: set[str] = set()
    pages = 0
    while url:
        if pages >= max_pages:
            raise FeedError("GitHub advisory pagination safety limit reached")
        payload, response_headers = request_fn(url, headers=headers)
        if not isinstance(payload, list):
            raise FeedError("GitHub returned an unexpected advisory response shape")
        for advisory in payload:
            ghsa_id = str(advisory.get("ghsa_id") or "")
            if ghsa_id and ghsa_id not in seen_ghsa:
                seen_ghsa.add(ghsa_id)
                items.append(advisory)
        pages += 1
        url = _next_link(_header(response_headers, "Link"))
    return items, pages


def fetch_kev(request_fn: Callable[..., tuple[Any, Any]] = request_json) -> tuple[list[dict[str, Any]], int]:
    payload, _ = request_fn(CISA_KEV, headers={})
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise FeedError("CISA returned an unexpected KEV response shape")
    items = payload["vulnerabilities"]
    return items, int(payload.get("count", len(items)))


def severity_for(score: float | int | None) -> str:
    if score is None:
        return "unknown"
    score = float(score)
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _cve_id(value: Any) -> str | None:
    candidate = str(value or "").strip().upper()
    return candidate if CVE_RE.fullmatch(candidate) else None


def _description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()
    return ""


def _safe_url(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value.startswith(("https://", "http://")) else None


def _add_ref(refs: list[dict[str, str]], seen: set[str], label: str, url: Any, source: str) -> None:
    safe = _safe_url(url)
    if safe and safe not in seen:
        seen.add(safe)
        refs.append({"label": label[:80], "url": safe, "source": source})


def _cvss(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            value = (values[0].get("cvssData") or {}).get("baseScore")
            if value is not None:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    pass
    return None


def _version_range(match: dict[str, Any], version: str) -> str:
    parts: list[str] = []
    if version and version not in {"*", "-", "\u002d"}:
        parts.append(version)
    for key, symbol in (
        ("versionStartIncluding", ">="),
        ("versionStartExcluding", ">"),
        ("versionEndIncluding", "<="),
        ("versionEndExcluding", "<"),
    ):
        bound = match.get(key)
        if bound and bound not in {"*", "-"}:
            parts.append(f"{symbol} {bound}")
    return ", ".join(parts) if parts else "Version details not specified in source"


def _nvd_affected(cve: dict[str, Any]) -> list[dict[str, str]]:
    affected: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def visit(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch") or []:
            criteria = str(match.get("criteria") or "")
            parts = criteria.split(":")
            if len(parts) < 6:
                continue
            vendor, product, version = parts[3], parts[4], parts[5]
            if vendor in {"*", "-"} and product in {"*", "-"}:
                continue
            entry = {
                "vendor": vendor.replace("_", " "),
                "product": product.replace("_", " "),
                "versions": _version_range(match, version),
                "source": "NVD",
            }
            identity = (entry["vendor"].lower(), entry["product"].lower(), entry["versions"].lower())
            if identity not in seen:
                seen.add(identity)
                affected.append(entry)
        for child in node.get("children") or []:
            if isinstance(child, dict):
                visit(child)

    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if isinstance(node, dict):
                visit(node)
    return affected[:60]


def _title(description: str, fallback: str) -> str:
    value = re.sub(r"\s+", " ", description).strip()
    if not value:
        return fallback[:160]
    first_sentence = re.split(r"(?<=[.!?])\s+", value, maxsplit=1)[0]
    return (first_sentence or value)[:180]


def _record(cve_id: str, published: str | None = None) -> dict[str, Any]:
    return {
        "id": cve_id,
        "title": "",
        "desc": "",
        "score": None,
        "sev": "unknown",
        "published": published,
        "modified": None,
        "window_date": None,
        "activity_at": None,
        "date_basis": None,
        "affected": [],
        "refs": [],
        "advisories": [],
        "sources": [],
        "kev": None,
        "primary_url": f"https://www.cve.org/CVERecord?id={cve_id}",
    }


def _add_source(record: dict[str, Any], source: str) -> None:
    if source not in record["sources"]:
        record["sources"].append(source)


def _add_affected(record: dict[str, Any], entry: dict[str, str]) -> None:
    identity = tuple(str(entry.get(key, "")).casefold() for key in ("vendor", "product", "versions"))
    if not any(tuple(str(existing.get(key, "")).casefold() for key in ("vendor", "product", "versions")) == identity for existing in record["affected"]):
        record["affected"].append(entry)


def build_records(
    nvd_items: list[dict[str, Any]],
    advisories: list[dict[str, Any]],
    kev_items: list[dict[str, Any]],
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    """Merge source records by canonical CVE ID, keeping both attribution and links."""
    records: dict[str, dict[str, Any]] = {}

    def add_ref(record: dict[str, Any], label: str, url: Any, source: str) -> None:
        known = {item["url"] for item in record["refs"]}
        _add_ref(record["refs"], known, label, url, source)

    for item in nvd_items:
        cve = item.get("cve", item)
        cve_id = _cve_id(cve.get("id"))
        if not cve_id or str(cve.get("vulnStatus", "")).lower() == "rejected":
            continue
        published = str(cve.get("published") or "") or None
        published_dt = parse_datetime(published)
        if not published_dt or not (start <= published_dt <= end):
            continue
        record = records.setdefault(cve_id, _record(cve_id, published))
        description = _description(cve.get("descriptions"))
        score = _cvss(cve)
        record.update({
            "title": _title(description, cve_id),
            "desc": description or "No English summary is available in the source record.",
            "score": score,
            "sev": severity_for(score),
            "published": published,
            "modified": cve.get("lastModified"),
            "window_date": published_dt.date().isoformat(),
            "activity_at": published,
            "date_basis": "CVE publication",
            "primary_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
        _add_source(record, "NVD")
        add_ref(record, "NVD record", f"https://nvd.nist.gov/vuln/detail/{cve_id}", "NVD")
        add_ref(record, "CVE Program record", f"https://www.cve.org/CVERecord?id={cve_id}", "CVE Program")
        for reference in cve.get("references") or []:
            if isinstance(reference, dict):
                add_ref(record, "Reference", reference.get("url"), "NVD")
        for product in _nvd_affected(cve):
            _add_affected(record, product)

    for advisory in advisories:
        cve_id = _cve_id(advisory.get("cve_id"))
        published = str(advisory.get("published_at") or "") or None
        published_dt = parse_datetime(published)
        if not cve_id or not published_dt or not (start <= published_dt <= end):
            continue
        record = records.setdefault(cve_id, _record(cve_id, advisory.get("nvd_published_at") or published))
        if not record["published"]:
            record["published"] = advisory.get("nvd_published_at") or published
        if not record["activity_at"]:
            cve_publication = parse_datetime(advisory.get("nvd_published_at") or record["published"])
            if cve_publication and start <= cve_publication <= end:
                record["activity_at"] = iso_z(cve_publication)
                record["window_date"] = cve_publication.date().isoformat()
                record["date_basis"] = "CVE publication"
            else:
                record["activity_at"] = published
                record["window_date"] = published_dt.date().isoformat()
                record["date_basis"] = "GitHub advisory publication"
        else:
            current_activity = parse_datetime(record["activity_at"])
            if current_activity is None or published_dt > current_activity:
                record["activity_at"] = published
                record["window_date"] = published_dt.date().isoformat()
                record["date_basis"] = "GitHub advisory publication"
        summary = str(advisory.get("summary") or "").strip()
        description = str(advisory.get("description") or "").strip() or summary
        if not record["desc"] and description:
            record["desc"] = description
            record["title"] = _title(summary or description, cve_id)
        cvss = advisory.get("cvss_severities") or {}
        scores = [((cvss.get(key) or {}).get("score")) for key in ("cvss_v4", "cvss_v3")]
        scores = [float(value) for value in scores if value is not None]
        if record["score"] is None and scores:
            record["score"] = max(scores)
            record["sev"] = severity_for(record["score"])
        elif record["sev"] == "unknown":
            advisory_severity = str(advisory.get("severity") or "unknown").lower()
            if advisory_severity in SEVERITY_ORDER:
                record["sev"] = advisory_severity
        _add_source(record, "GitHub Advisory Database")
        html_url = advisory.get("html_url") or advisory.get("url")
        if _safe_url(html_url) and not any(item["url"] == html_url for item in record["advisories"]):
            record["advisories"].append({"label": "GitHub Security Advisory", "url": html_url})
            add_ref(record, "GitHub security advisory", html_url, "GitHub")
        for reference in advisory.get("references") or []:
            add_ref(record, "Advisory reference", reference, "GitHub")
        for vulnerability in advisory.get("vulnerabilities") or []:
            package = vulnerability.get("package") or {}
            name = str(package.get("name") or "")
            ecosystem = str(package.get("ecosystem") or "")
            if name:
                versions = str(vulnerability.get("vulnerable_version_range") or "Version range not specified")
                patched = vulnerability.get("first_patched_version")
                if patched:
                    versions += f"; first patched: {patched}"
                _add_affected(record, {
                    "vendor": ecosystem or "Package",
                    "product": name,
                    "versions": versions,
                    "source": "GitHub Advisory Database",
                })

    start_day, end_day = start.date(), end.date()
    for item in kev_items:
        cve_id = _cve_id(item.get("cveID"))
        if not cve_id:
            continue
        date_added = str(item.get("dateAdded") or "")
        try:
            added_day = date.fromisoformat(date_added)
        except ValueError:
            continue
        record = records.get(cve_id)
        if record is None and not (start_day <= added_day <= end_day):
            continue
        if record is None:
            record = records.setdefault(cve_id, _record(cve_id))
            record["window_date"] = date_added
            record["activity_at"] = f"{date_added}T00:00:00Z"
            record["date_basis"] = "CISA KEV date added"
            record["title"] = str(item.get("vulnerabilityName") or cve_id)[:180]
            record["desc"] = str(item.get("shortDescription") or "CISA lists this vulnerability as known exploited.")
        elif start_day <= added_day <= end_day:
            kev_activity = datetime.combine(added_day, dt_time.min, tzinfo=timezone.utc)
            current_activity = parse_datetime(record.get("activity_at"))
            if current_activity is None or kev_activity > current_activity:
                record["window_date"] = date_added
                record["activity_at"] = f"{date_added}T00:00:00Z"
                record["date_basis"] = "CISA KEV date added"
        _add_source(record, "CISA KEV")
        record["kev"] = {
            "date_added": date_added,
            "vendor": str(item.get("vendorProject") or ""),
            "product": str(item.get("product") or ""),
            "due_date": str(item.get("dueDate") or ""),
            "required_action": str(item.get("requiredAction") or ""),
            "ransomware": str(item.get("knownRansomwareCampaignUse") or "Unknown"),
        }
        if item.get("vendorProject") or item.get("product"):
            _add_affected(record, {
                "vendor": str(item.get("vendorProject") or ""),
                "product": str(item.get("product") or ""),
                "versions": "Version details not specified by CISA",
                "source": "CISA KEV",
            })
        add_ref(record, "CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA")

    for record in records.values():
        if not record["title"]:
            record["title"] = record["id"]
        if not record["desc"]:
            record["desc"] = "No source summary is available yet. Review the linked primary records and advisories."
        if record["score"] is not None:
            record["sev"] = severity_for(record["score"])
        record["affected"].sort(key=lambda item: (item["vendor"].lower(), item["product"].lower(), item["versions"].lower()))
        record["refs"] = record["refs"][:14]
        record["advisories"] = record["advisories"][:6]
        record["sources"].sort(key=lambda source: {"NVD": 0, "GitHub Advisory Database": 1, "CISA KEV": 2}.get(source, 9))
    return sorted(records.values(), key=lambda record: (record.get("window_date") or "", record["id"]), reverse=True)


def build_manifest(
    records: list[dict[str, Any]],
    start: datetime,
    end: datetime,
    generated_at: datetime,
    source_status: list[dict[str, Any]],
    nvd_total: int,
    ghsa_total: int,
    kev_total: int,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    shards: dict[str, list[dict[str, Any]]] = defaultdict(list)
    valid_days = {(start.date() + timedelta(days=offset)).isoformat() for offset in range((end.date() - start.date()).days + 1)}
    for record in records:
        day = record.get("window_date")
        if day not in valid_days:
            raise FeedError(f"Record {record.get('id', 'unknown')} has no in-window activity date: {day!r}")
        shards[day].append(record)
    sharded_total = sum(len(items) for items in shards.values())
    if sharded_total != len(records):
        raise FeedError(f"Manifest/shard record count mismatch: {len(records)} vs {sharded_total}")
    day_summaries: list[dict[str, Any]] = []
    day = start.date()
    while day <= end.date():
        key = day.isoformat()
        items = shards.get(key, [])
        day_summaries.append({
            "date": key,
            "count": len(items),
            "critical": sum(item["sev"] == "critical" for item in items),
            "high": sum(item["sev"] == "high" for item in items),
            "medium": sum(item["sev"] == "medium" for item in items),
            "low": sum(item["sev"] == "low" for item in items),
            "unknown": sum(item["sev"] == "unknown" for item in items),
            "exploited": sum(bool(item.get("kev")) for item in items),
            "path": f"data/{key}.json",
        })
        day += timedelta(days=1)
    severity_counts = {
        severity: sum(item["sev"] == severity for item in records)
        for severity in SEVERITY_ORDER
    }
    manifest = {
        "schema_version": 2,
        "generated_at": iso_z(generated_at),
        "last_successful_update": iso_z(generated_at),
        "window": {
            "days": 30,
            "start": iso_z(start),
            "end": iso_z(end),
            "timezone": "UTC",
            "semantics": "NVD CVE publication timestamps; GitHub advisory publication timestamps; plus CISA KEV date-added entries in the window",
        },
        "complete": True,
        "totals": {
            "cves": sharded_total,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "unknown": severity_counts["unknown"],
            "known_exploited": sum(bool(item.get("kev")) for item in records),
        },
        "coverage": {
            "nvd_records_returned": nvd_total,
            "github_advisories_returned": ghsa_total,
            "cisa_kev_catalog_records": kev_total,
            "distinct_cve_records": sharded_total,
            "utc_days_sharded": len(day_summaries),
            "sources_complete": all(item.get("ok") is True for item in source_status),
        },
        "sources": SOURCE_CREDITS,
        "source_status": source_status,
        "days": day_summaries,
    }
    return manifest, dict(shards)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
        stream.write("\n")


def write_snapshot(output_dir: Path, manifest: dict[str, Any], shards: dict[str, list[dict[str, Any]]]) -> None:
    """Write every shard first and the manifest last so browsers never see a partial index."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="subzero-feed-") as temp:
        staged = Path(temp)
        for summary in manifest["days"]:
            day = summary["date"]
            _write_json(staged / f"{day}.json", shards.get(day, []))
        _write_json(staged / "manifest.json", manifest)
        expected_days = {item["date"] for item in manifest["days"]}
        for day in expected_days:
            os.replace(staged / f"{day}.json", output_dir / f"{day}.json")
        # The index changes last; versioned requests in the page avoid stale CDN shards.
        os.replace(staged / "manifest.json", output_dir / "manifest.json")
    for path in output_dir.glob("????-??-??.json"):
        if path.stem not in expected_days:
            path.unlink()


def refresh(
    output_dir: Path = DEFAULT_OUTPUT,
    now: datetime | None = None,
    request_fn: Callable[..., tuple[Any, Any]] = request_json,
    sleep_fn: Callable[[float], None] = time.sleep,
    nvd_api_key: str | None = None,
    github_token: str | None = None,
) -> dict[str, Any]:
    as_of = (now or utc_now()).astimezone(timezone.utc).replace(microsecond=0)
    start = as_of - timedelta(days=30)
    end = as_of
    # Fail closed if any feed fails: retain the last complete snapshot rather than
    # quietly publishing a partial source mix as if it were complete.
    nvd_items, nvd_total, nvd_pages = iter_nvd(start, end, request_fn, sleep_fn, api_key=nvd_api_key)
    ghsa_items, ghsa_pages = iter_github_advisories(start, end, request_fn, token=github_token)
    kev_items, kev_total = fetch_kev(request_fn)
    records = build_records(nvd_items, ghsa_items, kev_items, start, end)
    statuses = [
        {"name": "NVD CVE API 2.0", "ok": True, "pages": nvd_pages, "records": nvd_total},
        {"name": "GitHub Security Advisory Database", "ok": True, "pages": ghsa_pages, "advisories": len(ghsa_items)},
        {"name": "CISA KEV", "ok": True, "catalog_records": kev_total},
    ]
    manifest, shards = build_manifest(records, start, end, as_of, statuses, nvd_total, len(ghsa_items), kev_total)
    write_snapshot(output_dir, manifest, shards)
    print(
        f"Complete snapshot: {len(records)} unique CVEs across {len(manifest['days'])} UTC day shards; "
        f"NVD {nvd_total}/{nvd_pages} pages, GitHub {len(ghsa_items)}/{ghsa_pages} pages, CISA {kev_total} catalog entries; "
        f"window {iso_z(start)} to {iso_z(end)}"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--days", type=int, default=30, help="rolling publication window in days (default: 30)")
    args = parser.parse_args()
    if args.days != 30:
        parser.error("the public feed contract is a 30-day window; --days must be 30")
    try:
        refresh(
            output_dir=args.output_dir,
            nvd_api_key=os.environ.get("NVD_API_KEY") or None,
            github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None,
        )
    except Exception as exc:
        print(f"Feed refresh failed; existing snapshot left untouched: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
