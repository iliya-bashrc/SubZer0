#!/usr/bin/env python3
"""Build SubZer0's rolling 30-day, deduplicated static CVE feed.

Sources: NVD CVE API 2.0, GitHub's Global Security Advisories API, and CISA's
Known Exploited Vulnerabilities catalog. The output is sharded by UTC activity
day so the browser can load recent records first on slower devices.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import math
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
DEFAULT_OUTPUT = ROOT / "snapshot"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com/advisories"
CISA_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CSV = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_API = "https://api.first.org/data/v1/epss"
CVE_RE = re.compile(r"^CVE-\d{4,}-\d+$", re.I)
GHSA_RE = re.compile(r"^GHSA-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$", re.I)
CVSS_VECTOR_RE = re.compile(r"^CVSS:(?:3\.0|3\.1|4\.0)/[A-Za-z0-9:._/-]+$")
CVSS2_VECTOR_RE = re.compile(
    r"^(?:CVSS:2\.0/)?AV:[NAL]/AC:[LMH]/Au:[NSM]/C:[NPC]/I:[NPC]/A:[NPC]"
    r"(?:/E:(?:ND|U|POC|F|H))?(?:/RL:(?:ND|OF|TF|W|U))?(?:/RC:(?:ND|UC|UR|C))?"
    r"(?:/CDP:(?:ND|N|L|LM|MH|H))?(?:/TD:(?:ND|N|L|M|H))?"
    r"(?:/CR:(?:ND|L|M|H))?(?:/IR:(?:ND|L|M|H))?(?:/AR:(?:ND|L|M|H))?$"
)
MAX_CVSS_VECTOR_CHARS = 512
CVSS_VERSIONS = {"2.0", "3.0", "3.1", "4.0"}
NAIVE_SOURCE_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?$")
SOURCE_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$")
MAX_NVD_PAGE = 2000
MAX_NVD_RESULTS = 100_000
NVD_TOTAL_RESTARTS = 1
MAX_GHSA_ITEMS = 25_000
MAX_GHSA_PAGES = 250
MAX_KEV_ITEMS = 10_000
MAX_HTTP_JSON_BYTES = 32 * 1024 * 1024
MAX_TOTAL_UPSTREAM_JSON_BYTES = 256 * 1024 * 1024
MAX_EPSS_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_EPSS_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_EPSS_LINE_BYTES = 1024 * 1024
MAX_EPSS_ROWS = 5_000_000
MAX_EPSS_COMMENT_BYTES = 64 * 1024
MAX_EPSS_CACHE_BYTES = 4 * 1024 * 1024
MAX_CORE_RECORDS = 50_000
NVD_PAGE_PAUSE_SECONDS = 6
USER_AGENT = "SubZer0/1.0 (+https://github.com/iliya-bashrc/SubZer0)"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}
SOURCE_CREDITS = [
    {"name": "NVD CVE API 2.0", "url": "https://nvd.nist.gov/developers/vulnerabilities"},
    {"name": "GitHub Security Advisory Database", "url": "https://github.com/advisories"},
    {"name": "CISA Known Exploited Vulnerabilities catalog", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
]
EPSS_SOURCE = {"name": "FIRST EPSS", "url": "https://www.first.org/epss/data"}


class FeedError(RuntimeError):
    """Raised when a complete trustworthy snapshot could not be assembled."""


class NvdResultSetChangedError(FeedError):
    """Signals an upstream result-count change that may be resolved by a full retry."""


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


def normalize_source_timestamp(value: Any, label: str) -> str | None:
    """Keep source precision; make the historical implicit-UTC rule explicit."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not SOURCE_TIMESTAMP_RE.fullmatch(value) or not parse_datetime(value):
        raise FeedError(f"{label} is not a valid ISO-8601 timestamp")
    if NAIVE_SOURCE_TIMESTAMP_RE.fullmatch(value):
        return f"{value}Z"
    return value


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


class _JSONIngressBudget:
    def __init__(self, limit: int = MAX_TOTAL_UPSTREAM_JSON_BYTES) -> None:
        self.limit = limit
        self.used = 0

    def fetch(self, request_fn: Callable[..., tuple[Any, Any]], url: str, headers: dict[str, str] | None = None) -> tuple[Any, Any]:
        payload, response_headers = request_fn(url, headers=headers)
        declared = _header(response_headers, "Content-Length")
        if declared:
            if not re.fullmatch(r"\d+", declared):
                raise FeedError("Upstream returned an invalid Content-Length")
            response_bytes = int(declared)
        else:
            response_bytes = 0
        # Parsed JSON is serialized only to estimate responses whose transport omitted Content-Length.
        parsed_bytes = len(_json_bytes(payload))
        response_bytes = max(response_bytes, parsed_bytes)
        if response_bytes > MAX_HTTP_JSON_BYTES:
            raise FeedError("Upstream JSON response exceeds the configured byte limit")
        if self.used + response_bytes > self.limit:
            raise FeedError("Combined upstream JSON exceeds the configured ingestion budget")
        self.used += response_bytes
        return payload, response_headers


ALLOWED_SOURCE_HOSTS = {
    "services.nvd.nist.gov", "api.github.com", "www.cisa.gov",
    "epss.empiricalsecurity.com", "api.first.org",
}


def _validate_source_url(url: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise FeedError("Malformed source URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_SOURCE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or any(char.isspace() for char in url)
    ):
        raise FeedError("Refusing an unapproved upstream URL")


class _SameHostHTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        try:
            source = urllib.parse.urlsplit(request.full_url)
            target = urllib.parse.urlsplit(new_url)
            port = target.port
        except (TypeError, ValueError) as exc:
            raise FeedError("Malformed upstream redirect") from exc
        if (
            target.scheme != "https"
            or target.hostname != source.hostname
            or target.username is not None
            or target.password is not None
            or port not in (None, 443)
        ):
            raise FeedError("Refusing an off-origin upstream redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FeedError(f"Upstream JSON contains a duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise FeedError(f"Upstream JSON contains an invalid number: {value}")


def request_json(url: str, headers: dict[str, str] | None = None, timeout: int = 60) -> tuple[Any, Any]:
    _validate_source_url(url)
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    opener = urllib.request.build_opener(_SameHostHTTPSRedirect())
    for attempt in range(5):
        try:
            with opener.open(request, timeout=timeout) as response:
                content_length = _header(response.headers, "Content-Length")
                if content_length:
                    if not re.fullmatch(r"\d+", content_length):
                        raise FeedError("Upstream returned an invalid Content-Length")
                    declared_length = int(content_length)
                    if declared_length > MAX_HTTP_JSON_BYTES:
                        raise FeedError("Upstream JSON response exceeds the configured byte limit")
                body = response.read(MAX_HTTP_JSON_BYTES + 1)
                if len(body) > MAX_HTTP_JSON_BYTES:
                    raise FeedError("Upstream JSON response exceeds the configured byte limit")
                try:
                    payload = json.loads(
                        body.decode("utf-8", errors="strict"),
                        object_pairs_hook=_unique_json_object,
                        parse_constant=_reject_json_constant,
                    )
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise FeedError("Upstream returned invalid UTF-8 JSON") from exc
                return payload, response.headers
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
        except (TimeoutError, urllib.error.URLError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            if attempt == 4:
                raise FeedError(f"Could not read {urllib.parse.urlsplit(url).netloc}: {exc}") from exc
            delay = min(30, 2 ** attempt)
            print(f"Temporary source error; retrying in {delay}s", file=sys.stderr)
            time.sleep(delay)
    raise FeedError(f"Could not fetch {urllib.parse.urlsplit(url).netloc}")


def iter_nvd(
    start: datetime,
    end: datetime,
    request_fn: Callable[..., tuple[Any, Any]] = request_json,
    sleep_fn: Callable[[float], None] = time.sleep,
    page_size: int = MAX_NVD_PAGE,
    api_key: str | None = None,
    date_field: str = "modified",
) -> tuple[list[dict[str, Any]], int, int]:
    """Fetch a complete NVD result set, restarting once if pagination observes a concurrent change."""
    for attempt in range(NVD_TOTAL_RESTARTS + 1):
        try:
            return _iter_nvd_once(start, end, request_fn, sleep_fn, page_size, api_key, date_field)
        except NvdResultSetChangedError:
            if attempt >= NVD_TOTAL_RESTARTS:
                raise
            print("NVD totalResults changed during pagination; restarting the entire bounded query once.", file=sys.stderr)
            sleep_fn(NVD_PAGE_PAUSE_SECONDS)
    raise FeedError("NVD result set could not be stabilized")


def _iter_nvd_once(
    start: datetime,
    end: datetime,
    request_fn: Callable[..., tuple[Any, Any]],
    sleep_fn: Callable[[float], None],
    page_size: int,
    api_key: str | None,
    date_field: str,
) -> tuple[list[dict[str, Any]], int, int]:
    """Fetch every offset page using NVD publication or last-modified timestamps."""
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ValueError("NVD window start must be earlier than end")
    if not 1 <= page_size <= MAX_NVD_PAGE:
        raise ValueError(f"NVD page size must be between 1 and {MAX_NVD_PAGE}")
    if date_field not in {"published", "modified"}:
        raise ValueError("NVD date_field must be 'published' or 'modified'")
    prefix = "pub" if date_field == "published" else "lastMod"
    params = {
        f"{prefix}StartDate": nvd_time(start),
        f"{prefix}EndDate": nvd_time(end),
        "resultsPerPage": page_size,
    }
    headers = {"apiKey": api_key} if api_key else {}
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
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
        reported_total = payload.get("totalResults")
        if isinstance(reported_total, bool) or not isinstance(reported_total, int) or not 0 <= reported_total <= MAX_NVD_RESULTS:
            raise FeedError("NVD returned an invalid or excessive totalResults count")
        if total_results is None:
            total_results = reported_total
        elif reported_total != total_results:
            raise NvdResultSetChangedError("NVD result total changed during pagination")
        metadata = payload.get("resultsPerPage")
        if metadata is not None and (
            isinstance(metadata, bool) or not isinstance(metadata, int)
            or not 0 <= metadata <= page_size or metadata != len(payload["vulnerabilities"])
        ):
            raise FeedError("NVD resultsPerPage metadata is inconsistent")
        metadata_start = payload.get("startIndex")
        if metadata_start is not None and (
            isinstance(metadata_start, bool) or not isinstance(metadata_start, int) or metadata_start != start_index
        ):
            raise FeedError("NVD startIndex metadata is inconsistent")
        page = payload["vulnerabilities"]
        if not page and start_index < total_results:
            raise FeedError("NVD returned an empty page before the reported end of the result set")
        if len(page) > page_size or any(not isinstance(item, dict) for item in page):
            raise FeedError("NVD returned an invalid or oversized page")
        for item in page:
            cve = item.get("cve", item)
            cve_id = _cve_id(cve.get("id")) if isinstance(cve, dict) else None
            if not cve_id or cve_id in seen_ids:
                raise FeedError("NVD returned a missing or duplicate CVE identifier")
            seen_ids.add(cve_id)
        records.extend(page)
        pages += 1
        start_index += len(page)
    if pages > 1000:
        raise FeedError("NVD pagination safety limit reached")
    if len(records) != total_results:
        raise FeedError("NVD returned fewer records than its complete-result count")
    return records, int(total_results or 0), pages


def _next_link(link_header: str) -> str | None:
    for match in re.finditer(r'<([^>]+)>\s*;\s*rel="?([^";,]+)', link_header, re.I):
        if match.group(2).strip().lower() == "next":
            url = match.group(1).strip()
            _validate_source_url(url)
            parsed = urllib.parse.urlsplit(url)
            if parsed.hostname == "api.github.com" and parsed.path == "/advisories" and parsed.query:
                return url
            raise FeedError("GitHub returned an unexpected pagination URL")
    return None


def iter_github_advisories(
    start: datetime,
    end: datetime,
    request_fn: Callable[..., tuple[Any, Any]] = request_json,
    token: str | None = None,
    max_pages: int = MAX_GHSA_PAGES,
) -> tuple[list[dict[str, Any]], int]:
    """Traverse GitHub advisories published or updated in-window using official Link cursors."""
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ValueError("GitHub advisory window start must be earlier than end")
    if not 1 <= max_pages <= MAX_GHSA_PAGES:
        raise ValueError(f"GitHub advisory page limit must be between 1 and {MAX_GHSA_PAGES}")
    date_range = f"{start.date().isoformat()}..{end.date().isoformat()}"
    query = urllib.parse.urlencode({
        "per_page": 100,
        "modified": date_range,
        "sort": "updated",
        "direction": "desc",
    })
    url = f"{GITHUB_API}?{query}"
    headers = {"X-GitHub-Api-Version": "2026-03-10"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    items: list[dict[str, Any]] = []
    seen_ghsa: set[str] = set()
    pages = 0
    seen_urls: set[str] = set()
    while url:
        if pages >= max_pages:
            raise FeedError("GitHub advisory pagination safety limit reached")
        _validate_source_url(url)
        if url in seen_urls:
            raise FeedError("GitHub advisory pagination cursor repeated")
        seen_urls.add(url)
        payload, response_headers = request_fn(url, headers=headers)
        if not isinstance(payload, list) or len(payload) > 100:
            raise FeedError("GitHub returned an unexpected advisory response shape")
        for advisory in payload:
            if not isinstance(advisory, dict):
                raise FeedError("GitHub returned a malformed advisory object")
            ghsa_id = str(advisory.get("ghsa_id") or "")
            if not ghsa_id or ghsa_id in seen_ghsa:
                raise FeedError("GitHub returned a missing or duplicate advisory identifier")
            seen_ghsa.add(ghsa_id)
            items.append(advisory)
            if len(items) > MAX_GHSA_ITEMS:
                raise FeedError("GitHub advisory record safety limit reached")
        next_url = _next_link(_header(response_headers, "Link"))
        if not payload and next_url:
            raise FeedError("GitHub returned an empty advisory page with a next-page cursor")
        pages += 1
        url = next_url
    if pages == 0 or not items:
        raise FeedError("GitHub returned an empty advisory result set")
    return items, pages


def fetch_kev(request_fn: Callable[..., tuple[Any, Any]] = request_json) -> tuple[list[dict[str, Any]], int]:
    payload, _ = request_fn(CISA_KEV, headers={})
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise FeedError("CISA returned an unexpected KEV response shape")
    items = payload["vulnerabilities"]
    count = payload.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count != len(items) or not 0 < count <= MAX_KEV_ITEMS:
        raise FeedError("CISA KEV count is empty, excessive, or inconsistent with its vulnerability list")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise FeedError("CISA returned a malformed KEV record")
        cve_id = _cve_id(item.get("cveID"))
        if not cve_id or cve_id in seen:
            raise FeedError("CISA returned a missing or duplicate KEV CVE identifier")
        date_added = item.get("dateAdded")
        if not isinstance(date_added, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_added):
            raise FeedError("CISA returned an invalid KEV dateAdded value")
        try:
            if date.fromisoformat(date_added).isoformat() != date_added:
                raise ValueError
        except ValueError as exc:
            raise FeedError("CISA returned a non-canonical KEV dateAdded value") from exc
        seen.add(cve_id)
    return items, count


def parse_epss_csv(stream: Any, allowed_cves: set[str] | None = None) -> tuple[dict[str, dict[str, float]], str, str]:
    """Read the official daily EPSS CSV, retaining only the requested CVE IDs."""
    comments: list[str] = []
    comment_bytes = 0

    def data_lines():
        nonlocal comment_bytes
        for line in stream:
            line_bytes = len(line.encode("utf-8"))
            if line_bytes > MAX_EPSS_LINE_BYTES:
                raise FeedError("FIRST EPSS CSV line exceeded the line-size safety limit")
            if line.startswith("#"):
                if len(comments) < 32 and comment_bytes + line_bytes <= MAX_EPSS_COMMENT_BYTES:
                    comments.append(line.strip())
                    comment_bytes += line_bytes
            elif line.strip():
                yield line

    csv.field_size_limit(MAX_EPSS_LINE_BYTES)
    reader = csv.DictReader(data_lines())
    if not reader.fieldnames or len(reader.fieldnames) != 3 or len(set(reader.fieldnames)) != 3 or set(reader.fieldnames) != {"cve", "epss", "percentile"}:
        raise FeedError("FIRST EPSS returned an unexpected CSV header")
    metadata = " ".join(comments)
    match = re.search(r"score_date:([^,\s]+)", metadata, re.I)
    source_updated_at = match.group(1) if match else ""
    if not source_updated_at or not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", source_updated_at) or not parse_datetime(source_updated_at):
        raise FeedError("FIRST EPSS CSV did not provide a valid score_date")
    scores: dict[str, dict[str, float]] = {}
    seen_cves: set[str] = set()
    rows_seen = 0
    valid_rows = 0
    for row in reader:
        rows_seen += 1
        if rows_seen > MAX_EPSS_ROWS:
            raise FeedError("FIRST EPSS CSV exceeded the row-count safety limit")
        if len(str(row)) > MAX_EPSS_LINE_BYTES:
            raise FeedError("FIRST EPSS CSV row exceeded the line-size safety limit")
        if None in row:
            raise FeedError("FIRST EPSS CSV row contains unexpected extra columns")
        cve_id = _cve_id(row.get("cve"))
        if not cve_id:
            continue
        if cve_id in seen_cves:
            raise FeedError(f"FIRST EPSS returned a duplicate score row for {cve_id}")
        seen_cves.add(cve_id)
        valid_rows += 1
        if allowed_cves is not None and cve_id not in allowed_cves:
            continue
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            raise FeedError(f"FIRST EPSS returned an invalid score row for {cve_id}")
        if not math.isfinite(score) or not math.isfinite(percentile) or not 0 <= score <= 1 or not 0 <= percentile <= 1:
            raise FeedError(f"FIRST EPSS returned an out-of-range score row for {cve_id}")
        scores[cve_id] = {"score": score, "percentile": percentile}
    if rows_seen == 0 or valid_rows == 0:
        raise FeedError("FIRST EPSS CSV contained no valid CVE rows")
    score_date = source_updated_at[:10]
    return scores, score_date, source_updated_at


class _BoundedReader(io.RawIOBase):
    """Raw stream wrapper that refuses compressed and expanded EPSS bombs."""

    def __init__(self, source: Any, limit: int, label: str):
        super().__init__()
        self.source = source
        self.limit = limit
        self.label = label
        self.count = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:
        request_size = min(len(buffer), max(1, self.limit - self.count + 1))
        chunk = self.source.read(request_size)
        if not chunk:
            return 0
        self.count += len(chunk)
        if self.count > self.limit:
            raise FeedError(f"FIRST EPSS {self.label} data exceeded its byte limit")
        buffer[:len(chunk)] = chunk
        return len(chunk)


def fetch_epss_csv(allowed_cves: set[str] | None = None) -> tuple[dict[str, dict[str, float]], str, str]:
    """Stream FIRST's compressed current-day CSV; its API is not used for bulk sync."""
    _validate_source_url(EPSS_CSV)
    request = urllib.request.Request(EPSS_CSV, headers={"User-Agent": USER_AGENT, "Accept": "application/gzip, text/csv"})
    try:
        opener = urllib.request.build_opener(_SameHostHTTPSRedirect())
        with opener.open(request, timeout=120) as response:
            content_length = _header(response.headers, "Content-Length")
            if content_length:
                if not re.fullmatch(r"\d+", content_length):
                    raise FeedError("FIRST EPSS returned an invalid Content-Length")
                declared_length = int(content_length)
                if declared_length > MAX_EPSS_COMPRESSED_BYTES:
                    raise FeedError("FIRST EPSS compressed input exceeded its byte limit")
            bounded_compressed = io.BufferedReader(_BoundedReader(response, MAX_EPSS_COMPRESSED_BYTES, "compressed"))
            with gzip.GzipFile(fileobj=bounded_compressed) as compressed:
                bounded_expanded = io.BufferedReader(_BoundedReader(compressed, MAX_EPSS_UNCOMPRESSED_BYTES, "expanded"))
                with io.TextIOWrapper(bounded_expanded, encoding="utf-8", errors="strict", newline="") as stream:
                    return parse_epss_csv(stream, allowed_cves)
    except (OSError, EOFError, UnicodeError, urllib.error.URLError, gzip.BadGzipFile) as exc:
        raise FeedError(f"Could not read FIRST EPSS daily data: {exc}") from exc


def fetch_epss_api(cve_ids: set[str], request_fn: Callable[..., tuple[Any, Any]] = request_json) -> dict[str, dict[str, float]]:
    """Look up small batches of new CVEs; FIRST limits the cve parameter to 2000 characters."""
    ids = sorted(cve_ids)
    batches: list[list[str]] = []
    batch: list[str] = []
    for cve_id in ids:
        candidate = batch + [cve_id]
        if batch and len(",".join(candidate)) > 1850:
            batches.append(batch)
            batch = [cve_id]
        else:
            batch = candidate
    if batch:
        batches.append(batch)
    output: dict[str, dict[str, float]] = {}
    for chunk in batches:
        requested = set(chunk)
        query = urllib.parse.urlencode({"cve": ",".join(chunk)})
        payload, _ = request_fn(f"{EPSS_API}?{query}", headers={"Accept": "application/json"})
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list) or len(payload["data"]) > len(chunk):
            raise FeedError("FIRST EPSS API returned an unexpected response shape")
        seen: set[str] = set()
        for item in payload["data"]:
            if not isinstance(item, dict):
                raise FeedError("FIRST EPSS API returned a malformed score row")
            cve_id = _cve_id(item.get("cve"))
            if not cve_id or cve_id not in requested or cve_id in seen:
                raise FeedError("FIRST EPSS API returned an unexpected or duplicate CVE identifier")
            seen.add(cve_id)
            try:
                if isinstance(item.get("epss"), bool) or isinstance(item.get("percentile"), bool):
                    raise ValueError
                score = float(item["epss"])
                percentile = float(item["percentile"])
            except (KeyError, TypeError, ValueError) as exc:
                raise FeedError(f"FIRST EPSS API returned an invalid score row for {cve_id}") from exc
            if not math.isfinite(score) or not math.isfinite(percentile) or not 0 <= score <= 1 or not 0 <= percentile <= 1:
                raise FeedError(f"FIRST EPSS API returned an out-of-range score row for {cve_id}")
            output[cve_id] = {"score": score, "percentile": percentile}
    return output


def severity_for(score: float | int | None) -> str:
    if score is None:
        return "unknown"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if not 0 <= score <= 10:
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
    if not isinstance(value, str) or len(value) > 2048:
        return None
    value = value.strip()
    if not value or any(char.isspace() or ord(char) < 32 for char in value):
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in {"https", "http"}
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return None
    return value


def _add_ref(
    refs: list[dict[str, Any]],
    seen: set[str],
    label: str,
    url: Any,
    source: str,
    tags: Any = None,
) -> None:
    safe = _safe_url(url)
    if not safe:
        return
    safe_tags = sorted({str(tag).strip()[:40] for tag in tags if isinstance(tag, str) and tag.strip()}) if isinstance(tags, list) else []
    existing = next((item for item in refs if item.get("url") == safe), None)
    if existing:
        if safe_tags:
            existing["tags"] = sorted(set(existing.get("tags", [])) | set(safe_tags))
        return
    seen.add(safe)
    reference = {"label": label[:80], "url": safe, "source": source}
    if safe_tags:
        reference["tags"] = safe_tags
    refs.append(reference)


def _cvss(cve: dict[str, Any]) -> float | None:
    return _cvss_evidence(cve)[0]


def _checked_cvss_vector(value: Any, version: str, source: str) -> str:
    if version not in CVSS_VERSIONS:
        raise FeedError(f"{source} returned an unsupported CVSS version")
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise FeedError(f"{source} returned a non-text CVSS vector")
    if len(value) > MAX_CVSS_VECTOR_CHARS:
        raise FeedError(f"{source} returned a CVSS vector outside the configured character bound")
    if version == "2.0":
        if not CVSS2_VECTOR_RE.fullmatch(value):
            raise FeedError(f"{source} returned an unsupported CVSS 2.0 vector")
        return value
    if not CVSS_VECTOR_RE.fullmatch(value):
        raise FeedError(f"{source} returned an unsupported CVSS vector")
    if value.split("/", 1)[0] != f"CVSS:{version}":
        raise FeedError(f"{source} returned a CVSS vector with mismatched version evidence")
    return value


def _cvss_evidence(cve: dict[str, Any]) -> tuple[float | None, str, str, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            metric = values[0] if isinstance(values[0], dict) else {}
            data = metric.get("cvssData") or {}
            value = data.get("baseScore")
            if value is not None:
                try:
                    score = float(value)
                except (TypeError, ValueError):
                    raise FeedError("NVD returned a non-numeric CVSS base score")
                if not math.isfinite(score) or not 0 <= score <= 10:
                    raise FeedError("NVD returned an out-of-range CVSS base score")
                version = str(data.get("version") or {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1",
                                                       "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}[key])
                vector = _checked_cvss_vector(data.get("vectorString"), version, "NVD")
                return score, version, vector, "NVD"
    return None, "", "", ""


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
            if criteria.lower().startswith("cpe:2.3:") and len(parts) == 13:
                entry["cpe"] = criteria
            identity = (entry["vendor"].lower(), entry["product"].lower(), entry["versions"].lower(), entry.get("cpe", "").lower())
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
        "cvss_version": "",
        "cvss_vector": "",
        "cvss_source": "",
        "sev": "unknown",
        "published": published,
        "modified": None,
        "window_date": None,
        "activity_at": None,
        "date_basis": None,
        "affected": [],
        "refs": [],
        "related_cves": [],
        "advisories": [],
        "sources": [],
        "kev": None,
        "primary_url": f"https://www.cve.org/CVERecord?id={cve_id}",
    }


def _add_source(record: dict[str, Any], source: str) -> None:
    if source not in record["sources"]:
        record["sources"].append(source)


def _add_affected(record: dict[str, Any], entry: dict[str, str]) -> None:
    identity = tuple(str(entry.get(key, "")).casefold() for key in ("vendor", "product", "versions", "cpe"))
    if not any(tuple(str(existing.get(key, "")).casefold() for key in ("vendor", "product", "versions", "cpe")) == identity for existing in record["affected"]):
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

    def add_ref(record: dict[str, Any], label: str, url: Any, source: str, tags: Any = None) -> None:
        known = {item["url"] for item in record["refs"]}
        _add_ref(record["refs"], known, label, url, source, tags)

    for item in nvd_items:
        cve = item.get("cve", item)
        cve_id = _cve_id(cve.get("id"))
        if not cve_id or str(cve.get("vulnStatus", "")).lower() == "rejected":
            continue
        published = normalize_source_timestamp(cve.get("published"), f"NVD publication timestamp for {cve_id}")
        published_dt = parse_datetime(published)
        if not published_dt:
            raise FeedError(f"NVD returned an invalid publication timestamp for {cve_id}")
        modified = normalize_source_timestamp(cve.get("lastModified"), f"NVD lastModified timestamp for {cve_id}")
        modified_dt = parse_datetime(modified)
        candidates = []
        if start <= published_dt <= end:
            candidates.append((published_dt, published, "CVE publication"))
        if modified_dt and start <= modified_dt <= end:
            candidates.append((modified_dt, modified, "NVD last modified"))
        if not candidates:
            raise FeedError(f"NVD returned a CVE outside the requested publication/modified window: {cve_id}")
        activity_dt, activity_at, date_basis = max(candidates, key=lambda item: item[0])
        record = records.setdefault(cve_id, _record(cve_id, published))
        description = _description(cve.get("descriptions"))
        score, cvss_version, cvss_vector, cvss_source = _cvss_evidence(cve)
        record.update({
            "title": _title(description, cve_id),
            "desc": description or "No English summary is available in the source record.",
            "score": score,
            "cvss_version": cvss_version,
            "cvss_vector": cvss_vector,
            "cvss_source": cvss_source,
            "sev": severity_for(score),
            "published": published,
            "modified": modified,
            "window_date": activity_dt.date().isoformat(),
            "activity_at": activity_at,
            "date_basis": date_basis,
            "primary_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
        _add_source(record, "NVD")
        add_ref(record, "NVD record", f"https://nvd.nist.gov/vuln/detail/{cve_id}", "NVD")
        add_ref(record, "CVE Program record", f"https://www.cve.org/CVERecord?id={cve_id}", "CVE Program")
        for reference in cve.get("references") or []:
            if isinstance(reference, dict):
                ref_url = _safe_url(reference.get("url"))
                add_ref(record, "Reference", ref_url, "NVD", reference.get("tags"))
                if ref_url:
                    parsed = urllib.parse.urlsplit(ref_url)
                    target = None
                    if parsed.hostname == "nvd.nist.gov":
                        match = re.fullmatch(r"/vuln/detail/(CVE-\d{4,}-\d+)", parsed.path, re.I)
                        target = match.group(1) if match else None
                    elif parsed.hostname in {"cve.org", "www.cve.org"} and parsed.path.rstrip("/") == "/CVERecord":
                        target = urllib.parse.parse_qs(parsed.query).get("id", [None])[0]
                    linked_id = _cve_id(target)
                    if linked_id and linked_id != cve_id and not any(item["id"] == linked_id for item in record["related_cves"]):
                        record["related_cves"].append({"id": linked_id, "url": ref_url, "source": "NVD reference"})
        for product in _nvd_affected(cve):
            _add_affected(record, product)

    for advisory in advisories:
        cve_id = _cve_id(advisory.get("cve_id"))
        if not cve_id:
            continue
        published = normalize_source_timestamp(advisory.get("published_at"), "GitHub advisory publication timestamp")
        published_dt = parse_datetime(published)
        if not published_dt:
            raise FeedError("GitHub returned an advisory with an invalid publication timestamp")
        updated = normalize_source_timestamp(advisory.get("updated_at") or published, "GitHub advisory updated timestamp")
        updated_dt = parse_datetime(updated)
        nvd_published = normalize_source_timestamp(advisory.get("nvd_published_at"), "GitHub advisory NVD publication timestamp")
        candidates = []
        if start <= published_dt <= end:
            candidates.append((published_dt, published, "GitHub advisory publication"))
        if updated_dt and start <= updated_dt <= end:
            candidates.append((updated_dt, updated, "GitHub advisory updated"))
        nvd_publication_dt = parse_datetime(nvd_published)
        if nvd_publication_dt and start <= nvd_publication_dt <= end:
            candidates.append((nvd_publication_dt, nvd_published, "CVE publication"))
        if not candidates:
            continue
        ghsa_activity_dt, ghsa_activity_at, ghsa_date_basis = max(candidates, key=lambda item: item[0])
        record = records.setdefault(cve_id, _record(cve_id, nvd_published or published))
        if not record["published"]:
            record["published"] = nvd_published or published
        current_activity = parse_datetime(record.get("activity_at"))
        if current_activity is None or ghsa_activity_dt > current_activity:
            record["activity_at"] = ghsa_activity_at
            record["window_date"] = ghsa_activity_dt.date().isoformat()
            record["date_basis"] = ghsa_date_basis
        if not record.get("modified") and updated:
            record["modified"] = updated
        summary = str(advisory.get("summary") or "").strip()
        description = str(advisory.get("description") or "").strip() or summary
        if not record["desc"] and description:
            record["desc"] = description
            record["title"] = _title(summary or description, cve_id)
        cvss = advisory.get("cvss_severities") or {}
        scores: list[tuple[float, str, str]] = []
        if not isinstance(cvss, dict):
            raise FeedError("GitHub returned malformed CVSS severity metadata")
        for key in ("cvss_v4", "cvss_v3"):
            details = cvss.get(key) or {}
            if not isinstance(details, dict):
                raise FeedError("GitHub returned malformed CVSS severity metadata")
            value = details.get("score")
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise FeedError("GitHub returned a non-numeric CVSS base score")
            score_value = float(value)
            if not math.isfinite(score_value) or not 0 <= score_value <= 10:
                raise FeedError("GitHub returned an out-of-range CVSS base score")
            version = "4.0" if key == "cvss_v4" else "3.1"
            vector = _checked_cvss_vector(details.get("vector_string"), version, "GitHub")
            scores.append((score_value, version, vector))
        if record["score"] is None and scores:
            record["score"], record["cvss_version"], record["cvss_vector"] = max(scores, key=lambda item: item[0])
            record["cvss_source"] = "GitHub Advisory Database"
            record["sev"] = severity_for(record["score"])
        _add_source(record, "GitHub Advisory Database")
        html_url = advisory.get("html_url") or advisory.get("url")
        if _safe_url(html_url) and not any(item["url"] == html_url for item in record["advisories"]):
            record["advisories"].append({"label": "GitHub Security Advisory", "url": html_url,
                                          "published_at": published, "updated_at": updated})
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
            if added_day.isoformat() != date_added:
                raise ValueError
        except ValueError as exc:
            raise FeedError("CISA returned an invalid KEV dateAdded value") from exc
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
        record["related_cves"].sort(key=lambda item: item["id"])
        record["advisories"] = record["advisories"][:6]
        record["sources"].sort(key=lambda source: {"NVD": 0, "GitHub Advisory Database": 1, "CISA KEV": 2}.get(source, 9))
    return sorted(records.values(), key=lambda record: (record.get("window_date") or "", record["id"]), reverse=True)


def _json_bytes(value: Any) -> bytes:
    """Serialize the exact compact UTF-8 JSON bytes published to the static feed."""
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _gzip_bytes(raw: bytes) -> bytes:
    """Return deterministic gzip bytes without wall-clock or platform header variance."""
    compressed = bytearray(gzip.compress(raw, compresslevel=9, mtime=0))
    if len(compressed) >= 10 and compressed[:3] == b"\x1f\x8b\x08":
        compressed[9] = 255
    return bytes(compressed)


OVERVIEW_SCHEMA_VERSION = 3
SEARCH_INDEX_SCHEMA_VERSION = 3
LATEST_PREVIEW_LIMIT = 50
INDEX_SEVERITIES = ("critical", "high", "medium", "low", "none", "unknown")
INDEX_DATE_BASES = ("CVE publication", "GitHub advisory publication", "NVD last modified",
                    "GitHub advisory updated", "CISA KEV date added")
INDEX_SOURCE_BITS = {"NVD": 1, "GitHub Advisory Database": 2, "CISA KEV": 4}


def build_overview(
    records: list[dict[str, Any]],
    generated_at: datetime,
    epss_snapshot: dict[str, Any] | None = None,
    history: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a bounded Overview index and a small, observed-only recent-change preview."""
    def order(record: dict[str, Any]) -> tuple[datetime, str]:
        stamp = parse_datetime(record.get("activity_at"))
        if stamp is None:
            raise FeedError(f"Record {record.get('id', 'unknown')} has no valid activity timestamp")
        return stamp, str(record.get("id") or "")

    score_map = (epss_snapshot or {}).get("scores") or {}
    if not isinstance(score_map, dict):
        raise FeedError("EPSS scores must be an object when building the Overview index")
    summary_fields = ("id", "title", "sev", "score", "window_date", "activity_at", "date_basis", "sources")
    latest = sorted(records, key=order, reverse=True)[:LATEST_PREVIEW_LIMIT]
    summaries = []
    for record in latest:
        summary = {key: record[key] for key in summary_fields}
        kev = record.get("kev")
        summary["kev_date_added"] = kev.get("date_added") if isinstance(kev, dict) else None
        epss_value = score_map.get(record["id"])
        if epss_value is not None and (not isinstance(epss_value, dict) or set(epss_value) != {"score", "percentile"}):
            raise FeedError(f"EPSS value for {record['id']} is malformed while building the Overview index")
        summary["epss"] = dict(epss_value) if epss_value is not None else None
        summaries.append(summary)
    record_by_id = {str(record.get("id") or ""): record for record in records}
    priority = {"NEW_CVE": 0, "CVE_REOBSERVED": 1, "KEV_ADDED": 2, "KEV_CHANGED": 2,
                "KEV_REMOVED": 2, "CVSS_CHANGED": 3, "EPSS_CHANGED": 4,
                "AFFECTED_PRODUCTS_CHANGED": 5, "VERSION_RANGE_CHANGED": 5,
                "DESCRIPTION_CHANGED": 6, "TITLE_CHANGED": 6, "ADVISORY_ADDED": 7,
                "REFERENCE_ADDED": 8}
    eligible = [event for event in (history or {}).get("events", [])
                if isinstance(event, dict) and event.get("id") in record_by_id and event.get("type") in priority]
    eligible.sort(key=lambda event: (parse_datetime(str(event.get("observed_at") or "")) or datetime.min.replace(tzinfo=timezone.utc),
                                     -priority.get(str(event.get("type")), 99), str(event.get("id") or "")), reverse=True)
    recent_changes = []
    seen_changed_ids: set[str] = set()
    for event in eligible:
        cve_id = str(event.get("id") or "")
        if cve_id in seen_changed_ids:
            continue
        record = record_by_id[cve_id]
        recent_changes.append({
            "id": cve_id, "title": str(record.get("title") or cve_id), "type": event["type"],
            "observed_at": event["observed_at"], "source_time": event.get("source_time"),
            "source": str(event.get("source") or "Verified source comparison"),
        })
        seen_changed_ids.add(cve_id)
        if len(recent_changes) == 5:
            break
    return {
        "schema_version": OVERVIEW_SCHEMA_VERSION,
        "generated_at": iso_z(generated_at),
        "records": summaries,
        "recent_changes": recent_changes,
    }


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
        shard_bytes = _json_bytes(items)
        fingerprint = hashlib.sha256(shard_bytes).hexdigest()
        day_summaries.append({
            "date": key,
            "count": len(items),
            "bytes": len(shard_bytes),
            "sha256": fingerprint,
            "critical": sum(item["sev"] == "critical" for item in items),
            "high": sum(item["sev"] == "high" for item in items),
            "medium": sum(item["sev"] == "medium" for item in items),
            "low": sum(item["sev"] == "low" for item in items),
            "none": sum(item["sev"] == "none" for item in items),
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
            "semantics": "NVD CVE publication or last-modified timestamps; GitHub advisory publication or updated timestamps; plus CISA KEV date-added entries in the window",
        },
        "complete": True,
        "totals": {
            "cves": sharded_total,
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "none": severity_counts["none"],
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


def _load_epss_cache(output_dir: Path) -> dict[str, Any] | None:
    path = output_dir / "data" / "epss.json"
    try:
        if output_dir.is_symlink() or path.parent.is_symlink() or path.is_symlink():
            return None
        if path.stat().st_size > MAX_EPSS_CACHE_BYTES:
            return None
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        if value.get("schema_version") == 1 and isinstance(value.get("scores"), dict):
            return value
    except (OSError, json.JSONDecodeError, UnicodeError, AttributeError, FeedError):
        pass
    return None


def build_epss_snapshot(
    records: list[dict[str, Any]],
    output_dir: Path,
    as_of: datetime,
    csv_loader: Callable[[set[str] | None], tuple[dict[str, dict[str, float]], str, str]] = fetch_epss_csv,
    api_request_fn: Callable[..., tuple[Any, Any]] = request_json,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build an optional EPSS score sidecar; core CVE coverage never depends on it."""
    ids = {_cve_id(record.get("id")) for record in records}
    ids.discard(None)
    cache = _load_epss_cache(output_dir)
    cached_scores: dict[str, dict[str, float]] = {}
    if cache:
        for cve_id, value in cache["scores"].items():
            valid_id = _cve_id(cve_id)
            if valid_id not in ids or not isinstance(value, dict):
                continue
            if isinstance(value.get("score"), bool) or isinstance(value.get("percentile"), bool):
                continue
            try:
                score, percentile = float(value["score"]), float(value["percentile"])
            except (KeyError, TypeError, ValueError):
                continue
            if math.isfinite(score) and math.isfinite(percentile) and 0 <= score <= 1 and 0 <= percentile <= 1:
                cached_scores[valid_id] = {"score": score, "percentile": percentile}

    now_text = iso_z(as_of)
    checked = parse_datetime(str(cache.get("checked_at") or "")) if cache else None
    cache_age = as_of - checked if checked else None
    reuse_cache = bool(cache and cache_age is not None and timedelta(0) <= cache_age < timedelta(hours=8))
    scores: dict[str, dict[str, float]]
    score_date = str(cache.get("score_date") or "") if cache else ""
    source_updated_at = str(cache.get("source_updated_at") or "") if cache else ""
    error = str(cache.get("error") or "") if cache else ""
    reused = False

    if reuse_cache:
        scores = cached_scores
        reused = True
    else:
        try:
            downloaded_scores, score_date, source_updated_at = csv_loader(ids)
            if not isinstance(score_date, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", score_date):
                raise FeedError("FIRST EPSS returned an invalid score_date")
            if date.fromisoformat(score_date).isoformat() != score_date:
                raise FeedError("FIRST EPSS returned a non-canonical score_date")
            source_time = parse_datetime(source_updated_at)
            if source_time is None or source_time.date().isoformat() != score_date or not re.search(r"(?:Z|[+-]\d{2}:\d{2})$", source_updated_at):
                raise FeedError("FIRST EPSS returned invalid or mismatched score timestamps")
            if not isinstance(downloaded_scores, dict):
                raise FeedError("FIRST EPSS returned an invalid score map")
            scores = {}
            for raw_id, value in downloaded_scores.items():
                cve_id = _cve_id(raw_id)
                if not isinstance(raw_id, str) or cve_id != raw_id or cve_id not in ids:
                    raise FeedError("FIRST EPSS returned a score for an unexpected CVE")
                if not isinstance(value, dict) or set(value) != {"score", "percentile"}:
                    raise FeedError(f"FIRST EPSS returned a malformed score for {cve_id}")
                if isinstance(value["score"], bool) or isinstance(value["percentile"], bool):
                    raise FeedError(f"FIRST EPSS returned a non-numeric score for {cve_id}")
                try:
                    score, percentile = float(value["score"]), float(value["percentile"])
                except (TypeError, ValueError) as exc:
                    raise FeedError(f"FIRST EPSS returned a non-numeric score for {cve_id}") from exc
                if not math.isfinite(score) or not math.isfinite(percentile) or not 0 <= score <= 1 or not 0 <= percentile <= 1:
                    raise FeedError(f"FIRST EPSS returned an out-of-range score for {cve_id}")
                scores[cve_id] = {"score": score, "percentile": percentile}
            error = ""
        except Exception as exc:
            scores = cached_scores
            error = f"Latest FIRST EPSS download failed; retaining prior scores where available ({str(exc)[:140]})."

    if reused:
        missing = ids - set(scores)
        if missing:
            try:
                scores.update(fetch_epss_api(missing, api_request_fn))
            except Exception as exc:
                error = f"Could not look up {len(missing)} newly surfaced CVEs in FIRST EPSS ({str(exc)[:140]})."

    source_time = parse_datetime(source_updated_at)
    age = as_of - source_time if source_time else None
    fresh = age is not None and timedelta(0) <= age <= timedelta(hours=36)
    if not score_date:
        error = error or "No dated FIRST EPSS score set is available."
    elif not fresh:
        error = error or "The latest FIRST EPSS score set is older than 36 hours or has an invalid timestamp."
    status = {
        "name": EPSS_SOURCE["name"],
        "ok": bool(fresh and not error),
        "scores": len(scores),
        "records": len(ids),
        "score_date": score_date,
        "source_updated_at": source_updated_at,
        "checked_at": now_text,
        "note": error,
    }
    snapshot = {
        "schema_version": 1,
        "updated_at": now_text,
        "checked_at": now_text,
        "score_date": score_date,
        "source_updated_at": source_updated_at,
        "error": error,
        "scores": {cve_id: scores[cve_id] for cve_id in sorted(ids) if cve_id in scores},
    }
    return snapshot, status


def add_epss_metadata(manifest: dict[str, Any], snapshot: dict[str, Any], status: dict[str, Any]) -> None:
    """Attach optional EPSS provenance without changing the three core-feed success contract."""
    manifest["epss"] = {
        "path": "data/epss.json",
        "score_date": snapshot.get("score_date") or "",
        "source_updated_at": snapshot.get("source_updated_at") or "",
        "updated_at": snapshot.get("updated_at") or "",
        "scored_cves": len(snapshot.get("scores") or {}),
        "records": int(status.get("records") or 0),
    }
    sources = manifest.setdefault("sources", [])
    if not any(source.get("name") == EPSS_SOURCE["name"] for source in sources):
        sources.append(EPSS_SOURCE)
    statuses = manifest.setdefault("source_status", [])
    statuses[:] = [item for item in statuses if item.get("name") != EPSS_SOURCE["name"]]
    statuses.append(status)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def _load_snapshot_records(output_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for summary in manifest.get("days") or []:
        day = str(summary.get("date") or "")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
            raise FeedError("Retained snapshot contains an invalid day shard name")
        payload = json.loads((output_dir / f"{day}.json").read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise FeedError(f"Invalid retained feed shard for {day}")
        records.extend(item for item in payload if isinstance(item, dict) and _cve_id(item.get("id")))
    return records


def _canonical_change(value: Any) -> Any:
    """Normalize JSON values for semantic comparison without inventing meaning."""
    if isinstance(value, dict):
        return {key: _canonical_change(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        normalized = [_canonical_change(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    if isinstance(value, str):
        return " ".join(value.split())
    return value


def _event_value(value: Any, limit: int = 2_048) -> Any:
    """Keep event payloads bounded while retaining exact values when practical."""
    value = _canonical_change(value)
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return value if len(raw) <= limit else {"truncated": True, "preview": raw[:limit]}


def _normalize_kev_catalog(items: list[dict[str, Any]] | None) -> list[dict[str, str]] | None:
    if items is None:
        return None
    if not isinstance(items, list) or len(items) > 5_000:
        raise FeedError("CISA KEV history baseline is malformed or exceeds 5,000 entries")
    keys = {
        "cveID": 32, "dateAdded": 10, "vendorProject": 256, "product": 256,
        "vulnerabilityName": 512, "shortDescription": 4_096, "requiredAction": 2_048,
        "dueDate": 10, "knownRansomwareCampaignUse": 64, "notes": 1_024,
    }
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise FeedError("CISA KEV history contains a malformed catalog row")
        cve_id = _cve_id(item.get("cveID"))
        if not cve_id or cve_id in seen:
            raise FeedError("CISA KEV history contains an invalid or duplicate CVE ID")
        try:
            added = date.fromisoformat(str(item.get("dateAdded") or ""))
        except ValueError as exc:
            raise FeedError("CISA KEV history contains an invalid dateAdded value") from exc
        if added.isoformat() != item.get("dateAdded"):
            raise FeedError("CISA KEV history dateAdded value is not canonical")
        row: dict[str, str] = {}
        for key, limit in keys.items():
            value = cve_id if key == "cveID" else str(item.get(key) or "")
            if any(ord(char) < 32 and char not in "\t\n\r" for char in value) or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                raise FeedError(f"CISA KEV history {key} contains control or surrogate characters")
            row[key] = value[:limit]
        seen.add(cve_id)
        result.append(row)
    result.sort(key=lambda row: row["cveID"])
    if len(_json_bytes(result)) > 4 * 1024 * 1024:
        raise FeedError("CISA KEV history baseline exceeds its 4 MiB safety limit")
    return result


def _record_source_label(*records: dict[str, Any]) -> str:
    order = ("NVD", "GitHub Advisory Database", "CISA KEV")
    labels = {label for record in records for label in (record.get("sources") or []) if label in order}
    return " + ".join(label for label in order if label in labels) or "Verified source comparison"


def material_change_events(
    previous_records: list[dict[str, Any]],
    current_records: list[dict[str, Any]],
    previous_epss: dict[str, Any] | None,
    current_epss: dict[str, Any] | None,
    observed_at: datetime,
    previous_core_snapshot_at: datetime | None = None,
    previous_kev_catalog: list[dict[str, Any]] | None = None,
    current_kev_catalog: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Create source-backed diffs; rolling-window absence is never treated as deletion."""
    old_by_id = {_cve_id(item.get("id")): item for item in previous_records if _cve_id(item.get("id"))}
    new_by_id = {_cve_id(item.get("id")): item for item in current_records if _cve_id(item.get("id"))}
    old_scores = (previous_epss or {}).get("scores") or {}
    new_scores = (current_epss or {}).get("scores") or {}
    observed = iso_z(observed_at)
    events: list[dict[str, Any]] = []

    def emit(cve_id: str, kind: str, before: Any, after: Any, source_time: str | None, source: str) -> None:
        events.append({
            "id": cve_id, "type": kind, "observed_at": observed,
            "source_time": source_time or None, "source": source,
            "from": _event_value(before), "to": _event_value(after),
        })

    for cve_id in sorted(new_by_id.keys() - old_by_id.keys()):
        record = new_by_id[cve_id]
        published = parse_datetime(str(record.get("published") or ""))
        activity = parse_datetime(str(record.get("activity_at") or ""))
        source_time = record.get("activity_at") if isinstance(record.get("activity_at"), str) else None
        source_label = _record_source_label(record)
        if previous_core_snapshot_at and published and published > previous_core_snapshot_at:
            emit(cve_id, "NEW_CVE", None, {"title": record.get("title"), "published": record.get("published")},
                 record.get("published"), source_label)
        elif (previous_core_snapshot_at and activity and activity > previous_core_snapshot_at and
              record.get("date_basis") in {"NVD last modified", "GitHub advisory updated"}):
            emit(cve_id, "CVE_REOBSERVED", {"previous_window": "outside the retained 30-day feed"},
                 {"title": record.get("title"), "activity_at": source_time,
                  "date_basis": record.get("date_basis"),
                  "note": "A source reports recent activity; the prior full record is outside the retained feed window, so individual field differences cannot be reconstructed."},
                 source_time, source_label)

    fields = (
        ("desc", "DESCRIPTION_CHANGED"), ("title", "TITLE_CHANGED"),
        ("affected", "AFFECTED_PRODUCTS_CHANGED"),
        ("sources", "SOURCE_METADATA_CHANGED"), ("published", "SOURCE_METADATA_CHANGED"),
        ("modified", "SOURCE_METADATA_CHANGED"), ("date_basis", "SOURCE_METADATA_CHANGED"),
    )
    for cve_id in sorted(old_by_id.keys() & new_by_id.keys()):
        old, new = old_by_id[cve_id], new_by_id[cve_id]
        record_events = 0
        source_time = new.get("modified") if isinstance(new.get("modified"), str) else None
        source_label = _record_source_label(old, new)
        cvss_fields = ("score", "cvss_version", "cvss_vector", "cvss_source")
        old_cvss = {field: old.get(field) for field in cvss_fields}
        new_cvss = {field: new.get(field) for field in cvss_fields}
        if _canonical_change(old_cvss) != _canonical_change(new_cvss):
            emit(cve_id, "CVSS_CHANGED", old_cvss, new_cvss, source_time, source_label)
            record_events += 1
        for field, kind in fields:
            before, after = old.get(field), new.get(field)
            if _canonical_change(before) != _canonical_change(after):
                emit(cve_id, kind, before, after, source_time, source_label)
                record_events += 1
        old_affected = old.get("affected") if isinstance(old.get("affected"), list) else []
        new_affected = new.get("affected") if isinstance(new.get("affected"), list) else []
        old_products = {(str(item.get("vendor") or "").casefold(), str(item.get("product") or "").casefold()): item
                        for item in old_affected if isinstance(item, dict)}
        new_products = {(str(item.get("vendor") or "").casefold(), str(item.get("product") or "").casefold()): item
                        for item in new_affected if isinstance(item, dict)}
        if any(_canonical_change(old_products[key].get("versions")) != _canonical_change(new_products[key].get("versions"))
               for key in old_products.keys() & new_products.keys()):
            emit(cve_id, "VERSION_RANGE_CHANGED", old_affected, new_affected, source_time, source_label)
            record_events += 1

        for field, added_type, removed_type in (("refs", "REFERENCE_ADDED", "REFERENCE_REMOVED"),
                                                ("advisories", "ADVISORY_ADDED", "ADVISORY_REMOVED")):
            before_rows = old.get(field) if isinstance(old.get(field), list) else []
            after_rows = new.get(field) if isinstance(new.get(field), list) else []
            before_by_key = {json.dumps(_canonical_change(item), ensure_ascii=False, sort_keys=True, separators=(",", ":")): item for item in before_rows}
            after_by_key = {json.dumps(_canonical_change(item), ensure_ascii=False, sort_keys=True, separators=(",", ":")): item for item in after_rows}
            for key in sorted(after_by_key.keys() - before_by_key.keys()):
                changed = after_by_key[key]
                source = str(changed.get("source") or ("GitHub Advisory Database" if field == "advisories" else source_label))
                emit(cve_id, added_type, None, changed, source_time, source)
                record_events += 1
            for key in sorted(before_by_key.keys() - after_by_key.keys()):
                changed = before_by_key[key]
                source = str(changed.get("source") or ("GitHub Advisory Database" if field == "advisories" else source_label))
                emit(cve_id, removed_type, changed, None, source_time, source)
                record_events += 1

        old_kev, new_kev = old.get("kev"), new.get("kev")
        # Before a full catalog baseline exists, overlapping CVE records can reveal a
        # KEV change. Afterwards the complete catalog comparison is authoritative.
        if previous_kev_catalog is None and _canonical_change(old_kev) != _canonical_change(new_kev):
            kind = "KEV_ADDED" if old_kev is None and new_kev is not None else "KEV_REMOVED" if new_kev is None else "KEV_CHANGED"
            kev_time = new_kev.get("date_added") if isinstance(new_kev, dict) else source_time
            emit(cve_id, kind, old_kev, new_kev, kev_time or source_time, "CISA KEV catalog")
            record_events += 1

        try:
            before = float(old_scores[cve_id]["score"])
        except (KeyError, TypeError, ValueError):
            before = float("nan")
        try:
            after = float(new_scores[cve_id]["score"])
        except (KeyError, TypeError, ValueError):
            after = float("nan")
        if math.isfinite(after) and 0 <= after <= 1 and (not math.isfinite(before) or not 0 <= before <= 1):
            emit(cve_id, "EPSS_CHANGED", None, after, str((current_epss or {}).get("source_updated_at") or "") or None, "FIRST EPSS")
            record_events += 1
        elif math.isfinite(before) and 0 <= before <= 1 and not (math.isfinite(after) and 0 <= after <= 1):
            emit(cve_id, "EPSS_CHANGED", before, None,
                 str((current_epss or {}).get("source_updated_at") or "") or None, "FIRST EPSS")
            record_events += 1
        elif math.isfinite(before) and math.isfinite(after) and 0 <= before <= 1 and 0 <= after <= 1 and before != after:
            # Keep history meaningful: only record changes of >=1 percentage point or a
            # 2x move once the score reaches 5%; the raw daily score set remains available.
            absolute_jump = abs(after - before) >= 0.01
            relative_jump = min(before, after) > 0 and max(before, after) >= 0.05 and max(before, after) / min(before, after) >= 2
            if absolute_jump or relative_jump:
                emit(cve_id, "EPSS_CHANGED", before, after,
                     str((current_epss or {}).get("source_updated_at") or "") or None, "FIRST EPSS")
                record_events += 1
        if record_events:
            emit(cve_id, "CVE_UPDATED", None, {"changes": record_events}, source_time, source_label)

    if previous_kev_catalog is not None and current_kev_catalog is not None:
        old_kev = {_cve_id(item.get("cveID")): item for item in previous_kev_catalog
                   if isinstance(item, dict) and _cve_id(item.get("cveID"))}
        new_kev = {_cve_id(item.get("cveID")): item for item in current_kev_catalog
                   if isinstance(item, dict) and _cve_id(item.get("cveID"))}
        for cve_id in sorted(new_kev.keys() - old_kev.keys()):
            emit(cve_id, "KEV_ADDED", None, new_kev[cve_id], None, "CISA KEV catalog")
        for cve_id in sorted(old_kev.keys() - new_kev.keys()):
            emit(cve_id, "KEV_REMOVED", old_kev[cve_id], None, None, "CISA KEV catalog")
        for cve_id in sorted(old_kev.keys() & new_kev.keys()):
            if _canonical_change(old_kev[cve_id]) != _canonical_change(new_kev[cve_id]):
                emit(cve_id, "KEV_CHANGED", old_kev[cve_id], new_kev[cve_id], None, "CISA KEV catalog")

    # Never infer CVE deletion from omission in the rolling publication/modified window.
    return events


def build_change_history(
    output_dir: Path,
    current_records: list[dict[str, Any]],
    current_epss: dict[str, Any],
    current_manifest: dict[str, Any],
    observed_at: datetime,
    current_kev_catalog: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Append only observed comparisons between complete captures; retain a bounded 30-day window."""
    history_path = output_dir / "data" / "history.json"
    try:
        history = json.loads(history_path.read_text(encoding="utf-8"))
        if not isinstance(history, dict) or history.get("schema_version") != 1 or history.get("retention_days") != 30 or not isinstance(history.get("snapshots"), list) or not isinstance(history.get("events"), list):
            raise FeedError("Retained history file has an unsupported schema; refusing to replace it")
    except FileNotFoundError:
        history = {"schema_version": 1, "retention_days": 30, "baseline": None, "snapshots": [], "events": []}
    except json.JSONDecodeError as exc:
        raise FeedError("Retained history JSON is invalid; refusing to discard it") from exc

    previous_manifest = None
    previous_records: list[dict[str, Any]] = []
    if "kev_catalog" in history and not isinstance(history.get("kev_catalog"), list):
        raise FeedError("Retained CISA KEV history baseline is malformed; refusing to discard it")
    previous_kev_catalog = _normalize_kev_catalog(history.get("kev_catalog"))
    current_kev_catalog = _normalize_kev_catalog(current_kev_catalog)
    previous_epss: dict[str, Any] = {}
    try:
        previous_manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
        if previous_manifest.get("complete") is True:
            previous_records = _load_snapshot_records(output_dir / "data", previous_manifest)
            previous_epss = json.loads((output_dir / "data" / "epss.json").read_text(encoding="utf-8"))
        else:
            previous_manifest = None
    except (FileNotFoundError, json.JSONDecodeError, TypeError, AttributeError, FeedError):
        previous_manifest, previous_records, previous_epss = None, [], {}

    retention_start = observed_at - timedelta(days=30)
    snapshots = [item for item in history["snapshots"] if isinstance(item, dict) and parse_datetime(str(item.get("observed_at") or "")) and parse_datetime(str(item["observed_at"])) >= retention_start]
    events = [item for item in history["events"] if isinstance(item, dict) and parse_datetime(str(item.get("observed_at") or "")) and parse_datetime(str(item["observed_at"])) >= retention_start]
    if previous_manifest is not None:
        old_at = str(previous_manifest.get("generated_at") or "")
        if old_at and not history.get("baseline"):
            # The published capture time is known, but an observation time for this
            # legacy baseline is not; preserve only the timestamp the source recorded.
            history["baseline"] = {"core_snapshot_at": old_at,
                                   "epss_score_date": str((previous_epss or {}).get("score_date") or ""),
                                   "record_count": len(previous_records), "complete": True}
        events.extend(material_change_events(previous_records, current_records, previous_epss, current_epss,
                                             observed_at, parse_datetime(str(previous_manifest.get("generated_at") or "")),
                                             previous_kev_catalog, current_kev_catalog))

    core_at = str(current_manifest.get("generated_at") or iso_z(observed_at))
    snapshot = {"observed_at": iso_z(observed_at), "core_snapshot_at": core_at,
                "epss_score_date": str(current_epss.get("score_date") or ""),
                "record_count": len(current_records), "complete": current_manifest.get("complete") is True}
    if not any(item.get("observed_at") == snapshot["observed_at"] and item.get("core_snapshot_at") == core_at for item in snapshots):
        snapshots.append(snapshot)
    snapshots.sort(key=lambda item: str(item.get("observed_at") or ""))
    events.sort(key=lambda item: (str(item.get("observed_at") or ""), str(item.get("id") or ""), str(item.get("type") or "")))
    result = {"schema_version": 1, "retention_days": 30, "baseline": history.get("baseline"),
              "snapshots": snapshots[-800:], "events": events[-10_000:]}
    if current_kev_catalog is not None:
        result["kev_catalog"] = current_kev_catalog
    elif previous_kev_catalog is not None:
        result["kev_catalog"] = previous_kev_catalog
    return result


def build_search_index(records: list[dict[str, Any]], epss_snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    """Pack only list/search fields; full CVSS, EPSS, KEV and reference evidence stays in sidecars."""
    del epss_snapshot  # EPSS is stored once in its independently verified sidecar.
    rows = []
    for record in sorted(records, key=lambda item: (str(item.get("activity_at") or ""), str(item.get("id") or "")), reverse=True):
        affected = record.get("affected") if isinstance(record.get("affected"), list) else []
        # Preserve all bounded vendor/product labels and a short version hint for up to three products.
        compact_affected: list[list[str]] = []
        for index, item in enumerate(affected[:8]):
            if not isinstance(item, dict):
                continue
            vendor = item.get("vendor", "") if isinstance(item.get("vendor", ""), str) else ""
            product = item.get("product", "") if isinstance(item.get("product", ""), str) else ""
            version_hint = ""
            if index < 3 and isinstance(item.get("versions"), str):
                version_hint = " ".join(item["versions"].split())[:160]
            if vendor or product:
                compact_affected.append([vendor, product, version_hint])
        advisory_ids = []
        for advisory in (record.get("advisories") or []):
            if not isinstance(advisory, dict) or not isinstance(advisory.get("url"), str):
                continue
            parsed_url = urllib.parse.urlsplit(advisory["url"])
            candidate_id = parsed_url.path.rstrip("/").rsplit("/", 1)[-1]
            if parsed_url.scheme == "https" and parsed_url.netloc.lower() == "github.com" and GHSA_RE.fullmatch(candidate_id):
                advisory_ids.append(candidate_id.upper())
        advisory_ids = list(dict.fromkeys(advisory_ids))[:8]
        if record["sev"] not in INDEX_SEVERITIES or record["date_basis"] not in INDEX_DATE_BASES:
            raise FeedError(f"Cannot encode unknown severity or date basis for {record.get('id')}")
        severity_code = INDEX_SEVERITIES.index(record["sev"])
        date_basis_code = INDEX_DATE_BASES.index(record["date_basis"])
        source_mask = sum(bit for source, bit in INDEX_SOURCE_BITS.items() if source in record["sources"])
        rows.append([
            record["id"], record["title"], " ".join(str(record.get("desc") or "").split())[:320],
            record.get("score"), severity_code, isinstance(record.get("kev"), dict),
            record["activity_at"], date_basis_code, source_mask, compact_affected, advisory_ids,
        ])
    return {"schema_version": SEARCH_INDEX_SCHEMA_VERSION, "generated_at": records[0].get("activity_at") if records else "", "records": rows}

def _commit_snapshot(staged_root: Path, output_dir: Path) -> None:
    """Swap a fully validated sibling directory into place and restore on failure."""
    backup = output_dir.with_name(f".{output_dir.name}.backup-{os.getpid()}-{time.time_ns()}")
    had_previous = output_dir.exists()
    if had_previous and (output_dir.is_symlink() or not output_dir.is_dir()):
        raise FeedError("Refusing to replace a non-directory or symlink snapshot root")
    if had_previous:
        os.replace(output_dir, backup)
    try:
        os.replace(staged_root, output_dir)
    except BaseException as swap_error:
        if had_previous and backup.exists() and not output_dir.exists():
            try:
                os.replace(backup, output_dir)
            except Exception as restore_error:
                raise FeedError(
                    f"Snapshot swap failed ({swap_error!r}) and rollback failed ({restore_error!r}); "
                    f"the previous snapshot is preserved at {backup} for recovery"
                ) from restore_error
        raise
    if had_previous:
        shutil.rmtree(backup, ignore_errors=True)


def write_snapshot(
    output_dir: Path,
    manifest: dict[str, Any],
    shards: dict[str, list[dict[str, Any]]],
    epss_snapshot: dict[str, Any],
    history: dict[str, Any] | None = None,
) -> None:
    """Stage, validate, then atomically replace the entire current static snapshot."""
    from verify_data_snapshot import validate_snapshot

    output_dir = output_dir.expanduser().absolute()
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    if output_dir.exists() and (output_dir.is_symlink() or not output_dir.is_dir()):
        raise FeedError("Snapshot output must be a real directory")
    if not isinstance(epss_snapshot, dict):
        raise FeedError("EPSS sidecar is required, even when it records a stale/unavailable status")

    records = [record for items in shards.values() for record in items]
    if not records or len(records) != manifest.get("totals", {}).get("cves"):
        raise FeedError("Refusing to write an empty or internally inconsistent core feed")
    generated_at = parse_datetime(manifest.get("generated_at"))
    if generated_at is None:
        raise FeedError("Manifest generated_at is invalid")

    stage_root = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.staging-", dir=output_dir.parent))
    try:
        data_root = stage_root / "data"
        data_root.mkdir()
        for summary in manifest.get("days") or []:
            day = str(summary.get("date") or "")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
                raise FeedError("Manifest contains an invalid shard date")
            payload = shards.get(day, [])
            raw = _json_bytes(payload)
            if summary.get("count") != len(payload) or summary.get("bytes") != len(raw):
                raise FeedError(f"Manifest record/byte count mismatch for {day}")
            if summary.get("sha256") != hashlib.sha256(raw).hexdigest():
                raise FeedError(f"Manifest digest mismatch for {day}")
            (data_root / f"{day}.json").write_bytes(raw)

        overview = build_overview(records, generated_at, epss_snapshot, history)
        overview_bytes = _json_bytes(overview)
        index = build_search_index(records, epss_snapshot)
        index["generated_at"] = iso_z(generated_at)
        index_bytes = _json_bytes(index)
        compressed_index_bytes = _gzip_bytes(index_bytes)
        if history is None:
            # Direct snapshot builds establish one real baseline and no historical events.
            history = {"schema_version": 1, "retention_days": 30,
                       "baseline": {"core_snapshot_at": iso_z(generated_at),
                                    "epss_score_date": str((epss_snapshot or {}).get("score_date") or ""),
                                    "record_count": len(records), "complete": True},
                       "snapshots": [], "events": []}
        history_bytes = _json_bytes(history)
        manifest["overview"] = {
            "schema_version": OVERVIEW_SCHEMA_VERSION,
            "path": "data/overview.json",
            "bytes": len(overview_bytes),
            "sha256": hashlib.sha256(overview_bytes).hexdigest(),
            "count": len(overview["records"]),
            "recent_change_count": len(overview["recent_changes"]),
        }
        epss_bytes = _json_bytes(epss_snapshot)
        epss_meta = manifest.get("epss")
        if not isinstance(epss_meta, dict):
            raise FeedError("Manifest is missing EPSS provenance")
        epss_meta["bytes"] = len(epss_bytes)
        epss_meta["sha256"] = hashlib.sha256(epss_bytes).hexdigest()
        manifest["search_index"] = {
            "schema_version": SEARCH_INDEX_SCHEMA_VERSION, "path": "data/search-index.json.gz",
            "compression": "gzip", "bytes": len(compressed_index_bytes),
            "sha256": hashlib.sha256(compressed_index_bytes).hexdigest(),
            "uncompressed_bytes": len(index_bytes), "uncompressed_sha256": hashlib.sha256(index_bytes).hexdigest(),
            "count": len(index["records"]),
        }
        manifest["history"] = {"schema_version": 1, "path": "data/history.json", "bytes": len(history_bytes),
                               "sha256": hashlib.sha256(history_bytes).hexdigest(), "retention_days": 30,
                               "event_count": len(history["events"]), "snapshot_count": len(history["snapshots"]),
                               "kev_catalog_count": len(history.get("kev_catalog", []))}
        (data_root / "overview.json").write_bytes(overview_bytes)
        (data_root / "epss.json").write_bytes(epss_bytes)
        (data_root / "search-index.json.gz").write_bytes(compressed_index_bytes)
        (data_root / "history.json").write_bytes(history_bytes)
        _write_json(stage_root / "manifest.json", manifest)

        try:
            validate_snapshot(stage_root, write_report=True)
        except Exception as exc:
            raise FeedError(f"Staged snapshot failed offline integrity validation: {exc}") from exc
        _commit_snapshot(stage_root, output_dir)
    finally:
        if stage_root.exists():
            shutil.rmtree(stage_root, ignore_errors=True)


def refresh(
    output_dir: Path = DEFAULT_OUTPUT,
    now: datetime | None = None,
    request_fn: Callable[..., tuple[Any, Any]] = request_json,
    sleep_fn: Callable[[float], None] = time.sleep,
    nvd_api_key: str | None = None,
    github_token: str | None = None,
    epss_csv_loader: Callable[[set[str] | None], tuple[dict[str, dict[str, float]], str, str]] = fetch_epss_csv,
    epss_api_request_fn: Callable[..., tuple[Any, Any]] = request_json,
) -> dict[str, Any]:
    as_of = (now or utc_now()).astimezone(timezone.utc).replace(microsecond=0)
    start = as_of - timedelta(days=30)
    end = as_of
    # Fail closed if any feed fails: retain the last complete snapshot rather than
    # quietly publishing a partial source mix as if it were complete.
    ingress_budget = _JSONIngressBudget()

    def request_with_budget(url: str, headers: dict[str, str] | None = None) -> tuple[Any, Any]:
        return ingress_budget.fetch(request_fn, url, headers)

    def epss_request_with_budget(url: str, headers: dict[str, str] | None = None) -> tuple[Any, Any]:
        return ingress_budget.fetch(epss_api_request_fn, url, headers)

    nvd_items, nvd_total, nvd_pages = iter_nvd(start, end, request_with_budget, sleep_fn, api_key=nvd_api_key)
    if nvd_total == 0 or not nvd_items:
        raise FeedError("NVD returned no records; refusing to publish a partial feed")
    ghsa_items, ghsa_pages = iter_github_advisories(start, end, request_with_budget, token=github_token)
    if not ghsa_items:
        raise FeedError("GitHub returned no advisories; refusing to publish a partial feed")
    kev_items, kev_total = fetch_kev(request_with_budget)
    if not kev_items or kev_total != len(kev_items):
        raise FeedError("CISA KEV returned no or inconsistent catalog records; refusing to publish a partial feed")
    records = build_records(nvd_items, ghsa_items, kev_items, start, end)
    if not records or len(records) > MAX_CORE_RECORDS:
        raise FeedError(f"Merged CVE result is empty or exceeds the {MAX_CORE_RECORDS:,}-record safety limit")
    epss_snapshot, epss_status = build_epss_snapshot(records, output_dir, as_of, epss_csv_loader, epss_request_with_budget)
    statuses = [
        {"name": "NVD CVE API 2.0", "ok": True, "pages": nvd_pages, "records": nvd_total, "checked_at": iso_z(as_of)},
        {"name": "GitHub Security Advisory Database", "ok": True, "pages": ghsa_pages, "advisories": len(ghsa_items), "checked_at": iso_z(as_of)},
        {"name": "CISA KEV", "ok": True, "catalog_records": kev_total, "checked_at": iso_z(as_of)},
    ]
    manifest, shards = build_manifest(records, start, end, as_of, statuses, nvd_total, len(ghsa_items), kev_total)
    add_epss_metadata(manifest, epss_snapshot, epss_status)
    history = build_change_history(output_dir, records, epss_snapshot, manifest, as_of, kev_items)
    write_snapshot(output_dir, manifest, shards, epss_snapshot, history)
    print(
        f"Complete snapshot: {len(records)} unique CVEs across {len(manifest['days'])} UTC day shards; "
        f"NVD {nvd_total}/{nvd_pages} pages, GitHub {len(ghsa_items)}/{ghsa_pages} pages, CISA {kev_total} catalog entries; "
        f"FIRST EPSS {epss_status['scores']}/{epss_status['records']} scores dated {epss_status['score_date'] or 'unavailable'}; "
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
