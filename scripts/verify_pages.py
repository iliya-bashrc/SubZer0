#!/usr/bin/env python3
"""Wait for GitHub Pages to serve the expected committed snapshot and smoke-check its static assets."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "https://iliya-bashrc.github.io/SubZer0/"
ASSETS = ("index.html", "app.js", "styles.css", "community.css", "community.js")


def build_url(base_url: str, relative: str) -> str:
    base = base_url.rstrip("/") + "/"
    url = urljoin(base, relative.lstrip("/"))
    parts = urlsplit(url)
    query = dict((key, value) for key, value in (pair.split("=", 1) if "=" in pair else (pair, "") for pair in parts.query.split("&") if pair))
    query["pages-smoke"] = str(time.time_ns())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def fetch(base_url: str, relative: str, timeout: float = 10) -> bytes:
    request = Request(build_url(base_url, relative), headers={"Cache-Control": "no-cache", "Pragma": "no-cache", "User-Agent": "SubZer0-Pages-Smoke/1.0"})
    with urlopen(request, timeout=timeout) as response:
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"{relative} returned HTTP {response.status}")
        return response.read()


def fetch_json(base_url: str, relative: str) -> dict[str, Any]:
    try:
        value = json.loads(fetch(base_url, relative).decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{relative} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{relative} JSON root is not an object")
    return value


def verify_once(base_url: str, expected: dict[str, Any]) -> dict[str, Any]:
    page = fetch(base_url, "index.html").decode("utf-8", errors="strict")
    required_markup = ('id="main-content"', 'id="page-overview"', 'id="page-center"', 'id="page-community"', 'id="tab-overview"', 'id="tab-center"', 'id="tab-community"', 'id="skip-link"')
    missing = [marker for marker in required_markup if marker not in page]
    if missing:
        raise RuntimeError(f"deployed page markup is missing: {', '.join(missing)}")

    for asset in ASSETS[1:]:
        fetch(base_url, asset)

    public = fetch_json(base_url, "data/manifest.json")
    if public.get("generated_at") != expected.get("generated_at"):
        raise RuntimeError(f"public snapshot is {public.get('generated_at')}, expected {expected.get('generated_at')}")
    if public.get("days") != expected.get("days") or public.get("totals") != expected.get("totals"):
        raise RuntimeError("public data manifest differs from the committed manifest")
    if public.get("complete") is not True or public.get("coverage", {}).get("sources_complete") is not True:
        raise RuntimeError("public manifest does not declare a complete snapshot")

    api = fetch_json(base_url, "api/v1/manifest.json")
    if api.get("generated_at") != public.get("generated_at") or api.get("days") != public.get("days") or api.get("totals") != public.get("totals"):
        raise RuntimeError("public static API manifest is not synchronized with the public data manifest")

    days = public.get("days")
    if not isinstance(days, list) or not days:
        raise RuntimeError("public data manifest has no date shards")
    latest = days[-1]
    relative = latest.get("path")
    if not isinstance(relative, str) or not relative.startswith("data/") or ".." in Path(relative).parts:
        raise RuntimeError("latest public shard path is invalid")
    shard = fetch(base_url, relative)
    actual_hash = hashlib.sha256(shard).hexdigest()
    if actual_hash.lower() != str(latest.get("sha256", "")).lower():
        raise RuntimeError(f"latest public shard SHA-256 mismatch for {latest.get('date')}")
    try:
        records = json.loads(shard.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"latest public shard is not valid JSON: {exc}") from exc
    if not isinstance(records, list) or len(records) != int(latest.get("count", -1)):
        raise RuntimeError(f"latest public shard row count mismatch for {latest.get('date')}")

    return {"generated_at": str(public["generated_at"]), "latest_date": str(latest["date"]), "latest_count": len(records), "latest_sha256": actual_hash}


def verify_with_retry(base_url: str, expected: dict[str, Any], timeout_seconds: int, interval_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    attempt = 0
    while True:
        attempt += 1
        try:
            result = verify_once(base_url, expected)
            print(f"PAGES VERIFICATION PASSED: {result['generated_at']} is public; {result['latest_count']} rows verified for {result['latest_date']}; SHA-256 {result['latest_sha256']}", flush=True)
            return result
        except (HTTPError, URLError, TimeoutError, OSError, RuntimeError, UnicodeError, ValueError, TypeError) as exc:
            last_error = exc
            remaining = deadline - time.monotonic()
            elapsed = timeout_seconds - max(0, int(remaining))
            if remaining <= 0:
                break
            print(f"Pages attempt {attempt} not ready after {elapsed}s: {exc}; retrying in {min(interval_seconds, max(1, int(remaining)))}s", flush=True)
            time.sleep(min(interval_seconds, remaining))
    raise RuntimeError(f"Pages did not match the committed snapshot within {timeout_seconds}s: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parents[1] / "data" / "manifest.json")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--interval-seconds", type=int, default=15)
    args = parser.parse_args()
    if args.timeout_seconds < 1 or args.interval_seconds < 1:
        parser.error("timeout and interval must be positive")
    try:
        expected = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(expected, dict) or not isinstance(expected.get("generated_at"), str):
            raise ValueError("committed manifest is malformed")
        verify_with_retry(args.base_url, expected, args.timeout_seconds, args.interval_seconds)
    except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        print(f"PAGES VERIFICATION FAILED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
