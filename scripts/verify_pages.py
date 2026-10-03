#!/usr/bin/env python3
"""Wait for GitHub Pages to serve the exact locally validated static snapshot."""
from __future__ import annotations

import argparse
import hashlib
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import verify_data_snapshot as verifier

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT = ROOT / "snapshot"
DEFAULT_BASE_URL = "https://iliya-bashrc.github.io/SubZer0/"
USER_AGENT = "SubZer0-Pages-Verification/1.0 (+https://github.com/iliya-bashrc/SubZer0)"
FETCH_TIMEOUT_SECONDS = 30
MAX_SITE_ASSET_BYTES = 4 * 1024 * 1024
SITE_ASSETS = (
    "index.html",
    "app.js",
    "community.js",
    "styles.css",
    "feed.css",
    "severity-effects.css",
    "community.css",
    "assets/telegram-bugcod3.svg",
    "assets/telegram-rootaccessclub.svg",
)


class PagesVerificationError(RuntimeError):
    pass


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin: tuple[str, str, int | None], base_path: str) -> None:
        super().__init__()
        self.origin = origin
        self.base_path = base_path

    def redirect_request(self, request, response, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        port = parsed.port
        target = (parsed.scheme, parsed.hostname or "", port)
        if (
            target != self.origin
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith(self.base_path)
        ):
            raise PagesVerificationError("Refusing a cross-origin or out-of-site Pages redirect")
        return super().redirect_request(request, response, code, message, headers, new_url)


def _validate_base_url(value: str) -> tuple[str, tuple[str, str, int | None], str]:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise PagesVerificationError("Pages base URL is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "iliya-bashrc.github.io"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/SubZer0"
    ):
        raise PagesVerificationError("Pages base URL must be the configured HTTPS SubZer0 site")
    base = value.rstrip("/") + "/"
    return base, ("https", "iliya-bashrc.github.io", port), parsed.path.rstrip("/") + "/"


def _fetch(opener: urllib.request.OpenerDirector, base: str, relative_path: str, limit: int) -> bytes:
    if relative_path.startswith("/") or ".." in Path(relative_path).parts or "\\" in relative_path:
        raise PagesVerificationError("Refusing an unsafe Pages resource path")
    url = urllib.parse.urljoin(base, relative_path)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            if response.geturl() != url:
                raise PagesVerificationError("Pages redirected a resource unexpectedly")
            length = response.headers.get("Content-Length")
            if length:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise PagesVerificationError("Pages returned an invalid Content-Length") from exc
                if declared < 0 or declared > limit:
                    raise PagesVerificationError(f"Pages resource exceeds its {limit}-byte limit")
            body = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise PagesVerificationError(f"Pages returned HTTP {exc.code} for {relative_path}") from exc
    except urllib.error.URLError as exc:
        raise PagesVerificationError(f"Pages request failed for {relative_path}: {exc.reason}") from exc
    if len(body) > limit:
        raise PagesVerificationError(f"Pages resource exceeds its {limit}-byte limit")
    return body


def _resources(root: Path, manifest: dict[str, Any]) -> list[tuple[str, Path, int, str]]:
    resources: list[tuple[str, Path, int, str]] = []
    for day in manifest["days"]:
        resources.append(("snapshot/" + day["path"], root / day["path"], verifier.MAX_SHARD_BYTES, day["sha256"]))
    for key, limit in (("overview", verifier.MAX_OVERVIEW_BYTES), ("epss", verifier.MAX_EPSS_BYTES)):
        item = manifest[key]
        resources.append(("snapshot/" + item["path"], root / item["path"], limit, item["sha256"]))
    repo_root = root.parent
    for name in SITE_ASSETS:
        path = repo_root / name
        if path.is_symlink() or not path.is_file():
            raise PagesVerificationError(f"Required public application asset is missing or unsafe: {name}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        resources.append((name, path, MAX_SITE_ASSET_BYTES, digest))
    return resources


def verify_pages(
    root: Path,
    base_url: str = DEFAULT_BASE_URL,
    timeout_seconds: int = 900,
    interval_seconds: int = 15,
) -> dict[str, int | str]:
    root = Path(root).expanduser()
    report = verifier.validate_snapshot(root)
    root = root.resolve()
    local_manifest = (root / "manifest.json").read_bytes()
    manifest = verifier._loads(local_manifest, "manifest.json")
    base, origin, base_path = _validate_base_url(base_url)
    opener = urllib.request.build_opener(_SameOriginRedirect(origin, base_path))
    resources = _resources(root, manifest)
    deadline = time.monotonic() + timeout_seconds
    last_error = "remote manifest does not yet match the validated local manifest"
    attempts = 0

    while True:
        attempts += 1
        try:
            remote_manifest = _fetch(opener, base, "snapshot/manifest.json", verifier.MAX_MANIFEST_BYTES)
            if remote_manifest != local_manifest:
                raise PagesVerificationError("remote manifest does not yet match the validated local manifest")
            for relative_path, local_path, limit, expected_hash in resources:
                local_bytes = local_path.read_bytes()
                if len(local_bytes) > limit:
                    raise PagesVerificationError(f"Local Pages resource exceeds its {limit}-byte limit: {relative_path}")
                remote_bytes = _fetch(opener, base, relative_path, limit)
                if len(remote_bytes) != len(local_bytes):
                    raise PagesVerificationError(f"Pages byte count differs for {relative_path}")
                if hashlib.sha256(remote_bytes).hexdigest() != expected_hash:
                    raise PagesVerificationError(f"Pages SHA-256 differs for {relative_path}")
                if remote_bytes != local_bytes:
                    raise PagesVerificationError(f"Pages content differs from the locally validated {relative_path}")
            return {
                "generated_at": str(manifest["generated_at"]),
                "shards": len(manifest["days"]),
                "records": int(report["records"]),
                "bytes": int(report["static_json_bytes"]),
                "attempts": attempts,
            }
        except (PagesVerificationError, OSError) as exc:
            last_error = str(exc)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PagesVerificationError(f"Pages did not converge within {timeout_seconds}s: {last_error}")
        elapsed = timeout_seconds - remaining
        print(f"Pages is not yet serving the complete validated snapshot ({last_error}); elapsed {elapsed:.0f}s/{timeout_seconds}s.", flush=True)
        time.sleep(min(interval_seconds, remaining))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_SNAPSHOT, help="Validated snapshot root")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Configured public SubZer0 Pages base URL")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--interval-seconds", type=int, default=15)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.interval_seconds <= 0:
        parser.error("timeouts must be positive integers")
    try:
        result = verify_pages(args.root, args.base_url, args.timeout_seconds, args.interval_seconds)
    except (PagesVerificationError, verifier.SnapshotValidationError, OSError, ValueError, TypeError) as exc:
        print(f"PAGES VERIFICATION FAILED: {exc}")
        return 1
    print(
        "PAGES VERIFICATION PASSED: "
        f"{result['records']:,} CVEs across {result['shards']} shards and {result['bytes']:,} bytes; "
        f"generated {result['generated_at']}; exact manifest, hashes, byte counts and content match after {result['attempts']} attempt(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
