#!/usr/bin/env python3
"""Portable browser QA for SubZer0's manifest-verified static snapshot."""
from __future__ import annotations

import functools
import hashlib
import http.server
import json
import shutil
import threading
import time
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent
SCREENSHOTS = Path('/tmp/subzero-security-review-screenshots')
SCREENSHOTS.mkdir(parents=True, exist_ok=True)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, scenario: dict | None = None, **kwargs):
        self.scenario = scenario
        super().__init__(*args, **kwargs)

    def log_message(self, _format, *args):
        pass

    def do_GET(self):
        if self.scenario is None:
            return super().do_GET()
        path = urlsplit(self.path).path.lstrip('/')
        with self.scenario['lock']:
            self.scenario['request_counts'][path] = self.scenario['request_counts'].get(path, 0) + 1
            request_count = self.scenario['request_counts'][path]
            seen = self.scenario['seen'].setdefault(path, threading.Event())
            gate = self.scenario['gates'].get(path)
            response = self.scenario['responses'].get(path)
            declared_length = self.scenario['declared_lengths'].get(path)
        seen.set()
        if gate is not None and not gate.wait(timeout=10):
            response = (504, b'test gate timed out')
        if callable(response):
            response = response(request_count)
        if response is not None:
            status_code, body = response
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if declared_length is not None:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(declared_length))
            self.end_headers()
            self.close_connection = True
            return
        return super().do_GET()


class CacheSemanticsHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def __init__(self, *args, scenario: dict, **kwargs):
        self.scenario = scenario
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, _format, *args):
        pass

    def do_GET(self):
        path = urlsplit(self.path).path.lstrip('/') or 'index.html'
        with self.scenario['lock']:
            count = self.scenario['counts'].get(path, 0) + 1
            self.scenario['counts'][path] = count
            override = self.scenario['overrides'].get(path)
            response = self.scenario['responses'].get(path)
            cache_control = self.scenario['cache_control'].get(path, 'public, max-age=600')

        if response is not None:
            status, body = response(count) if callable(response) else response
        else:
            source = (ROOT / path).resolve()
            if not source.is_relative_to(ROOT.resolve()) or not source.is_file():
                status, body = 404, b'not found'
            else:
                status, body = 200, override if override is not None else source.read_bytes()

        etag = '"' + hashlib.sha256(body).hexdigest() + '"'
        if status == 200 and self.headers.get('If-None-Match') == etag:
            status, body = 304, b''
        event = {
            'path': path,
            'status': status,
            'body_bytes': len(body),
            'if_none_match': self.headers.get('If-None-Match'),
            'request_cache_control': self.headers.get('Cache-Control'),
            'etag': etag,
            'cache_control': cache_control,
        }
        with self.scenario['lock']:
            self.scenario['events'].append(event)

        self.send_response(status)
        content_type = 'application/json; charset=utf-8' if path.endswith('.json') else self.guess_type(path)
        if content_type.startswith('text/') or content_type in {'application/javascript', 'application/xml'}:
            content_type += '; charset=utf-8'
        self.send_header('Content-Type', content_type)
        self.send_header('Cache-Control', cache_control)
        self.send_header('ETag', etag)
        if status != 304:
            self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


def nfmt(value: int) -> str:
    return f"{value:,}"


def load_contract() -> tuple[dict, dict, dict[str, dict]]:
    manifest = json.loads((ROOT / 'snapshot' / 'manifest.json').read_text(encoding='utf-8'))
    overview = json.loads((ROOT / 'snapshot' / 'data' / 'overview.json').read_text(encoding='utf-8'))
    days = {day['date']: day for day in manifest['days']}
    return manifest, overview, days


def source_epss_stale(manifest: dict) -> bool:
    status = next(source for source in manifest['source_status'] if source['name'] == 'FIRST EPSS')
    try:
        updated = datetime.fromisoformat(manifest['epss']['source_updated_at'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        return True
    return status['ok'] is not True or age < 0 or age > 36 * 60 * 60


def browser_issue_track(page, issues: dict, origin: str) -> None:
    page.on('pageerror', lambda error: issues['page_errors'].append(str(error)))
    page.on('console', lambda message: issues['console_errors'].append(message.text) if message.type == 'error' else None)
    page.on('requestfailed', lambda request: issues['request_failures'].append(request.url))
    page.on('request', lambda request: issues['external_requests'].append(request.url)
            if not request.url.startswith((origin, 'data:')) else None)


def width_audit(page, width: int, height: int = 900) -> dict:
    page.set_viewport_size({'width': width, 'height': height})
    page.wait_for_timeout(50)
    metrics = page.evaluate('''() => ({
      viewport: window.innerWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
      activePage: document.querySelector('.page:not([hidden])')?.scrollWidth ?? 0,
      activePageId: document.querySelector('.page:not([hidden])')?.id ?? 'none'
    })''')
    assert metrics['document'] <= width, f'horizontal document overflow at {width}px: {metrics}'
    assert metrics['body'] <= width, f'horizontal body overflow at {width}px: {metrics}'
    assert metrics['activePage'] <= width, f"active-page overflow at {width}px: {metrics}"
    return metrics


def snapshot_override(manifest: dict, day: dict, records: list[dict]) -> tuple[bytes, bytes, str]:
    changed = json.loads(json.dumps(manifest))
    body = json.dumps(records, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    summary = next(item for item in changed['days'] if item['date'] == day['date'])
    summary['bytes'] = len(body)
    summary['sha256'] = hashlib.sha256(body).hexdigest()
    manifest_body = json.dumps(changed, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return manifest_body, body, day['date']


def install_snapshot_override(page, manifest_body: bytes, shard_body: bytes, day: str) -> None:
    page.route('**/snapshot/manifest.json', lambda route: route.fulfill(status=200, content_type='application/json; charset=utf-8', body=manifest_body))
    page.route(f'**/snapshot/data/{day}.json', lambda route: route.fulfill(status=200, content_type='application/json; charset=utf-8', body=shard_body))


def new_scenario() -> dict:
    return {
        'lock': threading.Lock(), 'request_counts': {}, 'seen': {}, 'gates': {},
        'responses': {}, 'declared_lengths': {},
    }


def scenario_request_count(scenario: dict, path: str) -> int:
    with scenario['lock']:
        return scenario['request_counts'].get(path, 0)


def wait_for_scenario_request(scenario: dict, path: str) -> None:
    with scenario['lock']:
        event = scenario['seen'].setdefault(path, threading.Event())
    assert event.wait(timeout=10), f'Browser did not request {path}'


def serve_scenario(scenario: dict) -> http.server.ThreadingHTTPServer:
    handler = functools.partial(QuietHandler, directory=str(ROOT), scenario=scenario)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run_snapshot_loader_tests(browser, manifest: dict) -> dict:
    day_paths = [f"snapshot/{day['path']}" for day in manifest['days']]
    manifest_path = 'snapshot/manifest.json'
    epss_path = f"snapshot/{manifest['epss']['path']}"
    result: dict = {}

    # The initial manifest is held; completed resources are then released out of manifest order.
    scenario = new_scenario()
    gates = {path: threading.Event() for path in [manifest_path, *day_paths, epss_path]}
    scenario['gates'] = gates
    server = serve_scenario(scenario)
    origin = f'http://127.0.0.1:{server.server_port}'
    page = browser.new_page(viewport={'width': 1440, 'height': 1000}, device_scale_factor=1)
    page.emulate_media(reduced_motion='reduce')
    try:
        page.goto(f'{origin}/?page=center', wait_until='domcontentloaded')
        loader = page.locator('#snapshot-loader')
        expect(loader).to_be_visible()
        assert page.locator('#feed-view').get_attribute('aria-busy') == 'true'
        assert page.locator('#record-list').get_attribute('aria-busy') == 'true'
        assert page.locator('#snapshot-manifest-state').inner_text() == 'Waiting'
        assert page.locator('#snapshot-shard-progress').is_hidden()
        assert page.locator('#snapshot-shard-count').get_attribute('aria-live') == 'polite'
        wait_for_scenario_request(scenario, manifest_path)
        page.wait_for_timeout(120)
        expect(loader).to_be_visible()
        assert page.locator('#snapshot-shard-count').inner_text() == 'Waiting for manifest'
        gates[manifest_path].set()

        progress = page.locator('#snapshot-shard-progress')
        page.wait_for_function('(count) => { const p = document.querySelector("#snapshot-shard-progress"); return !p.hidden && p.max === count; }', arg=len(day_paths), timeout=10_000)
        assert page.locator('#snapshot-manifest-state').inner_text() == 'Verified'
        assert progress.evaluate('(element) => element.value') == 0
        for path in day_paths[:6]:
            wait_for_scenario_request(scenario, path)

        # Release a later manifest shard first, and wait for its validated count before releasing an earlier one.
        gates[day_paths[4]].set()
        expect(page.locator('#snapshot-shard-count')).to_have_text(f'1 of {len(day_paths)} verified', timeout=20_000)
        assert progress.evaluate('(element) => element.value') == 1
        assert progress.get_attribute('aria-valuetext') == f'1 of {len(day_paths)} daily shards verified'
        wait_for_scenario_request(scenario, epss_path)
        gates[day_paths[1]].set()
        expect(page.locator('#snapshot-shard-count')).to_have_text(f'2 of {len(day_paths)} verified', timeout=20_000)
        assert progress.evaluate('(element) => element.value') == 2
        assert page.locator('#record-list .record-row').count() == 0
        expect(loader).to_be_visible()

        # Leaving and re-entering during the load retains the same work and count.
        before_reentry = {path: scenario_request_count(scenario, path) for path in day_paths}
        page.locator('#tab-overview').click()
        page.locator('#tab-center').click()
        expect(loader).to_be_visible()
        assert page.locator('#snapshot-shard-count').inner_text() == f'2 of {len(day_paths)} verified'
        assert before_reentry == {path: scenario_request_count(scenario, path) for path in day_paths}

        # Allow every shard except the final manifest entry; all visible progress remains factual.
        for path in day_paths[:-1]:
            gates[path].set()
        expect(page.locator('#snapshot-shard-count')).to_have_text(f'{len(day_paths) - 1} of {len(day_paths)} verified', timeout=60_000)
        assert page.locator('#snapshot-shard-progress').evaluate('(element) => element.value') == len(day_paths) - 1
        expect(loader).to_be_visible()
        assert page.locator('#record-list .record-row').count() == 0
        assert page.locator('#feed-view').get_attribute('aria-busy') == 'true'
        assert page.locator('#snapshot-epss-state').inner_text() == 'Waiting for daily shards'
        page.screenshot(path=str(SCREENSHOTS / '05-cve-loader-30-of-31-pending.png'), animations='disabled')

        # The final shard can complete and the view still stays busy until the EPSS schema is accepted.
        gates[day_paths[-1]].set()
        expect(page.locator('#snapshot-shard-count')).to_have_text(f'{len(day_paths)} of {len(day_paths)} verified', timeout=20_000)
        expect(loader).to_be_visible()
        assert page.locator('#snapshot-epss-state').inner_text() == 'Waiting for daily shards'
        for width, height in ((320, 740), (390, 844), (1440, 1000)):
            metrics = width_audit(page, width, height)
            assert metrics['activePageId'] == 'page-center'
        gates[epss_path].set()
        expect(page.locator('#snapshot-epss-state')).to_have_text('Verified', timeout=30_000)
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=30_000)
        expect(loader).to_be_hidden()
        assert page.locator('#feed-view').get_attribute('aria-busy') == 'false'
        assert page.locator('#record-list').get_attribute('aria-busy') == 'false'
        assert page.locator('.record-row').count() == 24

        # Re-entering after completion uses the in-memory, already-verified data without another request.
        before_loaded_reentry = {path: scenario_request_count(scenario, path) for path in [*day_paths, epss_path]}
        page.locator('#tab-overview').click()
        page.locator('#tab-center').click()
        expect(loader).to_be_hidden()
        assert before_loaded_reentry == {path: scenario_request_count(scenario, path) for path in [*day_paths, epss_path]}
        result['delayed_manifest'] = True
        result['out_of_order_shard_completion'] = {'completion_order': [manifest['days'][4]['date'], manifest['days'][1]['date']], 'progress': f'{len(day_paths)}/{len(day_paths)} verified'}
        result['held_until_last_shard_and_sidecar'] = True
        result['pending_and_loaded_reentry'] = True
        motion = page.locator('#snapshot-loader-status').evaluate("element => ({reduced: matchMedia('(prefers-reduced-motion: reduce)').matches, name: getComputedStyle(element, '::before').animationName, duration: getComputedStyle(element, '::before').animationDuration})")
        duration = motion['duration']
        duration_seconds = float(duration[:-2]) / 1000 if duration.endswith('ms') else float(duration[:-1])
        result['reduced_motion_static'] = motion['reduced'] and motion['name'] == 'none' and duration_seconds <= 0.00001
        result['responsive_loader'] = {'widths': [320, 390, 1440], 'horizontal_overflow': False}
        assert result['reduced_motion_static'], 'Loader status animation remains active with reduced motion enabled.'
    finally:
        for gate in gates.values():
            gate.set()
        page.close()
        server.shutdown()
        server.server_close()

    # A failed shard exits loading, presents the explicit retry state, then reloads successfully.
    retry_scenario = new_scenario()
    retry_gates = {path: threading.Event() for path in [*day_paths[1:], epss_path]}
    retry_scenario['gates'] = retry_gates
    retry_scenario['responses'][day_paths[0]] = lambda count: (503, b'upstream unavailable') if count == 1 else None
    retry_server = serve_scenario(retry_scenario)
    retry_origin = f'http://127.0.0.1:{retry_server.server_port}'
    retry_page = browser.new_page(viewport={'width': 1280, 'height': 900})
    try:
        retry_page.goto(f'{retry_origin}/?page=center', wait_until='domcontentloaded')
        expect(retry_page.locator('#result-status')).to_contain_text('could not be verified', timeout=30_000)
        expect(retry_page.locator('#snapshot-loader')).to_be_hidden()
        assert retry_page.locator('#feed-view').get_attribute('aria-busy') == 'false'
        assert retry_page.locator('#record-list').get_attribute('aria-busy') == 'false'
        expect(retry_page.get_by_role('button', name='Reload snapshot')).to_be_visible()
        retry_page.wait_for_timeout(180)
        expect(retry_page.locator('#snapshot-loader')).to_be_hidden()
        for gate in retry_gates.values():
            gate.set()
        retry_page.get_by_role('button', name='Reload snapshot').click()
        expect(retry_page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(retry_page.locator('#snapshot-loader')).to_be_hidden()
        assert scenario_request_count(retry_scenario, day_paths[0]) >= 2
        result['source_failure_exits_loading'] = True
        result['retry_reloads_verified_data'] = True
    finally:
        for gate in retry_gates.values():
            gate.set()
        retry_page.close()
        retry_server.shutdown()
        retry_server.server_close()

    oversized_scenario = new_scenario()
    oversized_scenario['declared_lengths'][day_paths[0]] = 16 * 1024 * 1024 + 1
    oversized_server = serve_scenario(oversized_scenario)
    oversized_origin = f'http://127.0.0.1:{oversized_server.server_port}'
    oversized_page = browser.new_page(viewport={'width': 1280, 'height': 900})
    try:
        oversized_page.goto(f'{oversized_origin}/?page=center', wait_until='domcontentloaded')
        expect(oversized_page.locator('#result-status')).to_contain_text('could not be verified', timeout=30_000)
        expect(oversized_page.locator('#snapshot-loader')).to_be_hidden()
        assert oversized_page.locator('#feed-view').get_attribute('aria-busy') == 'false'
        assert oversized_page.locator('#record-list .record-row').count() == 0
        result['oversized_shard_exits_loading'] = True
    finally:
        oversized_page.close()
        oversized_server.shutdown()
        oversized_server.server_close()
    return result


def new_cache_scenario() -> dict:
    return {
        'lock': threading.Lock(), 'counts': {}, 'events': [],
        'overrides': {}, 'responses': {}, 'cache_control': {},
    }


def cache_scenario_events(scenario: dict) -> list[dict]:
    with scenario['lock']:
        return list(scenario['events'])


def serve_cache_scenario(scenario: dict) -> http.server.ThreadingHTTPServer:
    handler = functools.partial(CacheSemanticsHandler, scenario=scenario)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run_http_cache_tests(browser, manifest: dict) -> dict:
    manifest_path = 'snapshot/manifest.json'
    manifest_raw = (ROOT / manifest_path).read_bytes()
    overview_ids = {item['id'] for item in json.loads((ROOT / 'snapshot' / 'data' / 'overview.json').read_bytes())['records']}
    target_day = None
    target_rows = None
    target = None
    for day in manifest['days']:
        if not day['count']:
            continue
        rows = json.loads((ROOT / 'snapshot' / day['path']).read_bytes())
        candidate = next((row for row in rows if row['id'] not in overview_ids), None)
        if candidate:
            target_day, target_rows, target = day, rows, candidate
            break
    assert target_day and target_rows and target, 'Could not choose a non-Overview CVE for the cache fixture.'

    changed_rows = json.loads(json.dumps(target_rows))
    changed_title = 'C' * len(target['title'].encode('utf-8'))
    assert changed_title != target['title'], 'Could not create a same-byte-length digest-mismatch fixture.'
    next(row for row in changed_rows if row['id'] == target['id'])['title'] = changed_title
    updated_manifest_raw, updated_shard_raw, _ = snapshot_override(manifest, target_day, changed_rows)
    target_path = f"snapshot/{target_day['path']}"
    expected_resource_paths = {
        manifest_path,
        *(f"snapshot/{day['path']}" for day in manifest['days']),
        f"snapshot/{manifest['overview']['path']}",
        f"snapshot/{manifest['epss']['path']}",
    }
    scenario = new_cache_scenario()
    server = serve_cache_scenario(scenario)
    origin = f'http://127.0.0.1:{server.server_port}'
    issues = {'page_errors': [], 'console_errors': [], 'request_failures': [], 'external_requests': []}
    context = browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    browser_issue_track(page, issues, origin)
    results: dict = {}
    try:
        cold_started = time.monotonic()
        page.goto(f'{origin}/?page=center', wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        cold_elapsed = time.monotonic() - cold_started
        cold_events = [event for event in cache_scenario_events(scenario) if event['path'] in expected_resource_paths]
        cold_full = [event for event in cold_events if event['status'] == 200]
        cold_counts = {path: sum(event['path'] == path for event in cold_full) for path in expected_resource_paths}
        assert all(count == 1 for count in cold_counts.values()), f'Cold load did not fetch each resource exactly once: {cold_counts}'
        cold_manifest_event = next(event for event in cold_full if event['path'] == manifest_path)
        assert cold_manifest_event['cache_control'] == 'public, max-age=600'
        cold_data_bytes = sum(event['body_bytes'] for event in cold_full if event['path'] != manifest_path)
        assert cold_data_bytes == sum(day['bytes'] for day in manifest['days']) + manifest['overview']['bytes'] + manifest['epss']['bytes']

        repeat_started = time.monotonic()
        repeat_marker = len(cache_scenario_events(scenario))
        page.reload(wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        repeat_elapsed = time.monotonic() - repeat_started
        repeat_events = [event for event in cache_scenario_events(scenario)[repeat_marker:] if event['path'] in expected_resource_paths]
        repeat_manifest = [event for event in repeat_events if event['path'] == manifest_path]
        assert len(repeat_manifest) == 1 and repeat_manifest[0]['status'] == 304, f'Manifest was not ETag-revalidated: {repeat_events}'
        assert repeat_manifest[0]['if_none_match'] == cold_manifest_event['etag'], 'Manifest revalidation omitted the cached ETag.'
        assert not [event for event in repeat_events if event['path'] != manifest_path], f'Unchanged data resources were re-requested: {repeat_events}'
        repeat_data_bytes = sum(event['body_bytes'] for event in repeat_events if event['path'] != manifest_path)
        assert repeat_data_bytes == 0
        results['cold_visit'] = {'seconds': round(cold_elapsed, 3), 'data_body_bytes': cold_data_bytes, 'resource_count': len(expected_resource_paths) - 1}
        results['unchanged_repeat'] = {
            'seconds': round(repeat_elapsed, 3), 'manifest_revalidation': '304 with matching ETag',
            'data_resource_requests': 0, 'data_body_bytes': repeat_data_bytes,
            'data_body_bytes_saved': cold_data_bytes,
            'data_body_savings_percent': 100.0,
        }

        # Re-entering the loaded page and using browser history preserves verified in-memory/cache data.
        reentry_marker = len(cache_scenario_events(scenario))
        page.locator('#tab-overview').click()
        page.locator('#tab-center').click()
        assert not [event for event in cache_scenario_events(scenario)[reentry_marker:] if event['path'] in expected_resource_paths]
        page.locator('#tab-overview').click()
        first_overview_id = json.loads((ROOT / 'snapshot' / 'data' / 'overview.json').read_bytes())['records'][0]['id']
        page.locator('.latest-id').first.click()
        expect(page.locator('#detail-heading')).to_have_text(first_overview_id, timeout=120_000)
        page.go_back(wait_until='domcontentloaded')
        page.go_forward(wait_until='domcontentloaded')
        expect(page.locator('#detail-heading')).to_have_text(first_overview_id, timeout=120_000)
        history_events = [event for event in cache_scenario_events(scenario)[reentry_marker:] if event['path'] in expected_resource_paths]
        assert not [event for event in history_events if event['path'] != manifest_path and event['body_bytes']], f'Re-entry/history redownloaded JSON bodies: {history_events}'
        results['same_page_and_history'] = {'in_memory_reentry': True, 'back_forward': True, 'data_body_bytes': 0}

        # A fresh manifest changes the hash for a same-path shard; the stale cached body must be retried once.
        page.goto(f'{origin}/?page=center', wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        with scenario['lock']:
            scenario['overrides'][manifest_path] = updated_manifest_raw
            scenario['overrides'][target_path] = updated_shard_raw
        update_marker = len(cache_scenario_events(scenario))
        page.reload(wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        page.locator('#record-search').fill(target['id'])
        expect(page.locator('.record-row')).to_have_count(1)
        expect(page.locator('.record-title')).to_have_text(changed_title)
        update_events = [event for event in cache_scenario_events(scenario)[update_marker:] if event['path'] in expected_resource_paths]
        new_manifest_events = [event for event in update_events if event['path'] == manifest_path]
        new_shard_events = [event for event in update_events if event['path'] == target_path]
        assert len(new_manifest_events) == 1 and new_manifest_events[0]['status'] == 200 and new_manifest_events[0]['body_bytes'] == len(updated_manifest_raw)
        assert len(new_shard_events) == 1 and new_shard_events[0]['status'] == 200 and new_shard_events[0]['body_bytes'] == len(updated_shard_raw), f'Changed shard was not fetched exactly once after cache mismatch: {new_shard_events}'
        results['changed_manifest_and_shard'] = {
            'manifest': 'fresh 200', 'changed_same_path_shard': 'one cache-reload request; digest and schema verified',
            'updated_record_rendered': target['id'], 'shard_response_body_bytes': len(updated_shard_raw),
        }

        # Force one resource's cached validator to expire, then confirm default fetch revalidates by ETag.
        expired_day = next(day for day in manifest['days'] if day['count'] and day['path'] != target_day['path'])
        expired_path = f"snapshot/{expired_day['path']}"
        with scenario['lock']:
            scenario['cache_control'][expired_path] = 'public, max-age=0'
        probe = page.evaluate('''async (path) => {
          const response = await fetch(path, {cache: 'no-cache', credentials: 'same-origin'});
          return {status: response.status, bytes: (await response.arrayBuffer()).byteLength};
        }''', f'/{expired_path}')
        assert probe == {'status': 200, 'bytes': expired_day['bytes']}, f'ETag probe did not recover the cached body: {probe}'
        probe_event = [event for event in cache_scenario_events(scenario) if event['path'] == expired_path][-1]
        assert probe_event['status'] == 304 and probe_event['if_none_match'], f'Expired ETag probe did not receive 304: {probe_event}'
        expiry_marker = len(cache_scenario_events(scenario))
        page.reload(wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expiry_events = [event for event in cache_scenario_events(scenario)[expiry_marker:] if event['path'] == expired_path]
        assert len(expiry_events) == 1 and expiry_events[0]['status'] == 304 and expiry_events[0]['if_none_match'], f'Default cache mode did not revalidate the expired ETag: {expiry_events}'
        results['expired_etag'] = {'probe_revalidation': 304, 'application_default_cache_revalidation': 304, 'body_bytes': 0}
    finally:
        context.close()

    # A tampered response is retried once, remains untrusted, and never renders partial rows.
    tampered_body = (ROOT / target_path).read_bytes()
    tampered_body = tampered_body[:-1] + (b' ' if tampered_body.endswith(b'\n') else b'!')
    with scenario['lock']:
        scenario['overrides'] = {manifest_path: manifest_raw}
        scenario['responses'] = {target_path: (200, tampered_body)}
        scenario['events'] = []
        scenario['counts'] = {}
    tamper_context = browser.new_context(viewport={'width': 1280, 'height': 900})
    tamper_page = tamper_context.new_page()
    browser_issue_track(tamper_page, issues, origin)
    try:
        tamper_page.goto(f'{origin}/?page=center', wait_until='load')
        expect(tamper_page.locator('#result-status')).to_contain_text('could not be verified', timeout=120_000)
        expect(tamper_page.locator('#record-list .record-row')).to_have_count(0)
        assert tamper_page.locator('#feed-view').get_attribute('aria-busy') == 'false'
        tamper_events = [event for event in cache_scenario_events(scenario) if event['path'] == target_path]
        assert len(tamper_events) == 2, f'Tampered shard did not receive exactly one retry: {tamper_events}'
        results['tampered_network_resource'] = {'attempts': len(tamper_events), 'rendered_records': 0, 'state': 'fail-closed'}
    finally:
        tamper_context.close()

    # Malformed JSON with a matching declared byte count/hash fails parsing without a retry or partial success.
    malformed = b'{not valid JSON'
    malformed_manifest = json.loads(json.dumps(manifest))
    malformed_day = malformed_manifest['days'][0]
    malformed_day['bytes'] = len(malformed)
    malformed_day['sha256'] = hashlib.sha256(malformed).hexdigest()
    malformed_manifest_raw = json.dumps(malformed_manifest, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    malformed_path = f"snapshot/{malformed_day['path']}"
    with scenario['lock']:
        scenario['overrides'] = {manifest_path: malformed_manifest_raw, malformed_path: malformed}
        scenario['responses'] = {}
        scenario['events'] = []
        scenario['counts'] = {}
    malformed_context = browser.new_context(viewport={'width': 1280, 'height': 900})
    malformed_page = malformed_context.new_page()
    browser_issue_track(malformed_page, issues, origin)
    try:
        malformed_page.goto(f'{origin}/?page=center', wait_until='load')
        expect(malformed_page.locator('#result-status')).to_contain_text('could not be verified', timeout=120_000)
        expect(malformed_page.locator('#record-list .record-row')).to_have_count(0)
        malformed_events = [event for event in cache_scenario_events(scenario) if event['path'] == malformed_path]
        assert len(malformed_events) == 1, f'Hash-valid malformed JSON should fail schema parsing without cache retry: {malformed_events}'
        results['malformed_json'] = {'attempts': 1, 'rendered_records': 0, 'state': 'fail-closed'}
    finally:
        malformed_context.close()
        server.shutdown()
        server.server_close()

    assert not issues['page_errors'], f"Cache browser page errors: {issues['page_errors']}"
    assert not issues['console_errors'], f"Cache browser console errors: {issues['console_errors']}"
    assert not issues['request_failures'], f"Cache browser request failures: {issues['request_failures']}"
    assert not issues['external_requests'], f"Unexpected external requests in cache tests: {issues['external_requests']}"
    return results


def run_swipe_navigation_tests(browser, origin: str, manifest: dict) -> dict:
    """Exercise the touch-only page gesture with real Chromium touch input."""
    issues = {'page_errors': [], 'console_errors': [], 'request_failures': [], 'external_requests': []}
    context = browser.new_context(
        viewport={'width': 390, 'height': 844}, device_scale_factor=1,
        is_mobile=True, has_touch=True,
    )
    page = context.new_page()
    browser_issue_track(page, issues, origin)
    cdp = context.new_cdp_session(page)
    url = f'{origin}/?page=overview'

    def dispatch_touch(kind: str, x: int | None = None, y: int | None = None, timestamp: float | None = None) -> None:
        points = [] if kind == 'touchEnd' else [{'x': x, 'y': y, 'id': 1}]
        event = {'type': kind, 'touchPoints': points}
        if timestamp is not None:
            event['timestamp'] = timestamp
        cdp.send('Input.dispatchTouchEvent', event)

    def swipe(
        start_x: int,
        start_y: int,
        delta_x: int,
        delta_y: int = 0,
        *,
        steps: int = 6,
        delay_ms: int = 12,
        initial_delay_ms: int = 0,
    ) -> None:
        dispatch_touch('touchStart', start_x, start_y)
        if initial_delay_ms:
            page.wait_for_timeout(initial_delay_ms)
        for step in range(1, steps + 1):
            dispatch_touch(
                'touchMove',
                round(start_x + delta_x * step / steps),
                round(start_y + delta_y * step / steps),
            )
            if delay_ms:
                page.wait_for_timeout(delay_ms)
        dispatch_touch('touchEnd')

    def expect_active(name: str) -> None:
        expect(page.locator(f'#page-{name}')).to_be_visible()
        for candidate in ('overview', 'center', 'community'):
            tab = page.locator(f'#tab-{candidate}')
            selected = candidate == name
            actual = tab.get_attribute('aria-selected')
            actual_tabs = page.locator('.nav-tab').evaluate_all(
                '(items) => items.map((item) => [item.id, item.getAttribute("aria-selected"), item.tabIndex])'
            )
            assert actual == str(selected).lower(), (
                f'{candidate} aria-selected={actual} after expecting {name}; tabs={actual_tabs}'
            )
            assert tab.evaluate('(element) => element.tabIndex') == (0 if selected else -1)
        page.wait_for_function("() => !document.querySelector('.page.is-swipe-settling')", timeout=2_000)

    def drag_from_edge(direction: str, distance: int = 150, *, y: int = 500, steps: int = 6, delay_ms: int = 12) -> None:
        x = 382 if direction == 'left' else 8
        dx = -distance if direction == 'left' else distance
        swipe(x, y, dx, steps=steps, delay_ms=delay_ms)

    def point(selector: str, x_fraction: float = 0.5, y_fraction: float = 0.5) -> tuple[int, int]:
        box = page.locator(selector).bounding_box()
        assert box is not None, f'Missing visible test target: {selector}'
        return round(box['x'] + box['width'] * x_fraction), round(box['y'] + box['height'] * y_fraction)

    def safe_drag_corridor(target_page, direction: str = 'left', distance: int = 190) -> dict:
        corridor = target_page.evaluate('''({direction, distance}) => {
          const active = document.querySelector('.page:not([hidden])');
          const blocked = 'a[href], button, input, select, textarea, option, summary, details, [role="button"], [role="link"], [role="combobox"], [role="textbox"], [role="dialog"], [aria-modal="true"], [contenteditable]:not([contenteditable="false"]), .record-list, .record-row, .center-dock, .filter-controls, .severity-distribution, .pagination, .detail-view, .snapshot-loader, .ui-stage, .snapshot-status-strip, .snapshot-rail, .latest-list, .snapshot-summary, article, .terminal-frame';
          const hasTextAtPoint = (x, y) => {
            let node = null;
            let offset = 0;
            if (typeof document.caretRangeFromPoint === 'function') {
              const range = document.caretRangeFromPoint(x, y);
              node = range?.startContainer ?? null;
              offset = range?.startOffset ?? 0;
            } else if (typeof document.caretPositionFromPoint === 'function') {
              const caret = document.caretPositionFromPoint(x, y);
              node = caret?.offsetNode ?? null;
              offset = caret?.offset ?? 0;
            }
            if (!node || node.nodeType !== Node.TEXT_NODE) return false;
            const text = node.textContent || '';
            for (const index of [offset, offset - 1]) {
              if (index < 0 || index >= text.length || /\\s/u.test(text[index])) continue;
              const character = document.createRange();
              character.setStart(node, index);
              character.setEnd(node, index + 1);
              for (const rect of character.getClientRects()) {
                if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) return true;
              }
            }
            return false;
          };
          const sign = direction === 'left' ? -1 : 1;
          const firstX = direction === 'left' ? innerWidth - distance - 24 : 24;
          const lastX = direction === 'left' ? distance + 24 : innerWidth - distance - 24;
          for (let y = 92; y < innerHeight - 28; y += 12) {
            for (let x = firstX; direction === 'left' ? x >= lastX : x <= lastX; x += direction === 'left' ? -12 : 12) {
              let safe = true;
              for (let offset = 0; offset <= distance; offset += 6) {
                const px = x + sign * offset;
                const hit = document.elementFromPoint(px, y);
                if (!(hit instanceof Element) || hit.closest('.page') !== active || hit.closest(blocked) || hasTextAtPoint(px, y)) {
                  safe = false;
                  break;
                }
              }
              if (safe) return {x, y, active: active?.id ?? null, target: document.elementFromPoint(x, y)?.tagName ?? null};
            }
          }
          return null;
        }''', {'direction': direction, 'distance': distance})
        assert corridor is not None, f'No empty safe desktop drag corridor found on {target_page.url}: {direction} {distance}px'
        return corridor

    def best_detail_record() -> str:
        best_id = ''
        best_weight = -1
        for day in manifest['days']:
            rows = json.loads((ROOT / 'snapshot' / day['path']).read_text(encoding='utf-8'))
            for record in rows:
                weight = len(str(record.get('desc') or ''))
                weight += 120 * len(record.get('refs') or [])
                weight += 110 * len(record.get('affected') or [])
                weight += 100 * len(record.get('advisories') or [])
                weight += 80 * len(record.get('related_cves') or [])
                if weight > best_weight:
                    best_id, best_weight = record['id'], weight
        return best_id

    try:
        page.goto(url, wait_until='load')
        expect_active('overview')
        assert page.evaluate("getComputedStyle(document.querySelector('#main-content')).touchAction") == 'pan-y pinch-zoom'

        # The first-page edge resists but never wraps; a short horizontal drag visibly follows the finger and returns.
        drag_from_edge('right', 220)
        expect_active('overview')
        start_x, start_y = 382, 500
        dispatch_touch('touchStart', start_x, start_y)
        dispatch_touch('touchMove', start_x - 24, start_y)
        visual = page.evaluate('''() => {
          const current = document.querySelector('#page-overview');
          const next = document.querySelector('#page-center');
          return {
            currentTracking: current.classList.contains('is-swipe-tracking'),
            currentTransform: getComputedStyle(current).transform,
            nextTracking: next.classList.contains('is-swipe-tracking'),
            nextTransform: getComputedStyle(next).transform,
          };
        }''')
        assert visual['currentTracking'] and visual['currentTransform'] != 'none', f'Current page did not track a short horizontal drag: {visual}'
        assert visual['nextTracking'] and visual['nextTransform'] != 'none', f'Adjacent page did not track alongside the current page: {visual}'
        dispatch_touch('touchEnd')
        expect_active('overview')
        page.wait_for_function("() => !document.querySelector('#page-overview').classList.contains('is-swipe-settling')", timeout=2_000)
        assert page.locator('#page-overview').evaluate('element => getComputedStyle(element).transform') == 'none'

        # A short, fast deliberate gesture may pass the distance threshold through velocity.
        fast_swipe_start = time.time()
        dispatch_touch('touchStart', 382, 500, timestamp=fast_swipe_start)
        dispatch_touch('touchMove', 334, 500, timestamp=fast_swipe_start + 0.04)
        dispatch_touch('touchEnd', timestamp=fast_swipe_start + 0.05)
        expect_active('center')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect_active('center')

        # All four adjacent routes work; the state remains synchronized with the existing tabs.
        drag_from_edge('right')
        expect_active('overview')
        drag_from_edge('left')
        expect_active('center')
        drag_from_edge('left')
        expect_active('community')
        assert page.url == url, f'Swipe changed the established page URL/history model: {page.url}'

        # The last-page edge cannot wrap. The terminal's blank panel padding remains a valid swipe surface.
        page.wait_for_function("() => !document.querySelector('#terminal-info').hidden", timeout=15_000)
        terminal = page.locator('.terminal-screen').bounding_box()
        assert terminal is not None
        panel_x, panel_y = round(terminal['x'] + 5), round(terminal['y'] + 4)
        panel_target = page.evaluate('([x, y]) => { const el = document.elementFromPoint(x, y); return {inside: Boolean(el?.closest(".terminal-frame")), control: Boolean(el?.closest("button, a[href], input, select, textarea"))}; }', [panel_x, panel_y])
        assert panel_target == {'inside': True, 'control': False}, f'Terminal swipe test did not start on safe panel background: {panel_target}'
        swipe(round(terminal['x'] + terminal['width'] - 5), panel_y, -180, steps=6, delay_ms=12)
        expect_active('community')
        swipe(panel_x, panel_y, 160, steps=6, delay_ms=12)
        expect_active('center')
        assert page.url == url, 'Community-to-Center swipe added or rewrote browser history.'

        # Search input and pagination controls keep their own horizontal/tap interaction.
        search_x, search_y = point('#record-search')
        swipe(search_x, search_y, -130, steps=5, delay_ms=12)
        expect_active('center')
        page.locator('#record-search').fill('')
        page.locator('#page-size').select_option('48')
        page.locator('#page-next').scroll_into_view_if_needed()
        next_x, next_y = point('#page-next')
        swipe(next_x, next_y, -130, steps=5, delay_ms=12)
        expect_active('center')
        page.locator('#page-next').click()
        expect(page.locator('#page-indicator')).to_contain_text('Page 2 of')
        page.evaluate("document.documentElement.style.scrollBehavior = 'auto'; window.scrollTo(0, 0)")
        page.wait_for_function('window.scrollY === 0')
        safe_start = page.evaluate("""() => {
          const target = document.elementFromPoint(382, 150);
          return {
            page: target?.closest('.page')?.id ?? null,
            blocked: Boolean(target?.closest('a[href], button, input, select, textarea, [role="button"], [role="link"], .record-row, .pagination, .detail-view, .ui-stage')),
          };
        }""")
        assert safe_start == {'page': 'page-center', 'blocked': False}, f'Post-pagination swipe did not start on a safe Center background: {safe_start}'
        drag_from_edge('left', y=150)
        expect_active('community')
        swipe(panel_x, panel_y, 160, steps=6, delay_ms=12)
        expect_active('center')
        expect(page.locator('#page-indicator')).to_contain_text('Page 2 of')

        # Vertical and vertical-dominant diagonal movement scroll the Center without changing pages.
        page.evaluate('window.scrollTo(0, 0)')
        scroll_before = page.evaluate('window.scrollY')
        swipe(8, 700, 0, -220, steps=6, delay_ms=12)
        page.wait_for_function('(before) => window.scrollY > before + 30', arg=scroll_before, timeout=3_000)
        expect_active('center')
        swipe(8, 600, 70, 100, steps=6, delay_ms=12)
        expect_active('center')

        # A long, verified record makes the detail view scrollable; content interactions do not initiate navigation.
        detail_id = best_detail_record()
        page.locator('#record-search').fill(detail_id)
        expect(page.locator('.record-row')).to_have_count(1)
        page.locator('.record-open').click()
        expect(page.locator('#detail-view')).to_be_visible()
        expect(page.locator('#detail-heading')).to_have_text(detail_id)
        assert page.locator('#detail-content a[href^="https://"]').count() > 0, 'CVE source links are missing from the detail view.'
        heading_x, heading_y = point('#detail-heading')
        swipe(heading_x, heading_y, -160, steps=5, delay_ms=12)
        expect_active('center')
        expect(page.locator('#detail-view')).to_be_visible()
        assert page.evaluate('document.documentElement.scrollHeight > window.innerHeight'), 'Selected CVE detail record did not exercise a vertically scrollable view.'
        detail_scroll_before = page.evaluate('window.scrollY')
        description_x, description_y = point('#detail-view .detail-description')
        swipe(description_x, description_y, 0, -180, steps=6, delay_ms=12)
        page.wait_for_function('(before) => window.scrollY > before + 20', arg=detail_scroll_before, timeout=3_000)
        expect_active('center')

        # Swiping from the safe page background preserves the detail, search, and URL state.
        page.evaluate('window.scrollTo(0, 0)')
        drag_from_edge('left')
        expect_active('community')
        assert page.url == url
        page.wait_for_function("() => !document.querySelector('#terminal-info').hidden", timeout=15_000)
        terminal = page.locator('.terminal-screen').bounding_box()
        assert terminal is not None
        panel_x, panel_y = round(terminal['x'] + 5), round(terminal['y'] + 4)

        # A real text-selection state arriving during a panel gesture cancels the page swipe.
        text_x, text_y = point('#terminal-info .info-description')
        dispatch_touch('touchStart', text_x, text_y)
        dispatch_touch('touchMove', text_x + 45, text_y)
        page.locator('#terminal-info .info-description').evaluate('''element => {
          const selection = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(element);
          selection.removeAllRanges();
          selection.addRange(range);
        }''')
        page.wait_for_timeout(30)
        dispatch_touch('touchEnd')
        expect_active('community')
        assert page.locator('#page-community').evaluate('element => !element.classList.contains("is-swipe-tracking")')
        page.evaluate('window.getSelection()?.removeAllRanges()')

        # The terminal background supports Community → Center while existing detail/search state survives.
        swipe(panel_x, panel_y, 160, steps=6, delay_ms=12)
        expect_active('center')
        expect(page.locator('#detail-view')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(detail_id)
        assert page.url == url
        page.locator('#back-to-results').click()
        expect(page.locator('#record-search')).to_have_value(detail_id)
        expect(page.locator('.record-row')).to_have_count(1)

        # Reduced motion keeps navigation available without applying a page slide.
        page.emulate_media(reduced_motion='reduce')
        assert page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches")
        page.evaluate('window.scrollTo(0, 0)')
        page.wait_for_function('window.scrollY === 0')
        safe_start = page.evaluate("""() => {
          const target = document.elementFromPoint(382, 150);
          return {
            page: target?.closest('.page')?.id ?? null,
            blocked: Boolean(target?.closest('a[href], button, input, select, textarea, [role="button"], [role="link"], .record-row, .pagination, .detail-view, .ui-stage')),
          };
        }""")
        assert safe_start == {'page': 'page-center', 'blocked': False}, f'Reduced-motion swipe did not start on a safe Center background: {safe_start}'
        drag_from_edge('left', y=150)
        expect_active('community')
        assert not page.locator('#page-community').evaluate('element => element.classList.contains("page-enter")')
        terminal = page.locator('.terminal-screen').bounding_box()
        assert terminal is not None
        swipe(round(terminal['x'] + 5), round(terminal['y'] + 4), 160, steps=6, delay_ms=12)
        expect_active('center')
        assert not page.locator('#page-center').evaluate('element => element.classList.contains("page-enter")')
        context.close()

        # Desktop drags only navigate from empty, text-free safe areas; text, controls, and click state stay native.
        desktop = browser.new_context(viewport={'width': 1280, 'height': 900}, has_touch=False)
        desktop_page = desktop.new_page()
        browser_issue_track(desktop_page, issues, origin)
        desktop_page.goto(url, wait_until='load')
        expect(desktop_page.locator('#page-overview')).to_be_visible()

        safe = safe_drag_corridor(desktop_page)
        desktop_page.mouse.click(safe['x'], safe['y'])
        expect(desktop_page.locator('#page-overview')).to_be_visible()

        heading = desktop_page.locator('#page-overview h1').bounding_box()
        assert heading is not None
        text_start = (round(heading['x'] + 8), round(heading['y'] + heading['height'] / 2))
        assert desktop_page.evaluate('([x, y]) => { const range = document.caretRangeFromPoint(x, y); return Boolean(range && range.startContainer.nodeType === Node.TEXT_NODE); }', list(text_start)), 'Desktop selection test did not start on actual Overview text.'
        desktop_page.mouse.move(*text_start)
        desktop_page.mouse.down()
        desktop_page.mouse.move(text_start[0] + 72, text_start[1], steps=5)
        desktop_page.mouse.up()
        assert desktop_page.evaluate('window.getSelection()?.toString().length > 0'), 'A mouse drag on Overview text no longer selects text.'
        expect(desktop_page.locator('#page-overview')).to_be_visible()
        desktop_page.evaluate('window.getSelection()?.removeAllRanges()')

        # Overview's stacked record cards are never desktop swipe surfaces, even in their blank margins.
        stage = desktop_page.locator('.ui-stage').bounding_box()
        assert stage is not None
        card_point = (round(stage['x'] + stage['width'] * 0.95), round(stage['y'] + stage['height'] * 0.08))
        assert desktop_page.evaluate('([x, y]) => Boolean(document.elementFromPoint(x, y)?.closest(".ui-stage"))', list(card_point))
        desktop_page.mouse.move(*card_point)
        desktop_page.mouse.down()
        desktop_page.mouse.move(card_point[0] - 190, card_point[1], steps=8)
        desktop_page.mouse.up()
        expect(desktop_page.locator('#page-overview')).to_be_visible()

        desktop_page.locator('#tab-community').click()
        expect(desktop_page.locator('#page-community')).to_be_visible()
        desktop_page.locator('#tab-overview').click()
        safe = safe_drag_corridor(desktop_page)
        desktop_page.mouse.move(safe['x'], safe['y'])
        desktop_page.mouse.down()
        desktop_page.mouse.move(safe['x'] - 36, safe['y'], steps=3)
        live_pair = desktop_page.evaluate('''() => {
          const current = document.querySelector('#page-overview');
          const next = document.querySelector('#page-center');
          return {
            currentTracking: current.classList.contains('is-swipe-tracking'),
            currentTransform: getComputedStyle(current).transform,
            nextTracking: next.classList.contains('is-swipe-tracking'),
            nextTransform: getComputedStyle(next).transform,
          };
        }''')
        assert live_pair['currentTracking'] and live_pair['currentTransform'] != 'none', f'Mouse drag did not move Overview during tracking: {live_pair}'
        assert live_pair['nextTracking'] and live_pair['nextTransform'] != 'none', f'Mouse drag did not move the adjacent page during tracking: {live_pair}'
        desktop_page.mouse.move(safe['x'] - 190, safe['y'], steps=10)
        desktop_page.mouse.up()
        expect(desktop_page.locator('#page-center')).to_be_visible()
        desktop_page.wait_for_function("() => !document.querySelector('.page.is-swipe-settling')", timeout=2_000)
        assert desktop_page.locator('#tab-center').get_attribute('aria-selected') == 'true'
        assert desktop_page.locator('#tab-center').evaluate('element => element.tabIndex') == 0
        assert desktop_page.locator('#tab-overview').evaluate('element => element.tabIndex') == -1
        assert desktop_page.url == url, 'A desktop drag changed the established URL/history model.'

        # A successful drag's generated click is contained; the next deliberate navigation-button click still works.
        desktop_page.locator('#tab-overview').click()
        desktop_page.locator('#explore-cves').click()
        expect(desktop_page.locator('#page-center')).to_be_visible()
        assert desktop_page.locator('#tab-center').get_attribute('aria-selected') == 'true'

        # Chromium's native input protocol emits pen Pointer Events; only a safe, primary-tip drag may navigate.
        desktop_page.locator('#tab-overview').click()
        safe = safe_drag_corridor(desktop_page)
        desktop_page.evaluate('''() => {
          window.__observedPenDown = false;
          document.addEventListener('pointerdown', event => {
            if (event.pointerType === 'pen' && event.isPrimary && event.button === 0) window.__observedPenDown = true;
          }, true);
        }''')
        pen = desktop.new_cdp_session(desktop_page)
        pen.send('Input.dispatchMouseEvent', {'type': 'mousePressed', 'x': safe['x'], 'y': safe['y'], 'button': 'left', 'buttons': 1, 'pointerType': 'pen'})
        pen.send('Input.dispatchMouseEvent', {'type': 'mouseMoved', 'x': safe['x'] - 190, 'y': safe['y'], 'buttons': 1, 'pointerType': 'pen'})
        pen.send('Input.dispatchMouseEvent', {'type': 'mouseReleased', 'x': safe['x'] - 190, 'y': safe['y'], 'button': 'left', 'buttons': 0, 'pointerType': 'pen'})
        assert desktop_page.evaluate('window.__observedPenDown'), 'Chromium did not deliver the expected primary pen Pointer Event.'
        expect(desktop_page.locator('#page-center')).to_be_visible()
        assert desktop_page.locator('#tab-center').get_attribute('aria-selected') == 'true'

        # A manual tab change immediately after a swipe wins over the pending page animation cleanup.
        desktop_page.locator('#tab-overview').click()
        desktop_page.wait_for_function("() => !document.querySelector('.page.is-swipe-settling')", timeout=2_000)
        expect(desktop_page.locator('#page-overview')).to_be_visible()
        expect(desktop_page.locator('#page-center')).to_be_hidden()
        assert desktop_page.locator('#tab-overview').get_attribute('aria-selected') == 'true'

        # A primary pen drag that starts on actual text leaves the text and active route native.
        heading = desktop_page.locator('#page-overview h1').bounding_box()
        assert heading is not None
        pen_text_x = round(heading['x'] + 8)
        pen_text_y = round(heading['y'] + heading['height'] / 2)
        pen.send('Input.dispatchMouseEvent', {'type': 'mousePressed', 'x': pen_text_x, 'y': pen_text_y, 'button': 'left', 'buttons': 1, 'pointerType': 'pen'})
        pen.send('Input.dispatchMouseEvent', {'type': 'mouseMoved', 'x': pen_text_x + 72, 'y': pen_text_y, 'buttons': 1, 'pointerType': 'pen'})
        pen.send('Input.dispatchMouseEvent', {'type': 'mouseReleased', 'x': pen_text_x + 72, 'y': pen_text_y, 'button': 'left', 'buttons': 0, 'pointerType': 'pen'})
        expect(desktop_page.locator('#page-overview')).to_be_visible()
        assert desktop_page.locator('#tab-overview').get_attribute('aria-selected') == 'true'

        desktop_page.emulate_media(reduced_motion='reduce')
        safe = safe_drag_corridor(desktop_page)
        desktop_page.mouse.move(safe['x'], safe['y'])
        desktop_page.mouse.down()
        desktop_page.mouse.move(safe['x'] - 190, safe['y'], steps=8)
        desktop_page.mouse.up()
        expect(desktop_page.locator('#page-center')).to_be_visible()
        assert not desktop_page.locator('#page-center').evaluate('element => element.classList.contains("page-enter")')

        desktop_page.locator('#tab-overview').focus()
        desktop_page.keyboard.press('ArrowRight')
        expect_active_name = desktop_page.locator('#tab-center').get_attribute('aria-selected')
        assert expect_active_name == 'true' and desktop_page.evaluate('document.activeElement.id') == 'tab-center'
        desktop_page.keyboard.press('Home')
        assert desktop_page.locator('#tab-overview').get_attribute('aria-selected') == 'true'
        for page_name in ('overview', 'center', 'community'):
            desktop_page.locator(f'#tab-{page_name}').click()
            desktop_page.locator(f'#tab-{page_name}').focus()
            desktop_page.keyboard.press('Shift+Tab')
            desktop_page.keyboard.press('Shift+Tab')
            assert desktop_page.evaluate('document.activeElement.matches(".skip-link")'), f'Skip link was not reached before the header from {page_name}.'
            desktop_page.keyboard.press('Enter')
            assert desktop_page.evaluate('document.activeElement.id') == 'main-content', f'Skip link did not focus the main region from {page_name}.'
            assert desktop_page.evaluate('location.hash') == '#main-content', f'Skip link target changed from main content on {page_name}.'
            expect(desktop_page.locator(f'#page-{page_name}')).to_be_visible()
        desktop_page.locator('#tab-overview').click()
        desktop.close()
    finally:
        context.close()

    assert not issues['page_errors'], f'Swipe browser page errors: {issues["page_errors"]}'
    assert not issues['console_errors'], f'Swipe browser console errors: {issues["console_errors"]}'
    assert not issues['request_failures'], f'Swipe browser request failures: {issues["request_failures"]}'
    assert not issues['external_requests'], f'Unexpected external requests in swipe tests: {issues["external_requests"]}'
    return {
        'mobile_viewport': [390, 844],
        'adjacent_routes_and_no_wrap': True,
        'finger_tracking_and_short_cancel': True,
        'fast_swipe': True,
        'vertical_and_diagonal_scroll': True,
        'search_pagination_and_detail_state_preserved': True,
        'detail_content_scroll_and_safe_interaction': True,
        'community_terminal_background_and_selection_cancel': True,
        'url_and_history_model_preserved': True,
        'reduced_motion_and_keyboard_navigation': True,
        'desktop_mouse_pen_safe_area_drag_and_click_selection_protection': True,
        'paired_page_live_transforms': True,
        'external_requests': 0,
    }


def main() -> None:
    manifest, overview, days = load_contract()
    expected_count = manifest['totals']['cves']
    expected_latest = [record['id'] for record in overview['records']]
    latest_day = next(day for day in reversed(manifest['days']) if day['count'])
    latest_shard = json.loads((ROOT / 'snapshot' / latest_day['path']).read_text(encoding='utf-8'))
    sample = latest_shard[0]
    sample_id = sample['id']
    sample_day = sample['window_date']
    sample_day_count = days[sample_day]['count']
    assert expected_latest and len(expected_latest) == min(3, expected_count)

    issues = {'page_errors': [], 'console_errors': [], 'request_failures': [], 'external_requests': []}
    handler = functools.partial(QuietHandler, directory=str(ROOT))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{server.server_port}'

    try:
        with sync_playwright() as playwright:
            launch = {'headless': True, 'args': ['--no-sandbox', '--disable-dev-shm-usage']}
            chromium = shutil.which('chromium')
            if chromium:
                launch['executable_path'] = chromium
            browser = playwright.chromium.launch(**launch)

            overview_page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            browser_issue_track(overview_page, issues, origin)
            overview_requests: list[str] = []
            overview_page.on('request', lambda request: overview_requests.append(request.url)
                             if '/snapshot/data/' in request.url and not request.url.endswith(('/overview.json', '/epss.json')) else None)
            overview_page.goto(f'{origin}/', wait_until='load')
            expect(overview_page.locator('#overview-status')).to_contain_text(f'{nfmt(expected_count)} CVE records')
            expect(overview_page.locator('#overview-status')).to_have_attribute('aria-busy', 'false')
            assert overview_page.locator('.latest-id').all_text_contents() == expected_latest
            assert overview_page.locator('.latest-id').evaluate_all('links => links.map(link => link.getAttribute("href"))') == [
                f'?page=center&cve={cve_id}' for cve_id in expected_latest
            ]
            assert overview_page.locator('#overview-generated-at time').get_attribute('datetime') == manifest['generated_at']
            for record in overview['records']:
                assert record['id'] in overview_page.locator('.ui-stage').inner_text()
            overview_page.wait_for_timeout(100)
            assert not overview_requests, f'Overview fetched full shards unnecessarily: {overview_requests}'
            csp = overview_page.locator('meta[http-equiv="Content-Security-Policy"]').get_attribute('content')
            assert "default-src 'self'" in csp and "script-src 'self'" in csp and "object-src 'none'" in csp
            overview_page.screenshot(path=str(SCREENSHOTS / '01-overview-desktop.png'))

            # Each Overview link is a real deep link into its exact verified record.
            overview_page.locator('.latest-id').first.click()
            expect(overview_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(overview_page.locator('#detail-heading')).to_have_text(expected_latest[0])
            expect(overview_page).to_have_url(f'{origin}/?page=center&cve={expected_latest[0]}')
            overview_page.keyboard.press('Escape')
            expect(overview_page.locator('#detail-view')).to_be_hidden()
            assert overview_page.evaluate('document.activeElement.dataset.cveId') == expected_latest[0]
            overview_page.goto(f'{origin}/?page=overview', wait_until='load')
            overview_page.locator('#explore-cves').click()
            expect(overview_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(overview_page.locator('.record-row')).to_have_count(min(24, expected_count))
            assert len(overview_requests) >= len(manifest['days'])
            overview_page.close()
            print('PASS: authenticated Overview content, generated timestamp, no eager shard fetch, complete lazy Explore, deep links, and focus restoration.')

            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            browser_issue_track(page, issues, origin)
            page.goto(f'{origin}/?page=center', wait_until='load')
            expect(page.locator('#page-center')).to_be_visible()
            expect(page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(page.locator('#snapshot-kev-total')).to_have_text(nfmt(manifest['totals']['known_exploited']))
            expect(page.locator('#result-status')).to_contain_text(f'of {nfmt(expected_count)} matching records')
            expect(page.locator('.record-row')).to_have_count(min(24, expected_count))
            assert page.locator('.record-row').first.get_attribute('data-cve-id') == expected_latest[0]
            assert page.locator('#record-list').get_attribute('aria-busy') == 'false'
            if source_epss_stale(manifest):
                expect(page.locator('#epss-warning')).to_be_visible()
                expect(page.locator('#epss-warning')).to_contain_text('marked stale')
                expect(page.locator('#epss-warning')).to_contain_text('not 0%')
            else:
                expect(page.locator('#epss-warning')).to_be_hidden()
            page.screenshot(path=str(SCREENSHOTS / '02-cve-center-desktop.png'))

            # Pagination and severity totals are calculated from the signed-off manifest contract.
            first_id = page.locator('.record-row').first.get_attribute('data-cve-id')
            page_count = (expected_count + 23) // 24
            page.locator('#page-next').click()
            expect(page.locator('#page-indicator')).to_have_text(f'Page 2 of {page_count}')
            expect(page.locator('#result-status')).to_contain_text(f'of {nfmt(expected_count)} matching records')
            assert page.locator('.record-row').first.get_attribute('data-cve-id') != first_id
            page.locator('#page-prev').click()
            page.locator('#page-size').select_option('48')
            expect(page.locator('.record-row')).to_have_count(min(48, expected_count))
            page.locator('#page-size').select_option('96')
            expect(page.locator('.record-row')).to_have_count(min(96, expected_count))
            page.locator('#page-size').select_option('24')
            for severity in ('critical', 'high', 'medium', 'low', 'unrated'):
                button = page.locator(f'.severity-tab[data-severity="{severity}"]')
                button.click()
                if severity == 'unrated':
                    total = manifest['totals']['none'] + manifest['totals']['unknown']
                else:
                    total = manifest['totals'][severity]
                expect(page.locator('#result-status')).to_contain_text(f'of {nfmt(total)} matching records')
                assert button.get_attribute('aria-pressed') == 'true'
                assert all(f'severity-{severity}' in classes.split() for classes in page.locator('.record-row').evaluate_all('rows => rows.map(row => row.className)'))
            page.locator('.severity-tab[data-severity="all"]').click()
            print('PASS: full-feed count, newest ordering, paging/page sizes, and all five severity groups match manifest totals.')

            # A one-day date filter and exact CVE search preserve complete-snapshot totals.
            page.locator('#date-filter summary').click()
            page.locator('#date-from').fill(sample_day)
            page.locator('#date-to').fill(sample_day)
            page.locator('#date-form button[type="submit"]').click()
            expect(page.locator('#result-status')).to_contain_text(f'of {nfmt(sample_day_count)} matching records')
            expect(page.locator('#snapshot-total')).to_have_text(nfmt(expected_count))
            page.locator('#record-search').fill(sample_id)
            expect(page.locator('.record-row')).to_have_count(1)
            expect(page.locator('.record-row').first).to_have_attribute('data-cve-id', sample_id)
            page.locator('.record-open').click()
            expect(page.locator('#detail-heading')).to_have_text(sample_id)
            expect(page.locator('#detail-content dt').filter(has_text='CVSS severity')).to_have_count(1)
            expect(page.locator('#detail-content dt').filter(has_text='EPSS probability')).to_have_count(1)
            expect(page.locator('#detail-content dt').filter(has_text='CISA KEV evidence')).to_have_count(1)
            page.screenshot(path=str(SCREENSHOTS / '03-cve-detail-desktop.png'), full_page=True)
            page.locator('#back-to-results').click()
            expect(page.locator('.record-row')).to_have_count(1)
            assert page.evaluate('document.activeElement.dataset.cveId') == sample_id
            page.locator('#record-search').fill('')
            page.locator('#date-filter summary').click()
            page.locator('#date-from').fill(manifest['window']['start'][:10])
            page.locator('#date-to').fill(manifest['window']['end'][:10])
            page.locator('#date-form button[type="submit"]').click()
            print('PASS: date filter, exact-ID search, separate signal details, and filtered result/focus restoration.')

            loader_results = run_snapshot_loader_tests(browser, manifest)
            print('PASS: truthful loader progress through delayed manifest, out-of-order verified shards, final sidecar validation, responsive/reduced-motion states, re-entry, source failure, and retry.')
            print('Loader QA details:', json.dumps(loader_results, sort_keys=True))

            cache_results = run_http_cache_tests(browser, manifest)
            print('PASS: HTTP cache revalidation, changed-hash retry, expired ETag, malformed/tampered fail-closed behavior, and zero unnecessary repeat JSON bodies.')
            print('HTTP cache QA details:', json.dumps(cache_results, sort_keys=True))

            # A correctly re-hashed malicious text fixture remains text, never active markup.
            malicious_rows = json.loads((ROOT / 'snapshot' / latest_day['path']).read_text(encoding='utf-8'))
            victim = next((record for record in malicious_rows if record['id'] not in expected_latest), malicious_rows[0])
            victim_id = victim['id']
            title_payload = '<img data-xss="title" src=x onerror="window.__subzeroXss=1">'
            description_payload = '<script data-xss="description">window.__subzeroXss=1</script>'
            label_payload = '<svg data-xss="label" onload="window.__subzeroXss=2">'
            victim['title'] = title_payload
            victim['desc'] = description_payload
            victim['refs'] = list(victim.get('refs') or []) + [{
                'label': label_payload, 'url': 'https://example.com/security/advisory', 'source': 'NVD'
            }]
            override_manifest, override_shard, override_day = snapshot_override(manifest, latest_day, malicious_rows)
            xss_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(xss_page, issues, origin)
            install_snapshot_override(xss_page, override_manifest, override_shard, override_day)
            xss_page.goto(f'{origin}/?page=center', wait_until='load')
            expect(xss_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            xss_page.locator('#record-search').fill(victim_id)
            expect(xss_page.locator('.record-row')).to_have_count(1)
            expect(xss_page.locator('.record-title')).to_have_text(title_payload)
            xss_page.locator('.record-open').click()
            expect(xss_page.locator('.detail-title')).to_have_text(title_payload)
            expect(xss_page.locator('.detail-description')).to_have_text(description_payload)
            assert xss_page.locator('img[data-xss], svg[data-xss], script[data-xss]').count() == 0
            assert xss_page.evaluate('window.__subzeroXss === undefined')
            assert label_payload in xss_page.locator('#detail-content').inner_text()
            xss_page.close()
            print('PASS: manifest-consistent untrusted text remains inert and no injected nodes or script execution occur.')

            # Tampering without changing the authenticated manifest hash fails closed and shows no partial rows.
            tampered_rows = json.loads((ROOT / 'snapshot' / latest_day['path']).read_text(encoding='utf-8'))
            tampered_rows[0]['title'] = f"{tampered_rows[0]['title']} altered"
            tampered_body = json.dumps(tampered_rows, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
            tamper_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(tamper_page, issues, origin)
            tamper_page.route(f'**/snapshot/data/{latest_day["date"]}.json', lambda route: route.fulfill(status=200, content_type='application/json; charset=utf-8', body=tampered_body))
            tamper_page.goto(f'{origin}/?page=center', wait_until='load')
            expect(tamper_page.locator('#result-status')).to_contain_text('could not be verified', timeout=120_000)
            expect(tamper_page.locator('#record-list .record-row')).to_have_count(0)
            expect(tamper_page.locator('#result-status')).to_contain_text('No partial records are shown')
            expect(tamper_page.locator('#snapshot-loader')).to_be_hidden()
            assert tamper_page.locator('#feed-view').get_attribute('aria-busy') == 'false'
            assert 'SHA-256' not in tamper_page.locator('#result-status').inner_text()
            tamper_page.close()

            # A correctly digested resource with an invalid record schema fails visibly, not as loading.
            invalid_rows = json.loads((ROOT / 'snapshot' / latest_day['path']).read_text(encoding='utf-8'))
            invalid_rows[0]['title'] = ''
            schema_manifest, schema_shard, schema_day = snapshot_override(manifest, latest_day, invalid_rows)
            schema_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(schema_page, issues, origin)
            install_snapshot_override(schema_page, schema_manifest, schema_shard, schema_day)
            schema_page.goto(f'{origin}/?page=center', wait_until='load')
            expect(schema_page.locator('#result-status')).to_contain_text('could not be verified', timeout=120_000)
            expect(schema_page.locator('#snapshot-loader')).to_be_hidden()
            assert schema_page.locator('#feed-view').get_attribute('aria-busy') == 'false'
            assert schema_page.locator('#record-list .record-row').count() == 0
            schema_page.close()

            # Oversized manifest response must be rejected without rendering any records.
            oversized_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(oversized_page, issues, origin)
            oversized_page.route('**/snapshot/manifest.json', lambda route: route.fulfill(
                status=200, content_type='application/json; charset=utf-8', body=b' ' * (512 * 1024 + 1)
            ))
            oversized_page.goto(f'{origin}/?page=center', wait_until='load')
            expect(oversized_page.locator('#result-status')).to_contain_text('could not be verified', timeout=30_000)
            expect(oversized_page.locator('#snapshot-loader')).to_be_hidden()
            assert oversized_page.locator('#feed-view').get_attribute('aria-busy') == 'false'
            expect(oversized_page.locator('#record-list .record-row')).to_have_count(0)
            oversized_page.close()
            print('PASS: bad digest, bad schema, oversized manifest/resource and source failures leave loading for the explicit retry state with no partial records.')

            # Exercise every page at mobile and desktop widths without external requests.
            page.locator('#tab-overview').click()
            width_metrics = {}
            for width in (320, 360, 375, 390, 414, 768, 1024, 1280, 1440):
                width_metrics[width] = {}
                for tab in ('overview', 'center', 'community'):
                    page.locator(f'#tab-{tab}').click()
                    width_metrics[width][tab] = width_audit(page, width)
            page.locator('#tab-community').click()
            expect(page.locator('#page-community')).to_be_visible()
            page.locator('#idle-prompt:not([hidden])').wait_for(timeout=10_000)
            expect(page.locator('#terminal-info')).to_be_visible()
            expect(page.locator('#join-bugcod3')).to_have_text('Join BugCod3')
            expect(page.locator('#join-rootaccessclub')).to_have_text('Join RootAccessClub')
            for link_id in ('join-bugcod3', 'join-rootaccessclub'):
                expect(page.locator(f'#{link_id}')).to_be_enabled()
            page.screenshot(path=str(SCREENSHOTS / '04-community-desktop.png'))
            print('PASS: all three pages fit 320–1440 CSS px; Community is reachable, accessible, and uses safe external links.')

            swipe_results = run_swipe_navigation_tests(browser, origin, manifest)
            print('PASS: touch swipe navigation, touch-safe controls, reduced motion, gesture cancellation, and state preservation.')
            print('Swipe QA details:', json.dumps(swipe_results, sort_keys=True))

            assert not issues['page_errors'], f"JavaScript errors: {issues['page_errors']}"
            assert not issues['console_errors'], f"Console errors: {issues['console_errors']}"
            assert not issues['request_failures'], f"Failed browser requests: {issues['request_failures']}"
            assert not issues['external_requests'], f"Unexpected external requests: {issues['external_requests']}"
            print('PASS: zero browser/page/console errors, zero failed requests, and no automatic external network requests.')
            print('Responsive metrics:', json.dumps(width_metrics, sort_keys=True))
            print(f'Screenshots: {SCREENSHOTS}')
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
