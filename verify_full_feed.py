#!/usr/bin/env python3
"""Portable browser QA for SubZer0's manifest-verified static snapshot."""
from __future__ import annotations

import base64
import functools
import gzip
import hashlib
import http.server
import json
import shutil
import threading
import time
from urllib.parse import urlencode, urlsplit
from datetime import datetime, timedelta, timezone
from pathlib import Path
from playwright.sync_api import expect, sync_playwright
ROOT = Path(__file__).resolve().parent
SCREENSHOTS = Path('/tmp/subzero-security-review-screenshots')
SCREENSHOTS.mkdir(parents=True, exist_ok=True)


class BrowserWithoutServiceWorkers:
    """Keep route-mocked regression pages deterministic; offline coverage opts in explicitly."""
    def __init__(self, browser):
        self.browser = browser

    def new_context(self, *args, **kwargs):
        kwargs['service_workers'] = 'block'
        return self.browser.new_context(*args, **kwargs)

    def new_page(self, *args, **kwargs):
        context = self.new_context(*args, **kwargs)
        page = context.new_page()
        page.on('close', lambda: context.close())
        return page

    def close(self):
        self.browser.close()


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
            self.send_header('Content-Type', 'application/gzip' if path.endswith('.gz') else 'application/json; charset=utf-8')
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


def read_search_index(manifest: dict) -> dict:
    config = manifest['search_index']
    compressed = (ROOT / 'snapshot' / config['path']).read_bytes()
    assert len(compressed) == config['bytes']
    assert hashlib.sha256(compressed).hexdigest() == config['sha256']
    raw = gzip.decompress(compressed) if config.get('compression') == 'gzip' else compressed
    if config.get('compression') == 'gzip':
        assert len(raw) == config['uncompressed_bytes']
        assert hashlib.sha256(raw).hexdigest() == config['uncompressed_sha256']
    return json.loads(raw)


def decode_search_rows(payload: dict) -> list[dict]:
    if payload.get('schema_version') != 3:
        return payload['records']
    severities = ('critical', 'high', 'medium', 'low', 'none', 'unknown')
    date_bases = ('CVE publication', 'GitHub advisory publication', 'NVD last modified',
                  'GitHub advisory updated', 'CISA KEV date added')
    source_bits = ((1, 'NVD'), (2, 'GitHub Advisory Database'), (4, 'CISA KEV'))
    decoded = []
    for row in payload['records']:
        if not isinstance(row, list) or len(row) != 11:
            raise AssertionError('Packed search-index row does not match the v3 eleven-column schema.')
        cve_id, title, summary, score, severity_code, kev, activity_at, basis_code, source_mask, affected, advisories = row
        decoded.append({
            'id': cve_id, 'title': title, 'summary': summary, 'score': score,
            'sev': severities[severity_code], 'kev': kev, 'activity_at': activity_at,
            'date_basis': date_bases[basis_code],
            'sources': [name for bit, name in source_bits if source_mask & bit],
            'affected': [{'vendor': item[0], 'product': item[1], 'versions': item[2]} for item in affected],
            'advisory_ids': advisories, 'detail_path': f"data/{activity_at[:10]}.json",
        })
    return decoded


def read_decoded_search_rows(manifest: dict) -> list[dict]:
    return decode_search_rows(read_search_index(manifest))


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
    page.on('pageerror', lambda error: issues['page_errors'].append(f'{error}\n{getattr(error, "stack", "")}'))
    page.on('console', lambda message: issues['console_errors'].append(message.text) if message.type == 'error' else None)
    page.on('requestfailed', lambda request: issues['request_failures'].append(request.url))
    page.on('request', lambda request: issues['external_requests'].append(request.url)
            if not request.url.startswith((origin, 'data:')) else None)


def run_offline_cache_tests(browser, origin: str, manifest: dict, expected_count: int, issues: dict) -> dict:
    context = browser.new_context(
        viewport={'width': 390, 'height': 844}, device_scale_factor=1,
        is_mobile=True, has_touch=True, service_workers='allow')
    page = context.new_page()
    browser_issue_track(page, issues, origin)
    index = read_decoded_search_rows(manifest)
    history = json.loads((ROOT / 'snapshot' / manifest['history']['path']).read_bytes())
    cached_record = index[0]
    missing_record = next(row for row in index if row['detail_path'] != cached_record['detail_path'])
    cached_shard_path = f"snapshot/{cached_record['detail_path']}"
    missing_shard_path = f"snapshot/{missing_record['detail_path']}"
    try:
        page.goto(f'{origin}/?page=overview', wait_until='load', timeout=30_000)
        expect(page.locator('#overview-status')).to_contain_text('CVE records', timeout=30_000)
        page.wait_for_function('Boolean(navigator.serviceWorker && navigator.serviceWorker.controller)', timeout=30_000)

        page.locator('#tab-center').click()
        expect(page.locator('#page-center .snapshot-status-strip__state')).to_contain_text('compact search index verified', timeout=120_000)
        expect(page.locator('.record-row').first).to_be_visible(timeout=30_000)
        page.locator('#tab-changes').click()
        expect(page.locator('#page-changes')).to_be_visible()
        expect(page.locator('#change-event-list')).to_be_visible(timeout=30_000)
        page.locator('#tab-center').click()
        page.locator('.record-open').first.click()
        expect(page.locator('#detail-heading')).to_have_text(cached_record['id'], timeout=30_000)
        page.wait_for_function('''async (expected) => {
          const cache=await caches.open('subzero-offline-v4');
          const keys=await cache.keys();
          const paths=new Set(keys.map(request=>new URL(request.url).pathname));
          return expected.every(path=>paths.has(new URL(path,`${location.origin}/`).pathname));
        }''', arg=[
            'index.html','app.js','community.js','styles.css','feed.css','severity-effects.css','community.css',
            'assets/telegram-mark.svg','assets/telegram-bugcod3.svg','assets/telegram-rootaccessclub.svg',
            'snapshot/manifest.json',f"snapshot/{manifest['overview']['path']}",f"snapshot/{manifest['search_index']['path']}",
            f"snapshot/{manifest['epss']['path']}",f"snapshot/{manifest['history']['path']}",cached_shard_path])
        cache_audit = page.evaluate('''async ({cachedPath, missingPath}) => {
          const cache=await caches.open('subzero-offline-v4');
          const keys=await cache.keys();
          const paths=new Set(keys.map(request=>new URL(request.url).pathname));
          const fullShardPaths=[...paths].filter(path=>path.includes('/snapshot/data/') && /^[0-9]{4}-[0-9]{2}-[0-9]{2}[.]json$/.test(path.split('/').pop()));
          return {cachedShardPresent:paths.has(new URL(cachedPath,`${location.origin}/`).pathname),
            missingShardPresent:paths.has(new URL(missingPath,`${location.origin}/`).pathname),cachedShardCount:fullShardPaths.length};
        }''', {'cachedPath': cached_shard_path, 'missingPath': missing_shard_path})
        assert cache_audit['cachedShardPresent'] and not cache_audit['missingShardPresent'] and cache_audit['cachedShardCount'] == 1, cache_audit
        page.screenshot(path=str(SCREENSHOTS / '05-offline-cache-warmed-mobile.png'), animations='disabled')

        devtools = context.new_cdp_session(page)
        devtools.send('Network.setCacheDisabled', {'cacheDisabled': True})
        context.add_init_script("Object.defineProperty(Navigator.prototype, 'onLine', {configurable: true, get: () => false});")
        context.set_offline(True)
        page.goto(f'{origin}/?page=center&cve={cached_record["id"]}', wait_until='domcontentloaded', timeout=30_000)
        expect(page.locator('#page-center .snapshot-status-strip__state')).to_have_attribute('data-state', 'offline', timeout=120_000)
        offline_status = page.locator('#page-center .snapshot-status-strip__state')
        expect(offline_status).to_contain_text('OFFLINE')
        expect(offline_status).to_contain_text(f'the compact {nfmt(expected_count)}-record index and EPSS set were verified against the captured manifest')
        expect(offline_status).to_contain_text('Detail opens only when its shard is cached')
        expect(page.locator('#page-center .snapshot-status-strip')).to_contain_text(manifest['generated_at'][:4])
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(expected_count))
        expect(page.locator('#detail-heading')).to_have_text(cached_record['id'], timeout=30_000)
        expect(page.locator('#detail-history')).to_be_visible(timeout=30_000)
        expect(page.locator('#detail-content')).to_contain_text('Observed change history')

        page.locator('#tab-latest').click()
        expect(page.locator('#latest-page-list .latest-page-item').first).to_be_visible()
        latest_count = page.locator('#latest-page-list .latest-page-item').count()
        assert latest_count > 0
        page.locator('#tab-overview').click()
        expect(page.locator('#page-overview [data-snapshot-state]')).to_have_attribute('data-state', 'offline')
        mobile_metrics = page.evaluate('''() => {
          const nav=document.querySelector('.page-nav'); const rect=nav.getBoundingClientRect();
          return {viewportWidth:innerWidth,documentWidth:document.documentElement.scrollWidth,
            navPosition:getComputedStyle(nav).position,navBottom:rect.bottom,viewportHeight:innerHeight};
        }''')
        assert mobile_metrics['documentWidth'] <= mobile_metrics['viewportWidth'], mobile_metrics
        assert mobile_metrics['navPosition'] == 'fixed' and mobile_metrics['navBottom'] > mobile_metrics['viewportHeight'] - 100, mobile_metrics

        # Chromium reports the service worker's deliberate offline 503 as a console error.
        # Isolate and validate only this expected warning; unrelated console errors remain fatal.
        offline_console_start = len(issues['console_errors'])
        page.goto(f'{origin}/?page=center&search={missing_record["id"]}', wait_until='domcontentloaded', timeout=30_000)
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
        expect(page.locator('.record-row')).to_have_count(1, timeout=30_000)
        page.locator('.record-open').click()
        expect(page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
        expect(page.locator('.detail-load-error')).to_contain_text('OFFLINE')
        assert page.locator('#detail-heading').count() == 0
        observed_offline_errors = issues['console_errors'][offline_console_start:]
        assert len(observed_offline_errors) == 1 and observed_offline_errors[0].startswith(
            'Failed to load resource: the server responded with a status of 503'
        ), observed_offline_errors
        del issues['console_errors'][offline_console_start:]
        page.locator('#back-to-results').click()
        expect(page.locator('.record-row')).to_have_count(1)

        return {
            'offline_verified_index_records': expected_count,
            'offline_cached_dataset_age_year': manifest['generated_at'][:4],
            'cached_history_events': len(history['events']),
            'cached_dossier_opens_offline': True,
            'uncached_shard_fails_closed': True,
            'index_remains_searchable_after_missing_shard': True,
            'cached_detail_shards': cache_audit['cachedShardCount'],
            'mobile': mobile_metrics,
        }
    finally:
        context.close()


def run_background_snapshot_update_test(browser, origin: str, manifest: dict, overview: dict, issues: dict) -> dict:
    page = browser.new_page(viewport={'width': 1280, 'height': 900})
    browser_issue_track(page, issues, origin)
    try:
        page.goto(f'{origin}/?page=overview', wait_until='load', timeout=30_000)
        expect(page.locator('#overview-status')).to_contain_text('CVE records', timeout=30_000)
        candidate = json.loads(json.dumps(manifest))
        capture_time = datetime.fromisoformat(manifest['generated_at'].replace('Z', '+00:00'))
        candidate['generated_at'] = (capture_time + timedelta(minutes=1)).isoformat().replace('+00:00', 'Z')
        candidate['last_successful_update'] = candidate['generated_at']
        candidate['window']['end'] = candidate['generated_at']
        for source in candidate['source_status']:
            if 'checked_at' in source:
                source['checked_at'] = candidate['generated_at']
        candidate_overview = json.loads(json.dumps(overview))
        candidate_overview['generated_at'] = candidate['generated_at']
        overview_bytes = json.dumps(candidate_overview, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        candidate['overview']['bytes'] = len(overview_bytes)
        candidate['overview']['sha256'] = hashlib.sha256(overview_bytes).hexdigest()
        assert candidate['generated_at'] > manifest['generated_at']
        response_body = json.dumps(candidate, separators=(',', ':'))
        page.route('**/snapshot/manifest.json', lambda route: route.fulfill(
            status=200, content_type='application/json; charset=utf-8', body=response_body
        ))
        page.route('**/snapshot/data/overview.json', lambda route: route.fulfill(
            status=200, content_type='application/json; charset=utf-8', body=overview_bytes
        ))
        page.evaluate('''() => {
          const previous = Date.now();
          Date.now = () => previous + 16 * 60 * 1000;
          document.dispatchEvent(new Event('visibilitychange'));
        }''')
        notice = page.locator('#snapshot-update-notice')
        expect(notice).to_be_visible(timeout=30_000)
        expect(page.locator('#snapshot-update-copy')).to_contain_text('newer captured snapshot')
        expect(page.locator('#snapshot-update-copy')).to_contain_text('manifest and Overview preview are verified')
        expect(page.locator('#snapshot-update-copy')).to_contain_text('reload to verify the compact search index')
        page.locator('#snapshot-update-dismiss').click()
        expect(notice).to_be_hidden()
        return {'background_interval_triggered': True, 'manifest_and_overview_preview_verified_before_reload': True, 'dismissible_notice': True}
    finally:
        page.close()


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


def assert_header_background_pixels(page, screenshot_path: Path, expected_rgb: tuple[int, int, int]) -> int:
    screenshot = page.screenshot(path=str(screenshot_path), animations='disabled')
    sample = page.evaluate('''async ({screenshotBase64}) => {
      const image = new Image();
      image.src = `data:image/png;base64,${screenshotBase64}`;
      await image.decode();
      const canvas = document.createElement('canvas');
      canvas.width = image.naturalWidth;
      canvas.height = image.naturalHeight;
      const context = canvas.getContext('2d', {willReadFrequently: true});
      context.drawImage(image, 0, 0);
      const header = document.querySelector('.site-header');
      const bounds = header.getBoundingClientRect();
      const content = [...header.querySelectorAll('.wordmark, .page-nav, .preview-mark')]
        .map(element => element.getBoundingClientRect());
      const scaleX = image.naturalWidth / innerWidth;
      const scaleY = image.naturalHeight / innerHeight;
      const points = [];
      for (let y = Math.ceil(bounds.top + 6); y < Math.floor(bounds.bottom - 6); y += 3) {
        for (let x = 6; x < innerWidth - 6; x += 4) {
          const overContent = content.some(rect => x >= rect.left - 5 && x <= rect.right + 5 && y >= rect.top - 5 && y <= rect.bottom + 5);
          if (!overContent) points.push([x, y]);
        }
      }
      const pixels = points.map(([x, y]) => Array.from(context.getImageData(Math.floor(x * scaleX), Math.floor(y * scaleY), 1, 1).data));
      return {pixels, width: image.naturalWidth, height: image.naturalHeight};
    }''', {'screenshotBase64': base64.b64encode(screenshot).decode('ascii')})
    expected = [*expected_rgb, 255]
    mismatches = [pixel for pixel in sample['pixels'] if pixel != expected]
    assert len(sample['pixels']) >= 8, f'not enough clean header background pixels to audit {screenshot_path.name}: {sample}'
    assert not mismatches, f'Center sticky header screenshot contains non-palette pixels/ghosting: {mismatches[:8]} at {screenshot_path.name}'
    return len(sample['pixels'])


def stable_search_toolbar_audit(browser, origin: str, issues: dict, expected_count: int, manifest: dict) -> list[dict]:
    page = browser.new_page(viewport={'width': 1440, 'height': 900})
    browser_issue_track(page, issues, origin)
    metrics_by_width = []
    try:
        page.goto(f'{origin}/?page=center', wait_until='load', timeout=30_000)
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
        expect(page.locator('#research-toolbar')).to_be_visible()
        expect(page.locator('#record-list')).to_have_attribute('aria-busy', 'false')

        # The slash shortcut focuses the real search control; filtering remains URL-backed.
        page.locator('#record-search').evaluate('(input) => input.blur()')
        page.keyboard.press('/')
        expect(page.locator('#record-search')).to_be_focused()
        search = page.locator('#record-search')
        search.fill('CVE-')
        expect(page.locator('.record-row')).to_have_count(min(24, expected_count))
        page.locator('#page-size').select_option('48')
        expect(page.locator('.record-row')).to_have_count(min(48, expected_count))
        page.locator('.severity-tab[data-severity="high"]').click()
        high_count = manifest['totals']['high']
        expect(page.locator('.record-row')).to_have_count(min(48, high_count))

        page.locator('#date-filter summary').click()
        page.locator('#date-from').fill(manifest['window']['start'][:10])
        page.locator('#date-to').fill(manifest['window']['end'][:10])
        page.locator('#date-form button[type="submit"]').click()
        expect(page.locator('#result-status')).to_contain_text(f'of {nfmt(high_count)} matching records')

        for width, height in ((320, 740), (360, 800), (390, 844), (412, 892), (768, 800), (1024, 900), (1440, 900)):
            page.set_viewport_size({'width': width, 'height': height})
            page.evaluate('window.scrollTo({top:0,behavior:"instant"})')
            page.wait_for_timeout(40)
            top_state = page.evaluate('''() => {
              const toolbar=document.querySelector('#research-toolbar');
              const input=document.querySelector('#record-search');
              const rect=toolbar.getBoundingClientRect();
              const inputRect=input.getBoundingClientRect();
              const header=document.querySelector('.site-header').getBoundingClientRect();
              const tabs=document.querySelector('.page-nav').getBoundingClientRect();
              return {width:innerWidth,documentWidth:document.documentElement.scrollWidth,
                toolbarPosition:getComputedStyle(toolbar).position,toolbarTop:rect.top,toolbarWidth:rect.width,
                inputWidth:inputRect.width,inputHeight:inputRect.height,inputValue:input.value,
                inputVisible:input.getClientRects().length>0&&getComputedStyle(input).visibility==='visible',
                inputLabel:input.getAttribute('aria-label'),shortcut:input.getAttribute('aria-keyshortcuts'),
                headerBottom:header.bottom,tabsPosition:getComputedStyle(document.querySelector('.page-nav')).position,
                tabs:{left:tabs.left,right:tabs.right},oldDock:document.querySelector('.center-dock, .center-search-anchor')!==null,
                returnControl:document.querySelector('#header-search-return')!==null};
            }''')
            assert top_state['documentWidth'] == width, f'horizontal overflow at {width}x{height}: {top_state}'
            assert top_state['toolbarPosition'] == 'sticky' and top_state['inputVisible'], top_state
            assert not top_state['oldDock'] and not top_state['returnControl'], f'legacy scroll-morph controls remain: {top_state}'
            assert top_state['inputLabel'] and top_state['shortcut'] == '/' and top_state['inputValue'] == 'CVE-', top_state
            page.evaluate('window.scrollTo({top:1400,behavior:"instant"})')
            page.wait_for_timeout(60)
            scrolled = page.evaluate('''() => {
              const toolbar=document.querySelector('#research-toolbar');
              const rect=toolbar.getBoundingClientRect();
              const input=document.querySelector('#record-search');
              const inputRect=input.getBoundingClientRect();
              const header=document.querySelector('.site-header').getBoundingClientRect();
              return {top:rect.top,inputWidth:inputRect.width,inputHeight:inputRect.height,
                inputValue:input.value,visible:input.getClientRects().length>0&&getComputedStyle(input).visibility==='visible',
                headerBottom:header.bottom,scrollY,position:getComputedStyle(toolbar).position};
            }''')
            assert scrolled['position'] == 'sticky' and scrolled['visible'] and scrolled['inputValue'] == 'CVE-', scrolled
            assert abs(scrolled['top'] - scrolled['headerBottom']) <= 2, f'search is not predictably sticky below the global header: {scrolled}'
            assert abs(scrolled['inputWidth'] - top_state['inputWidth']) <= 1 and abs(scrolled['inputHeight'] - top_state['inputHeight']) <= 1, f'search geometry changed on scroll: {top_state}, {scrolled}'
            if width <= 412:
                assert top_state['tabsPosition'] == 'fixed' and top_state['tabs']['left'] >= 0 and top_state['tabs']['right'] <= width, top_state
            if width in (390, 1440):
                page.screenshot(path=str(SCREENSHOTS / f'stable-search-{width}x{height}.png'), animations='disabled')
            metrics_by_width.append({'width':width,'height':height,'top':round(scrolled['top'],1),'input_width':round(scrolled['inputWidth'],1),'overflow':False})

        # A dossier opens from the indexed row and browser Back restores research state.
        page.set_viewport_size({'width':1440,'height':900})
        page.evaluate('window.scrollTo({top:0,behavior:"instant"})')
        first = page.locator('.record-open').first
        first_id = first.get_attribute('data-cve-id')
        first.click()
        expect(page.locator('#detail-view')).to_be_visible(timeout=30_000)
        expect(page.locator('#detail-content')).to_contain_text(first_id, timeout=30_000)
        page.go_back(wait_until='domcontentloaded')
        expect(page.locator('#record-search')).to_have_value('CVE-')
        expect(page.locator('#record-list')).to_be_visible()
        page.go_forward(wait_until='domcontentloaded')
        expect(page.locator('#detail-heading')).to_have_text(first_id, timeout=30_000)
        page.locator('#back-to-results').click()
        expect(page.locator('#record-search')).to_have_value('CVE-')
        expect(page.locator('#record-list')).to_be_visible()
        return metrics_by_width
    finally:
        page.close()


def snapshot_override(manifest: dict, day: dict, records: list[dict]) -> tuple[bytes, bytes, str]:
    changed = json.loads(json.dumps(manifest))
    body = json.dumps(records, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    summary = next(item for item in changed['days'] if item['date'] == day['date'])
    summary['bytes'] = len(body)
    summary['sha256'] = hashlib.sha256(body).hexdigest()
    manifest_body = json.dumps(changed, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    return manifest_body, body, day['date']


def install_snapshot_override(page, manifest_body: bytes, shard_body: bytes, day: str,
                              index_body: bytes | None = None) -> None:
    page.route('**/snapshot/manifest.json', lambda route: route.fulfill(status=200, content_type='application/json; charset=utf-8', body=manifest_body))
    page.route(f'**/snapshot/data/{day}.json', lambda route: route.fulfill(status=200, content_type='application/json; charset=utf-8', body=shard_body))
    if index_body is not None:
        page.route('**/snapshot/data/search-index.json.gz', lambda route: route.fulfill(status=200, content_type='application/gzip', body=index_body))


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
    manifest_path = 'snapshot/manifest.json'
    index_path = f"snapshot/{manifest['search_index']['path']}"
    epss_path = f"snapshot/{manifest['epss']['path']}"
    index_rows = read_decoded_search_rows(manifest)
    target = index_rows[0]
    target_id = target['id']
    target_path = f"snapshot/{target['detail_path']}"
    detail_day = next(day for day in manifest['days'] if day['path'] == target['detail_path'])
    day_paths = [f"snapshot/{day['path']}" for day in manifest['days']]
    result: dict = {}

    # Delay the manifest and the compact sidecars independently; Explore remains empty until both verify.
    scenario = new_scenario()
    gates = {path: threading.Event() for path in (manifest_path, index_path, epss_path, target_path)}
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
        expect(page.locator('#snapshot-loader-title')).to_have_text('Verifying the search index')
        assert page.locator('#snapshot-manifest-state').inner_text() == 'Waiting'
        wait_for_scenario_request(scenario, manifest_path)
        gates[manifest_path].set()
        page.wait_for_function('(count) => { const p=document.querySelector("#snapshot-shard-progress"); return !p.hidden && p.max===count; }', arg=manifest['totals']['cves'], timeout=30_000)
        assert page.locator('#snapshot-manifest-state').inner_text() == 'Verified'
        wait_for_scenario_request(scenario, index_path)
        wait_for_scenario_request(scenario, epss_path)
        assert page.locator('#snapshot-shard-progress').evaluate('(element) => element.value') == 0
        assert page.locator('.record-row').count() == 0
        gates[epss_path].set()
        page.wait_for_timeout(100)
        expect(loader).to_be_visible()
        assert page.locator('.record-row').count() == 0
        # A narrow viewport still exposes the honest loading state and does not animate under reduced motion.
        for width, height in ((320, 740), (390, 844), (1440, 1000)):
            metrics = width_audit(page, width, height)
            assert metrics['activePageId'] == 'page-center'
        page.set_viewport_size({'width':1440,'height':1000})
        gates[index_path].set()
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=30_000)
        expect(page.locator('#snapshot-loader')).to_be_hidden()
        assert page.locator('#feed-view').get_attribute('aria-busy') == 'false'
        assert page.locator('#record-list').get_attribute('aria-busy') == 'false'
        expect(page.locator('#snapshot-shard-count')).to_have_text(f"{nfmt(manifest['totals']['cves'])} of {nfmt(manifest['totals']['cves'])} indexed")
        assert page.locator('.record-row').count() == 24
        assert all(scenario_request_count(scenario, path) == 0 for path in day_paths), 'Explore eagerly requested a detail shard.'
        progress = page.locator('#snapshot-shard-progress')
        assert progress.get_attribute('aria-valuetext') == f"{nfmt(manifest['totals']['cves'])} of {nfmt(manifest['totals']['cves'])} index records verified"
        motion = page.locator('#snapshot-loader-status').evaluate("element => ({reduced:matchMedia('(prefers-reduced-motion: reduce)').matches,name:getComputedStyle(element,'::before').animationName,duration:getComputedStyle(element,'::before').animationDuration})")
        result['reduced_motion_static'] = motion['reduced'] and motion['name'] == 'none'
        assert result['reduced_motion_static'], f'Loader remains animated with reduced motion enabled: {motion}'

        # Only an explicit dossier open requests its daily shard; until release, no unverified detail is shown.
        page.locator('.record-open').first.click()
        wait_for_scenario_request(scenario, target_path)
        expect(page.locator('.detail-loading')).to_be_visible()
        assert page.locator('#detail-heading').count() == 0
        gates[target_path].set()
        expect(page.locator('#detail-heading')).to_have_text(target_id, timeout=30_000)
        expect(page.locator('#detail-history')).to_be_visible(timeout=30_000)
        assert scenario_request_count(scenario, target_path) == 1
        result.update({
            'index_verified_before_any_detail': True,
            'index_records': manifest['search_index']['count'],
            'eager_detail_shards': 0,
            'lazy_detail_path': detail_day['path'],
            'detail_shard_bytes': detail_day['bytes'],
            'detail_request_count': 1,
            'history_loaded_with_detail': True,
            'responsive_loader_widths': [320, 390, 1440],
        })
    finally:
        for gate in gates.values():
            gate.set()
        page.close()
        server.shutdown()
        server.server_close()

    # A missing shard produces a dossier error, keeps the verified index usable, and retries only on user action.
    retry_scenario = new_scenario()
    retry_scenario['responses'][target_path] = lambda count: (503, b'detail shard unavailable') if count == 1 else None
    retry_server = serve_scenario(retry_scenario)
    retry_origin = f'http://127.0.0.1:{retry_server.server_port}'
    retry_page = browser.new_page(viewport={'width': 1280, 'height': 900})
    try:
        retry_page.goto(f'{retry_origin}/?page=center&search={target_id}', wait_until='load')
        expect(retry_page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(retry_page.locator('.record-row')).to_have_count(1)
        retry_page.locator('.record-open').click()
        expect(retry_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
        assert retry_page.locator('#detail-heading').count() == 0
        expect(retry_page.locator('.detail-load-error')).to_contain_text('No partial dossier is shown')
        retry_page.get_by_role('button', name='Retry detail').click()
        expect(retry_page.locator('#detail-heading')).to_have_text(target_id, timeout=30_000)
        assert scenario_request_count(retry_scenario, target_path) == 2
        result['missing_shard'] = {'partial_dossier': False, 'user_retry_requests': 2, 'index_records_retained': True}
    finally:
        retry_page.close()
        retry_server.shutdown()
        retry_server.server_close()

    # A digest mismatch is retried once; the failure state never renders details.
    corrupt = (ROOT / target_path).read_bytes()
    corrupt = corrupt[:-1] + (b' ' if corrupt.endswith(b'\n') else b'!')
    corrupt_scenario = new_scenario()
    corrupt_scenario['responses'][target_path] = (200, corrupt)
    corrupt_server = serve_scenario(corrupt_scenario)
    corrupt_origin = f'http://127.0.0.1:{corrupt_server.server_port}'
    corrupt_page = browser.new_page(viewport={'width': 1280, 'height': 900})
    try:
        corrupt_page.goto(f'{corrupt_origin}/?page=center&search={target_id}', wait_until='load')
        expect(corrupt_page.locator('.record-row')).to_have_count(1, timeout=120_000)
        corrupt_page.locator('.record-open').click()
        expect(corrupt_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
        assert corrupt_page.locator('#detail-heading').count() == 0
        assert scenario_request_count(corrupt_scenario, target_path) == 2
        result['corrupted_shard'] = {'integrity_retries': 1, 'partial_dossier': False}
    finally:
        corrupt_page.close()
        corrupt_server.shutdown()
        corrupt_server.server_close()

    # A declared oversized shard is rejected before a successful dossier can be rendered.
    oversized_scenario = new_scenario()
    oversized_scenario['declared_lengths'][target_path] = 16 * 1024 * 1024 + 1
    oversized_server = serve_scenario(oversized_scenario)
    oversized_origin = f'http://127.0.0.1:{oversized_server.server_port}'
    oversized_page = browser.new_page(viewport={'width': 1280, 'height': 900})
    try:
        oversized_page.goto(f'{oversized_origin}/?page=center&search={target_id}', wait_until='load')
        expect(oversized_page.locator('.record-row')).to_have_count(1, timeout=120_000)
        oversized_page.locator('.record-open').click()
        expect(oversized_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
        assert oversized_page.locator('#detail-heading').count() == 0
        result['oversized_shard'] = {'limit_bytes': 16 * 1024 * 1024, 'partial_dossier': False}
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
    index_path = f"snapshot/{manifest['search_index']['path']}"
    epss_path = f"snapshot/{manifest['epss']['path']}"
    history_path = f"snapshot/{manifest['history']['path']}"
    manifest_raw = (ROOT / manifest_path).read_bytes()
    index_rows = read_decoded_search_rows(manifest)
    index_by_id = {row['id']: row for row in index_rows}
    overview_ids = {item['id'] for item in json.loads((ROOT / 'snapshot' / manifest['overview']['path']).read_bytes())['records']}

    target_day = target_rows = target = None
    for day in manifest['days']:
        if not day['count']:
            continue
        rows = json.loads((ROOT / 'snapshot' / day['path']).read_bytes())
        candidate = next((row for row in rows if row['id'] not in overview_ids and row.get('refs') and row['id'] in index_by_id), None)
        if candidate:
            target_day, target_rows, target = day, rows, candidate
            break
    assert target_day and target_rows and target, 'Could not choose a detail-only record with reference provenance for the cache fixture.'
    target_path = f"snapshot/{target_day['path']}"
    target_index = index_by_id[target['id']]
    changed_rows = json.loads(json.dumps(target_rows))
    changed_label = 'Verified reference updated after fresh manifest'
    next(row for row in changed_rows if row['id'] == target['id'])['refs'][0]['label'] = changed_label
    updated_manifest_raw, updated_shard_raw, _ = snapshot_override(manifest, target_day, changed_rows)

    initial_paths = {manifest_path, index_path, epss_path}
    detail_paths = {f"snapshot/{day['path']}" for day in manifest['days']}
    scenario = new_cache_scenario()
    server = serve_cache_scenario(scenario)
    origin = f'http://127.0.0.1:{server.server_port}'
    issues = {'page_errors': [], 'console_errors': [], 'request_failures': [], 'external_requests': []}
    cache_browser = browser.browser if isinstance(browser, BrowserWithoutServiceWorkers) else browser
    context = cache_browser.new_context(viewport={'width': 1280, 'height': 900}, service_workers='allow')
    context.add_init_script("window.__subzeroLongTasks=[]; if(window.PerformanceObserver && PerformanceObserver.supportedEntryTypes.includes('longtask')) new PerformanceObserver(list=>window.__subzeroLongTasks.push(...list.getEntries().map(entry=>entry.duration))).observe({entryTypes:['longtask']});")
    page = context.new_page()
    browser_issue_track(page, issues, origin)
    results: dict = {}
    try:
        cold_started = time.monotonic()
        page.goto(f'{origin}/?page=center', wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        page.wait_for_function('Boolean(navigator.serviceWorker && navigator.serviceWorker.controller)', timeout=30_000)
        cold_elapsed = time.monotonic() - cold_started
        cold_events = [event for event in cache_scenario_events(scenario) if event['path'] in initial_paths]
        cold_full = [event for event in cold_events if event['status'] == 200]
        cold_counts = {path: sum(event['path'] == path for event in cold_full) for path in initial_paths}
        assert all(count == 1 for count in cold_counts.values()), f'Index-first visit did not fetch manifest and both compact sidecars once: {cold_counts}'
        assert not [event for event in cache_scenario_events(scenario) if event['path'] in detail_paths], 'Initial Explore visit fetched a full detail shard.'
        cold_manifest_event = next(event for event in cold_full if event['path'] == manifest_path)
        assert cold_manifest_event['cache_control'] == 'public, max-age=600'
        cold_data_bytes = sum(event['body_bytes'] for event in cold_full if event['path'] != manifest_path)
        assert cold_data_bytes == manifest['search_index']['bytes'] + manifest['epss']['bytes']

        # Search latency uses the actual input-to-one-row interaction; JS and memory metrics are sampled in Chromium.
        search_started = time.perf_counter()
        page.locator('#record-search').fill(target['id'])
        expect(page.locator('.record-row')).to_have_count(1, timeout=30_000)
        search_latency_ms = round((time.perf_counter() - search_started) * 1000, 2)
        client_metrics = page.evaluate('''() => {
          const latest=name=>{const entries=performance.getEntriesByName(name); return entries.length?entries.at(-1).duration:null};
          const script=performance.getEntriesByType('resource').find(entry=>entry.name.endsWith('/app.js'));
          return {list_render_ms:latest('subzero-list-render'),index_verify_render_ms:latest('subzero-index-verified-and-rendered'),
            app_script_resource_ms:script?.duration ?? null,app_script_transfer_bytes:script?.transferSize ?? null,
            long_task_count:window.__subzeroLongTasks?.length ?? null,max_long_task_ms:window.__subzeroLongTasks?.length?Math.max(...window.__subzeroLongTasks):0,
            used_heap_mib:performance.memory?.usedJSHeapSize?Math.round(performance.memory.usedJSHeapSize/1048576*100)/100:null};
        }''')

        # Detail payload size/latency is measured separately from the compact full-feed index.
        detail_marker = len(cache_scenario_events(scenario))
        detail_started = time.perf_counter()
        page.locator('.record-open').click()
        expect(page.locator('#detail-heading')).to_have_text(target['id'], timeout=60_000)
        expect(page.locator('#detail-content')).to_contain_text(target['refs'][0]['label'])
        detail_latency_ms = round((time.perf_counter() - detail_started) * 1000, 2)
        detail_events = [event for event in cache_scenario_events(scenario)[detail_marker:] if event['path'] == target_path and event['status'] == 200]
        assert len(detail_events) == 1 and detail_events[0]['body_bytes'] == target_day['bytes'], f'Dossier did not fetch exactly one complete, manifest-sized shard: {detail_events}'
        history_events = [event for event in cache_scenario_events(scenario)[detail_marker:] if event['path'] == history_path and event['status'] == 200]
        assert len(history_events) == 1 and history_events[0]['body_bytes'] == manifest['history']['bytes']

        page.set_viewport_size({'width':390,'height':844})
        mobile_render = page.evaluate('''() => ({viewport_width:innerWidth,document_width:document.documentElement.scrollWidth,
          first_row_width:document.querySelector('.record-row')?.getBoundingClientRect().width})''')
        assert mobile_render['document_width'] <= mobile_render['viewport_width'], mobile_render
        page.screenshot(path=str(SCREENSHOTS / '07-explore-search-mobile.png'), animations='disabled')

        repeat_started = time.monotonic()
        repeat_marker = len(cache_scenario_events(scenario))
        page.reload(wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        repeat_elapsed = time.monotonic() - repeat_started
        repeat_events = [event for event in cache_scenario_events(scenario)[repeat_marker:] if event['path'] in initial_paths]
        repeat_manifest = [event for event in repeat_events if event['path'] == manifest_path]
        assert len(repeat_manifest) == 1 and repeat_manifest[0]['status'] == 304
        assert repeat_manifest[0]['if_none_match'] == cold_manifest_event['etag']
        assert not [event for event in repeat_events if event['path'] != manifest_path], f'Fresh compact data was re-requested: {repeat_events}'

        # Verified day-shard references do not multiply requests on same-page navigation.
        reentry_marker = len(cache_scenario_events(scenario))
        page.locator('#tab-overview').click()
        expect(page.locator('#overview-status')).to_contain_text('CVE records')
        page.locator('#tab-center').click()
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']))
        reentry_events = [event for event in cache_scenario_events(scenario)[reentry_marker:] if event['path'] in initial_paths | {target_path, history_path}]
        assert not [event for event in reentry_events if event['body_bytes']], f'In-memory reentry downloaded verified JSON bodies: {reentry_events}'

        results['measured_performance'] = {
            'initial_index_plus_epss_bytes': cold_data_bytes,
            'index_bytes': manifest['search_index']['bytes'],
            'index_uncompressed_bytes': manifest['search_index']['uncompressed_bytes'],
            'index_budget_bytes': 3 * 1024 * 1024,
            'index_compression_ratio': round(manifest['search_index']['bytes'] / manifest['search_index']['uncompressed_bytes'], 4),
            'detail_shard_bytes_on_open': detail_events[0]['body_bytes'],
            'initial_index_load_seconds': round(cold_elapsed, 3),
            'detail_open_seconds': detail_latency_ms / 1000,
            'search_interaction_ms': search_latency_ms,
            'synchronous_list_render_ms': round(client_metrics['list_render_ms'], 2) if client_metrics['list_render_ms'] is not None else None,
            'index_verified_and_rendered_ms': round(client_metrics['index_verify_render_ms'], 2) if client_metrics['index_verify_render_ms'] is not None else None,
            'app_script_resource_ms': round(client_metrics['app_script_resource_ms'], 2) if client_metrics['app_script_resource_ms'] is not None else None,
            'app_script_transfer_bytes': client_metrics['app_script_transfer_bytes'],
            'long_task_count': client_metrics['long_task_count'],
            'max_long_task_ms': round(client_metrics['max_long_task_ms'], 2) if client_metrics['max_long_task_ms'] is not None else None,
            'used_heap_mib_when_supported': client_metrics['used_heap_mib'],
            'mobile_render': mobile_render,
        }
        results['unchanged_repeat'] = {'seconds': round(repeat_elapsed,3),'manifest_revalidation':'304 with matching ETag','sidecar_body_bytes':0,'same_page_reentry':True}

        # Explicit retry must bypass a same-path cached candidate and fetch exact bytes.
        reload_marker = len(cache_scenario_events(scenario))
        reload_probe = page.evaluate('''async path=>{const response=await fetch(path,{cache:'reload',credentials:'same-origin'});return {status:response.status,bytes:(await response.arrayBuffer()).byteLength}}''',f'/{index_path}')
        assert reload_probe == {'status':200,'bytes':manifest['search_index']['bytes']}, reload_probe
        reload_events = [event for event in cache_scenario_events(scenario)[reload_marker:] if event['path'] == index_path]
        assert len(reload_events) == 1 and reload_events[0]['status'] == 200 and reload_events[0]['body_bytes'] == manifest['search_index']['bytes'], reload_events
        results['explicit_cache_reload']={'compact_index_status':200,'body_bytes':reload_probe['bytes']}

        # Fresh manifest points to new same-path content; old browser-cached shard must fail digest and reload once.
        with scenario['lock']:
            scenario['overrides'][manifest_path] = updated_manifest_raw
            scenario['overrides'][target_path] = updated_shard_raw
        update_marker = len(cache_scenario_events(scenario))
        page.goto(f'{origin}/?page=center&cve={target["id"]}', wait_until='load')
        expect(page.locator('#detail-heading')).to_have_text(target['id'], timeout=120_000)
        expect(page.locator('#detail-content')).to_contain_text(changed_label)
        update_events = cache_scenario_events(scenario)[update_marker:]
        new_manifest_events = [event for event in update_events if event['path']==manifest_path]
        new_shard_events = [event for event in update_events if event['path']==target_path]
        assert len(new_manifest_events)==1 and new_manifest_events[0]['status']==200
        assert len(new_shard_events)==1 and new_shard_events[0]['status']==200 and new_shard_events[0]['body_bytes']==len(updated_shard_raw), new_shard_events
        results['fresh_manifest_changed_shard']={'manifest':'fresh 200','same_path_shard':'one digest-triggered cache reload','verified_detail_text':changed_label}
    finally:
        context.close()

    # A bad shard is retried once and never becomes a partial dossier; the compact search index remains valid.
    tampered_body = (ROOT / target_path).read_bytes()
    tampered_body = tampered_body[:-1] + (b' ' if tampered_body.endswith(b'\n') else b'!')
    with scenario['lock']:
        scenario['overrides'] = {manifest_path: manifest_raw}
        scenario['responses'] = {target_path: (200, tampered_body)}
        scenario['events'] = []; scenario['counts'] = {}
    tamper_context = browser.new_context(viewport={'width': 1280, 'height': 900})
    tamper_page = tamper_context.new_page()
    browser_issue_track(tamper_page, issues, origin)
    try:
        tamper_page.goto(f'{origin}/?page=center&search={target["id"]}', wait_until='load')
        expect(tamper_page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(tamper_page.locator('.record-row')).to_have_count(1)
        tamper_page.locator('.record-open').click()
        expect(tamper_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
        assert tamper_page.locator('#detail-heading').count()==0
        tamper_events=[event for event in cache_scenario_events(scenario) if event['path']==target_path]
        assert len(tamper_events)==2, tamper_events
        results['tampered_shard']={'attempts':2,'partial_dossier':False,'verified_index_retained':True}
    finally:
        tamper_context.close()

    # Valid manifest digest but malformed JSON fails parsing without a retry or partial dossier.
    malformed=b'{not valid JSON'
    malformed_manifest=json.loads(json.dumps(manifest))
    malformed_day=next(day for day in malformed_manifest['days'] if day['count'])
    malformed_record=next(row for row in index_rows if row['detail_path']==malformed_day['path'])
    malformed_day['bytes']=len(malformed); malformed_day['sha256']=hashlib.sha256(malformed).hexdigest()
    malformed_manifest_raw=json.dumps(malformed_manifest,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
    malformed_path=f"snapshot/{malformed_day['path']}"
    with scenario['lock']:
        scenario['overrides']={manifest_path:malformed_manifest_raw,malformed_path:malformed}
        scenario['responses']={};scenario['events']=[];scenario['counts']={}
    malformed_context=browser.new_context(viewport={'width':1280,'height':900})
    malformed_page=malformed_context.new_page()
    browser_issue_track(malformed_page,issues,origin)
    try:
        malformed_page.goto(f'{origin}/?page=center&search={malformed_record["id"]}',wait_until='load')
        expect(malformed_page.locator('.record-row')).to_have_count(1,timeout=120_000)
        malformed_page.locator('.record-open').click()
        expect(malformed_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
        assert malformed_page.locator('#detail-heading').count()==0
        malformed_events=[event for event in cache_scenario_events(scenario) if event['path']==malformed_path]
        assert len(malformed_events)==1,malformed_events
        results['malformed_json_shard']={'attempts':1,'partial_dossier':False,'verified_index_retained':True}
    finally:
        malformed_context.close();server.shutdown();server.server_close()

    assert not issues['page_errors'],f"Cache browser page errors: {issues['page_errors']}"
    assert not issues['console_errors'],f"Cache browser console errors: {issues['console_errors']}"
    assert not issues['request_failures'],f"Cache browser request failures: {issues['request_failures']}"
    assert not issues['external_requests'],f'Unexpected external requests in cache tests: {issues["external_requests"]}'
    return results


def run_shareable_search_state_tests(browser, origin: str, issues: dict, manifest: dict) -> dict:
    """Exercise query-backed filters and real advisory/KEV metadata in Chromium."""
    all_records: list[dict] = []
    for day in manifest['days']:
        all_records.extend(json.loads((ROOT / 'snapshot' / day['path']).read_text(encoding='utf-8')))

    advisory_target = None
    advisory_term = ''
    for record in all_records:
        base = ' '.join(str(value) for value in (
            record.get('id', ''), record.get('title', ''), record.get('desc', ''),
            record.get('date_basis', ''), *record.get('sources', []),
            *(part for item in record.get('affected', []) for part in (item.get('vendor', ''), item.get('product', ''), item.get('versions', ''), item.get('cpe', ''))),
        )).casefold()
        for advisory in record.get('advisories', []):
            candidate = urlsplit(str(advisory.get('url') or '')).path.rstrip('/').rsplit('/', 1)[-1]
            if candidate.upper().startswith('GHSA-') and candidate.casefold() not in base:
                advisory_target, advisory_term = record, candidate
                break
        if advisory_target:
            break
    assert advisory_target is not None, 'No advisory identifier outside the former title/product search fields was found.'

    epss_scores = json.loads((ROOT / 'snapshot' / 'data' / 'epss.json').read_text(encoding='utf-8'))['scores']
    epss_minimum = 40
    kev_target = next((record for record in all_records
                       if isinstance(record.get('kev'), dict)
                       and str(record['kev'].get('vendor') or '').strip()
                       and str(record['kev'].get('product') or '').strip()
                       and len(str(record['kev'].get('vendor') or '')) <= 200
                       and len(str(record['kev'].get('product') or '')) <= 200
                       and isinstance(record.get('score'), (int, float))
                       and not isinstance(record.get('score'), bool)
                       and 0 < float(record['score']) < 10
                       and record['id'] in epss_scores
                       and epss_scores[record['id']]['score'] * 100 >= epss_minimum
                       and any(source not in record.get('sources', []) for source in ('NVD', 'GitHub Advisory Database'))
                       and 'CISA KEV' in record.get('sources', [])), None)
    assert kev_target is not None, 'No real KEV record with a captured EPSS score and source attribution was found in the validated snapshot.'
    kev = kev_target['kev']
    rejected_source = next(source for source in ('NVD', 'GitHub Advisory Database') if source not in kev_target['sources'])
    cvss_minimum = round(float(kev_target['score']), 1)
    cvss_minimum_text = f'{cvss_minimum:g}'
    cvss_above_target_text = f'{cvss_minimum + 0.1:.1f}'.rstrip('0').rstrip('.')
    raw_severity = kev_target.get('sev')
    severity = raw_severity if raw_severity in {'critical', 'high', 'medium', 'low'} else 'unrated'
    day = str(kev_target['window_date'])
    query_state = urlencode({
        'page': 'center', 'search': kev['product'], 'severity': severity,
        'kev': 'true', 'vendor': kev['vendor'], 'from': day, 'to': day,
        'source': 'CISA KEV', 'epssMin': str(epss_minimum), 'cvssMin': cvss_minimum_text,
        'size': '96', 'pageIndex': '1',
    })

    page = browser.new_page(viewport={'width': 1280, 'height': 900})
    browser_issue_track(page, issues, origin)
    try:
        page.goto(f'{origin}/?{urlencode({"page": "center", "search": advisory_term})}', wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(page.locator('#record-search')).to_have_value(advisory_term)
        advisory_row = page.locator(f'.record-row[data-cve-id="{advisory_target["id"]}"]')
        assert advisory_row.count() > 0, f'Search for {advisory_term} did not find advisory record {advisory_target["id"]}.'
        expect(page).to_have_url(f'{origin}/?page=center&search={advisory_term}')

        page.goto(f'{origin}/?{query_state}', wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        expect(page.locator('#vendor-filter')).to_have_value(kev['vendor'])
        expect(page.locator('#kev-only')).to_be_checked()
        expect(page.locator(f'.severity-tab[data-severity="{severity}"]')).to_have_attribute('aria-pressed', 'true')
        expect(page.locator('#page-size')).to_have_value('96')
        expect(page.locator('#date-from')).to_have_value(day)
        expect(page.locator('#date-to')).to_have_value(day)
        expect(page.locator('#source-filter')).to_have_value('CISA KEV')
        expect(page.locator('#epss-min')).to_have_value(str(epss_minimum))
        expect(page.locator('#cvss-min')).to_have_value(cvss_minimum_text)
        target_row = page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]')
        assert target_row.count() > 0, f'Combined URL filters did not retain real KEV record {kev_target["id"]}.'
        for cve_id in page.locator('.record-row').evaluate_all('(rows) => rows.map((row) => row.dataset.cveId)'):
            assert 'CISA KEV' in next(row for row in all_records if row['id'] == cve_id)['sources']
            assert epss_scores[cve_id]['score'] * 100 >= epss_minimum

        page.locator('#source-filter').select_option(rejected_source)
        assert page.evaluate('new URLSearchParams(location.search).get("source")') == rejected_source
        assert page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]').count() == 0
        page.locator('#source-filter').select_option('CISA KEV')
        page.locator('#epss-min').fill('50')
        assert page.evaluate('new URLSearchParams(location.search).get("epssMin")') == '50'
        assert page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]').count() == 0
        page.locator('#epss-min').fill(str(epss_minimum))
        assert page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]').count() > 0
        page.locator('#cvss-min').fill(cvss_above_target_text)
        assert page.evaluate('new URLSearchParams(location.search).get("cvssMin")') == cvss_above_target_text
        assert page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]').count() == 0
        page.locator('#cvss-min').fill(cvss_minimum_text)
        assert page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]').count() > 0

        page.locator('#record-search').fill('')
        assert page.evaluate('new URLSearchParams(location.search).get("search")') is None
        page.locator('#record-search').fill(kev['product'])
        assert page.evaluate('new URLSearchParams(location.search).get("search")') == kev['product']
        page.locator('#vendor-filter').fill('')
        assert page.evaluate('new URLSearchParams(location.search).get("vendor")') is None
        page.locator('#vendor-filter').fill(kev['vendor'])
        assert page.evaluate('new URLSearchParams(location.search).get("vendor")') == kev['vendor']
        page.locator('#kev-only').uncheck()
        assert page.evaluate('new URLSearchParams(location.search).get("kev")') is None
        page.locator('#kev-only').check()
        assert page.evaluate('new URLSearchParams(location.search).get("kev")') == 'true'
        page.locator('.severity-tab[data-severity="all"]').click()
        assert page.evaluate('new URLSearchParams(location.search).get("severity")') is None
        page.locator(f'.severity-tab[data-severity="{severity}"]').click()
        assert page.evaluate('new URLSearchParams(location.search).get("severity")') == severity
        page.locator('#page-size').select_option('24')
        assert page.evaluate('new URLSearchParams(location.search).get("size")') is None
        page.locator('#page-size').select_option('96')
        assert page.evaluate('new URLSearchParams(location.search).get("size")') == '96'
        page.locator('#date-filter summary').click()
        page.locator('#date-form button[type="submit"]').click()
        assert page.evaluate('''() => {
          const params = new URLSearchParams(location.search);
          return params.get('from') === params.get('to') && params.get('from') !== null;
        }''')

        target_row.locator('.record-open').click()
        expect(page.locator('#detail-heading')).to_have_text(kev_target['id'])
        state = page.evaluate('''() => Object.fromEntries(new URLSearchParams(location.search))''')
        assert state.get('cve') == kev_target['id'] and state.get('search') == kev['product'], state
        page.locator('#tab-community').click()
        expect(page.locator('#page-community')).to_be_visible()
        state = page.evaluate('''() => Object.fromEntries(new URLSearchParams(location.search))''')
        assert state.get('page') == 'community' and state.get('cve') == kev_target['id'], state
        page.locator('#tab-center').click()
        expect(page.locator('#detail-view')).to_be_visible()
        state = page.evaluate('''() => Object.fromEntries(new URLSearchParams(location.search))''')
        assert state.get('page') == 'center' and state.get('cve') == kev_target['id'], state
        page.locator('.wordmark').click()
        expect(page.locator('#page-overview')).to_be_visible()
        state = page.evaluate('''() => Object.fromEntries(new URLSearchParams(location.search))''')
        assert state.get('page') == 'overview' and state.get('cve') == kev_target['id'], state
        page.reload(wait_until='load')
        expect(page.locator('#page-overview')).to_be_visible()
        page.locator('#tab-center').click()
        expect(page.locator('#detail-view')).to_be_visible()
        expect(page.locator('#source-filter')).to_have_value('CISA KEV')
        expect(page.locator('#epss-min')).to_have_value(str(epss_minimum))
        expect(page.locator('#cvss-min')).to_have_value(cvss_minimum_text)
        page.locator('#back-to-results').click()
        expect(page.locator('#detail-view')).to_be_hidden()
        assert page.evaluate('new URLSearchParams(location.search).get("cve")') is None

        page.locator('#date-filter summary').click()
        page.keyboard.press('Escape')
        assert not page.locator('#date-filter').evaluate('(element) => element.open')
        assert page.evaluate('document.activeElement.id') == 'date-summary'

        page.locator('.wordmark').click()
        expect(page.locator('#page-overview')).to_be_visible()
        assert page.evaluate('new URLSearchParams(location.search).get("page")') is None
        page.locator('#tab-center').click()
        expect(page.locator('#page-center')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        expect(page.locator('#vendor-filter')).to_have_value(kev['vendor'])
        expect(page.locator('#kev-only')).to_be_checked()
        page.reload(wait_until='load')
        expect(page.locator('#page-center')).to_be_visible()
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        expect(page.locator('#vendor-filter')).to_have_value(kev['vendor'])
        expect(page.locator('#kev-only')).to_be_checked()
        expect(page.locator('#source-filter')).to_have_value('CISA KEV')
        expect(page.locator('#epss-min')).to_have_value(str(epss_minimum))
        expect(page.locator('#cvss-min')).to_have_value(cvss_minimum_text)
        expect(page.locator('#page-size')).to_have_value('96')
        row_count = page.locator(f'.record-row[data-cve-id="{kev_target["id"]}"]').count()
        assert row_count > 0, page.evaluate('''(id) => ({
          url: location.href,
          filters: {
            search: document.querySelector('#record-search').value,
            vendor: document.querySelector('#vendor-filter').value,
            kev: document.querySelector('#kev-only').checked,
            source: document.querySelector('#source-filter').value,
            epssMin: document.querySelector('#epss-min').value,
            severity: document.querySelector('.severity-tab[aria-pressed="true"]')?.dataset.severity,
            from: document.querySelector('#date-from').value,
            to: document.querySelector('#date-to').value,
            size: document.querySelector('#page-size').value,
          },
          target: id,
          resultStatus: document.querySelector('#result-status').textContent,
          visibleIds: [...document.querySelectorAll('.record-row')].map((row) => row.dataset.cveId),
        })''', kev_target['id'])

        deep_link = f'{origin}/?page=center&cve={kev_target["id"].lower()}'
        page.goto(deep_link, wait_until='load')
        expect(page.locator('#detail-heading')).to_have_text(kev_target['id'], timeout=120_000)
        expect(page).to_have_url(f'{origin}/?page=center&cve={kev_target["id"]}')

        history_url = f'{origin}/?{urlencode({"page": "center", "search": advisory_term})}'
        page.goto(history_url, wait_until='load')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        expect(page.locator('#record-search')).to_have_value(advisory_term)
        history_length = page.evaluate('history.length')
        page.locator('#tab-community').click()
        expect(page.locator('#page-community')).to_be_visible()
        page.locator('#tab-center').click()
        expect(page.locator('#record-search')).to_have_value(advisory_term)
        page.locator('#record-search').fill(kev['product'])
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        assert page.evaluate('history.length') == history_length + 2, 'Search edits added a history entry or page changes failed to do so.'
        page.locator('#tab-community').click()
        assert page.evaluate('history.length') == history_length + 3
        page.go_back()
        expect(page.locator('#page-center')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        page.go_back()
        expect(page.locator('#page-community')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(advisory_term)
        page.go_back()
        expect(page.locator('#page-center')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(advisory_term)
        page.go_forward()
        expect(page.locator('#page-community')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(advisory_term)
        page.go_forward()
        expect(page.locator('#page-center')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        page.go_forward()
        expect(page.locator('#page-community')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(kev['product'])
        return {
            'advisory_search': advisory_term,
            'kev_filter': True,
            'explicit_vendor_filter': kev['vendor'],
            'shareable_search_and_severity': True,
            'date_and_page_size_restore': True,
            'cve_detail_deep_link_case_normalization': True,
            'cross_page_detail_preservation': True,
            'overview_route_with_latent_detail_reloads_correctly': True,
            'browser_back_forward_restores_routes_and_filters': True,
            'filter_edits_replace_history_entry': True,
            'escape_closes_date_filter_and_restores_focus': True,
            'wordmark_returns_to_overview': True,
        }
    finally:
        page.close()


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
        # Swipe previews are visible before the route is committed; wait for the semantic active state first.
        expect(page.locator(f'#tab-{name}')).to_have_attribute('aria-selected', 'true')
        expect(page.locator(f'#page-{name}')).to_be_visible()
        for candidate in ('overview', 'latest', 'center', 'changes', 'community'):
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

    def safe_touch_corridor(direction: str = 'left', distance: int = 150) -> dict | None:
        return page.evaluate('''({direction, distance}) => {
          const active = document.querySelector('.page:not([hidden])');
          const blocked = 'a[href], button, input, select, textarea, option, summary, details, [role="button"], [role="link"], [role="combobox"], [role="textbox"], [role="dialog"], [aria-modal="true"], [contenteditable]:not([contenteditable="false"]), .record-list, .record-row, .research-toolbar, .filter-controls, .severity-distribution, .pagination, .detail-view, .snapshot-loader, .overview-kpis, .overview-grid, .activity-panel, .latest-preview-row, .latest-page-item, .latest-list, .source-intelligence';
          const hasTextAtPoint = (x, y) => {
            let node = null, offset = 0;
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
              const range = document.createRange();
              range.setStart(node, index); range.setEnd(node, index + 1);
              for (const rect of range.getClientRects()) if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) return true;
            }
            return false;
          };
          const sign = direction === 'left' ? -1 : 1;
          const firstX = direction === 'left' ? innerWidth - 4 : 4;
          const lastX = firstX + sign * distance;
          for (let y = Math.max(110, document.querySelector('.site-header').getBoundingClientRect().bottom + 2); y < innerHeight - 24; y += 4) {
            for (let x = firstX; direction === 'left' ? x >= lastX : x <= lastX; x += sign * 4) {
              let safe = true;
              for (let offset = 0; offset <= distance; offset += 4) {
                const px = x + sign * offset;
                const hit = document.elementFromPoint(px, y);
                if (!(hit instanceof Element) || hit.closest('.page') !== active || hit.closest(blocked) || hasTextAtPoint(px, y)) { safe = false; break; }
              }
              if (safe) return {x, y, active: active?.id ?? null};
            }
          }
          return null;
        }''', {'direction': direction, 'distance': distance})

    def drag_from_edge(direction: str, distance: int = 150, *, y: int = 500, steps: int = 6, delay_ms: int = 12) -> None:
        active_id = page.locator('.page:not([hidden])').get_attribute('id')
        if active_id in {'page-latest', 'page-changes'}:
            corridor = safe_touch_corridor(direction, distance)
            assert corridor is not None, f'No safe touch swipe corridor on {active_id}: {direction} {distance}px'
            x, y = corridor['x'], corridor['y']
        else:
            edge_inset = 3
            x = page.evaluate('window.innerWidth') - edge_inset if direction == 'left' else edge_inset
        dx = -distance if direction == 'left' else distance
        swipe(x, y, dx, steps=steps, delay_ms=delay_ms)

    def point(selector: str, x_fraction: float = 0.5, y_fraction: float = 0.5) -> tuple[int, int]:
        box = page.locator(selector).bounding_box()
        assert box is not None, f'Missing visible test target: {selector}'
        return round(box['x'] + box['width'] * x_fraction), round(box['y'] + box['height'] * y_fraction)

    def safe_drag_corridor(target_page, direction: str = 'left', distance: int = 190) -> dict:
        corridor = target_page.evaluate('''({direction, distance}) => {
          const active = document.querySelector('.page:not([hidden])');
          const blocked = 'a[href], button, input, select, textarea, option, summary, details, [role="button"], [role="link"], [role="combobox"], [role="textbox"], [role="dialog"], [aria-modal="true"], [contenteditable]:not([contenteditable="false"]), .record-list, .record-row, .research-toolbar, .filter-controls, .severity-distribution, .pagination, .detail-view, .snapshot-loader, .overview-kpis, .overview-grid, .activity-panel, .latest-preview-row, .latest-page-item, .latest-list, .source-intelligence, .snapshot-status-strip, .snapshot-rail, .latest-page-list, .snapshot-summary, article, .terminal-frame';
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
        short_corridor = safe_touch_corridor('left', 24)
        assert short_corridor is not None, 'Overview has no empty surface for short-swipe tracking.'
        start_x, start_y = short_corridor['x'], short_corridor['y']
        dispatch_touch('touchStart', start_x, start_y)
        dispatch_touch('touchMove', start_x - 24, start_y)
        visual = page.evaluate('''() => {
          const current = document.querySelector('#page-overview');
          const next = document.querySelector('#page-latest');
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
        fast_corridor = safe_touch_corridor('left', 48)
        assert fast_corridor is not None, 'Overview has no empty surface for the fast-swipe test.'
        fast_swipe_start = time.time()
        dispatch_touch('touchStart', fast_corridor['x'], fast_corridor['y'], timestamp=fast_swipe_start)
        dispatch_touch('touchMove', fast_corridor['x'] - 48, fast_corridor['y'], timestamp=fast_swipe_start + 0.04)
        dispatch_touch('touchEnd', timestamp=fast_swipe_start + 0.05)
        expect_active('latest')
        expect(page.locator('#latest-page-status')).to_contain_text('verified latest records')

        # All four adjacent routes work; the state remains synchronized with the existing tabs.
        drag_from_edge('right')
        expect_active('overview')
        drag_from_edge('left')
        expect_active('latest')
        drag_from_edge('left')
        expect_active('center')
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']), timeout=120_000)
        drag_from_edge('left')
        expect_active('changes')
        drag_from_edge('left')
        expect_active('community')
        expect(page).to_have_url(f'{origin}/?page=community')

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
        expect_active('changes')
        expect(page).to_have_url(f'{origin}/?page=changes')
        page.locator('#tab-center').click()
        expect_active('center')

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
            blocked: Boolean(target?.closest('a[href], button, input, select, textarea, [role="button"], [role="link"], .record-row, .pagination, .detail-view, .overview-kpis, .overview-grid, .activity-panel, .latest-preview-row, .latest-page-item, .latest-list, .source-intelligence')),
          };
        }""")
        assert safe_start == {'page': 'page-center', 'blocked': False}, f'Post-pagination swipe did not start on a safe Center background: {safe_start}'
        drag_from_edge('left', y=150)
        expect_active('changes')
        drag_from_edge('left', y=150)
        expect_active('community')
        swipe(panel_x, panel_y, 160, steps=6, delay_ms=12)
        expect_active('changes')
        page.locator('#tab-center').click()
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
        expect_active('changes')
        drag_from_edge('left')
        expect_active('community')
        route_state = page.evaluate('''() => {
          const params = new URLSearchParams(location.search);
          return {page: params.get('page'), cve: params.get('cve'), size: params.get('size')};
        }''')
        assert route_state == {'page': 'community', 'cve': detail_id, 'size': '48'}, route_state
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

        # The terminal background supports Community → Changes; the Explore tab restores retained detail/search state.
        swipe(panel_x, panel_y, 160, steps=6, delay_ms=12)
        expect_active('changes')
        page.locator('#tab-center').click()
        expect_active('center')
        expect(page.locator('#detail-view')).to_be_visible()
        expect(page.locator('#record-search')).to_have_value(detail_id)
        route_state = page.evaluate('''() => {
          const params = new URLSearchParams(location.search);
          return {page: params.get('page'), cve: params.get('cve'), size: params.get('size')};
        }''')
        assert route_state == {'page': 'center', 'cve': detail_id, 'size': '48'}, route_state
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
            blocked: Boolean(target?.closest('a[href], button, input, select, textarea, [role="button"], [role="link"], .record-row, .pagination, .detail-view, .overview-kpis, .overview-grid, .activity-panel, .latest-preview-row, .latest-page-item, .latest-list, .source-intelligence')),
          };
        }""")
        assert safe_start == {'page': 'page-center', 'blocked': False}, f'Post-pagination swipe did not start on a safe Center background: {safe_start}'
        drag_from_edge('left', y=150)
        expect_active('changes')
        assert page.locator('#page-archive').count() == 0 and page.locator('#tab-archive').count() == 0
        page.locator('#tab-community').click()
        expect_active('community')
        assert not page.locator('#page-community').evaluate('element => element.classList.contains("page-enter")')
        terminal = page.locator('.terminal-screen').bounding_box()
        assert terminal is not None
        swipe(round(terminal['x'] + 5), round(terminal['y'] + 4), 160, steps=6, delay_ms=12)
        expect_active('changes')
        assert page.locator('#page-archive').count() == 0 and page.locator('#tab-archive').count() == 0
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

        # The real snapshot activity chart is an interaction surface, never a desktop swipe corridor.
        activity = desktop_page.locator('.activity-panel').bounding_box()
        assert activity is not None
        chart_point = (round(activity['x'] + activity['width'] * 0.96), round(activity['y'] + activity['height'] * 0.08))
        assert desktop_page.evaluate('([x, y]) => Boolean(document.elementFromPoint(x, y)?.closest(".activity-panel"))', list(chart_point))
        desktop_page.mouse.move(*chart_point)
        desktop_page.mouse.down()
        desktop_page.mouse.move(chart_point[0] - 190, chart_point[1], steps=8)
        desktop_page.mouse.up()
        expect(desktop_page.locator('#page-overview')).to_be_visible()

        desktop_page.locator('#tab-community').click()
        expect(desktop_page.locator('#page-community')).to_be_visible()
        desktop_page.locator('#tab-overview').click()
        desktop_page.wait_for_timeout(300)  # Let the 250ms page-entry animation settle before measuring a text-free swipe corridor.
        safe = safe_drag_corridor(desktop_page)
        desktop_page.mouse.move(safe['x'], safe['y'])
        desktop_page.mouse.down()
        desktop_page.mouse.move(safe['x'] - 36, safe['y'], steps=3)
        live_pair = desktop_page.evaluate('''() => {
          const current = document.querySelector('#page-overview');
          const next = document.querySelector('#page-latest');
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
        expect(desktop_page.locator('#page-latest')).to_be_visible()
        desktop_page.wait_for_function("() => !document.querySelector('.page.is-swipe-settling')", timeout=2_000)
        assert desktop_page.locator('#tab-latest').get_attribute('aria-selected') == 'true'
        assert desktop_page.locator('#tab-latest').evaluate('element => element.tabIndex') == 0
        assert desktop_page.locator('#tab-overview').evaluate('element => element.tabIndex') == -1
        expect(desktop_page).to_have_url(f'{origin}/?page=latest')

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
        expect(desktop_page.locator('#page-latest')).to_be_visible()
        assert desktop_page.locator('#tab-latest').get_attribute('aria-selected') == 'true'

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
        expect(desktop_page.locator('#page-latest')).to_be_visible()
        assert not desktop_page.locator('#page-latest').evaluate('element => element.classList.contains("page-enter")')

        desktop_page.locator('#tab-overview').focus()
        desktop_page.keyboard.press('ArrowRight')
        expect_active_name = desktop_page.locator('#tab-latest').get_attribute('aria-selected')
        assert expect_active_name == 'true' and desktop_page.evaluate('document.activeElement.id') == 'tab-latest'
        desktop_page.keyboard.press('Home')
        assert desktop_page.locator('#tab-overview').get_attribute('aria-selected') == 'true'
        for page_name in ('overview', 'latest', 'center', 'changes', 'community'):
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


def run_discovery_and_retry_tests(browser, origin: str, manifest: dict, overview: dict) -> dict:
    # Verify truthful Latest, legacy route disposition, observed Changes, and fail-closed history retry.
    navigation_issues = {'page_errors': [], 'console_errors': [], 'request_failures': [], 'external_requests': []}
    page = browser.new_page(viewport={'width':1280,'height':900})
    browser_issue_track(page,navigation_issues,origin)
    expected_latest=[record['id'] for record in overview['records']]
    production_history=json.loads((ROOT/'snapshot'/manifest['history']['path']).read_bytes())
    try:
        page.goto(f'{origin}/?page=overview',wait_until='load')
        expect(page.locator('#overview-status')).to_contain_text('CVE records',timeout=30_000)
        expect(page.locator('#source-check-age')).to_contain_text('Approximate snapshot age at page load')
        assert page.locator('#source-check-list .source-check-row').count()==len(manifest['source_status'])
        for i,source in enumerate(manifest['source_status']):
            row=page.locator('#source-check-list .source-check-row').nth(i)
            expect(row.locator('.source-check-row__identity strong')).to_have_text(source['name'])
            expect(row.locator('.source-check-row__result')).to_have_attribute('data-outcome','success' if source['ok'] else 'unavailable')
            assert row.locator('.source-check-row__result time').count()==int(bool(source.get('checked_at')))

        page.goto(f'{origin}/?page=latest',wait_until='load')
        expect(page.locator('#latest-page-status')).to_contain_text('verified latest records',timeout=30_000)
        assert page.locator('.latest-page-item__id').all_text_contents()==expected_latest
        assert page.locator('#latest-record-count').inner_text()==nfmt(len(expected_latest))
        assert page.locator('.latest-page-item__id').evaluate_all('links=>links.map(link=>link.getAttribute("href"))')==[
            f'?page=center&cve={cve_id}' for cve_id in expected_latest]
        assert page.locator('#latest-generated-at').get_attribute('datetime')==manifest['generated_at']
        assert page.locator('#latest-activity-at').get_attribute('datetime')==overview['records'][0]['activity_at']
        page.screenshot(path=str(SCREENSHOTS/'05-latest-desktop.png'),animations='disabled')

        source_name=next(source for record in overview['records'] for source in record['sources'])
        page.locator('#latest-filter-source').select_option(source_name)
        source_expected=[record['id'] for record in overview['records'] if source_name in record['sources']]
        assert page.locator('.latest-page-item__id').all_text_contents()==source_expected
        page.locator('#latest-filter-source').select_option('all')
        page.locator('#latest-filter-epss').fill('0')
        epss_expected=[record['id'] for record in overview['records'] if record['epss'] is not None]
        assert page.locator('.latest-page-item__id').all_text_contents()==epss_expected
        page.locator('#latest-filter-epss').fill('')
        page.locator('#latest-filter-kev').check()
        kev_expected=[record['id'] for record in overview['records'] if record['kev_date_added'] is not None]
        assert page.locator('.latest-page-item__id').all_text_contents()==kev_expected
        page.locator('#latest-filter-kev').uncheck()
        page.locator('#latest-filter-search').fill(expected_latest[0])
        assert page.locator('.latest-page-item__id').all_text_contents()==[expected_latest[0]]
        page.locator('#latest-filter-search').fill('')
        assert page.locator('.latest-page-item__id').all_text_contents()==expected_latest

        # Old archive bookmarks become Explore date filters; there is no phantom Archive page or nav tab.
        legacy_day=next(day for day in manifest['days'] if day['count'])['date']
        page.goto(f'{origin}/?page=archive&from={legacy_day}&to={legacy_day}',wait_until='load')
        expect(page.locator('#page-center')).to_be_visible()
        expect(page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']),timeout=120_000)
        expect(page.locator('#date-from')).to_have_value(legacy_day)
        expect(page.locator('#date-to')).to_have_value(legacy_day)
        expect(page).to_have_url(f'{origin}/?page=center&from={legacy_day}&to={legacy_day}')
        assert page.locator('#page-archive').count()==0 and page.locator('#tab-archive').count()==0
        page.screenshot(path=str(SCREENSHOTS/'06-explore-legacy-route-desktop.png'),animations='disabled')
    finally:
        page.close()

    # Production history is derived from complete captures; intercepted synthetic events below remain test-only.
    production_page=browser.new_page(viewport={'width':1280,'height':900})
    browser_issue_track(production_page,navigation_issues,origin)
    try:
        production_page.goto(f'{origin}/?page=center',wait_until='load')
        expect(production_page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']),timeout=120_000)
        production_page.locator('#tab-changes').click()
        expect(production_page.locator('#page-changes')).to_be_visible()
        expect(production_page.locator('#change-event-count')).to_have_text(nfmt(len(production_history['events'])),timeout=30_000)
        if not production_history['events']:
            expect(production_page.locator('#change-event-list')).to_contain_text('No changes are shown until two complete captures can be compared.')
            expect(production_page.locator('#change-window-note')).to_contain_text('baseline capture')
        else:
            expect(production_page.locator('#change-event-list .change-event-row')).to_have_count(min(40, len(production_history['events'])))
        production_page.screenshot(path=str(SCREENSHOTS/'07-changes-captured-desktop.png'),animations='disabled')
        production_page.set_viewport_size({'width':390,'height':844})
        if production_history['events']:
            production_id=production_history['events'][0]['id']
            production_page.locator('#change-search').fill(production_id)
            expect(production_page.locator('#change-event-list .change-event-row')).not_to_have_count(0)
            assert production_page.evaluate('new URLSearchParams(location.search).get("changeSearch")') == production_id
            production_page.locator('#change-search').fill('')
        mobile_changes=production_page.evaluate('''() => ({viewport:innerWidth,document:document.documentElement.scrollWidth,
          searchHeight:document.querySelector('#change-search').getBoundingClientRect().height,
          filterHeight:document.querySelector('[data-change-filter="all"]').getBoundingClientRect().height})''')
        assert mobile_changes['document'] <= mobile_changes['viewport'], mobile_changes
        assert mobile_changes['searchHeight'] >= 40 and mobile_changes['filterHeight'] >= 40, mobile_changes
        production_page.evaluate('window.scrollTo(0,document.body.scrollHeight); window.scrollTo(0,0);')
        production_page.screenshot(path=str(SCREENSHOTS/'07-changes-captured-mobile.png'),animations='disabled')
    finally:
        production_page.close()

    # Synthetic records below exist only in this browser fixture; the repository history remains untouched.
    rows=read_decoded_search_rows(manifest)
    assert len(rows)>=3
    synthetic_history=json.loads(json.dumps(production_history))
    observed=manifest['generated_at']
    synthetic_history['events']=[
        {'id':rows[0]['id'],'type':'CVSS_CHANGED','observed_at':observed,'source_time':rows[0].get('modified') or rows[0]['activity_at'],'source':'NVD last modified','from':5.0,'to':8.0},
        {'id':rows[1]['id'],'type':'KEV_ADDED','observed_at':observed,'source_time':None,'source':'CISA KEV','from':None,'to':{'date_added':observed[:10]}},
        {'id':rows[2]['id'],'type':'CVE_REOBSERVED','observed_at':observed,'source_time':rows[2]['activity_at'],'source':'NVD last modified','from':{'previous_window':'outside the retained 30-day feed'},'to':{'note':'A source reports recent activity; the prior full record is outside the retained 30-day feed window, so individual field differences cannot be reconstructed.'}},
    ]
    synthetic_history_raw=json.dumps(synthetic_history,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
    synthetic_manifest=json.loads(json.dumps(manifest))
    synthetic_manifest['history']['bytes']=len(synthetic_history_raw)
    synthetic_manifest['history']['sha256']=hashlib.sha256(synthetic_history_raw).hexdigest()
    synthetic_manifest['history']['event_count']=len(synthetic_history['events'])
    synthetic_manifest_raw=json.dumps(synthetic_manifest,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
    synthetic_page=browser.new_page(viewport={'width':1280,'height':900})
    browser_issue_track(synthetic_page,navigation_issues,origin)
    synthetic_page.route('**/snapshot/manifest.json',lambda route:route.fulfill(status=200,content_type='application/json; charset=utf-8',body=synthetic_manifest_raw))
    synthetic_page.route(f"**/snapshot/{manifest['history']['path']}",lambda route:route.fulfill(status=200,content_type='application/json; charset=utf-8',body=synthetic_history_raw))
    try:
        synthetic_page.goto(f'{origin}/?page=center',wait_until='load')
        expect(synthetic_page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']),timeout=120_000)
        synthetic_page.locator('#tab-changes').click()
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(3,timeout=30_000)
        expect(synthetic_page.locator('#change-event-count')).to_have_text('3')
        first_event=synthetic_page.locator('#change-event-list .change-event').first
        if len(rows[0]['title']) == 180:
            displayed_title = synthetic_page.locator('.change-event__title').first.text_content() or ''
            assert displayed_title.endswith('…'), displayed_title
        expect(first_event).to_contain_text('Observed')
        expect(first_event).to_contain_text('Source time')
        expect(first_event).to_contain_text('NVD last modified')
        synthetic_page.screenshot(path=str(SCREENSHOTS/'07-changes-desktop.png'),animations='disabled')

        synthetic_page.locator('[data-change-filter="CVSS_CHANGED"]').click()
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        expect(synthetic_page.locator('[data-change-filter="CVSS_CHANGED"]')).to_have_attribute('aria-pressed','true')
        assert synthetic_page.evaluate('new URLSearchParams(location.search).get("changeType")') == 'CVSS_CHANGED'
        synthetic_page.locator('[data-change-filter="KEV"]').click()
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        expect(synthetic_page.locator('#change-event-list .change-event-row:visible .change-type')).to_have_text('KEV ADDED')
        assert synthetic_page.evaluate('new URLSearchParams(location.search).get("changeType")') == 'KEV'
        synthetic_page.locator('[data-change-filter="all"]').click()
        synthetic_page.locator('#change-search').fill(rows[2]['id'])
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        assert synthetic_page.evaluate('new URLSearchParams(location.search).get("changeSearch")') == rows[2]['id']
        synthetic_page.locator('#change-search').fill('')
        synthetic_page.locator('#change-from').fill(observed[:10])
        synthetic_page.locator('#change-to').fill(observed[:10])
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(3)
        assert synthetic_page.evaluate('new URLSearchParams(location.search).get("changeFrom")') == observed[:10]
        assert synthetic_page.evaluate('new URLSearchParams(location.search).get("changeTo")') == observed[:10]
        synthetic_page.locator('#change-search').fill(rows[2]['id'])
        share_state = synthetic_page.evaluate('Object.fromEntries(new URLSearchParams(location.search))')
        synthetic_page.reload(wait_until='load')
        expect(synthetic_page.locator('#change-search')).to_have_value(rows[2]['id'])
        expect(synthetic_page.locator('#change-from')).to_have_value(observed[:10])
        expect(synthetic_page.locator('#change-to')).to_have_value(observed[:10])
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        assert synthetic_page.evaluate('Object.fromEntries(new URLSearchParams(location.search))') == share_state
        synthetic_page.locator('#change-search').fill('CVE_REOBSERVED')
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        expect(synthetic_page.locator('.change-event__diff')).to_contain_text('outside the retained 30-day feed')
        expect(synthetic_page.locator('.change-event__diff')).to_contain_text('cannot be reconstructed')
        synthetic_page.locator('#change-search').fill('')
        synthetic_page.locator('[data-change-filter="CVSS_CHANGED"]').click()
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        expect(synthetic_page.locator('.change-event__id').first).to_have_text(rows[0]['id'])
        synthetic_page.locator('.change-event__id').first.click()
        expect(synthetic_page.locator('#detail-heading')).to_have_text(rows[0]['id'],timeout=60_000)
        expect(synthetic_page.locator('#detail-history')).to_be_visible(timeout=30_000)
        if len(rows[0]['title']) == 180:
            displayed_detail_title = synthetic_page.locator('#detail-summary').text_content() or ''
            assert displayed_detail_title.endswith('…'), displayed_detail_title
        expect(synthetic_page.locator('#detail-content')).to_contain_text('CVSS CHANGED')
        synthetic_page.go_back(wait_until='domcontentloaded')
        expect(synthetic_page.locator('#page-changes')).to_be_visible()
        synthetic_page.go_forward(wait_until='domcontentloaded')
        expect(synthetic_page.locator('#detail-heading')).to_have_text(rows[0]['id'],timeout=30_000)
        synthetic_page.go_back(wait_until='domcontentloaded')
        expect(synthetic_page.locator('#page-changes')).to_be_visible()
        synthetic_page.locator('[data-change-filter="all"]').click()
        synthetic_page.set_viewport_size({'width':390,'height':844})
        expect(synthetic_page.locator('#change-search')).to_be_visible()
        synthetic_page.locator('#change-search').fill(rows[2]['id'])
        expect(synthetic_page.locator('#change-event-list .change-event-row')).to_have_count(1)
        mobile_changes = synthetic_page.evaluate('''() => ({viewport:innerWidth,document:document.documentElement.scrollWidth,
          searchHeight:document.querySelector('#change-search').getBoundingClientRect().height,
          filterHeight:document.querySelector('[data-change-filter="all"]').getBoundingClientRect().height})''')
        assert mobile_changes['document'] <= mobile_changes['viewport'], mobile_changes
        assert mobile_changes['searchHeight'] >= 40 and mobile_changes['filterHeight'] >= 40, mobile_changes
        synthetic_page.evaluate('window.scrollTo(0,document.body.scrollHeight); window.scrollTo(0,0);')
        synthetic_page.screenshot(path=str(SCREENSHOTS/'07-changes-mobile.png'),animations='disabled')
        assert not synthetic_page.locator('#tab-archive').count() and not synthetic_page.locator('#page-archive').count()
    finally:
        synthetic_page.close()

    # History network failure displays no events, and a user retry restores only the hash-verified sidecar.
    retry_issues={'page_errors':[],'console_errors':[],'request_failures':[],'external_requests':[]}
    retry_page=browser.new_page(viewport={'width':1280,'height':900})
    browser_issue_track(retry_page,retry_issues,origin)
    attempts={'count':0}
    def abort_first_history(route):
        attempts['count']+=1
        if attempts['count']==1: route.abort()
        else: route.continue_()
    retry_page.route(f"**/snapshot/{manifest['history']['path']}",abort_first_history)
    try:
        retry_page.goto(f'{origin}/?page=center',wait_until='load')
        expect(retry_page.locator('#snapshot-total')).to_have_text(nfmt(manifest['totals']['cves']),timeout=120_000)
        retry_page.locator('#tab-changes').click()
        expect(retry_page.locator('#changes-retry')).to_be_visible(timeout=30_000)
        expect(retry_page.locator('#change-event-list')).to_contain_text('Change history could not be verified. No events are displayed.')
        assert retry_page.locator('#change-event-list .change-event-row').count()==0
        retry_page.locator('#changes-retry').click()
        expect(retry_page.locator('#change-event-count')).to_have_text(nfmt(len(production_history['events'])),timeout=30_000)
        expect(retry_page.locator('#changes-retry')).to_be_hidden()
        assert retry_page.evaluate('document.activeElement.id')=='change-page-status'
        assert attempts['count']==2,attempts
        assert len(retry_issues['request_failures'])==1 and retry_issues['request_failures'][0].endswith('/'+manifest['history']['path']),retry_issues['request_failures']
        retry_issues['request_failures'].clear()
        expected_abort=[message for message in retry_issues['console_errors'] if 'net::ERR_FAILED' in message]
        assert len(expected_abort)==1 and len(retry_issues['console_errors'])==1,retry_issues['console_errors']
        retry_issues['console_errors'].clear()
        assert not retry_issues['page_errors'] and not retry_issues['external_requests'],retry_issues
    finally:
        retry_page.close()

    assert not navigation_issues['page_errors'],navigation_issues['page_errors']
    assert not navigation_issues['console_errors'],navigation_issues['console_errors']
    assert not navigation_issues['request_failures'],navigation_issues['request_failures']
    assert not navigation_issues['external_requests'],navigation_issues['external_requests']
    return {
        'latest_ids_match_verified_activity_order':expected_latest,
        'newest_activity_matches_overview_timestamp':True,
        'legacy_archive_bookmark_redirects_to_explore_with_dates':True,
        'archive_navigation_removed':True,
        'production_history_event_count':len(production_history['events']),
        'production_history_observation_times':sorted({event['observed_at'] for event in production_history['events']}),
        'production_history_source_provenance_valid':all(isinstance(event.get('source'),str) and event['source'] and event.get('observed_at') for event in production_history['events']),
        'synthetic_only_changes_filter_search_and_provenance_checks':True,
        'history_retry_attempts':attempts['count'],
        'history_failure_has_no_partial_events':True,
        'retry_restores_focus_to_live_status':True,
        'external_requests':0,
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
    assert expected_latest and len(expected_latest) == min(50, expected_count)

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
            raw_browser = playwright.chromium.launch(**launch)
            browser = BrowserWithoutServiceWorkers(raw_browser)

            overview_page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            browser_issue_track(overview_page, issues, origin)
            overview_requests: list[str] = []
            overview_page.on('request', lambda request: overview_requests.append(urlsplit(request.url).path.removeprefix('/snapshot/'))
                             if '/snapshot/data/' in request.url and not request.url.endswith(('/overview.json', '/epss.json', '/search-index.json.gz', '/history.json')) else None)
            overview_page.goto(f'{origin}/', wait_until='load')
            expect(overview_page.locator('#overview-status')).to_contain_text(f'{nfmt(expected_count)} CVE records')
            expect(overview_page.locator('#overview-status')).to_have_attribute('aria-busy', 'false')
            expect(overview_page.locator('#page-overview .overview-footer')).to_contain_text('Nothing here is a live upstream check')
            overview_preview_ids = expected_latest[:4]
            assert overview_page.locator('.latest-preview-row__id').all_text_contents() == overview_preview_ids
            assert overview_page.locator('.latest-preview-row__id').evaluate_all('links => links.map(link => link.getAttribute("href"))') == [
                f'?page=center&cve={cve_id}' for cve_id in overview_preview_ids
            ]
            assert overview_page.locator('#page-overview [data-snapshot-generated]').get_attribute('datetime') == manifest['generated_at']
            assert overview_page.locator('.activity-chart .chart-bar').count() == len(manifest['days'])
            assert overview_page.locator('.source-check-row').count() == len(manifest['source_status'])
            for cve_id in overview_preview_ids:
                assert cve_id in overview_page.locator('.snapshot-rail').inner_text()
            overview_page.wait_for_timeout(100)
            assert not overview_requests, f'Overview fetched full shards unnecessarily: {overview_requests}'
            csp = overview_page.locator('meta[http-equiv="Content-Security-Policy"]').get_attribute('content')
            assert "default-src 'self'" in csp and "script-src 'self'" in csp and "object-src 'none'" in csp
            overview_page.screenshot(path=str(SCREENSHOTS / '01-overview-desktop.png'))

            # Each Overview link is a real deep link into its exact verified record.
            overview_page.locator('.latest-preview-row__id').first.click()
            expect(overview_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(overview_page.locator('#detail-heading')).to_have_text(expected_latest[0])
            expect(overview_page).to_have_url(f'{origin}/?page=center&cve={expected_latest[0]}')
            overview_page.go_back(wait_until='load')
            expect(overview_page.locator('#page-overview')).to_be_visible()
            overview_page.go_forward(wait_until='load')
            expect(overview_page.locator('#detail-heading')).to_have_text(expected_latest[0])
            overview_page.keyboard.press('Escape')
            expect(overview_page.locator('#detail-view')).to_be_hidden()
            assert overview_page.evaluate('document.activeElement.dataset.cveId') == expected_latest[0]
            overview_page.goto(f'{origin}/?page=overview', wait_until='load')
            overview_page.locator('#explore-cves').click()
            expect(overview_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(overview_page.locator('.record-row')).to_have_count(min(24, expected_count))
            expected_detail_path = f"data/{overview['records'][0]['window_date']}.json"
            assert overview_requests == [expected_detail_path], f'Explore requested unexpected full detail shards: {overview_requests}'
            overview_page.close()
            print('PASS: data-derived Overview KPIs/chart/source checks, index-first Explore, one lazy detail shard, deep links, and focus restoration.')

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
                expect(page.locator('#epss-warning')).to_contain_text('Stale')
                expect(page.locator('#epss-warning')).to_contain_text('not 0%')
            else:
                expect(page.locator('#epss-warning')).to_be_visible()
                expect(page.locator('#epss-warning')).to_contain_text('score set current at capture')
                expect(page.locator('#epss-warning')).to_contain_text('Missing scores are not 0%.')
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
            assert page.locator('#date-filter').get_attribute('open') is not None
            page.locator('#date-from').fill(sample_day)
            page.locator('#date-to').fill(sample_day)
            page.locator('#date-form button[type="submit"]').click()
            assert page.locator('#date-filter').get_attribute('open') is None
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
            expect(page.locator('#detail-content')).to_contain_text('CWE classification')
            expect(page.locator('#detail-content')).to_contain_text('Not supplied in the validated snapshot schema.')
            why_section = page.locator('.detail-why')
            expect(why_section).to_contain_text('Evidence summary from this verified capture')
            expect(why_section).to_contain_text('CVSS' if isinstance(sample.get('score'), (int, float)) else 'No numeric CVSS score')
            expect(why_section).to_contain_text('FIRST EPSS')
            expect(why_section).to_contain_text('CISA KEV')
            assert page.locator('.detail-tabs .detail-tab').all_text_contents() == ['Summary', 'Why This Matters', 'Record', 'Signals', 'Affected', 'References', 'Sources', 'History']
            for section_id in ('detail-why', 'detail-record', 'detail-signals', 'detail-affected', 'detail-references', 'detail-sources', 'detail-history'):
                tab = page.locator(f'.detail-tabs .detail-tab[href="#{section_id}"]')
                tab.click()
                expect(page.locator(f'#{section_id}')).to_be_visible()
                assert tab.get_attribute('aria-current') == 'location'
            page.evaluate('window.scrollTo(0, 0)')
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
            print('PASS: manifest ETag revalidation, cache-first repeat load, explicit network reload, changed-hash retry, and malformed/tampered fail-closed behavior.')
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
            victim['refs'] = [{
                'label': label_payload, 'url': 'https://example.com/security/advisory', 'source': 'NVD'
            }, *(victim.get('refs') or [])[:11]]
            override_manifest, override_shard, override_day = snapshot_override(manifest, latest_day, malicious_rows)
            malicious_index = read_search_index(manifest)
            index_victim = next(row for row in malicious_index['records'] if row[0] == victim_id)
            index_victim[1] = title_payload
            index_victim[2] = ' '.join(description_payload.split())[:320]
            malicious_index_raw = json.dumps(malicious_index, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
            malicious_index_body = gzip.compress(malicious_index_raw, compresslevel=9, mtime=0)
            overridden_manifest = json.loads(override_manifest)
            overridden_manifest['search_index']['bytes'] = len(malicious_index_body)
            overridden_manifest['search_index']['sha256'] = hashlib.sha256(malicious_index_body).hexdigest()
            overridden_manifest['search_index']['uncompressed_bytes'] = len(malicious_index_raw)
            overridden_manifest['search_index']['uncompressed_sha256'] = hashlib.sha256(malicious_index_raw).hexdigest()
            override_manifest = json.dumps(overridden_manifest, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
            xss_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(xss_page, issues, origin)
            install_snapshot_override(xss_page, override_manifest, override_shard, override_day, malicious_index_body)
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
            tampered_id = tampered_rows[0]['id']
            tampered_body = json.dumps(tampered_rows, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
            tamper_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(tamper_page, issues, origin)
            tamper_page.route(f'**/snapshot/data/{latest_day["date"]}.json', lambda route: route.fulfill(status=200, content_type='application/json; charset=utf-8', body=tampered_body))
            tamper_page.goto(f'{origin}/?page=center&search={tampered_id}', wait_until='load')
            expect(tamper_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(tamper_page.locator('#record-list .record-row')).to_have_count(1)
            tamper_page.locator('.record-open').click()
            expect(tamper_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
            expect(tamper_page.locator('.detail-load-error')).to_contain_text('failed integrity verification')
            assert tamper_page.locator('#detail-heading').count() == 0
            assert tamper_page.locator('#detail-content img, #detail-content svg, #detail-content script').count() == 0
            tamper_page.close()

            # A correctly digested resource with an invalid record schema fails visibly, not as loading.
            invalid_rows = json.loads((ROOT / 'snapshot' / latest_day['path']).read_text(encoding='utf-8'))
            invalid_rows[0]['title'] = ''
            invalid_id = invalid_rows[0]['id']
            schema_manifest, schema_shard, schema_day = snapshot_override(manifest, latest_day, invalid_rows)
            schema_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(schema_page, issues, origin)
            install_snapshot_override(schema_page, schema_manifest, schema_shard, schema_day)
            schema_page.goto(f'{origin}/?page=center&search={invalid_id}', wait_until='load')
            expect(schema_page.locator('#snapshot-total')).to_have_text(nfmt(expected_count), timeout=120_000)
            expect(schema_page.locator('#record-list .record-row')).to_have_count(1)
            schema_page.locator('.record-open').click()
            expect(schema_page.locator('.detail-load-error')).to_be_visible(timeout=30_000)
            assert schema_page.locator('#detail-heading').count() == 0
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
            print('PASS: bad digests, invalid detail schema, oversized manifest/resources and source failures fail visibly without rendering unverified partial data.')

            # Exercise every page at mobile and desktop widths without external requests.
            page.locator('#tab-overview').click()
            width_metrics = {}
            for width in (320, 360, 375, 390, 414, 768, 1024, 1280, 1440):
                width_metrics[width] = {}
                for tab in ('overview', 'latest', 'center', 'changes', 'community'):
                    page.locator(f'#tab-{tab}').click()
                    width_metrics[width][tab] = width_audit(page, width)
            stable_search_metrics = stable_search_toolbar_audit(browser, origin, issues, expected_count, manifest)
            print('PASS: the sticky Explore search toolbar keeps one stable geometry; focus, filtering and result layout remain usable while scrolling.')
            print('Search release metrics:', json.dumps(stable_search_metrics, sort_keys=True))
            url_state_metrics = run_shareable_search_state_tests(browser, origin, issues, manifest)
            print('PASS: shareable search/filter state, advisory lookup, explicit KEV/vendor filtering, route/deep-link restoration, wordmark navigation, and Escape focus behavior.')
            print('URL state QA details:', json.dumps(url_state_metrics, sort_keys=True))
            page.locator('#tab-community').click()
            expect(page.locator('#page-community')).to_be_visible()
            page.locator('#idle-prompt:not([hidden])').wait_for(timeout=10_000)
            expect(page.locator('#terminal-info')).to_be_visible()
            expect(page.locator('#join-bugcod3')).to_have_text('Join BugCod3')
            expect(page.locator('#join-rootaccessclub')).to_have_text('Join RootAccessClub')
            for link_id in ('join-bugcod3', 'join-rootaccessclub'):
                expect(page.locator(f'#{link_id}')).to_be_enabled()
            page.screenshot(path=str(SCREENSHOTS / '04-community-desktop.png'))
            print('PASS: all five pages fit 320–1440 CSS px; Community is reachable, accessible, and uses safe external links.')

            discovery_metrics = run_discovery_and_retry_tests(browser, origin, manifest, overview)
            print('PASS: captured source status, Latest links, truthful Changes and legacy-route disposition, and fail-closed explicit retry.')
            print('Discovery QA details:', json.dumps(discovery_metrics, sort_keys=True))

            swipe_results = run_swipe_navigation_tests(browser, origin, manifest)
            print('PASS: touch swipe navigation, touch-safe controls, reduced motion, gesture cancellation, and state preservation.')
            print('Swipe QA details:', json.dumps(swipe_results, sort_keys=True))

            update_metrics = run_background_snapshot_update_test(browser, origin, manifest, overview, issues)
            print('PASS: the background same-origin check exposes a dismissible notice only after the newer manifest and index verify.')
            print('Background-update QA details:', json.dumps(update_metrics, sort_keys=True))

            offline_metrics = run_offline_cache_tests(raw_browser, origin, manifest, expected_count, issues)
            print('PASS: service-worker shell cache, fully verified offline Overview/Latest/Explore, mobile bottom rail, and fail-closed missing-shard behavior.')
            print('Offline QA details:', json.dumps(offline_metrics, sort_keys=True))

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
