#!/usr/bin/env python3
"""Portable browser QA for SubZer0's manifest-verified static snapshot."""
from __future__ import annotations

import functools
import hashlib
import http.server
import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent
SCREENSHOTS = Path('/tmp/subzero-security-review-screenshots')
SCREENSHOTS.mkdir(parents=True, exist_ok=True)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass


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
            assert 'SHA-256' not in tamper_page.locator('#result-status').inner_text()
            tamper_page.close()

            # Oversized manifest response must be rejected without rendering any records.
            oversized_page = browser.new_page(viewport={'width': 1280, 'height': 900})
            browser_issue_track(oversized_page, issues, origin)
            oversized_page.route('**/snapshot/manifest.json', lambda route: route.fulfill(
                status=200, content_type='application/json; charset=utf-8', body=b' ' * (512 * 1024 + 1)
            ))
            oversized_page.goto(f'{origin}/?page=center', wait_until='load')
            expect(oversized_page.locator('#result-status')).to_contain_text('could not be verified', timeout=30_000)
            expect(oversized_page.locator('#record-list .record-row')).to_have_count(0)
            oversized_page.close()
            print('PASS: unauthenticated data tampering and oversized manifest responses fail closed with generic errors and no partial feed.')

            # Exercise every page at mobile and desktop widths without external requests.
            page.locator('#tab-overview').click()
            width_metrics = {}
            for width in (320, 360, 390, 412, 768, 1024, 1440):
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
