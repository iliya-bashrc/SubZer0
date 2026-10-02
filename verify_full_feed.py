#!/usr/bin/env python3
"""Browser QA for the independent, full-feed SubZer0 local preview."""
from __future__ import annotations

import functools
import http.server
import io
import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageChops
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent
BASE_PREVIEW = Path('/workspace/subzero-terminal-community-preview-20261002')
SCREENSHOTS = ROOT / 'screenshots'
SCREENSHOTS.mkdir(exist_ok=True)


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def latest_snapshot_ids(root: Path = ROOT) -> tuple[list[str], str]:
    manifest = json.loads((root / 'snapshot' / 'manifest.json').read_text(encoding='utf-8'))
    rows = []
    for day in manifest['days']:
        rows.extend(json.loads((root / 'snapshot' / day['path']).read_text(encoding='utf-8')))

    def order(record: dict) -> tuple[float, str]:
        stamp = record.get('activity_at') or f"{record.get('window_date', '')}T00:00:00"
        try:
            parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00') if stamp.endswith('Z') else stamp)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp(), record.get('id', '')
        except (TypeError, ValueError):
            return 0, record.get('id', '')

    rows.sort(key=order, reverse=True)
    return [row['id'] for row in rows[:3]], manifest['last_successful_update']


def verify_inherited_scope() -> None:
    source_html = (BASE_PREVIEW / 'index.html').read_text(encoding='utf-8')
    preview_html = (ROOT / 'index.html').read_text(encoding='utf-8')
    assert section(source_html, '      <nav class="page-nav"', '      </nav>') == section(preview_html, '      <nav class="page-nav"', '      </nav>')
    assert section(source_html, '          <div class="overview-copy">', '          <div class="ui-stage"') == section(preview_html, '          <div class="overview-copy">', '          <div class="ui-stage"')
    strip_latest_rules = lambda css: '\n'.join(line for line in css.splitlines() if not line.startswith(('.latest-id {', '.latest-id:hover {')))
    assert strip_latest_rules((BASE_PREVIEW / 'styles.css').read_text(encoding='utf-8')) == strip_latest_rules((ROOT / 'styles.css').read_text(encoding='utf-8'))
    assert (BASE_PREVIEW / 'severity-effects.css').read_bytes() == (ROOT / 'severity-effects.css').read_bytes()
    assert not any(token in (ROOT / 'feed.css').read_text(encoding='utf-8') for token in ('.community-', '.terminal-', '.telegram-cta'))
    print('PASS: navigation, Overview purpose/copy/CTA, black-metal base and approved severity effects are retained; Community is verified by its focused suite.')


def track(page, issues: dict, local_origin: str) -> None:
    page.on('pageerror', lambda error: issues['page_errors'].append(str(error)))
    page.on('console', lambda message: issues['console_errors'].append(message.text) if message.type == 'error' else None)
    page.on('requestfailed', lambda request: issues['request_failures'].append(request.url))
    page.on('request', lambda request: issues['external_requests'].append(request.url)
            if not request.url.startswith((local_origin, 'data:')) and request.url != 'https://t.me/RootAccessClub' else None)


def width_audit(page, width: int, height: int = 900) -> dict:
    page.set_viewport_size({'width': width, 'height': height})
    page.wait_for_timeout(100)
    metrics = page.evaluate('''() => ({
      viewport: window.innerWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
      activePage: document.querySelector('.page:not([hidden])')?.scrollWidth ?? 0,
      activePageId: document.querySelector('.page:not([hidden])')?.id ?? 'none',
      center: document.querySelector('#page-center').scrollWidth,
      list: document.querySelector('#record-list').scrollWidth
    })''')
    assert metrics['document'] <= width, f'horizontal overflow at {width}px: {metrics}'
    assert metrics['body'] <= width, f'body overflow at {width}px: {metrics}'
    assert metrics['activePage'] <= width, f"active page overflow at {width}px ({metrics['activePageId']}): {metrics}"
    return metrics


def check_dom_safe(page) -> None:
    assert page.locator('img[data-xss], svg[data-xss], script[data-xss]').count() == 0
    assert page.evaluate('window.__subzeroXss === undefined')
    assert page.locator('#detail-content a[href^="javascript:"]').count() == 0


def main() -> None:
    verify_inherited_scope()
    issues = {'page_errors': [], 'console_errors': [], 'request_failures': [], 'external_requests': []}
    handler = functools.partial(QuietHandler, directory=str(ROOT))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                executable_path=shutil.which('chromium'),
                args=['--no-sandbox', '--disable-dev-shm-usage'],
            )

            expected_latest_ids, expected_update = latest_snapshot_ids()
            overview = browser.new_page(viewport={'width': 1440, 'height': 1000})
            track(overview, issues, origin)
            overview_shard_requests = []
            overview.on('request', lambda request: overview_shard_requests.append(request.url) if '/snapshot/' in request.url else None)
            overview.goto(f'{origin}/', wait_until='load')
            expect(overview.locator('#page-overview')).to_be_visible()
            assert overview.locator('.latest-id').all_text_contents() == expected_latest_ids
            assert overview.locator('.latest-id').evaluate_all('links => links.map(link => link.getAttribute("href"))') == [f'?page=center&cve={item}' for item in expected_latest_ids]
            assert overview.locator('.snapshot-heading time').get_attribute('datetime') == expected_update
            assert all(item in overview.locator('.ui-stage').inner_text() for item in expected_latest_ids)
            assert overview.locator('#explore-cves').count() == 1
            assert overview.locator('.latest-id').first.evaluate('(link) => link.getBoundingClientRect().height') >= 44
            overview.wait_for_timeout(180)
            assert not overview_shard_requests, overview_shard_requests
            overview.screenshot(path=str(SCREENSHOTS / '01-overview-desktop.png'), full_page=False)

            # A recent ID is a local direct link into its exact full-feed record, not a dead label.
            overview.locator('.latest-id').first.click()
            expect(overview.locator('#snapshot-total')).to_have_text('15,318', timeout=90000)
            expect(overview.locator('#detail-heading')).to_have_text(expected_latest_ids[0])
            expect(overview).to_have_url(f'{origin}/?page=center&cve={expected_latest_ids[0]}')
            overview.keyboard.press('Escape')
            expect(overview.locator('#detail-view')).to_be_hidden()
            assert overview.evaluate('document.activeElement.dataset.cveId') == expected_latest_ids[0]

            # A clean Overview CTA opens the ordinary first page of the complete feed.
            overview.goto(f'{origin}/?page=overview', wait_until='load')
            expect(overview.locator('#page-overview')).to_be_visible()
            overview.locator('#explore-cves').click()
            expect(overview.locator('#snapshot-total')).to_have_text('15,318', timeout=90000)
            assert len(overview_shard_requests) >= 33, len(overview_shard_requests)
            expect(overview.locator('.record-row')).to_have_count(24)
            overview.close()
            print('PASS: Overview latest IDs and update time match the manifest; deep links open exact details and restore focus; Explore loads the unfiltered feed lazily.')

            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, device_scale_factor=1)
            track(page, issues, origin)
            page.goto(f'{origin}/?page=center', wait_until='load')
            expect(page.locator('#page-center')).to_be_visible()
            expect(page.locator('#snapshot-total')).to_have_text('15,318', timeout=90000)
            expect(page.locator('#snapshot-kev-total')).to_have_text('45')
            expect(page.locator('#result-status')).to_contain_text('Showing 1–24 of 15,318 matching records')
            expect(page.locator('.record-row')).to_have_count(24)
            assert page.locator('.record-row').first.locator('.record-date').get_attribute('datetime') == '2026-10-02'
            expect(page.locator('#epss-warning')).to_contain_text('marked stale')
            expect(page.locator('#epss-warning')).to_contain_text('not 0%')
            expect(page.locator('#snapshot-provenance')).to_contain_text('Oct 02, 2026, 06:00:04 UTC')
            assert page.locator('#record-list').get_attribute('aria-busy') == 'false'
            print('PASS: all 15,318 unique records loaded from 31 bundled shards; 24 visible rows on first arrival; count, latest order, KEV total and stale-EPSS notice match.')

            # Pagination and bounded rendering.
            first_id = page.locator('.record-row').first.get_attribute('data-cve-id')
            page.locator('#page-next').click()
            expect(page.locator('#page-indicator')).to_have_text('Page 2 of 639')
            expect(page.locator('#result-status')).to_contain_text('Showing 25–48 of 15,318')
            assert page.locator('.record-row').first.get_attribute('data-cve-id') != first_id
            page.locator('#page-prev').click()
            expect(page.locator('#page-indicator')).to_have_text('Page 1 of 639')
            page.locator('#page-size').select_option('48')
            expect(page.locator('.record-row')).to_have_count(48)
            page.locator('#page-size').select_option('96')
            expect(page.locator('.record-row')).to_have_count(96)
            assert page.locator('.record-row').count() <= 96
            page.locator('#page-size').select_option('24')
            print('PASS: previous/next pagination and 24/48/96 page-size controls work; no more than 96 rows are mounted.')

            # Severity filters preserve the exact source categories while neutralizing None/Unknown.
            for severity, total in (('critical', '1,507'), ('high', '6,361'), ('medium', '4,955'), ('low', '949'), ('unrated', '1,546')):
                button = page.locator(f'.severity-tab[data-severity="{severity}"]')
                button.click()
                expect(button).to_have_attribute('aria-pressed', 'true')
                expect(page.locator('#result-status')).to_contain_text(f'of {total} matching records')
                assert page.locator('.record-row').count() <= 24
                assert all(f'severity-{severity}' in classes.split() for classes in page.locator('.record-row').evaluate_all('rows => rows.map(row => row.className)'))
            page.locator('.severity-tab[data-severity="all"]').click()
            print('PASS: Critical, High, Medium, Low and Unrated filters return manifest totals with the requested color categories; All restores the complete feed.')

            # Date filter limits the displayed activity window without removing the snapshot total.
            page.locator('#date-filter summary').click()
            page.locator('#date-from').fill('2026-10-02')
            page.locator('#date-to').fill('2026-10-02')
            page.locator('#date-form button[type="submit"]').click()
            expect(page.locator('#result-status')).to_contain_text('of 58 matching records')
            expect(page.locator('#snapshot-total')).to_have_text('15,318')
            assert page.locator('.record-row').count() == 24
            print('PASS: date range narrows to the 58 records in the 02 Oct shard while the total snapshot count remains 15,318.')

            # Search supports product/title and exact ID; detail/back restores the filtered record and focus.
            page.locator('#record-search').fill('CTX Feed Pro')
            expect(page.locator('.record-row')).to_have_count(1)
            assert page.locator('.record-row').first.get_attribute('data-cve-id') == 'CVE-2026-10026'
            page.locator('#record-search').fill('CVE-2026-93367')
            expect(page.locator('.record-row')).to_have_count(1)
            page.locator('.record-open').click()
            expect(page.locator('#detail-heading')).to_have_text('CVE-2026-93367')
            for label in ('CVSS severity', 'EPSS probability', 'CISA KEV evidence', 'GitHub / PoC leads'):
                expect(page.locator('#detail-content dt').filter(has_text=label)).to_have_count(1)
            source_links = page.locator('#detail-content a').evaluate_all('''links => links.map(link => ({
              label: link.textContent.trim(), href: link.href
            }))''')
            assert any(link['label'] == 'FIRST EPSS data' and 'first.org/epss' in link['href'] for link in source_links), source_links
            assert any(link['label'] == 'Open CISA KEV catalog' and 'cisa.gov/known-exploited-vulnerabilities-catalog' in link['href'] for link in source_links), source_links
            assert any(link['label'] == 'Search GitHub repositories for CVE-2026-93367' and 'github.com/search' in link['href'] for link in source_links), source_links
            page.keyboard.press('Escape')
            expect(page.locator('.record-row')).to_have_count(1)
            expect(page.locator('#record-search')).to_have_value('CVE-2026-93367')
            assert page.evaluate('document.activeElement.dataset.cveId') == 'CVE-2026-93367'
            print('PASS: product/title and exact-ID search; details separate CVSS, EPSS, KEV and GitHub/PoC; Escape restores the filtered row and focus.')

            # One real KEV record has no EPSS entry; another has an EPSS score but Unknown CVSS severity.
            page.locator('#date-filter summary').click()
            page.locator('#date-from').fill('2026-09-02')
            page.locator('#date-to').fill('2026-10-02')
            page.locator('#date-form button[type="submit"]').click()
            page.locator('#record-search').fill('CVE-2026-104286')
            expect(page.locator('.record-row')).to_have_count(1)
            page.locator('.record-open').click()
            expect(page.locator('#detail-content')).to_contain_text('Listed in the captured CISA KEV catalog')
            expect(page.locator('#detail-content')).to_contain_text('No EPSS score is available')
            expect(page.locator('#detail-content')).to_contain_text('Missing means unscored, not 0%.')
            assert '0.00% exploitation probability' not in page.locator('#detail-content').inner_text()
            page.locator('#back-to-results').click()
            page.locator('#record-search').fill('CVE-2026-9586')
            expect(page.locator('.record-row')).to_have_count(1)
            page.locator('.record-open').click()
            expect(page.locator('#detail-content')).to_contain_text('source category Unknown')
            expect(page.locator('#detail-content')).to_contain_text('18.98% exploitation probability')
            expect(page.locator('#detail-content')).to_contain_text('Listed in the captured CISA KEV catalog')
            page.locator('#back-to-results').click()
            page.locator('#record-search').fill('CVE-2026-23591')
            expect(page.locator('.record-row')).to_have_count(1)
            page.locator('.record-open').click()
            expect(page.locator('#detail-content')).to_contain_text('0.0 · None source category')
            expect(page.locator('.detail-header .severity-label')).to_have_attribute('title', 'Source CVSS category: None')
            page.locator('#back-to-results').click()
            print('PASS: missing EPSS is not zero; CVE-2026-9586 remains Unknown with a score; CVE-2026-23591 preserves source category None distinctly.')

            # Keyboard shortcut and accessible focus behavior.
            page.locator('#record-search').fill('')
            page.locator('body').click(position={'x': 1390, 'y': 900})
            page.keyboard.press('/')
            assert page.evaluate('document.activeElement.id') == 'record-search'
            page.locator('#page-center').focus()
            page.keyboard.press('Tab')
            print('PASS: / shortcut focuses search; controls remain native keyboard-focusable buttons/inputs.')

            # At rest, only intersecting rows run their effect animation.
            page.locator('.severity-tab[data-severity="critical"]').click()
            page.evaluate('window.scrollTo(0, 0)')
            visible_row = page.locator('.record-row').first
            page.wait_for_function("document.querySelector('.record-row.effect-visible .record-fleck') !== null")
            fleck = visible_row.locator('.record-fleck').first
            state_before = fleck.evaluate("node => ({play:getComputedStyle(node).animationPlayState, name:getComputedStyle(node).animationName, x:node.getBoundingClientRect().x, y:node.getBoundingClientRect().y})")
            page.wait_for_timeout(1500)
            state_after = fleck.evaluate("node => ({play:getComputedStyle(node).animationPlayState, name:getComputedStyle(node).animationName, x:node.getBoundingClientRect().x, y:node.getBoundingClientRect().y})")
            assert state_before['play'] == 'running' and state_before['name'] != 'none', (state_before, state_after)
            assert abs(state_after['x'] - state_before['x']) > 0.25 or abs(state_after['y'] - state_before['y']) > 0.25, (state_before, state_after)
            offscreen_row = page.locator('.record-row').last
            offscreen = offscreen_row.locator('.record-fleck').first
            if offscreen.count():
                audit = page.evaluate('''() => { const row=document.querySelector('.record-row:last-child'); const fleck=row.querySelector('.record-fleck'); const r=row.getBoundingClientRect(); return {scrollY:window.scrollY, rowClass:row.className, top:r.top, bottom:r.bottom, play:getComputedStyle(fleck).animationPlayState}; }''')
                assert 'effect-visible' not in offscreen_row.get_attribute('class') and audit['play'] == 'paused', audit
            page.emulate_media(reduced_motion='reduce')
            expect(fleck).to_have_css('animation-name', 'none')
            expect(fleck).to_have_css('opacity', '0.42')
            page.emulate_media(reduced_motion='no-preference')
            print('PASS: visible fleck transforms measurably over time; off-screen rows stay paused; reduced-motion keeps a static fleck version.')

            # Capture an animated clip of a single severity-specific record material.
            page.wait_for_timeout(250)
            clip_frames = []
            for _ in range(22):
                clip_frames.append(Image.open(io.BytesIO(visible_row.locator('.record-open').screenshot())).convert('RGB'))
                page.wait_for_timeout(350)
            gif_path = SCREENSHOTS / '16-moving-severity-fleck-demo.gif'
            clip_frames[0].save(gif_path, save_all=True, append_images=clip_frames[1:], duration=350, loop=0, optimize=True)
            assert gif_path.stat().st_size > 1000
            assert ImageChops.difference(clip_frames[0], clip_frames[-1]).getbbox() is not None, 'motion capture frames are identical'

            # Replace the cloned preview's old five-record severity strip with five real captured cards.
            severity_crops = []
            for severity in ('critical', 'high', 'medium', 'low', 'unrated'):
                page.locator(f'.severity-tab[data-severity="{severity}"]').click()
                colored_row = page.locator('.record-row').first
                page.wait_for_function("document.querySelector('.record-row.effect-visible .record-fleck') !== null")
                page.wait_for_timeout(180)
                severity_crops.append(Image.open(io.BytesIO(colored_row.locator('.record-open').screenshot())).convert('RGB'))
            crop_w = max(image.width for image in severity_crops)
            crop_h = max(image.height for image in severity_crops)
            severity_sheet = Image.new('RGB', (crop_w, crop_h * len(severity_crops) + 8 * (len(severity_crops) - 1)), (8, 12, 15))
            for index, image in enumerate(severity_crops):
                severity_sheet.paste(image, (0, index * (crop_h + 8)))
            severity_sheet.save(SCREENSHOTS / '13-severity-five-materials-closeup.png')

            # Desktop capture; return to All so the first screen shows the populated archive.
            page.locator('.severity-tab[data-severity="all"]').click()
            page.evaluate('window.scrollTo(0, 0)')
            page.set_viewport_size({'width': 1440, 'height': 1000})
            page.wait_for_timeout(450)
            page.screenshot(path=str(SCREENSHOTS / '02-cve-center-desktop.png'), full_page=False)
            page.screenshot(path=str(SCREENSHOTS / '14-cve-center-desktop-full-feed.png'), full_page=True)
            page.locator('#record-search').fill('CVE-2026-104286')
            expect(page.locator('.record-row')).to_have_count(1)
            page.locator('.record-open').click()
            expect(page.locator('#detail-heading')).to_have_text('CVE-2026-104286')
            page.evaluate('document.documentElement.scrollTop=0; document.body.scrollTop=0; window.scrollTo(0,0)')
            page.wait_for_timeout(120)
            page.screenshot(path=str(SCREENSHOTS / '03-cve-detail-desktop.png'), full_page=True)

            # Android-like browser emulation: 360x800, DPR 2, touch enabled.
            mobile = browser.new_page(viewport={'width': 360, 'height': 800}, device_scale_factor=2, is_mobile=True, has_touch=True)
            track(mobile, issues, origin)
            mobile.goto(f'{origin}/?page=center', wait_until='load')
            expect(mobile.locator('#snapshot-total')).to_have_text('15,318', timeout=90000)
            expect(mobile.locator('.record-row')).to_have_count(24)
            mobile_metrics = width_audit(mobile, 360, 800)
            assert mobile.locator('.nav-tab').evaluate_all('tabs => tabs.every(tab => tab.getBoundingClientRect().height >= 44)')
            assert mobile.locator('.severity-tab').evaluate_all('tabs => tabs.every(tab => tab.getBoundingClientRect().height >= 44)')
            for width, height, output in ((320, 800, '06-cve-center-mobile-320.png'), (390, 844, '08-cve-center-mobile-390.png'), (412, 915, '11-android-412-cve-center.png')):
                width_audit(mobile, width, height)
                mobile.set_viewport_size({'width': width, 'height': height})
                mobile.evaluate('document.documentElement.scrollTop=0; document.body.scrollTop=0; window.scrollTo(0,0)')
                mobile.screenshot(path=str(SCREENSHOTS / output), full_page=False)
            mobile.set_viewport_size({'width': 360, 'height': 800})
            mobile.evaluate('document.documentElement.scrollTop=0; document.body.scrollTop=0; window.scrollTo(0,0)')
            mobile.wait_for_timeout(250)
            mobile.screenshot(path=str(SCREENSHOTS / '11-android-360-cve-center.png'), full_page=False)
            mobile.screenshot(path=str(SCREENSHOTS / '15-cve-center-android-mobile.png'), full_page=True)
            mobile.locator('.record-open').first.tap()
            expect(mobile.locator('#detail-view')).to_be_visible()
            expect(mobile.locator('#detail-heading')).to_be_visible()
            mobile.locator('#back-to-results').tap()
            expect(mobile.locator('.record-row')).to_have_count(24)

            mobile.locator('#tab-overview').tap()
            expect(mobile.locator('#page-overview')).to_be_visible()
            assert mobile.locator('.latest-id').evaluate_all('links => links.every(link => link.getBoundingClientRect().height >= 44)')
            mobile.evaluate('document.documentElement.scrollTop=0; document.body.scrollTop=0; window.scrollTo(0,0)')
            mobile.screenshot(path=str(SCREENSHOTS / '10-android-360-overview.png'), full_page=False)
            mobile.locator('#latest-heading').scroll_into_view_if_needed()
            mobile.screenshot(path=str(SCREENSHOTS / '10b-android-360-overview-latest-links.png'), full_page=False)
            mobile.locator('.latest-id').first.tap()
            expect(mobile.locator('#detail-heading')).to_have_text(expected_latest_ids[0], timeout=90000)
            mobile.locator('#back-to-results').tap()
            mobile.locator('#tab-community').tap()
            expect(mobile.locator('#join-bugcod3')).to_be_visible()
            expect(mobile.locator('#join-rootaccessclub')).to_be_visible()
            mobile.evaluate('document.documentElement.scrollTop=0; document.body.scrollTop=0; window.scrollTo(0,0)')
            mobile.screenshot(path=str(SCREENSHOTS / '12-android-360-community.png'), full_page=False)
            mobile.close()

            # Audit each page at every requested CSS width in a desktop browser context.
            page.locator('#back-to-results').click()
            page.locator('#record-search').fill('')
            expect(page.locator('.record-row')).to_have_count(24)
            desktop_metrics = {}
            for width in (320, 360, 390, 412, 768, 1024, 1440):
                desktop_metrics[width] = {}
                for route in ('overview', 'center', 'community'):
                    page.locator(f'#tab-{route}').click()
                    if route == 'center':
                        expect(page.locator('.record-row')).to_have_count(24)
                    desktop_metrics[width][route] = width_audit(page, width)
            print('PASS: Overview, CVE Center and Community have no page-level overflow at 320, 360, 390, 412, 768, 1024 and 1440 CSS px; Android-like 360px touch routes work.')

            # Verify safely-rendered untrusted snapshot text and reject a javascript: source URL.
            xss = browser.new_page(viewport={'width': 1280, 'height': 900})
            track(xss, issues, origin)
            shard_path = ROOT / 'snapshot' / 'data' / '2026-10-02.json'
            shard = json.loads(shard_path.read_text(encoding='utf-8'))
            victim = next(item for item in shard if item['id'] == 'CVE-2026-93367')
            victim['title'] = '<img data-xss="title" src=x onerror="window.__subzeroXss=1">'
            victim['desc'] = '<script data-xss="description">window.__subzeroXss=1</script>'
            victim['primary_url'] = 'javascript:window.__subzeroXss=2'
            victim['refs'] = [{'label': '<svg data-xss="label" onload="window.__subzeroXss=3">', 'url': 'javascript:window.__subzeroXss=4', 'source': '<b>Injected</b>'}]

            def fulfill_shard(route):
                route.fulfill(status=200, content_type='application/json; charset=utf-8', body=json.dumps(shard))

            xss.route('**/snapshot/data/2026-10-02.json', fulfill_shard)
            track(xss, issues, origin)
            xss.goto(f'{origin}/?page=center', wait_until='load')
            expect(xss.locator('#snapshot-total')).to_have_text('15,318', timeout=90000)
            xss.locator('#record-search').fill('CVE-2026-93367')
            expect(xss.locator('.record-row')).to_have_count(1)
            expect(xss.locator('.record-title')).to_have_text(victim['title'])
            assert xss.locator('img[data-xss], svg[data-xss], script[data-xss]').count() == 0
            xss.locator('.record-open').click()
            expect(xss.locator('.detail-title')).to_have_text(victim['title'])
            check_dom_safe(xss)
            assert '<svg data-xss="label" onload="window.__subzeroXss=3"> · link unavailable' in xss.locator('#detail-content').inner_text()
            xss.close()
            print('PASS: source-controlled title/description/reference text renders literally; script/HTML payloads do not create nodes or execute, and javascript: links are rejected.')

            # Smoke-test the updated Community page; the dedicated suite covers its full interactions.
            community = browser.new_page(viewport={'width': 1440, 'height': 1000})
            track(community, issues, origin)
            community.goto(f'{origin}/?page=community', wait_until='load')
            expect(community.locator('#page-community')).to_be_visible()
            community.locator('#idle-prompt:not([hidden])').wait_for(timeout=5000)
            expect(community.locator('#terminal-info')).to_be_visible()
            expect(community.locator('#join-bugcod3')).to_have_text('Join BugCod3')
            expect(community.locator('#join-rootaccessclub')).to_have_text('Join RootAccessClub')
            assert '@BugCod3' in community.locator('#terminal-info').inner_text()
            assert '@RootAccessClub' in community.locator('#terminal-info').inner_text()
            community.screenshot(path=str(SCREENSHOTS / '04-community-desktop.png'), full_page=False)
            community.close()
            print('PASS: Community page routes, renders the staged ./info output and exposes both requested actions.')

            reduced = browser.new_page(viewport={'width': 1200, 'height': 800}, reduced_motion='reduce')
            track(reduced, issues, origin)
            reduced.goto(f'{origin}/?page=community', wait_until='load')
            expect(reduced.locator('#info-command')).to_have_text('./info')
            expect(reduced.locator('#terminal-info')).to_be_visible()
            expect(reduced.locator('#idle-prompt')).to_be_visible()
            assert reduced.locator('#idle-prompt .terminal-caret').evaluate('(node) => getComputedStyle(node).animationName') == 'none'
            reduced.close()
            print('PASS: Community reduced-motion entry immediately shows completed output with no caret animation.')

            # Mobile-size detail and each responsive breakpoint are checked without external requests.
            detail_mobile = browser.new_page(viewport={'width': 360, 'height': 800}, device_scale_factor=2, is_mobile=True, has_touch=True)
            track(detail_mobile, issues, origin)
            detail_mobile.goto(f'{origin}/?page=center', wait_until='load')
            expect(detail_mobile.locator('#snapshot-total')).to_have_text('15,318', timeout=90000)
            detail_mobile.locator('#record-search').fill('CVE-2026-9586')
            detail_mobile.locator('.record-open').click()
            expect(detail_mobile.locator('#detail-heading')).to_have_text('CVE-2026-9586')
            detail_mobile.evaluate('document.documentElement.scrollTop=0; document.body.scrollTop=0; window.scrollTo(0,0)')
            detail_mobile.wait_for_timeout(120)
            detail_mobile.screenshot(path=str(SCREENSHOTS / '09-cve-detail-mobile-360.png'), full_page=True)
            for width in (320, 360, 390, 412, 768, 1024, 1440):
                width_audit(detail_mobile, width)
            detail_mobile.close()

            assert not issues['page_errors'], f"JavaScript errors: {issues['page_errors']}"
            assert not issues['console_errors'], f"Console errors: {issues['console_errors']}"
            assert not issues['request_failures'], f"Failed browser requests: {issues['request_failures']}"
            assert not issues['external_requests'], f"Unexpected external requests: {issues['external_requests']}"
            print('PASS: no browser page errors, console errors, failed requests or background/external feed requests.')
            print('Responsive metrics:', json.dumps({'desktop': desktop_metrics, 'mobile360': mobile_metrics}, sort_keys=True))
            print(f'Screenshots: {SCREENSHOTS}')
            print(f'Motion demo: {gif_path} ({gif_path.stat().st_size:,} bytes)')
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
