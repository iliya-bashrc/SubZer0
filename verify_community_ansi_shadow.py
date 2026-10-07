#!/usr/bin/env python3
"""Render and interact with the independent SubZer0 Community preview using local Chromium only."""
from __future__ import annotations

import json
import argparse
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from playwright.sync_api import Browser, Page, Route, sync_playwright

ROOT = Path(__file__).resolve().parent
BASELINE_REF = os.environ.get('SUBZERO_BASELINE_REF', 'origin/main')
BASELINE_DIR = os.environ.get('SUBZERO_BASELINE_DIR')
SCREENSHOTS = Path(os.environ.get('SUBZERO_COMMUNITY_SCREENSHOT_DIR', '/tmp/subzero-community-ansi-shadow-qa'))
RESULT_PATH = Path(os.environ.get('SUBZERO_COMMUNITY_RESULT_PATH', '/tmp/subzero-community-ansi-shadow-results.json'))
EXPECTED_ANSI_ROWS = (
    '███████╗██╗   ██╗██████╗ ███████╗███████╗██████╗  ██████╗' + " ",
    '██╔════╝██║   ██║██╔══██╗╚══███╔╝██╔════╝██╔══██╗██╔═████╗',
    '███████╗██║   ██║██████╔╝  ███╔╝ █████╗  ██████╔╝██║██╔██║',
    '╚════██║██║   ██║██╔══██╗ ███╔╝  ██╔══╝ ██╔══██╗████╔╝██║' + " ",
    '███████║╚██████╔╝██████╔╝███████╗███████╗██║  ██║╚██████╔╝',
    '╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝' + " ",
    " " * 58,
)
EXPECTED_ANSI_BANNER = "\n".join(EXPECTED_ANSI_ROWS)
SCREENSHOTS.mkdir(parents=True, exist_ok=True)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        pass


def serve(directory: Path) -> ThreadingHTTPServer:
    handler = partial(QuietHandler, directory=str(directory))
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def assert_no_page_errors(page: Page, errors: list[str]) -> None:
    if errors:
        raise AssertionError('Browser errors: ' + '; '.join(errors))


def watch_errors(page: Page, errors: list[str]) -> None:
    page.on('pageerror', lambda error: errors.append(f'pageerror: {error}'))
    page.on('console', lambda message: errors.append(f'console: {message.text}') if message.type == 'error' else None)


def load(page: Page, url: str) -> None:
    page.goto(url, wait_until='domcontentloaded', timeout=30000)


def wait_idle(page: Page) -> None:
    page.locator('#idle-prompt:not([hidden])').wait_for(state='visible', timeout=4000)
    page.locator('#terminal-info:not([hidden])').wait_for(state='visible', timeout=4000)


def local_interceptor(attempts: list[str]):
    def intercept(route: Route) -> None:
        attempts.append(route.request.url)
        route.fulfill(
            status=200,
            content_type='text/html; charset=utf-8',
            body='<!doctype html><title>Intercepted locally</title><main id="local-intercept">Local Telegram destination intercepted for this test.</main>',
        )
    return intercept


def wait_for_local_destination(page: Page, destination: str, attempts: list[str], started: float) -> float:
    page.wait_for_function('(url) => location.href === url', arg=destination, timeout=3000)
    page.locator('#local-intercept').wait_for(state='visible', timeout=3000)
    elapsed = time.monotonic() - started
    assert len(attempts) == 1, f'Expected exactly one intercepted navigation, got {attempts!r}'
    assert attempts[0] == destination, f'Wrong destination: {attempts[0]}'
    assert 0.8 <= elapsed <= 1.35, f'Navigation delay outside the intended brief pause: {elapsed:.3f}s'
    return elapsed


def terminal_metrics(page: Page) -> dict[str, Any]:
    return page.evaluate('''() => {
      const box = (selector) => {
        const element = document.querySelector(selector);
        if (!element) return null;
        const rect = element.getBoundingClientRect();
        return {left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height,
          clientWidth: element.clientWidth, scrollWidth: element.scrollWidth, clientHeight: element.clientHeight, scrollHeight: element.scrollHeight};
      };
      return {
        viewport: {width: innerWidth, height: innerHeight},
        document: {width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight},
        body: {width: document.body.scrollWidth, height: document.body.scrollHeight},
        frame: box('.terminal-frame'), screen: box('.terminal-screen'), info: box('#terminal-info'),
        actions: [...document.querySelectorAll('.community-action')].map((el) => ({
          text: el.innerText, accessibleName: el.getAttribute('aria-label'), disabled: el.disabled, width: el.getBoundingClientRect().width,
          top: el.getBoundingClientRect().top, bottom: el.getBoundingClientRect().bottom,
          height: el.getBoundingClientRect().height, clientWidth: el.clientWidth, scrollWidth: el.scrollWidth
        })),
        icons: [...document.querySelectorAll('.community-action__icon')].map((el) => {
          const image = el.querySelector('img');
          const rect = el.getBoundingClientRect();
          const imageRect = image?.getBoundingClientRect();
          return {src: image?.getAttribute('src') ?? null, loaded: Boolean(image?.complete && image.naturalWidth > 0), width: rect.width, height: rect.height,
            imageWidth: imageRect?.width ?? 0, imageHeight: imageRect?.height ?? 0};
        }),
        actionInsideTerminal: document.querySelector('.community-actions').closest('.terminal-frame') !== null,
        infoText: document.querySelector('#terminal-info').innerText,
        communityText: document.querySelector('#page-community').innerText,
        disclaimerText: document.querySelector('.community-disclaimer')?.innerText ?? null,
        promptText: document.querySelector('#idle-prompt').innerText,
        bannerText: document.querySelector('.terminal-banner').textContent,
        bannerFontSize: getComputedStyle(document.querySelector('.terminal-banner')).fontSize,
        bannerRect: box('.terminal-banner')
      };
    }''')


def assert_terminal_fits(metrics: dict[str, Any]) -> None:
    width, height = metrics['viewport']['width'], metrics['viewport']['height']
    assert metrics['document']['width'] <= width, f'Horizontal page overflow at {width}px: {metrics}'
    assert metrics['body']['width'] <= width, f'Body overflow at {width}px: {metrics}'
    assert metrics['document']['height'] <= height, f'Unwanted page scrolling at {width}px: {metrics}'
    assert metrics['frame']['left'] >= 0 and metrics['frame']['right'] <= width, f'Terminal frame clips at {width}px: {metrics}'
    assert metrics['frame']['top'] >= 0 and metrics['frame']['bottom'] <= height, f'Terminal frame extends past viewport at {width}px: {metrics}'
    assert metrics['screen']['scrollWidth'] <= metrics['screen']['clientWidth'], f'Terminal content overflows horizontally at {width}px: {metrics}'
    assert metrics['bannerText'] == EXPECTED_ANSI_BANNER, f'ANSI Shadow banner changed at {width}px.'
    assert metrics['bannerRect']['scrollWidth'] <= metrics['bannerRect']['clientWidth'], f'ANSI Shadow banner overflows at {width}px: {metrics}'
    assert metrics['actionInsideTerminal'], 'Community actions are outside the terminal frame.'
    assert all(item['top'] >= 0 and item['bottom'] <= height for item in metrics['actions']), f'Community actions do not fit at {width}px: {metrics}'
    assert [item['text'] for item in metrics['actions']] == ['Join BugCod3', 'Join RootAccessClub']
    assert [item['accessibleName'] for item in metrics['actions']] == ['Join BugCod3 on Telegram', 'Join RootAccessClub on Telegram']
    assert [item['src'] for item in metrics['icons']] == ['assets/telegram-mark.svg', 'assets/telegram-mark.svg']
    assert all(item['loaded'] and item['width'] == 34 and item['height'] == 34 and item['imageWidth'] == 24 and item['imageHeight'] == 24 for item in metrics['icons']), f'Telegram icon sizing or layout slot changed at {width}px: {metrics}'
    assert all('@' not in item['text'] for item in metrics['actions'])
    assert all(item['width'] >= 46 and item['height'] >= 46 for item in metrics['actions']), f'Tap target is below 46px at {width}px: {metrics}'
    assert all(item['scrollWidth'] <= item['clientWidth'] for item in metrics['actions']), f'Action label clips at {width}px: {metrics}'
    assert 'CVE Intelligence & Vulnerability Research' in metrics['infoText']
    assert 'A platform for discovering, tracking\nand exploring security vulnerabilities.' in metrics['infoText']
    assert 'CREATED BY' in metrics['infoText'] and 'STATUS' in metrics['infoText']
    assert metrics['disclaimerText'] is None
    assert 'SubZer0 is not affiliated with Telegram.' not in metrics['communityText']
    assert '@BugCod3' in metrics['infoText'] and '@RootAccessClub' in metrics['infoText']
    assert '● ONLINE' in metrics['infoText']
    assert 'user@subzero' in metrics['promptText'] and '~/SubZer0' in metrics['promptText']


def screenshot_comparison(browser: Browser, base_url: str, preview_url: str, page_name: str, width: int, height: int, file_stem: str) -> dict[str, Any]:
    from PIL import Image, ImageChops, ImageDraw

    captures: list[Path] = []
    counts: list[int] = []
    overview_action_counts: list[int] = []
    action_bounds: list[dict[str, Any]] = []
    center_dock_bounds: list[dict[str, Any]] = []
    for label, url in (('baseline', base_url), ('preview', preview_url)):
        page = browser.new_page(viewport={'width': width, 'height': height}, device_scale_factor=1)
        errors: list[str] = []
        watch_errors(page, errors)
        page.emulate_media(reduced_motion='reduce')
        load(page, f'{url}/?page={page_name}')
        if page_name == 'center':
            page.wait_for_function("() => document.querySelectorAll('#record-list .record-row').length >= 24", timeout=30000)
            counts.append(page.locator('#record-list .record-row').count())
        elif page_name == 'overview':
            page.locator('#latest-list, .latest-list').wait_for(state='visible')
            assert page.get_by_role('button', name='Explore CVEs').is_visible()
        else:
            wait_idle(page)
        geometry = page.evaluate('''() => ({
          viewportWidth: document.documentElement.clientWidth,
          documentWidth: document.documentElement.scrollWidth,
          bodyWidth: document.body.scrollWidth,
          activePageWidth: document.querySelector('.page:not([hidden])')?.scrollWidth ?? 0
        })''')
        assert geometry['documentWidth'] <= width and geometry['bodyWidth'] <= width and geometry['activePageWidth'] <= width, f'Horizontal overflow on {page_name} at {width}px: {geometry}'
        if page_name == 'community':
            frame_box = page.locator('.terminal-frame').bounding_box()
            action_box = page.locator('.community-actions').bounding_box()
            button_boxes = [button.bounding_box() for button in page.locator('.community-action').all()]
            assert frame_box is not None and action_box is not None and all(box is not None for box in button_boxes)
            action_bounds.append({'frame': frame_box, 'actions': action_box, 'buttons': button_boxes})
        elif page_name == 'center':
            dock_box = page.locator('.center-dock').bounding_box()
            search_box = page.locator('#record-search').bounding_box()
            filter_box = page.locator('#filter-controls').bounding_box()
            assert dock_box is not None and search_box is not None and filter_box is not None
            center_dock_bounds.append({'dock': dock_box, 'search': search_box, 'filters': filter_box})
        page.wait_for_timeout(120)
        destination = SCREENSHOTS / f'{file_stem}-{label}.png'
        page.screenshot(path=str(destination), animations='disabled')
        captures.append(destination)
        if page_name == 'overview':
            page.get_by_role('button', name='Explore CVEs').click()
            page.wait_for_function("() => document.querySelector('#page-center').hidden === false")
            page.wait_for_function("() => document.querySelectorAll('#record-list .record-row').length >= 24", timeout=30000)
            overview_action_counts.append(page.locator('#record-list .record-row').count())
        assert_no_page_errors(page, errors)
        page.close()
    with Image.open(captures[0]) as original, Image.open(captures[1]) as updated:
        assert original.size == updated.size, f'Screenshot dimensions differ for {page_name} at {width}px.'
        difference = ImageChops.difference(original.convert('RGB'), updated.convert('RGB'))
        if page_name == 'community':
            assert len(action_bounds) == 2
            baseline, preview = action_bounds
            baseline_frame, preview_frame = baseline['frame'], preview['frame']
            assert all(abs(baseline_frame[key] - preview_frame[key]) <= 0.5 for key in ('x', 'width')), f'Community frame width changed at {width}px: {action_bounds}'
            assert abs((baseline_frame['y'] + baseline_frame['height'] / 2) - (preview_frame['y'] + preview_frame['height'] / 2)) <= 0.5, f'Community frame is no longer centered at {width}px: {action_bounds}'
            frame_height_reduction = baseline_frame['height'] - preview_frame['height']
            assert 0 < frame_height_reduction <= 24, f'Removing the single disclaimer changed Community frame height unexpectedly at {width}px: {action_bounds}'
            baseline_actions, preview_actions = baseline['actions'], preview['actions']
            assert all(abs(baseline_actions[key] - preview_actions[key]) <= 0.5 for key in ('x', 'width', 'height')), f'Community action layout changed at {width}px: {action_bounds}'
            assert abs((baseline_actions['y'] - baseline_frame['y']) - (preview_actions['y'] - preview_frame['y'])) <= 0.5, f'Community actions moved within the terminal at {width}px: {action_bounds}'
            assert len(baseline['buttons']) == len(preview['buttons']) == 2
            for before, after in zip(baseline['buttons'], preview['buttons']):
                assert all(abs(before[key] - after[key]) <= 0.5 for key in ('x', 'width', 'height')), f'Telegram button dimensions changed at {width}px: {action_bounds}'
                assert abs((before['y'] - baseline_frame['y']) - (after['y'] - preview_frame['y'])) <= 0.5, f'Telegram buttons moved within the terminal at {width}px: {action_bounds}'
            left = max(0, int(min(baseline_frame['x'], preview_frame['x'])))
            top = max(0, int(min(baseline_frame['y'], preview_frame['y'])))
            right = min(original.width - 1, int(max(baseline_frame['x'] + baseline_frame['width'], preview_frame['x'] + preview_frame['width'])) + 1)
            bottom = min(original.height - 1, int(max(baseline_frame['y'] + baseline_frame['height'], preview_frame['y'] + preview_frame['height'])) + 1)
            mask = Image.new('L', original.size, 255)
            ImageDraw.Draw(mask).rectangle((left, top, right, bottom), fill=0)
            difference = ImageChops.composite(difference, Image.new('RGB', original.size, (0, 0, 0)), mask)
        elif page_name == 'center':
            assert len(center_dock_bounds) == 2
            baseline, preview = center_dock_bounds
            for component in ('dock', 'search', 'filters'):
                before, after = baseline[component], preview[component]
                assert all(abs(before[key] - after[key]) <= 0.5 for key in ('x', 'y', 'width', 'height')), f'CVE {component} geometry changed at {width}px: {center_dock_bounds}'
            before, after = baseline['dock'], preview['dock']
            left = max(0, int(min(before['x'], after['x'])))
            top = max(0, int(min(before['y'], after['y'])))
            right = min(original.width - 1, int(max(before['x'] + before['width'], after['x'] + after['width'])) + 1)
            bottom = min(original.height - 1, int(max(before['y'] + before['height'], after['y'] + after['height'])) + 1)
            if left <= right and top <= bottom:
                mask = Image.new('L', original.size, 255)
                ImageDraw.Draw(mask).rectangle((left, top, right, bottom), fill=0)
                difference = ImageChops.composite(difference, Image.new('RGB', original.size, (0, 0, 0)), mask)
        changed_pixels = sum(max(pixel) > 1 for pixel in difference.getdata())
    assert changed_pixels == 0, f'{page_name} render materially changed in the isolated Community update at {width}px ({changed_pixels} pixels differ by more than one RGB level).'
    expected_mask = 'Community terminal frame' if page_name == 'community' else 'CVE search dock' if page_name == 'center' else 'none'
    return {'page': page_name, 'viewport': [width, height], 'expected_mask': expected_mask, 'changed_pixels_outside_expected_mask_over_one_rgb_level': changed_pixels, 'pixel_tolerance_per_channel': 1, 'baseline_record_rows': counts[0] if counts else None, 'preview_record_rows': counts[1] if counts else None, 'overview_action_record_rows': overview_action_counts if overview_action_counts else None}


def install_action_trace(page: Page, button_id: str) -> None:
    page.evaluate('''(buttonId) => {
      const trace = {clickedAt: null, characters: [], openingAt: null};
      const button = document.getElementById(buttonId);
      const command = document.querySelector('#action-command');
      const status = document.querySelector('#action-status');
      button.addEventListener('click', () => { trace.clickedAt = performance.now(); }, {capture: true, once: true});
      let lastCommand = '';
      new MutationObserver(() => {
        const text = command.textContent;
        if (text && text !== lastCommand) {
          trace.characters.push({text, at: performance.now()});
          lastCommand = text;
        }
      }).observe(command, {childList: true, characterData: true, subtree: true});
      new MutationObserver(() => {
        if (status.textContent.startsWith('Opening ') && trace.openingAt === null) {
          trace.openingAt = performance.now();
        }
      }).observe(status, {childList: true, characterData: true, subtree: true});
      window.__communityActionTrace = trace;
    }''', button_id)


def wait_for_action_opening(page: Page, destination: str, reduced: bool = False) -> dict[str, Any]:
    expected_command = f'xdg-open "{destination}"'
    expected_status = f'Opening {destination}...'
    page.wait_for_function(
        "destination => document.querySelector('#action-status').textContent === `Opening ${destination}...`",
        arg=destination,
        timeout=6000,
    )
    status = page.locator('#action-status')
    command = page.locator('#action-command').inner_text()
    assert command == expected_command, f'Wrong simulated command: {command!r}'
    assert status.inner_text() == expected_status, f'Wrong simulated status: {status.inner_text()!r}'
    assert status.is_visible(), 'Opening status is not visible.'
    assert status.get_attribute('role') == 'status', 'Opening status is not exposed as a status announcement.'
    assert status.get_attribute('aria-live') == 'polite', 'Opening status is missing aria-live="polite".'
    trace = page.evaluate('window.__communityActionTrace')
    assert trace['clickedAt'] is not None, 'The Community action click was not traced.'
    if reduced:
        assert [item['text'] for item in trace['characters']] == [expected_command], 'Reduced motion should fill the display command immediately.'
        typing_seconds = 0.0
        character_interval_ms = 0.0
    else:
        expected_prefixes = [expected_command[:index] for index in range(1, len(expected_command) + 1)]
        observed_prefixes = [item['text'] for item in trace['characters']]
        assert observed_prefixes == expected_prefixes, f'Command was not typed one visible character at a time: {observed_prefixes!r}'
        last_character_at = trace['characters'][-1]['at']
        assert trace['openingAt'] is not None and trace['openingAt'] >= last_character_at, 'Opening state began before the command finished.'
        typing_seconds = (last_character_at - trace['clickedAt']) / 1000
        minimum_typing_seconds = max(0.5, (len(expected_command) - 1) * 0.020)
        assert typing_seconds >= minimum_typing_seconds, f'Command did not remain visibly staged long enough: {typing_seconds:.3f}s.'
        character_interval_ms = (last_character_at - trace['characters'][0]['at']) / (len(trace['characters']) - 1)
    return {'command': expected_command, 'status': expected_status, 'character_count': len(expected_command), 'typing_seconds': round(typing_seconds, 3), 'average_character_interval_ms': round(character_interval_ms, 1), 'opening_status_live': True}


def test_actions(browser: Browser, base_url: str, reduced: bool = False) -> dict[str, Any]:
    results: dict[str, Any] = {}
    destination_map = {
        'join-bugcod3': 'https://www.t.me/BugCod3',
        'join-rootaccessclub': 'https://www.t.me/RootAccessClub',
    }
    for button_id, destination in destination_map.items():
        context = browser.new_context(viewport={'width': 390, 'height': 844}, reduced_motion='reduce' if reduced else 'no-preference')
        page = context.new_page()
        errors: list[str] = []
        attempts: list[str] = []
        watch_errors(page, errors)
        page.route('https://www.t.me/**', local_interceptor(attempts))
        load(page, f'{base_url}/?page=community')
        wait_idle(page)
        button = page.locator(f'#{button_id}')
        install_action_trace(page, button_id)
        button.click()
        assert button.is_disabled(), f'{button_id} was not disabled during navigation.'
        expected_name = 'BugCod3' if button_id == 'join-bugcod3' else 'RootAccessClub'
        if reduced:
            flow = wait_for_action_opening(page, destination, reduced=True)
        else:
            assert page.locator('#action-status').inner_text() == 'Typing command...', 'The terminal did not expose its typing state.'
            page.wait_for_function(
                'length => { const value = document.querySelector("#action-command").textContent; return value.length >= 4 && value.length < length; }',
                arg=len(f'xdg-open "{destination}"'),
                timeout=3000,
            )
            if button_id == 'join-bugcod3':
                page.screenshot(path=str(SCREENSHOTS / 'community-opening-bugcod3-390.png'), animations='disabled')
            # Dispatch a synthetic second click to verify the handler's duplicate-action guard,
            # even though a real second activation is already blocked by the disabled button.
            page.evaluate("id => document.getElementById(id).dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}))", button_id)
            flow = wait_for_action_opening(page, destination)
        opening_observed_at = time.monotonic()
        elapsed = wait_for_local_destination(page, destination, attempts, opening_observed_at)
        flow['navigation_delay_after_opening_seconds'] = round(elapsed, 3)
        assert page.locator('#local-intercept').inner_text() == 'Local Telegram destination intercepted for this test.'
        assert_no_page_errors(page, errors)
        results[expected_name] = {'destination': destination, **flow, 'intercepted_locally': True, 'navigation_attempts': len(attempts), 'reduced_motion': reduced}
        context.close()
    return results


def test_reduced_motion_initial(browser: Browser, base_url: str) -> dict[str, Any]:
    context = browser.new_context(viewport={'width': 390, 'height': 844}, reduced_motion='reduce')
    page = context.new_page()
    errors: list[str] = []
    watch_errors(page, errors)
    load(page, f'{base_url}/?page=community')
    state = page.evaluate('''() => ({
      command: document.querySelector('#info-command').textContent,
      infoVisible: !document.querySelector('#terminal-info').hidden,
      idleVisible: !document.querySelector('#idle-prompt').hidden,
      cursorAnimation: getComputedStyle(document.querySelector('#idle-prompt .terminal-caret')).animationName
    })''')
    assert state == {'command': './info', 'infoVisible': True, 'idleVisible': True, 'cursorAnimation': 'none'}, f'Reduced-motion entry did not settle immediately: {state}'
    page.screenshot(path=str(SCREENSHOTS / 'community-reduced-motion-390.png'), animations='disabled')
    assert_no_page_errors(page, errors)
    context.close()
    return {'startup_typing_skipped': True, 'info_and_idle_prompt_immediate': True, 'cursor_animation': 'none'}


def test_keyboard_activation(browser: Browser, base_url: str) -> dict[str, Any]:
    results: dict[str, Any] = {}
    cases = [('join-bugcod3', 'Enter', 'https://www.t.me/BugCod3'), ('join-rootaccessclub', 'Space', 'https://www.t.me/RootAccessClub')]
    for button_id, key, destination in cases:
        context = browser.new_context(viewport={'width': 390, 'height': 844})
        page = context.new_page()
        errors: list[str] = []
        attempts: list[str] = []
        watch_errors(page, errors)
        page.route('https://www.t.me/**', local_interceptor(attempts))
        load(page, f'{base_url}/?page=community')
        wait_idle(page)
        button = page.locator(f'#{button_id}')
        if key == 'Enter':
            # Traverse the real tab order from the page, then activate the native button.
            for _ in range(12):
                await_id = page.evaluate('document.activeElement?.id || ""')
                if await_id == button_id:
                    break
                page.keyboard.press('Tab')
            assert page.evaluate('document.activeElement?.id') == button_id, 'Tab order did not reach the first Community action.'
            assert page.evaluate("document.activeElement.matches(':focus-visible')"), 'Keyboard focus is not visibly indicated.'
        else:
            button.focus()
            assert page.evaluate("document.activeElement.matches(':focus-visible')"), 'Focused Community action has no visible focus state.'
        install_action_trace(page, button_id)
        page.keyboard.press(key)
        assert button.is_disabled(), f'{button_id} did not enter its disabled state on {key}.'
        flow = wait_for_action_opening(page, destination)
        opening_observed_at = time.monotonic()
        flow['navigation_delay_after_opening_seconds'] = round(wait_for_local_destination(page, destination, attempts, opening_observed_at), 3)
        assert_no_page_errors(page, errors)
        results[button_id] = {'key': key, 'visible_focus': True, 'destination': destination, **flow, 'intercepted_locally': True}
        context.close()
    return results


def test_leave_and_return(browser: Browser, base_url: str) -> dict[str, Any]:
    context = browser.new_context(viewport={'width': 390, 'height': 844})
    page = context.new_page()
    errors: list[str] = []
    attempted: list[str] = []
    watch_errors(page, errors)
    page.route('https://www.t.me/**', local_interceptor(attempted))
    load(page, f'{base_url}/?page=community')
    wait_idle(page)
    install_action_trace(page, 'join-bugcod3')
    page.locator('#join-bugcod3').click()
    assert page.locator('#join-bugcod3').is_disabled()
    assert page.locator('#action-status').inner_text() == 'Typing command...'
    page.locator('#tab-overview').click()
    page.wait_for_timeout(2400)
    assert page.url == f'{base_url}/', 'Navigating to Overview did not update the route URL.'
    assert page.locator('#page-overview').is_visible(), 'Overview did not become the active route.'
    assert not attempted, f'Unexpected external destination after leaving page: {attempted}'
    page.locator('#tab-community').click()
    wait_idle(page)
    assert page.locator('#action-session').is_hidden(), 'A previous opening state survived return to Community.'
    assert not page.locator('#join-bugcod3').is_disabled()
    assert page.locator('#info-command').inner_text() == './info'
    install_action_trace(page, 'join-rootaccessclub')
    page.locator('#join-rootaccessclub').click()
    wait_for_action_opening(page, 'https://www.t.me/RootAccessClub')
    page.locator('#tab-overview').click()
    page.wait_for_timeout(1100)
    assert not attempted, f'Navigation continued after leaving during the Opening delay: {attempted}'
    assert_no_page_errors(page, errors)
    context.close()
    return {'leaving_cancels_typing_and_opening_navigation': True, 'return_replays_clean_info_session': True}


def test_history_return_after_action(browser: Browser, base_url: str) -> dict[str, Any]:
    context = browser.new_context(viewport={'width': 390, 'height': 844})
    page = context.new_page()
    errors: list[str] = []
    attempts: list[str] = []
    watch_errors(page, errors)
    page.route('https://www.t.me/**', local_interceptor(attempts))
    load(page, f'{base_url}/?page=community')
    wait_idle(page)
    install_action_trace(page, 'join-rootaccessclub')
    page.locator('#join-rootaccessclub').click()
    flow = wait_for_action_opening(page, 'https://www.t.me/RootAccessClub')
    opening_observed_at = time.monotonic()
    flow['navigation_delay_after_opening_seconds'] = round(
        wait_for_local_destination(page, 'https://www.t.me/RootAccessClub', attempts, opening_observed_at), 3
    )
    page.go_back(wait_until='domcontentloaded')
    page.wait_for_url(f'{base_url}/?page=community', timeout=5000)
    wait_idle(page)
    assert page.locator('#action-session').is_hidden(), 'Opening state survived browser history return.'
    assert not page.locator('#join-rootaccessclub').is_disabled(), 'Community actions stayed disabled after browser history return.'
    assert_no_page_errors(page, errors)
    context.close()
    return {'same_tab_back_returns_to_clean_terminal': True, 'community_actions_reenabled': True, 'destination_intercepted_locally': True, **flow}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--community-only', action='store_true',
        help='Run Community interaction/layout checks without comparing redesigned Overview/CVE Center pixels to an older baseline.',
    )
    community_only = parser.parse_args().community_only
    temporary_baseline = None
    if community_only:
        baseline_root = ROOT
        baseline_ref = 'pixel comparison skipped (Community-only mode)'
    elif BASELINE_DIR:
        baseline_root = Path(BASELINE_DIR).resolve()
        if not baseline_root.is_dir():
            raise SystemExit(f'Baseline directory not found: {baseline_root}')
        baseline_ref = BASELINE_DIR
    else:
        baseline_ref = BASELINE_REF
        temporary_baseline = tempfile.TemporaryDirectory(prefix='subzero-community-baseline-')
        baseline_root = Path(temporary_baseline.name)
        archive_path = baseline_root / 'baseline.tar'
        with archive_path.open('wb') as archive_file:
            subprocess.run(['git', 'archive', '--format=tar', baseline_ref], cwd=ROOT, stdout=archive_file, check=True)
        with tarfile.open(archive_path, 'r:') as archive:
            archive.extractall(path=baseline_root)
        archive_path.unlink()
    baseline_server = serve(baseline_root)
    preview_server = serve(ROOT)
    base_url = f'http://127.0.0.1:{baseline_server.server_port}'
    preview_url = f'http://127.0.0.1:{preview_server.server_port}'
    results: dict[str, Any] = {'scope': {'baseline': str(baseline_root), 'baseline_ref': baseline_ref, 'preview': str(ROOT), 'telegram_interception': 'Playwright locally fulfills every www.t.me request; no Telegram service is contacted.'}}
    errors: list[str] = []
    try:
        with sync_playwright() as playwright:
            browser_options: dict[str, Any] = {'headless': True, 'args': ['--no-sandbox']}
            chromium_path = os.environ.get('CHROMIUM_EXECUTABLE') or shutil.which('chromium')
            if chromium_path:
                browser_options['executable_path'] = chromium_path
            browser = playwright.chromium.launch(**browser_options)

            # The staged state is captured while the real command is being typed.
            staged = browser.new_page(viewport={'width': 1440, 'height': 1000}, device_scale_factor=1)
            watch_errors(staged, errors)
            load(staged, f'{preview_url}/?page=community')
            staged.locator('#info-command').wait_for(state='attached')
            deadline = time.monotonic() + 2
            partial = ''
            while time.monotonic() < deadline:
                partial = staged.locator('#info-command').inner_text()
                if 1 < len(partial) < len('./info'):
                    break
                time.sleep(0.01)
            assert 1 < len(partial) < len('./info'), f'No staged typing state observed; command was {partial!r}.'
            assert staged.locator('#terminal-info').is_hidden(), 'Information output appeared before ./info finished typing.'
            assert staged.locator('#join-bugcod3').is_disabled(), 'Community actions became enabled before the info state completed.'
            staged.screenshot(path=str(SCREENSHOTS / 'community-staged-typing-1440.png'), animations='disabled')
            wait_idle(staged)
            staged.screenshot(path=str(SCREENSHOTS / 'community-idle-1440.png'), animations='disabled')
            results['staged_typing'] = {'command_prefix': partial, 'info_hidden_until_command_finishes': True, 'actions_enabled_after_idle': not staged.locator('#join-bugcod3').is_disabled()}
            staged.close()

            # Render at every requested width. Also save an idle capture for each viewport.
            layout_results = []
            for width, height in ((320, 640), (320, 740), (320, 844), (360, 740), (360, 844), (390, 844), (768, 624), (768, 960), (1440, 624), (1440, 1000)):
                page = browser.new_page(viewport={'width': width, 'height': height}, device_scale_factor=1)
                page_errors: list[str] = []
                watch_errors(page, page_errors)
                page.emulate_media(reduced_motion='reduce')
                load(page, f'{preview_url}/?page=community')
                wait_idle(page)
                page.wait_for_timeout(50)
                metrics = terminal_metrics(page)
                assert_terminal_fits(metrics)
                page.screenshot(path=str(SCREENSHOTS / f'community-idle-{width}x{height}.png'), animations='disabled')
                assert_no_page_errors(page, page_errors)
                layout_results.append({'viewport': [width, height], 'page_scroll': False, 'horizontal_overflow': False, 'touch_targets_at_least_46px': True, 'banner': 'exact ANSI Shadow, responsive font ' + metrics['bannerFontSize']})
                page.close()
            results['responsive_layouts'] = layout_results

            if not community_only:
                overview = browser.new_page(viewport={'width': 1440, 'height': 900}, device_scale_factor=1)
                overview_errors: list[str] = []
                watch_errors(overview, overview_errors)
                overview.emulate_media(reduced_motion='reduce')
                load(overview, f'{preview_url}/?page=overview')
                overview.locator('#latest-list .latest-preview-row').first.wait_for(state='visible', timeout=30000)
                explore_action = overview.get_by_role('button', name='Explore records')
                assert explore_action.is_visible(), 'The redesigned Overview Explore action is not visible on desktop.'
                explore_action.click()
                overview.locator('#record-list .record-row').first.wait_for(state='visible', timeout=30000)
                assert overview.locator('#tab-center').get_attribute('aria-selected') == 'true'
                results['overview_to_explore'] = {'cta': 'Explore records', 'verified_rows_loaded': overview.locator('#record-list .record-row').count()}
                assert_no_page_errors(overview, overview_errors)
                overview.close()
                results['whole_site_pixel_regression'] = {
                    'status': 'Not applicable after the approved full redesign of Overview, Latest, Explore and global navigation; the redesigned Overview-to-Explore route is tested semantically above.',
                    'community_terminal': 'Exact banner/content, geometry, responsive layouts, keyboard controls and locally intercepted actions remain covered below.'
                }

            # The actions and timing are browser-driven, while both Telegram destinations are intercepted locally.
            results['actions'] = test_actions(browser, preview_url)
            results['keyboard_activation'] = test_keyboard_activation(browser, preview_url)
            results['reduced_motion_initial'] = test_reduced_motion_initial(browser, preview_url)
            results['reduced_motion_actions'] = test_actions(browser, preview_url, reduced=True)
            results['leave_return'] = test_leave_and_return(browser, preview_url)
            results['history_return'] = test_history_return_after_action(browser, preview_url)

            # No pageerror or console errors in the top-level staged path.
            assert_no_page_errors(staged, errors)
            results['browser_errors'] = {'page_errors': 0, 'console_errors': 0}
            browser.close()
    finally:
        baseline_server.shutdown()
        preview_server.shutdown()
        baseline_server.server_close()
        preview_server.server_close()
        if temporary_baseline is not None:
            temporary_baseline.cleanup()

    result_path = RESULT_PATH
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(results, indent=2))
    print(f'PASS: detailed test results written to {result_path}')


if __name__ == '__main__':
    main()
