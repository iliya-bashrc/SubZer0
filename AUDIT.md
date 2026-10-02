# End-to-end refinement audit

This revision was made only in `/workspace/subzero-full-preview-end-to-end-refinement-20261002/`, after a read-only desktop and mobile review of the approved standalone preview. The black-metal three-page direction, Overview purpose/copy/CTA, CVE Center layout and terminal Community experience were retained.

## Changes driven by testing

The Overview’s example records and time label did not match the newest records and explicit `last_successful_update` in the bundled snapshot. They now show the top three records from the verified feed—CVE-2026-19660, CVE-2026-10026 and CVE-2026-93367—with the manifest timestamp **2026-10-02 06:00:04 UTC**. Their IDs are keyboard-focusable direct links to the matching CVE details; the link hit area is at least 44px tall.

A direct-link smoke test also exposed that the detail-return code looked for the CVE ID on the focused button even though only its row carried that ID. The record button now carries the key the restoration code expects, so Escape returns focus to the originating record. The test suite verifies this for both an Overview deep link and a filtered Center result. The inherited `verify_preview.py` still expected the superseded five-record sample; it is now a compatibility entry point to `verify_full_feed.py`, the authoritative full-feed suite.

The existing regression suite was expanded to derive Overview expectations from the manifest, verify exact links and source labels/hosts, measure the active page at every required width, exercise mobile latest-link taps, and capture the final Community opening state. The copied preview’s older screenshots for stale Overview content and a mislabeled mobile-detail width were removed or replaced; the screenshot set now corresponds to this revision.

## Verification results

The final run passed `node --check app.js`, Python compilation, the compatibility-entry import and `python3 verify_full_feed.py`. It loaded **15,318 records from 31 bundled shards**, checked the 45 KEV count, 24-row default, pagination at 24/48/96, all five severity filters, the 58-record Oct 2 date range, exact-ID and product/title search, and detail/back behavior. It confirmed stale EPSS status, missing EPSS as unscored rather than zero, and the distinct source values None and Unknown. Detail links are visibly attributed to FIRST EPSS, CISA and GitHub; hostile snapshot text stayed literal and unsafe `javascript:` links were rejected.

Overview, CVE Center and Community passed page-level overflow checks at **320, 360, 390, 412, 768, 1024 and 1440 CSS pixels**. Android-like Chromium emulation at 360×800 (DPR 2, touch enabled) exercised page navigation, 44px links and record taps. Visible flecks moved, off-screen effects stayed paused, and reduced-motion checks passed. The Community command/status path and final destination were verified with a local route interception; no shell command was run and no live-channel navigation was made. The run ended with **no browser errors, console errors, failed requests or unexpected external requests**.

Two post-change visual review passes covered the Overview, followed by final desktop captures of all three pages and mobile captures of all three at 360px. The supporting images are in [`screenshots/`](screenshots/), including a scrolled Overview image showing the latest links and a detail capture.

## Scope, integrity and remaining limits

All **69 files** in the approved source preview matched the saved pre-edit SHA-256 inventory; `sha256sum -c /tmp/subzero-approved-preview-before.sha256` reported every entry `OK`. No production repository, live site, older preview, reusable skill, upload, public host, deployment, commit or PR was changed or created. Browser servers and test traffic were loopback-only and have been stopped.

The preview remains a dated static capture, not a live feed; EPSS remains marked stale as of 2026-09-29. Browser emulation is not a physical-device test, and no separate automated screen-reader or formal WCAG contrast audit was run. The Community terminal remains a visual simulation; only a user’s deliberate CTA click in an ordinary preview session proceeds to the external channel.
