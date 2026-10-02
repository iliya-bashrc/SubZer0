# SubZer0 full-feed preview

This is the **independent static GitHub Pages edition** of the three-page preview previously shown at the [Cloudflare Worker preview](https://subzero-independent-preview-20261002-1810.fourth-hickory.workers.dev/). It is published at [GitHub Pages](https://iliya-bashrc.github.io/SubZer0/), remains separate from the current production UI, and does not run the former production updater. The CVE Center reads only the captured files in `snapshot/`; Overview, CVE Center and the terminal-inspired Community page are available from one static page.

## Run locally

From this directory, start a loopback-only static server:

```bash
cd /workspace/subzero-full-preview-end-to-end-refinement-20261002
python3 -m http.server 8766 --bind 127.0.0.1
```

Open [http://127.0.0.1:8766/](http://127.0.0.1:8766/) for Overview or [http://127.0.0.1:8766/?page=center](http://127.0.0.1:8766/?page=center) for the archive. Stop the server with `Ctrl+C`. Use HTTP rather than opening `index.html` as a `file:` URL so the browser can read the bundled JSON shards. The server is bound to loopback; it does not publish the preview.

## Pages and captured data

The **Overview** keeps SubZer0’s concise purpose and two evidence clarifications, with three current records from the captured feed. Each CVE ID links directly to that record’s detail in the CVE Center; the displayed time is the manifest’s `last_successful_update`, not a claim that the preview is live. The **CVE Center** opens with its complete local snapshot and supports product/title or ID search, severity and date filters, 24/48/96-row pagination, and source-attributed record details. The **Community** page retains the terminal visual simulation and “Join the Telegram channel” action. Its displayed `xdg-open "https://www.t.me/RootAccessClub"` command is decorative text only; no shell command runs. A user click proceeds to the channel at `https://t.me/RootAccessClub`.

The bundled snapshot contains **15,318 CVE records across 31 validated date shards**, covering **2026-09-02 to 2026-10-02 UTC**. The last successful update recorded by the manifest is **2026-10-02 06:00:04 UTC**. The source totals are 1,507 Critical, 6,361 High, 4,955 Medium, 949 Low, 1,527 None, 19 Unknown and 45 CISA KEV listings. CVSS severity, FIRST EPSS probability, CISA KEV membership and GitHub advisory/repository leads remain separate signals. EPSS is marked stale by the manifest at **2026-09-29**; **558 records without an EPSS value are unscored, not 0%**. Validation and provenance details are in [`snapshot/VALIDATION.json`](snapshot/VALIDATION.json) and [`SOURCE-NOTES.md`](SOURCE-NOTES.md); the publisher’s source manifest is [available here](https://iliya-bashrc.github.io/SubZer0/api/v1/manifest.json).

## Test the copy

The full local browser suite is:

```bash
node --check app.js
python3 -m py_compile capture_snapshot.py verify_full_feed.py verify_preview.py
python3 verify_full_feed.py
```

`verify_preview.py` remains as a compatibility entry point and runs the same full-feed suite; it no longer asserts the obsolete five-record sample. The suite starts its own ephemeral loopback server and requires Chromium, Python Playwright and Pillow. It checks Overview data/links and lazy loading, full record counts, search, severity/date filtering, pagination, details and focus return, data/link safety, reduced motion, community navigation, touch targets, and page-level overflow. Every page is audited at 320, 360, 390, 412, 768, 1024 and 1440 CSS-pixel widths. The Community destination is intercepted locally during tests, so the test does not navigate to the live channel or execute a shell command. Android-like browser emulation is not a physical-device test. Each run refreshes the browser captures under `screenshots/`.

The optional `capture_snapshot.py` refresh tool is **not** needed to run this preview and was not used for this revision; running it would require network access and replace bundled snapshot files.

## Final review captures

- Desktop: [Overview](screenshots/01-overview-desktop.png), [CVE Center](screenshots/02-cve-center-desktop.png), [Community](screenshots/04-community-desktop.png), and the [Community opening state](screenshots/04-community-opening-desktop.png).
- Android-like 360×800: [Overview](screenshots/10-android-360-overview.png), [Overview latest links](screenshots/10b-android-360-overview-latest-links.png), [CVE Center](screenshots/11-android-360-cve-center.png), and [Community](screenshots/12-android-360-community.png).
- Supporting evidence: [desktop record detail](screenshots/03-cve-detail-desktop.png), [full-feed desktop capture](screenshots/14-cve-center-desktop-full-feed.png), [mobile detail](screenshots/09-cve-detail-mobile-360.png), [severity materials](screenshots/13-severity-five-materials-closeup.png), and [visible-row fleck motion](screenshots/16-moving-severity-fleck-demo.gif).

## Scope

The Overview, CVE Center, Community screen, snapshot data, scripts and screenshots are the selected independent Worker preview; only this README’s hosting and run-scope instructions were updated for GitHub Pages. This is a static snapshot, not the current production UI, and it does not automatically refresh. The `Local preview` indicator is retained from the exact selected screen. No Cloudflare Worker deployment, bindings, account settings, DNS, or other GitHub repository was changed. See [`AUDIT.md`](AUDIT.md) for the preview’s iteration log, results and remaining limits.
