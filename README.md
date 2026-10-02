# SubZer0 full-feed preview

This is the **independent static GitHub Pages edition** of the three-page preview previously shown at the [Cloudflare Worker preview](https://subzero-independent-preview-20261002-1810.fourth-hickory.workers.dev/). It is published at [GitHub Pages](https://iliya-bashrc.github.io/SubZer0/), remains separate from the current production UI, and does not run the former production updater. The CVE Center reads only the captured files in `snapshot/`; Overview, CVE Center and the terminal-inspired Community page are available from one static page.

## Run locally

From the repository root, start a loopback-only static server:

```bash
python3 -m http.server 8766 --bind 127.0.0.1
```

Open the [published GitHub Pages site](https://iliya-bashrc.github.io/SubZer0/) or [http://127.0.0.1:8766/](http://127.0.0.1:8766/) for Overview; use [http://127.0.0.1:8766/?page=center](http://127.0.0.1:8766/?page=center) for the archive. Stop the local server with `Ctrl+C`. Use HTTP rather than opening `index.html` as a `file:` URL so the browser can read the bundled JSON shards. The local server is bound to loopback; it does not publish the preview.

## Pages and captured data

The **Overview** keeps SubZer0’s concise purpose and two evidence clarifications, with three current records from the captured feed. Each CVE ID links directly to that record’s detail in the CVE Center; the displayed time is the manifest’s `last_successful_update`, not a claim that the preview is live. The **CVE Center** opens with its complete local snapshot and supports product/title or ID search, severity and date filters, 24/48/96-row pagination, and source-attributed record details. The **Community** page presents the ANSI Shadow banner in a Zsh-like terminal, stages `./info`, and shows the requested creator and online-status output. Its native **Join BugCod3** and **Join RootAccessClub** buttons display the matching `xdg-open` command as simulated terminal text, then navigate to their Telegram destinations; the page never runs a shell command.

The bundled snapshot contains **15,318 CVE records across 31 validated date shards**, covering **2026-09-02 to 2026-10-02 UTC**. The last successful update recorded by the manifest is **2026-10-02 06:00:04 UTC**. The source totals are 1,507 Critical, 6,361 High, 4,955 Medium, 949 Low, 1,527 None, 19 Unknown and 45 CISA KEV listings. CVSS severity, FIRST EPSS probability, CISA KEV membership and GitHub advisory/repository leads remain separate signals. EPSS is marked stale by the manifest at **2026-09-29**; **558 records without an EPSS value are unscored, not 0%**. Validation and provenance details are in [`snapshot/VALIDATION.json`](snapshot/VALIDATION.json) and [`SOURCE-NOTES.md`](SOURCE-NOTES.md); the captured snapshot manifest is [available here](snapshot/manifest.json).

## Test the copy

The full local browser suite is:

```bash
node --check app.js
python3 -m py_compile capture_snapshot.py verify_full_feed.py verify_preview.py verify_community_ansi_shadow.py
python3 verify_full_feed.py
python3 verify_community_ansi_shadow.py
```

`verify_preview.py` remains as a compatibility entry point and runs the same full-feed suite; it no longer asserts the obsolete five-record sample. The full-feed suite starts its own ephemeral loopback server and requires Chromium, Python Playwright and Pillow. It checks Overview data/links and lazy loading, full record counts, search, severity/date filtering, pagination, details and focus return, data/link safety, reduced motion, touch targets, and page-level overflow. The dedicated Community suite checks the exact banner and terminal behavior, locally intercepts both Telegram destinations, compares Overview and CVE Center renders pixel-for-pixel with the current `origin/main` baseline at 1440×1000, 390×844 and 320×740, and checks responsive Community layouts. It does not contact Telegram or execute a shell command. Android-like browser emulation is not a physical-device test. The full-feed suite refreshes browser captures under `screenshots/`; the Community suite writes temporary QA captures under `/tmp`.

The included `capture_snapshot.py` script is **not** needed to run this static preview and was not used for this revision. It still targets the prior publisher’s `/api/v1/manifest.json` endpoint, which is no longer part of this Pages copy; it does not refresh the published site. This repository has no automatic snapshot refresh.

## Final review captures

- Desktop: [Overview](screenshots/01-overview-desktop.png), [CVE Center](screenshots/02-cve-center-desktop.png), and [CVE detail](screenshots/03-cve-detail-desktop.png). The current Community captures are generated temporarily by the focused browser suite rather than stored as repository screenshots.
- Android-like 360×800: [Overview](screenshots/10-android-360-overview.png), [Overview latest links](screenshots/10b-android-360-overview-latest-links.png), and [CVE Center](screenshots/11-android-360-cve-center.png).
- Supporting evidence: [desktop record detail](screenshots/03-cve-detail-desktop.png), [full-feed desktop capture](screenshots/14-cve-center-desktop-full-feed.png), [mobile detail](screenshots/09-cve-detail-mobile-360.png), [severity materials](screenshots/13-severity-five-materials-closeup.png), and [visible-row fleck motion](screenshots/16-moving-severity-fleck-demo.gif).

## Scope

The Overview and CVE Center, snapshot data, and shared styles and application logic remain the selected independent preview. This update replaces only the Community page and its page-specific behavior and tests. This is a static snapshot, not the current production UI, and it does not automatically refresh. The `Local preview` indicator is retained from the exact selected screen. No Cloudflare Worker deployment, bindings, account settings, or DNS were changed. See [`AUDIT.md`](AUDIT.md) for the preview’s iteration log, results and remaining limits.
