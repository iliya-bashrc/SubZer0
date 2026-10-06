![SubZer0 — CVE intelligence and vulnerability research, with maintainers @RootAccessClub and @BugCod3](assets/subzero-readme-banner.svg)

# SubZer0

SubZer0 is a static CVE intelligence browser published with [GitHub Pages](https://iliya-bashrc.github.io/SubZer0/). The browser reads integrity-declared JSON from the same origin. It does not call vulnerability APIs directly and has no backend dependency.

[![Join @RootAccessClub on Telegram](assets/telegram-rootaccessclub.svg)](https://t.me/RootAccessClub) [![Join @BugCod3 on Telegram](assets/telegram-bugcod3.svg)](https://t.me/BugCod3)

*SubZer0 is independent and is not affiliated with Telegram.*

## Views

- **Overview** — snapshot totals, source-check results captured at generation time, severity distribution, daily activity and newest feed records plus a short, source-verified change preview. It does not represent those source checks as live.
- **Latest** — up to 50 actual feed records ordered by their newest source activity timestamp, with source, activity-time and available exploitation signals kept distinct.
- **Changes** — a filterable 30-day log of observed record and catalog differences. Every event distinguishes the upstream source timestamp, when present, from the time SubZer0 observed the change.
- **Explore** — the stable research toolbar searches a compact, structured index before any detail shard is fetched. Search covers CVE ID, title and short summary, source, bounded affected-vendor/product/version hints, and GHSA identifiers. CVSS, EPSS, KEV, source, vendor, date and pagination filters remain independently represented in the URL.
- **CVE dossier** — opens one daily detail shard on demand, then verifies its declared size, SHA-256 and schema before rendering CVSS (including a supplied vector/version/scoring source when captured), separate EPSS and KEV evidence, affected products/CPEs, references, advisories, source provenance, an evidence-backed timeline and observed change history. Source records are treated as untrusted text; no combined risk score or missing classification is invented.
- **Community** — the terminal-style introduction and Telegram destinations remain a separate experience. Its displayed `xdg-open` command is a visual simulation; no shell command runs in the browser.

The small-screen layout uses safe-area-aware navigation and stacked research rows. Adjacent-page swipe navigation is supported without intercepting links, controls, text selection or vertical scrolling. The interface remains dependency-free vanilla HTML, CSS and JavaScript.

## Snapshot, freshness and offline use

The currently checked-in capture was generated at **2026-10-05T14:41:08Z**. It contains **14,614 CVE records** across 31 UTC day shards and **14,456 EPSS scores** dated **2026-10-04**. The history has **1,504 source-backed events for 287 CVEs**, derived from two comparisons across three complete captures: baseline **2026-10-04T17:08:24Z**, then observations at **2026-10-05T13:15:51Z** and **2026-10-05T14:41:08Z**. That is about **21.5 hours of observed history**, not a full 30 days of coverage; feed omission is never treated as deletion. A newer live refresh was rejected when NVD's result total changed during pagination, so this remains the last validated capture, not a live-source status. These values describe this capture only; the [manifest](snapshot/manifest.json) and [validation record](snapshot/VALIDATION.json) are authoritative.

Freshness labels describe the age of the static capture and its recorded source metadata, not current upstream health. **FRESH** means up to six hours old; **DELAYED** is over six and up to 24 hours; **STALE** is older than 24 hours; **DEGRADED** marks a recorded source/EPSS issue or failed verification; **OFFLINE** identifies use of a cached capture. Snapshot age is approximate and uses the viewing device's clock. A source check shown in the interface is the result recorded at generation time, not a current check.

Explore first verifies the manifest, a deterministic gzip-compressed schema-v3 search index and the separate EPSS sidecar; it does **not** download all full-record shards to display the list. The index uses bounded column-packed rows and declares separate compressed and expanded SHA-256 hashes. A dossier fetches only the necessary full shard. The service worker keeps same-origin app resources and bounded snapshot data; a fresh manifest is checked before cache candidates are used, and the application verifies compressed and expanded bytes before parsing. When offline, cached records go through the same integrity checks. If a required detail shard is not cached, the dossier stays closed and reports the cached snapshot age rather than presenting partial or unverified evidence. Cache storage is best-effort, limited to the rolling 31-shard window and 128 MiB of logical snapshot data.

While the page is open, the app checks the same-origin manifest and compact Overview index every 15 minutes, when a hidden page becomes visible, and when connectivity returns. A newer manifest that passes size, schema and digest checks produces a reload-or-dismiss notice; the app does not silently replace data already on screen. This does not poll NVD, GitHub, CISA or FIRST, and it does not report current upstream or GitHub Actions health.

## Data collection and change history

The scheduled GitHub Actions workflow runs every six hours UTC and can be started manually from `main`. The updater collects recent NVD CVE modifications, GitHub security advisories updated in the rolling window, the complete CISA KEV catalog and FIRST EPSS scores. It retains the original source publication/update timestamps; the record activity date uses the newest in-window source activity, or the CISA catalog's supplied `dateAdded` for a newly entering KEV-only record. NVD offsets and GitHub cursors are fully paginated and validated.

History is generated by comparing complete, validated captures—not by assuming that omission from a rolling feed means deletion. A CVE first seen during the retained comparison window can be labeled new; a CVE modified outside the rolling feed can be called re-observed rather than newly published. Changes to older KEV catalog entries are compared against a separately retained complete catalog state. EPSS score changes retain their score-set date. History is bounded to 30 days, and its baseline/empty state is explicit. Source timestamps and SubZer0 observation timestamps are never conflated.

A core-source failure, incomplete pagination, invalid response, failed test or failed integrity check stops publication and keeps the previous complete snapshot. EPSS is optional; a retained old score set is labeled stale or unavailable rather than current. The app served to visitors only reads static same-origin files.

## Data contract and trust

The manifest declares SHA-256 hashes, exact sizes, counts and paths for the full-record day shards and bounded Overview, compressed search-index, EPSS and history sidecars. The compact search index is schema v3, capped at **3 MiB compressed / 12 MiB expanded**, and cross-checked against every full record. Full descriptions, references, exact CPE configurations and detailed source evidence remain in detail shards.

A hash detects a file that differs from its same-origin manifest; it is **not a digital signature** or independent proof of source authenticity. The page renders feed-controlled text using DOM text nodes, accepts parsed HTTP(S) references without URL credentials, and opens external destinations with `noopener noreferrer`. GitHub Pages does not provide this repository with configurable response headers; in particular, a meta Content Security Policy cannot enforce `frame-ancestors`.

See [DATA-CONTRACT.md](DATA-CONTRACT.md), [PERFORMANCE.md](PERFORMANCE.md), [source and trust notes](SOURCE-NOTES.md), and the clearly labeled [historical audit](AUDIT.md).

## Shareable state and legacy routes

The current page query uses `page=overview|latest|center|changes|community`; `center` remains the stable URL name for Explore. The former `?page=archive` bookmark is mapped to Explore (`page=center`) while preserving valid `from` and `to` date filters. Archive is not a separate page and has no primary-navigation tab.

Explore supports `search=…`, `severity=critical|high|medium|low|unrated`, `cvssMin=0..10`, `kev=true`, `vendor=…`, `source=NVD|GitHub%20Advisory%20Database|CISA%20KEV`, `epssMin=0..100`, inclusive UTC `from=…` and `to=…`, `size=24|48|96`, one-based `pageIndex`, and `cve=CVE-…` to open a dossier. Changes supports `changeType`, `changeSearch`, `changeFrom`, `changeTo` and one-based `changePage`. CVSS and EPSS thresholds are distinct: records without the relevant score are excluded when a numeric minimum is active, including zero.

The Explore toolbar remains in one stable position while scrolling; it is not moved or resized by a scroll-triggered compact/released mode. `/` focuses search; the query and filter state are shareable in the URL. Changes filters and pagination are also URL-backed. Opening a dossier creates a browser-history entry; Back and Forward restore the page state. Searchable summaries are intentionally compact; full references, descriptions and technical detail are available after a hash-verified dossier shard is opened.

## Run and validate locally

Serve the repository over HTTP so the browser can load same-origin files:

```bash
python3 -m http.server 8766 --bind 127.0.0.1
```

Open [Overview](http://127.0.0.1:8766/), [Latest](http://127.0.0.1:8766/?page=latest), [Changes](http://127.0.0.1:8766/?page=changes), or [Explore](http://127.0.0.1:8766/?page=center). Stop the server with `Ctrl+C`.

The deterministic unit tests make no upstream requests. The Playwright suites exercise the actual checked-in records and verify route, data, integrity, cache, keyboard, touch and responsive behavior; Community navigation is locally intercepted. Development dependencies are hash-pinned in `requirements-dev.txt`.

```bash
node --check app.js
node --check sw.js
node --check community.js
python3 -m py_compile scripts/*.py tests/*.py verify_full_feed.py verify_community_ansi_shadow.py
python3 scripts/verify_data_snapshot.py
python3 -m unittest discover -s tests -v
python3 verify_full_feed.py
python3 verify_community_ansi_shadow.py --community-only
```

`scripts/verify_pages.py` checks whether the public Pages site serves the expected application assets and a manifest-consistent snapshot. It is intended for post-deployment verification, not for claiming that an unmerged branch is live.

## Optional Cloudflare Worker preview

GitHub Pages remains the primary static deployment and has no Worker dependency. The optional Worker is only a static-asset pass-through; it does not provide an API or contact vulnerability sources. Its Wrangler configuration requires a `previews` block, and the feature-branch preview build stages an allowlisted `dist/` containing the app shell, images and verified snapshot. Repository scripts, tests and documentation are not copied into that asset bundle. Cloudflare's branch trigger runs `node scripts/build_worker_assets.mjs` before `npx wrangler preview`; it does not run a production deploy command.

To exercise the Worker path locally without publishing:

```bash
node scripts/build_worker_assets.mjs
node --test tests/worker.test.mjs tests/worker-assets.test.mjs
npx --yes wrangler@4.147.0 deploy --dry-run
```

## License

No license file is present in this repository, so no license is declared here.
