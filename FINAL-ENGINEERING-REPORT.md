# SubZer0 CVE Intelligence Browser — Implementation Report

## Product

The existing browser now has data-driven Overview, Latest, Explore, Changes and Community views. Overview presents the capture window, source-check metadata, severity distribution and a verified recent-change preview. Explore uses a stable search bar, shareable filters, URL-restored pagination and a compact verified index; full CVE shards load only when a dossier is opened. Dossiers separate CVSS, EPSS and KEV signals, display captured CVSS vectors and affected-product evidence when present, and expose cited references. Changes is a searchable, date/type-filtered, paginated feed with distinct source and observation timestamps, direct links and browser-history restoration. The mobile filter disclosure, bottom navigation, swipe gestures, reduced-motion behavior and focus handling were exercised in a real browser.

The static pipeline now publishes a deterministic gzip-packed search index with compressed and uncompressed SHA-256 metadata, bounded streaming decompression, verified Overview previews and source-backed complete-capture history. It preserves source CVSS 2.0 vectors in NVD's unprefixed form and accepts bounded CVSS 3.x/4.x vectors without truncation. Failed or inconsistent source responses fail closed rather than replacing the last complete snapshot.

## Data and history

The current source capture remains the complete **2026-10-05T14:41:08Z** main-branch capture: **14,614 CVEs**, **31 UTC shards**, **40 KEV records** and **14,456 EPSS scores** dated **2026-10-04**. Its 31 source-shard hashes and the entire EPSS payload match the original published capture; only derived search, Overview, validation and history sidecars changed.

The checked-in capture contains no CVSS vector or version fields; **4,080** records contain affected-product evidence. The dossier labels absent vectors as “Not captured in this snapshot,” which does not make a claim about fields omitted by the older ingestion pipeline or the current upstream response. The new producer retains supplied vectors on a future successful capture.

The Changes sidecar contains **1,504 source-backed events for 287 CVEs**, derived by the normal producer from three complete captures: baseline **2026-10-04T17:08:24Z** (14,903 records), then observations at **2026-10-05T13:15:51Z** (14,608 records) and **2026-10-05T14:41:08Z** (14,614 records). The verified comparison coverage is about **21.55 hours**; the 30-day rule is a retention ceiling, not a claim of 30 days of available observations. Feed omission is never interpreted as deletion, and no unavailable full CISA KEV catalog baseline was reconstructed.

A later full-source refresh was attempted but rejected because NVD's `totalResults` changed during both bounded pagination walks. The updater permits one complete retry for that moving-total condition and still aborts on a second inconsistency. No live-feed candidate was promoted; the data above are a dated capture, not a claim about present upstream status.

## Verification and performance

Final local gates pass: **56 Python tests**, Python/JavaScript syntax checks, full offline snapshot validation, and the complete interactive Playwright suite. Browser coverage includes the actual populated Changes page, offline caching of all 1,504 events, filters and direct links, lazy details, digest failures, hostile text, retry behavior, touch navigation and reduced motion. It reported zero browser/page/console errors, failed requests or automatic external requests; all five views fit 320–1,440 CSS px without horizontal overflow.

Compared with the captured pre-rebuild build, index-plus-EPSS first-view bodies fell from **14,236,374 B** to **2,301,565 B**—**11,934,809 B (83.83%) fewer**. The current compressed index is **1,494,118 B** and expands to **7,904,199 B**. In the final local run, initial index load measured **0.821 s**, integrity-through-first-list-render **665 ms**, exact-ID search **101.71 ms** including debounce, one **45,373-byte** dossier shard opened in **0.166 s**, and an unchanged repeat load transferred no repeated index/EPSS bodies. See [measured performance](PERFORMANCE.md) for the capture methodology and caveats.

## Status

The changes are on the existing [`feat/full-intelligence-rebuild-2026-10-05`](https://github.com/iliya-bashrc/SubZer0/tree/feat/full-intelligence-rebuild-2026-10-05) branch and existing [PR #25](https://github.com/iliya-bashrc/SubZer0/pull/25). This report does not claim the branch is merged or deployed; GitHub Pages remains unchanged until the reviewed PR is merged and Pages publishes it. The application remains a static snapshot browser, without a backend or live server-side queries.
