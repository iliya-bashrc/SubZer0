# SubZer0 CVE Intelligence Browser — Engineering Report

## IMPLEMENTED
Rebuilt the browser around a compact schema-v2 search index, manifest sidecars, incremental multi-source updates, observed-change history, and on-demand detail shards. Replaced the scroll-driven search dock and Archive page with stable Explore and Changes views; retained old Archive bookmarks as an Explore date-filter alias.

## TESTED
All **47 Python unit tests** pass, the strict snapshot validator passes, and the complete Playwright suite passes with no browser/page/console errors, failed requests, or automatic external requests. Coverage includes integrity failures, lazy loading, shareable routes, filters, history honesty, touch/swipe, reduced motion, accessibility/focus behavior, offline caching, and fail-closed missing shards. The five views were checked from 320 to 1,440 CSS pixels.

## PERFORMANCE
In the final local Chromium run, the 14,614-record index was **13,428,927 bytes**; index plus EPSS sidecar totaled **14,236,374 bytes**. The first Explore load measured **1.08 s**, index verification through first-list render **897.2 ms**, and exact-ID interaction **93.36 ms** (5.4 ms synchronous list render). Opening one dossier loaded one **45,373-byte** shard in **0.161 s**. These are local acceptance-test measurements, not public Pages or low-end-device benchmarks.

## SECURITY
The static client verifies same-origin SHA-256 digests before accepting the manifest, index, sidecars, and detail shards; untrusted source text is rendered inert. The service worker uses a bounded cache-first model (128 MiB, 31 days), revalidates changed hashes, and fails closed when offline data is absent or invalid. The browser suite confirmed no automatic third-party requests.

## DATA PIPELINE
The pipeline collects NVD, GitHub advisory, CISA KEV, and FIRST EPSS data incrementally using source update timestamps. The validated capture contains **14,614 unique CVEs in 31 UTC shards**, **40 KEV records**, and **14,456 EPSS scores** across **46,485,928 JSON bytes**. CVSS severity, EPSS probability, and KEV status remain distinct signals; source timestamps and SubZer0 observation times are recorded separately. The capture manifest was generated at **2026-10-05T14:41:08Z**.

## PRODUCT / UX
Explore keeps search geometry stable while scrolling and restores query, filters, pagination, routes, and dossier state through browser history. Changes shows only evidenced differences with source/observation provenance; dossiers load detail and observed history on demand. The redesign adds semantic page/region structure, responsive mobile navigation and swipe, keyboard/focus restoration, reduced-motion support, and clearer offline/retry states. Source-capped 180-character titles are marked with a word-boundary ellipsis in the UI; stored source-derived text is unchanged.

## REMAINING LIMITATIONS
GitHub Pages remains static: there is no backend, database, or live server-side query. Offline dossiers are available only when their verified shard is cached; missing shards remain searchable but do not open. This checked-in capture is the initial comparison baseline, so its production history contains **0 observed change events**; earlier field differences cannot be reconstructed retroactively, and none are fabricated. Performance numbers are from local Chromium only; public Pages latency and physical low-end devices were not benchmarked. The work is on `feat/full-intelligence-rebuild-2026-10-05` for owner review and is not merged or deployed.
