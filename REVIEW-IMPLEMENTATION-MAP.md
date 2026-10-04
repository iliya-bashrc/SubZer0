# SubZer0 review-branch implementation map

**Purpose:** record the verified pre-edit architecture, baseline, and first implementation slice for owner review. This file and all following work are confined to `review/overview-intelligence-20261005`; nothing here changes or deploys `main`.

## Branch and production boundary

- Repository: `iliya-bashrc/SubZer0`
- Base: `main` / `origin/main` at `7dcb0a96e920f732211a253d303419c8f465bde0` (PR #23 merge commit)
- Review branch: `review/overview-intelligence-20261005`, created directly from that exact SHA
- PR #23 merged at `2026-10-04T22:33:58Z`; its security checks and Pages build/deployment both completed successfully on the supplied SHA.
- GitHub Pages is configured as legacy branch publishing from `main` at `/`, with deployment status `built`. This work will not edit the Pages source/configuration, run a deployment, merge a PR, or publish to production.

## Architecture map (observed on the clean base)

```text
Official upstreams (NVD, GitHub Advisories, CISA KEV; optional FIRST EPSS)
        │
        ▼
.github/workflows/update.yml (main-only, scheduled every six hours or manual)
  prepare [read-only] → scripts/update_data.py → complete staged snapshot
                      → scripts/verify_data_snapshot.py + offline/browser gates
  publish [contents:write only] → independently revalidate → snapshot/ only
  verify-pages [read-only] → scripts/verify_pages.py after publication
        │
        ▼
snapshot/manifest.json (schema v2, provenance, source_status, per-file hashes)
snapshot/data/YYYY-MM-DD.json (31 rolling UTC-day shards)
snapshot/data/overview.json (schema v1, three newest records)
snapshot/data/epss.json (separate FIRST EPSS score sidecar)
snapshot/VALIDATION.json (checked-in validation record)
        │ same-origin static files only; no browser calls to upstream APIs
        ▼
index.html + vanilla app.js + styles.css / severity-effects.css / feed.css /
community.css + community.js; strict CSP, text-only untrusted rendering,
manifest/schema/size/count/path/hash validation, fail-closed loading and URL state
        │
        ├── Overview: verified manifest + hash-verified overview sidecar only;
        │   captured source-check provenance and approximate age; no shard fetch
        ├── Latest: the three actual newest sidecar records, linked to details
        ├── Explore: existing CVE Center; lazily verifies shards/EPSS, then search,
        │   filters, paging, detail, shareable URL and browser history
        ├── Archive: date/count summaries and Explore filters inside this manifest's
        │   validated rolling window only; no implied cross-snapshot history
        └── Community: existing terminal-style interaction and explicit Telegram
            navigation; external links remain user-activated, not auto-fetched
```

### Data and trust contract

- The checked-in snapshot is a captured 30-day rolling window, generated at `2026-10-04T17:08:24Z`: 14,903 CVEs, 31 daily shards, 40 CISA KEV records, 14,749 EPSS scores, 33,869,716 JSON bytes. Its source checks are successful **as recorded in that snapshot**, not a claim about current upstream health.
- EPSS date, source-updated timestamp, coverage and stale/unavailable state are separate from CVSS severity and CISA KEV membership. Missing EPSS is unscored, not zero. No combined priority score is present.
- Hashes ensure downloaded files agree with the same-origin manifest; they are not a signature or independent authenticity proof.
- No validated cross-snapshot history or retained long-term archive exists. Any Archive view in this slice must say it is bounded to this rolling snapshot and must not imply change history or records beyond its window.
- Latest can use the already-versioned, bounded `overview.json` sidecar (three actual newest records). No new artifact, schema migration, upstream service, API key, cache policy, or runtime dependency is needed.

### First review-candidate slice delivered

- Preserve the established dark black-metal visual system, ice/steel action accents, semantic severity colors, system-safe typography, 8px spacing rhythm, existing desktop/mobile behavior, and Community implementation.
- Delivered five meaningful views: **Overview**, **Latest**, **Explore** (the existing CVE Center), **Archive** (date-browse inside the current rolling window only), and **Community**. Latest renders real sidecar records; Archive rows link into the existing URL-backed Explore date filters.
- Overview shows captured source status, provided source coverage and exact capture timestamps only from the validated manifest, plus an explicitly approximate age based on the visitor's device clock. A user-activated workflow-runs link replaces browser polling; the page never presents captured values as current health.
- Added a real manifest/Overview-sidecar retry action that re-requests the static data and has a regression scenario for a first failure, no partial content, recovery and focus announcement. The existing fail-closed full-feed loading/retry path in Explore remains intact.
- Extended shareable routing and adjacent keyboard/touch navigation to five views while retaining browser Back/Forward, mobile layouts, reduced-motion behavior, accessible labels and safe text rendering.
- Deliberately omitted automatic browser updates, a claimed 15-minute cadence, a separate Latest artifact, long-term/cross-snapshot Archive, new upstream API/credentials, and a command palette. Static Pages has no safe candidate-artifact handoff for foreground freshness without new infrastructure; the five explicit tabs and existing `/` shortcut provide direct access without an additional dialog or state model.
- All changes remain on the isolated review branch until the owner separately approves release. No Pages deploy, production publication, merge, new runtime dependency, or upstream updater run is part of this slice.

## Pre-edit baseline record

All checks below ran on the clean review branch at `7dcb0a96e920f732211a253d303419c8f465bde0`, before application code edits.

| Check | Result |
|---|---|
| `node --check app.js` and `node --check community.js` | Pass |
| `python3 -m unittest discover -s tests -v` | Pass — 41 tests |
| `python3 scripts/verify_data_snapshot.py` | Pass — 14,903 CVEs / 31 shards / 14,749 EPSS values / 33,869,716 bytes; generated `2026-10-04T17:08:24Z` |
| `python3 verify_full_feed.py` | Pass — Overview, lazy full-feed verification, filters/search/detail/focus, loading and retries, cache/integrity/error cases, URL/back-forward, reduced motion, mobile/desktop, touch/swipe; zero browser/page/console errors, failed requests, or automatic external requests |
| `python3 verify_community_ansi_shadow.py --community-only` | Pass — keyboard/reduced motion/actions and history; Telegram navigation intercepted locally; zero browser errors |
| `python3 scripts/verify_pages.py --root snapshot --timeout-seconds 60 --interval-seconds 5` | Pass — public site matched local manifest, application assets, hashes, byte counts and content on attempt 1 |
| `python3 -m pytest -q` | Not available in this environment (`No module named pytest`); the repository's documented test command is the passing standard-library `unittest` suite, so no dependency was added |

### Existing scheduled-refresh failure found during baseline inspection

GitHub Actions run [37236058061](https://github.com/iliya-bashrc/SubZer0/actions/runs/37236058061), scheduled on the prior `main` SHA `951ce65feaa1da12e2d2133cd606eaa74d4c151b`, collected upstream data and passed candidate snapshot validation. It then failed the second unittest step because `test_real_checked_in_full_snapshot_validates` asserted a historical hard-coded total of 15,318 while the just-generated valid snapshot contained 14,608. The isolated publish and verify-pages jobs were skipped, so that candidate was not published. This is a pre-existing test brittleness, not evidence of an upstream fetch failure. Correcting the fixed-count assertion to compare validated records against the same snapshot's validated manifest is a compatible test-only reliability fix; the updater will not be run against upstream sources during this task.

## Post-edit verification (2026-10-05)

| Check | Result |
|---|---|
| `node --check app.js`, `node --check community.js`, `python3 -m py_compile …`, `git diff --check` | Pass |
| `python3 -m unittest discover -s tests -v` | Pass — 41 deterministic tests, no upstream requests |
| `python3 scripts/verify_data_snapshot.py` | Pass — 14,903 CVEs, 31 UTC shards, 14,749 EPSS values, 33,869,716 JSON bytes; unchanged checked-in snapshot generated `2026-10-04T17:08:24Z` |
| `python3 verify_full_feed.py` | Pass — all five views at nine widths (320–1440 px); Explore search/filter/detail, hash/cache/loading failures, routing/history, keyboard/touch/desktop swipes, reduced motion, precise retry recovery, zero unexpected console/page errors, failed non-test requests or automatic external requests |
| `python3 verify_community_ansi_shadow.py --community-only` | Pass — ten desktop/mobile viewports; keyboard, action, history and reduced-motion checks; Telegram destinations intercepted locally; zero browser errors |
| Focused Latest/Archive/retry browser scenario | Pass — three sidecar record IDs match the validated sidecar; 31 Archive dates match the manifest; links restore exact UTC date filters; one simulated sidecar outage shows no unverified records and explicit retry restores data and focus; zero external requests |
| Focused touch/mouse/pen navigation regression | Pass — adjacent five-view routes, swipe cancellation, no-wrap, scrolling, state preservation, reduced-motion behavior and safe Community background interactions |

Desktop screenshots from the final Chromium run were copied outside the repository to `/workspace/subzero-review-artifacts-20261005/`. No schema, feed payload, workflow, runtime dependency, upstream refresh, production deployment, or merge changed during this slice. The next phase is owner review of the branch PR; any release remains a separate owner-approved action.
