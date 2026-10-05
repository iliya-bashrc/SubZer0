# SubZer0 redesign implementation map

SubZer0 remains a dependency-free static application: GitHub Actions builds and validates the snapshot; GitHub Pages serves the application and JSON; browser code never calls NVD, GitHub Advisories, CISA or FIRST directly.

- Repository: `iliya-bashrc/SubZer0`
- Existing review branch: `review/overview-intelligence-20261005`
- Pull request: [#24](https://github.com/iliya-bashrc/SubZer0/pull/24), based on production `main` at `7dcb0a96e920f732211a253d303419c8f465bde0` before this update.
- The redesign preserves vanilla HTML/CSS/JS, the existing snapshot updater and GitHub Actions security boundaries, plus the separate Community terminal. It does not introduce a framework, backend, new upstream service, API credential or combined severity score.

## Architecture

```text
NVD + GitHub Security Advisories + CISA KEV + FIRST EPSS
                         │
                         ▼
.github/workflows/update.yml
  main-only scheduled/manual candidate collection
  → complete snapshot validation + deterministic/browser gates
  → isolated publish of snapshot/ only
  → read-only public Pages verification
                         │
                         ▼
GitHub Pages: same-origin static application and validated JSON
  index.html + app.js + styles.css + feed.css + community.js/css
  sw.js (bounded same-origin app-shell cache)
  snapshot/manifest.json
  snapshot/data/overview.json (bounded schema-v2 index, up to 50 records)
  snapshot/data/YYYY-MM-DD.json (31 rolling UTC daily shards)
  snapshot/data/epss.json (separate FIRST EPSS evidence)
                         │
                         ▼
Browser: manifest/schema/size/path/count/hash checks before render
  Overview + Latest: manifest and Overview sidecar
  Explore: every required daily shard plus EPSS sidecar before full results
  Archive: dates represented by this rolling manifest only
  Community: existing terminal-inspired content and explicit outbound links
```

## Views and query behavior

- **Overview** presents validated CVE and CISA KEV totals, FIRST EPSS coverage, the actual daily distribution, captured source checks and four links to real latest records. Captured metadata is not presented as live source health.
- **Latest** searches and facets the hash-verified top-50 sidecar locally, with source, EPSS minimum and KEV controls. A record opens in the complete Explore view.
- **Explore** searches the complete verified snapshot and keeps CVSS severity, numeric CVSS minimum, EPSS probability minimum, CISA KEV membership and feed-source attribution independent. Activity dates, supplied vendor, search, pagination and detail state remain shareable through the URL.
- **Archive** is a UTC-date/count index for the current rolling window, linked to matching inclusive Explore date filters; it is not permanent retention or cross-snapshot history.
- **Community** keeps its original terminal identity, keyboard-accessible behavior and user-activated Telegram navigation.

CVE dossiers distinguish CVSS severity, FIRST EPSS probability, CISA KEV evidence and advisory/research leads. The “Why This Matters” section summarizes only the selected record's actual validated evidence and explicitly avoids a combined score or live assessment. The checked-in record schema has no CWE classification field, so the UI says when CWE is not supplied rather than inferring one.

The shared compact header identifies the active page. On small screens, the five destinations move to a safe-area-aware bottom rail and dense feed rows transform into cards. Search, filters, dossier sections, focus return, keyboard navigation, touch/mouse gestures and reduced-motion behavior remain accessible.

## Data integrity, freshness and offline use

The checked-in capture was generated at `2026-10-04T17:08:24Z`: 14,903 CVEs across 31 UTC date shards, 40 captured CISA KEV records and 14,749 EPSS scores dated `2026-10-04`. The window covers a rolling 30 days of activity; these values describe that capture, not current conditions.

The updater generates an Overview schema-v2 sidecar containing up to 50 actual records and the EPSS/KEV evidence available for each. The manifest records byte sizes and SHA-256 digests. The browser retains strict bounds, schema validation, safe text/link rendering, timeouts and no-partial-data behavior. A same-origin digest verifies consistency with the manifest; it is not a digital signature or independent authenticity proof.

Snapshot state is capture-relative and uses the viewer's approximate device clock: **FRESH** through six hours, **DELAYED** over six and through 24 hours, **STALE** after 24 hours, **DEGRADED** for captured source/EPSS issues or failed verification, and **OFFLINE** when the application uses successfully verified cached data. Source status rows and timestamps are values recorded in the captured manifest, not live checks.

The service worker caches the same-origin app shell. The application stores snapshot files only after their byte limits, manifest digests, schemas and relevant cross-file consistency have passed. In offline mode each file is verified again; Explore refuses partial results if any required shard is missing. Caching is best-effort and limited to files previously verified in that browser.

A same-origin background check runs every 15 minutes while visible and also on visibility return/reconnection. It validates a candidate manifest and compact Overview index, then offers reload or dismissal if a newer capture exists. It neither polls upstream vulnerability sources nor silently replaces the snapshot already displayed.

## Verification and publication boundary

Static gates include `node --check` for application, worker and Community JavaScript; Python compilation; `python3 scripts/verify_data_snapshot.py`; `python3 -m unittest discover -s tests -v`; and `git diff --check`. `python3 verify_full_feed.py` exercises record filtering, source/EPSS/CVSS thresholds, deep links, dossiers, browser history, integrity/tamper and retry behavior, the mobile transformation, offline cache, background-update notice and fail-closed missing-shard behavior. `python3 verify_community_ansi_shadow.py` smoke-tests the redesigned Overview “Explore records” action before checking the preserved Community terminal, exact banner text/geometry, responsive states, keyboard/reduced-motion behavior and locally intercepted Telegram actions; `--community-only` runs only Community checks. Cross-route pixel equality is intentionally not asserted after the approved whole-site redesign. `scripts/verify_pages.py` checks the public Pages app assets and the deployed snapshot after release.

GitHub Pages is configured for the `main` branch at `/`. The Cloudflare Git integration is a separate deployment system: its production build watches `main` and runs `npx wrangler deploy`, while its PR-branch preview uses a separate `npx wrangler preview` build. Therefore merging this PR also triggers a **production Cloudflare Worker deployment**, not only a Pages build. That Worker release requires its own explicit narrow authorization; Pages approval alone does not authorize a separate Worker publication. No Cloudflare resource or production deployment is changed by this implementation map.
