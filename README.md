# SubZer0 — Vulnerability Intel

A lightweight, static CVE dashboard for the RootAccessClub community. GitHub Pages serves the site and date-sharded feed; the browser does not call vulnerability APIs directly and needs no client-side credentials.

## What the feed includes

A scheduled Python job builds a rolling 30-day snapshot from three public sources. NVD records qualify by the CVE publication timestamp; GitHub advisories qualify by the advisory publication timestamp, which can be later than the CVE's original publication; CISA KEV entries qualify by the catalog's calendar-day `dateAdded` value.

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) supplies CVE details, CVSS scores, references, and CPE-based affected-product/version ranges. Results are paginated by `startIndex` until `totalResults` is covered; NVD's unauthenticated request pacing is respected.
- [GitHub's Global Security Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) supplements records with a CVE ID, advisory summary, affected package ranges, patched versions, and direct advisory links. The date-filtered results are followed through the API's `Link` cursor.
- [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) adds an exploitation marker, CISA action/due-date information, and vendor/product details. A KEV entry added during the window can appear even when its CVE was originally published earlier; CISA's `dateAdded` has calendar-day precision.

Records are deduplicated by CVE ID. A record retains source attribution, linked references, affected-version data when supplied, and CISA KEV status. CVSS is shown only when a source provides a score; a KEV flag is not presented as a CVSS severity.

## Lightweight delivery and freshness

`scripts/update_data.py` writes `data/manifest.json` plus one compact JSON shard per UTC activity date. The manifest records the exact source-specific date window, source page counts, distinct CVE total, severity/KEV counts, and the timestamp of the last complete successful snapshot. The browser opens the newest two date shards first, loads older shards as the visitor pages back, and loads the whole selected date range only when a full-range search or complete-window sort is used.

The GitHub Actions refresh is scheduled hourly. GitHub may queue scheduled runs, and source/API response time adds latency. While a page is open it checks the manifest every two minutes, then refreshes only the date shards already loaded; new CVEs are announced without reloading the page. This is scheduled polling, not a push feed, so actual appearance can lag a source publication by about an hour or more if a scheduled run is delayed. The interface shows the last successful snapshot time and latest browser check separately.

GitHub Pages is already configured to publish the `main` branch root. That existing route is preserved: commits to the feed and site are published through Pages automatically, so no Pages setting change or separate deploy workflow is needed.

## Run locally

```sh
python3 -m unittest discover -s tests -v
python3 scripts/update_data.py
python3 -m http.server 8080
```

Open `http://localhost:8080/`. The feed generator uses the Python standard library. An optional `NVD_API_KEY` can be supplied through the environment to raise NVD's request allowance; the scheduled workflow uses its built-in GitHub token for advisory API requests and does not need user-supplied secrets.

## Use notes

Severity filters, date inputs, sort controls, and search work over the selected window; search loads older date shards on demand. Every card has a one-click CVE-ID copy action and a GitHub PoC repository search clearly marked **unverified**. Treat search results as leads, not validated exploits; verify the CVE and affected version in the linked primary/advisory source before acting.

The site is designed for small screens and low-power phones: no UI framework, third-party font, analytics, or browser-side API polling of upstream services; recent records load first, older records are sharded, and reduced-motion settings are respected.

> This product uses data from the NVD API but is not endorsed or certified by the NVD.
