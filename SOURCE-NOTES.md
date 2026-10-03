# Data provenance and trust boundaries

## Snapshot provenance

The current checked-in snapshot has `generated_at` **2026-10-02T06:00:04Z** and covers the rolling 30-day window **2026-09-02T06:00:04Z through 2026-10-02T06:00:04Z**. It contains **15,318 unique CVE records** in 31 date shards, including 45 CISA KEV listings. The manifest is [`snapshot/manifest.json`](snapshot/manifest.json); the full JSON records are under [`snapshot/data/`](snapshot/data/).

The 2026-10-03 security-review migration preserved every existing daily-shard and EPSS file byte-for-byte. It retained the original `generated_at`, added a small derived Overview sidecar, and updated the manifest and [`snapshot/VALIDATION.json`](snapshot/VALIDATION.json) to describe and validate the current static file layout. The Overview sidecar is derived only from the included records. This migration was not an upstream data refresh, and fixture tests did not make source API calls.

A subsequent scheduled refresh obtains records from the official [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0), [GitHub Security Advisory Database](https://api.github.com/advisories) and [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), with scores from [FIRST EPSS](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz) and an optional [FIRST API](https://api.first.org/data/v1/epss) fallback. The app served in a browser does not contact those services; it reads only the static snapshot from its own origin.

The offline verifier records manifest and shard hashes, exact byte and row counts, total CVE/severity/KEV counts, EPSS coverage and data-size limits. The producer stages a complete replacement, validates it before an atomic directory swap, and restores the prior snapshot if the swap fails. The browser independently checks the manifest-declared SHA-256 values before rendering. These hashes detect accidental corruption or a shard that disagrees with its manifest; they do **not** authenticate the source against an attacker able to replace both the manifest and files on the same Pages origin.

## Snapshot totals and source meaning

| Source CVSS category | Count | Center treatment |
|---|---:|---|
| Critical | 1,507 | Critical, red |
| High | 6,361 | High, orange |
| Medium | 4,955 | Medium, gold |
| Low | 949 | Low, icy blue |
| None | 1,527 | Neutral Unrated; source category retained |
| Unknown | 19 | Neutral Unrated; source category retained |
| CISA KEV listings | 45 | Separate catalog evidence |

“Unrated” is a browsing group only; it does not replace the source's `None` or `Unknown` value. A supplied numeric CVSS value is kept distinct from a missing score. The project does not invent or calculate a combined “SubZer0 priority score.”

The signal layers are intentionally independent:

- **CVSS** is the severity score/category supplied by a CVE record.
- **EPSS** is FIRST's probability estimate and percentile; the score-set date and staleness are shown.
- **CISA KEV** records catalog membership and the catalog's supplied date, product and action fields.
- **GitHub advisories** and user-started repository searches are leads, not proof of a working exploit or current exploitation.

## EPSS freshness

The snapshot contains **14,760 EPSS score entries** for 15,318 CVE records. The captured EPSS score date is **2026-09-29**, with source timestamp **2026-09-29T12:00:22Z**; the manifest marks this set stale. The app shows that state in the CVE Center and record details. A missing EPSS entry means **unscored**, not zero probability.

The updater treats EPSS as optional data: if the daily CSV and API fallback both fail validation or are unavailable, it may retain the previous score set but records it as stale/unavailable. A stale score is never reported as current. The NVD, GitHub and CISA core sources are required; an empty, malformed, inconsistent or incomplete core response aborts the refresh.

## Trust boundaries and browser behavior

Snapshot titles, descriptions, products, labels, references and catalog text are untrusted data. The interface creates DOM nodes and assigns content with `textContent`; it does not interpret snapshot strings as HTML. Links accept parsed HTTP or HTTPS URLs only, reject credentials and active schemes, and open new tabs with `noopener noreferrer`. Reference navigation occurs only after a person activates a link; ordinary data fetching is same-origin.

The Pages application has a restrictive same-origin Content Security Policy in its HTML, no inline JavaScript, and explicit client-side limits for manifests, shards, total snapshot bytes, record counts, request duration and shard concurrency. GitHub Pages does not provide a repository-controlled HTTP response-header configuration here, so CSP protections that can only be delivered as HTTP headers—especially `frame-ancestors`—cannot be enforced by the HTML meta policy. The audit documents this hosting limitation.
