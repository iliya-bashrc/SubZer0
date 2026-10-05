# Data provenance and trust boundaries

## Current checked-in capture

The verified static capture in this branch is dated **2026-10-05T14:41:08Z**. Its manifest declares **14,614 unique CVEs** across 31 UTC day shards. The FIRST EPSS sidecar contains **14,456 score entries** for **2026-10-04**; the remaining records are unscored in that score set, not assigned zero probability. The compact search index is a deterministic derivative of the checked-in full records. After the schema-v3 rebuild, every source day-shard SHA-256 matches its manifest declaration; no upstream source record, publication time, capture time or EPSS value was rewritten.

The history sidecar contains **1,504 source-backed events for 287 CVEs**, produced by the normal event builder from three complete main-branch captures: baseline commit [`44f17b5`](https://github.com/iliya-bashrc/SubZer0/commit/44f17b5) at **2026-10-04T17:08:24Z** (14,903 records), then [`ae3a7e9`](https://github.com/iliya-bashrc/SubZer0/commit/ae3a7e9) at **2026-10-05T13:15:51Z** (14,608 records) and [`01303fb`](https://github.com/iliya-bashrc/SubZer0/commit/01303fb) at **2026-10-05T14:41:08Z** (14,614 records). Event `observed_at` values use those later capture times; source timestamps remain separate when supplied. Thus 30-day retention is supported, but presently verified observation coverage spans only about **21.5 hours**. A full historical CISA KEV catalog baseline was not present and was not reconstructed. See the [manifest](snapshot/manifest.json), [validation record](snapshot/VALIDATION.json), and [data contract](DATA-CONTRACT.md) for exact hashes, sizes, sidecar counts and schema rules.

A fresh full-source refresh was attempted but not promoted: the NVD API changed its `totalResults` during both bounded complete page traversals, so the updater failed closed and preserved the validated capture. The branch adds a single whole-query restart for this specific transient, then aborts on a second inconsistency. The history above comes only from real complete captures already recorded in main-branch Git history, not test fixtures. The public Pages deployment remains the previously published main-branch application until this reviewed PR is merged and Pages publishes it; local branch behavior is not represented as already live.

## Sources and update semantics

The scheduled updater collects from the official [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0), [GitHub Security Advisory Database](https://api.github.com/advisories), the complete [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), and FIRST EPSS via the [daily compressed CSV](https://epss.empiricalsecurity.com/epss_scores-current.csv.gz) with the [FIRST EPSS API](https://api.first.org/data/v1/epss) as fallback. The application shown in a browser calls none of these upstream APIs; it reads same-origin static files.

NVD records are queried by last-modified time for the rolling window. GitHub advisories use the official `modified` date filter and cursor pagination. Their original CVE/advisory publication timestamps and NVD/GitHub source update timestamps remain distinct fields. The record's activity date is selected from the most recent eligible NVD, advisory or KEV activity timestamp; CISA `dateAdded` is a catalog date rather than a KEV modification timestamp. The original publication date of an older modified CVE remains unchanged.

Every full capture checks API response shape, identifiers, pagination totals/cursors, time ranges and configured byte/count bounds. CISA's full current catalog is obtained, not inferred from its intersection with a rolling feed. FIRST scores are retained with their score-set date and source timestamp. A core-source failure, empty result, incomplete page traversal, malformed response, invalid score or failed staged validation aborts the update and preserves the previous complete snapshot. EPSS may be retained as stale/unavailable only when its status explicitly says so.

## Timeline and change-history semantics

The UI distinguishes **source time**, **SubZer0 observation time** and **published snapshot time**:

| Time | Meaning | Example field |
|---|---|---|
| Source time | Timestamp/date supplied by NVD, GitHub, CISA or FIRST | `published`, `modified`, `updated_at`, `dateAdded`, EPSS `source_updated_at` |
| Observation time | Time a workflow observed a difference between complete captures | History event `observed_at` |
| Capture time | Time represented by the complete static snapshot | `manifest.generated_at` |

History compares complete snapshots, records meaningful evidence-backed differences, and is retained for 30 days. New publication requires source publication later than the preceding complete capture. A recently modified record whose original publication predates that capture and whose old detail is outside the rolling feed is marked **re-observed**, not newly created; the UI explains that field-level comparison is unavailable. Changes in a complete CISA catalog are compared with a separately retained full-catalog baseline once that baseline exists. The updater never infers CVE deletion from its absence in a rolling feed.

FIRST EPSS additions, removals and material value differences are identified separately from CVSS changes. To avoid a noisy event log, score-to-score changes require an absolute move of at least 0.01 or a twofold move once the larger value reaches 0.05; the complete score sidecar still retains the raw daily values. A CISA KEV entry comparison may have no source modification time, because the catalog provides a date-added field rather than a change timestamp; the event remains labeled with its actual observation time and `source_time: null`.

## Signal meaning and data limits

- **CVSS** is the supplied severity score/category, not an exploitation-probability estimate. NVD's CVSS 2.0 `vectorString` is preserved in its source-native unprefixed form; 3.x/4.0 vectors retain their version prefix. Version-specific syntax and a 512-character cap are checked without truncating source evidence.
- **FIRST EPSS** is a dated probability estimate and percentile; missing scores are unscored, not zero.
- **CISA KEV** is catalog membership with the source's supplied date and action fields; absence does not prove that exploitation never occurred.
- **GitHub advisories and external references** are source-attributed research leads, not proof of a working exploit.
- This validated record schema has no reliable CWE field. The dossier says when a CWE is not supplied rather than fabricating one.
- No combined SubZer0 risk/prioritization score is invented.

## Trust boundaries

Snapshot text is untrusted. The UI creates text nodes rather than parsing it as HTML. URLs are parsed, limited to HTTP or HTTPS, reject embedded credentials and active schemes, and open external links with `noopener noreferrer`. Search uses a bounded compact index; full references, descriptions and configurations live only in integrity-checked detail shards.

The offline producer and browser validate path allowlists, schemas, duplicates, exact lengths, record counts, score ranges and SHA-256 digests. An atomic staging/commit preserves the prior snapshot if a complete candidate fails. The same-origin manifest digest protects against accidental corruption and mismatched cache entries; it is **not** a digital signature and does not authenticate a manifest against an attacker who can replace the manifest and files together.

The site uses a restrictive same-origin Content Security Policy in its HTML and has no inline script. GitHub Pages does not expose configurable response headers through this branch-based setup, so a meta policy cannot provide `frame-ancestors`; this remains a hosting-level limitation.

## References

- [NVD CVE API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [GitHub REST global security advisories](https://docs.github.com/rest/security-advisories/global-advisories)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST EPSS](https://www.first.org/epss/)
- [Snapshot/data contract](DATA-CONTRACT.md)
