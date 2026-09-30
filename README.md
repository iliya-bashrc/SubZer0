# SubZer0

SubZer0 is a vulnerability intelligence hub that collects and deduplicates CVE records into a searchable, date-filtered feed. It presents source-backed descriptions, affected products and versions, CVSS severity, optional EPSS probability, and CISA KEV status as distinct signals. The static site and generated data are published from the root of `main` through GitHub Pages.

**Live site:** <https://iliya-bashrc.github.io/SubZer0/> · **Repository:** <https://github.com/iliya-bashrc/SubZer0> · **Telegram:** <https://t.me/RootAccessClub>

## Data sources and interpretation

The hourly collection pipeline uses three core sources:

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) supplies CVE descriptions, available CVSS metrics, reference URLs and tags, CPE criteria, affected-product/version data, and direct CVE links present in NVD references.
- [GitHub Global Security Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) supplements records with advisory text, package/version details, numeric CVSS scores where present, and advisory links.
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) identifies catalog-listed vulnerabilities and supplies CISA's date-added, affected-product, and remediation details where provided.

Records are merged by canonical CVE ID, retaining source attribution and unique references rather than showing duplicate source-specific CVEs. Source reference tags are preserved. A reference highlighted as `Exploit` means NVD supplied that tag; SubZer0 does not validate the linked code. A related-CVE link is shown only when a direct CVE record URL is present in the NVD reference data; no relationship type is inferred. CPE criteria and affected versions are shown only when supplied by the relevant source. Product names are not inferred from free text.

The rolling feed covers 30 days of NVD CVE publication, GitHub advisory publication, and CISA KEV additions. A KEV listing is retained for a matching record even when its catalog date is older than the feed window. Records are stored in UTC-date JSON shards; because the exact rolling interval can intersect partial first and last UTC dates, it may span 31 calendar-date shards. The manifest's timestamp window defines inclusion. It carries coverage, source status, snapshot timestamps, severity counts, and a SHA-256 checksum for each shard's exact published bytes.

[FIRST EPSS](https://www.first.org/epss/data) is separate, optional enrichment. Its daily score set estimates the probability that exploitation activity will be observed in the next 30 days. EPSS scores and their score-set date are shown only when available; missing data is not `0%` and is not labeled `AWAITING SCORE` without an upstream status proving that condition. EPSS percentile is a relative rank, not a probability. A missing or stale EPSS set does not block core CVE collection.

CVSS is severity, not exploit likelihood. Numeric scores map to **Critical** (9.0–10.0), **High** (7.0–8.9), **Medium** (4.0–6.9), **Low** (0.1–3.9), neutral **None** (0.0), or neutral **Unrated** when a score is unavailable. The neutral filter includes None and Unrated. A numeric score from NVD or a GitHub advisory may be displayed; text-only advisory severity is not substituted for numeric CVSS. CISA KEV means the CVE is listed in that catalog; absence is not proof that exploitation has never occurred. GitHub repository-search results are unverified leads, not evidence of a working exploit or exploitation. Search absence is not proof that no public PoC exists.

## Feed behavior

The homepage provides the feed, snapshot time, source coverage, and EPSS score-set date. Search matches CVE IDs, descriptions, vendors, products, versions, and source names. Users can filter by severity, UTC date range, and exact source-backed vendor/product values; when both facets are selected they must match the same affected pair. Grouping places each CVE once under one source-priority affected pair to avoid duplicate cards. Users can also sort by date, severity, or the custom priority heuristic and open source-linked details. `Absolute Zero` means **Critical and listed in CISA KEV**. Filtered JSON and CSV exports include the filters and available records; CSV fields are escaped to reduce spreadsheet-formula injection risk.

The two newest date shards inside the selected range load first. Each request reveals up to 24 more cards (records); after 200 cards are mounted, the displayed window advances instead of continually growing the DOM. Older-shard loading shows one skeleton per outstanding shard request; usable data is retained if a later request fails. A search, vendor/product filter, Absolute Zero selection, non-new sort, or export loads every shard in the selected range before reporting a complete result.

Saved filter views, stars, read/unread markers, compact mode, and vendor/product watchlists are stored locally in this browser only. They are not sent to the feed pipeline. Share links contain only structured, public filters (date, severity, sort, vendor/product, grouping, Absolute Zero, and compact mode); free-text search and local stars/read/watch data are excluded. `/` focuses search; `j`/`k` move between visible records and `c` copies the focused CVE ID. These shortcuts are inactive in text-entry controls and while the detail dialog is open.

The details panel can make an explicit, on-demand GitHub repository search. It displays the API's raw matching repository count and up to three repository results, marked unverified. The count is not the number of confirmed PoCs; API errors and rate limits are reported as unavailable rather than as zero. NVD-tagged Exploit references are highlighted separately and are not asserted to be working exploits.

While open, the page checks the manifest every two minutes and when it becomes visible. Manifest checks bypass the browser cache; shard URLs include the snapshot version. Each per-day `sha256` is the SHA-256 of the exact compact UTF-8 JSON shard bytes, including the final newline, so clients can verify a downloaded file directly; it also reveals changes when record totals stay the same. A newer snapshot remains staged until the user selects **View updates**. Only newly identified Critical IDs that enter the feed after that explicit action trigger the ambient arrival treatment; it respects reduced-motion preferences.

## Composite priority (custom triage heuristic)

The 0–100 composite is a **SubZer0 heuristic**, not an official CVSS, FIRST, NVD, or CISA score, and not proof of exploitation or safety. The underlying source signals remain separately visible.

| Input | Base weight | Normalized value |
| --- | ---: | --- |
| CVSS | 25% | Numeric CVSS score ÷ 10 × 100 |
| EPSS | 25% | FIRST probability × 100 |
| CISA KEV | 25% | 100 when listed; 0 when not listed in a complete current catalog snapshot |
| PoC reference | 15% | 60 when an NVD reference is explicitly tagged `Exploit`; this does not verify code |
| Recency | 10% | 100 at the sourced activity timestamp, declining linearly to 0 over 30 days |

Only available component weights are renormalized. Missing EPSS is not zero; missing PoC tags are not proof of absence; a missing CVSS score is not low severity; and absence from KEV is not evidence of no exploitation. The score is shown only when at least 3 of the 5 inputs are available, with its input coverage and missing components. GitHub search counts are not used as a score input. The card and detail view identify it as custom; methodology and component notes are available in the page.

## Retained changes, freshness, and trends

`data/history.json` stores a rolling 30 days of complete snapshots and material comparisons. The pipeline compares CVE IDs present in both complete snapshots so feed-window expiry is not described as a KEV removal. A severity event requires numeric CVSS in both snapshots and a category change. KEV entry/removal compares the same CVE across snapshots. A material EPSS change is an absolute difference of at least 0.10, or a twofold change when both scores are nonzero and the larger is at least 0.05. The one-time `scripts/backfill_history.py` utility reconstructs retained history from verifiable committed snapshots; later updates append comparisons to published history.

The site does **not** claim a Trending/Hot ranking: the static feed has no measured public-attention data. The `highest severity` ordering is a CVSS sort, not a trend or exploit-popularity score.

The core-source snapshot timestamp is the collection run time, not an upstream publication timestamp. NVD, GitHub advisories, and CISA do not provide per-source upstream update timestamps in this feed, so average source delays are not calculated. FIRST EPSS freshness uses the actual dated score set. Collection runs hourly at minute 35 UTC; upstream publication, API availability, Actions queueing, and Pages/CDN delivery can add delay. This is scheduled polling, not a real-time push service.

**Automated notifications are not configured.** GitHub Pages has no secure server-side relay, Telegram bot/webhook credential, or authorized recipient/chat ID/webhook destination. Automated Telegram, Discord, and webhook delivery is disabled. The visible “Share to Telegram” link is manually user-triggered and does not send alerts.

## Static snapshot API

[`api/v1/manifest.json`](https://iliya-bashrc.github.io/SubZer0/api/v1/manifest.json) is a read-only **static snapshot index** served by GitHub Pages, not a dynamic API server. It mirrors the current manifest and links to the published date shards, exact facets, EPSS sidecar, and retained history. Responses reflect the latest committed/deployed snapshot; they do not accept queries or trigger data collection.

## Repository layout

- `index.html`, `styles.css`, `app.js` — responsive static interface, accessible controls, feed rendering, polling, and update notices.
- `data/manifest.json` — rolling-window coverage, totals, source health, timestamps, facets/history links, and shard index.
- `data/YYYY-MM-DD.json` — normalized CVE records grouped by UTC activity date, including source-backed CPE, references/tags, and direct related CVE links when available.
- `data/facets.json` — exact source-backed vendor and product suggestions.
- `data/epss.json` — optional FIRST EPSS scores and score-set metadata.
- `data/history.json` — rolling retained complete snapshots and material changes.
- `api/v1/manifest.json` — static API index mirroring the published feed manifest.
- `scripts/update_data.py` — source fetching, retries, CVE-ID normalization/deduplication, enrichment, validation, fingerprinting, and atomic snapshot writing.
- `scripts/backfill_history.py` — one-time backfill from verifiable complete feed snapshots committed to Git.
- `.github/workflows/update.yml` — scheduled/manual feed generation and publication to `main`.
- `.github/workflows/checks.yml` — Python tests and JavaScript syntax check on pushes and pull requests.
- `tests/` — frontend-contract, feed-pipeline, retained-history, and backfill unit tests.

## Run and test locally

The static frontend has no framework or external runtime dependency. With Python 3 and Node.js available:

```sh
python3 -m unittest discover -s tests -v
node --check app.js
python3 -m http.server 8080
```

Open <http://localhost:8080/>. To collect a new feed locally, run:

```sh
python3 scripts/update_data.py
```

The feed generator uses the Python standard library. It uses public NVD, GitHub, CISA, and FIRST endpoints. `GITHUB_TOKEN` or `GH_TOKEN` can be supplied for GitHub API access; GitHub Actions uses its built-in token. `NVD_API_KEY` is optional and can increase NVD request allowance. To refresh only EPSS for an existing snapshot, run `python3 scripts/update_data.py --epss-only`. To reconstruct retained history from commits in the current checkout, run `python3 scripts/backfill_history.py`.

## GitHub Pages and Actions

GitHub Pages is configured to publish `/` from the `main` branch. A commit to `main` publishes site changes and triggers the Pages build. **Site and feed checks** runs the Python test suite and `node --check app.js` for pushes and pull requests. **Refresh vulnerability feed** runs hourly and can also be started manually; it requires complete core-source coverage before publishing generated shards, sidecars, and both manifest indexes to `main`. The workflow uses the repository's `GITHUB_TOKEN` with contents-write permission and rebases its commit onto the current branch before a normal push. `NVD_API_KEY` is an optional repository secret.

## Data limitations

Upstream data may be delayed, revised, incomplete, or unavailable. A source's failure or missing field is not treated as proof of absence; product/version coverage depends on source records. CVSS, EPSS, and CISA KEV are distinct signals with different meanings and update schedules. The custom priority heuristic cannot establish exploitation, impact, safety, or the absence of evidence. This product uses data from the NVD API but is not endorsed or certified by the NVD.
