# SubZer0

SubZer0 is a vulnerability intelligence hub that collects and deduplicates CVE records into a searchable, date-filtered feed. It presents source-backed descriptions, affected products, CVSS severity, optional EPSS probability, and CISA KEV status separately. The static site and generated data are published from the root of `main` through GitHub Pages.

**Live site:** <https://iliya-bashrc.github.io/SubZer0/> · **Repository:** <https://github.com/iliya-bashrc/SubZer0> · **Telegram:** <https://t.me/RootAccessClub>

## Data sources and interpretation

The hourly collection pipeline uses three core sources:

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) supplies CVE descriptions, available CVSS metrics, references, and CPE-based affected-product/version data.
- [GitHub Global Security Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) supplements records with advisory text, package/version details, numeric CVSS scores where present, and advisory links.
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) identifies catalog-listed vulnerabilities and supplies CISA's date-added, affected-product, and remediation details where provided.

Records are merged by canonical CVE ID, retaining source attribution and unique references rather than showing duplicate source-specific CVEs. The rolling feed covers 30 days of NVD CVE publication, GitHub advisory publication, and CISA KEV additions. A KEV listing is retained for a matching record even when its catalog date is older than the feed window. Records are stored in UTC-date JSON shards; the manifest carries coverage, source status, snapshot timestamps, severity counts, and a SHA-256 fingerprint for each shard.

[FIRST EPSS](https://www.first.org/epss/data) is separate, optional enrichment. Its daily score set estimates the probability that exploitation activity will be observed in the next 30 days. EPSS scores and their score-set date are shown only when available; missing data is not `0%`. EPSS percentile is a relative rank, not a probability. A missing or stale EPSS set does not block core CVE collection.

CVSS is severity, not exploit likelihood. Numeric scores map to **Critical** (9.0–10.0), **High** (7.0–8.9), **Medium** (4.0–6.9), **Low** (0.1–3.9), neutral **None** (0.0), or neutral **Unrated** when a score is unavailable. The neutral filter includes None and Unrated. Severity styling uses red for Critical, amber/orange for High, gold for Medium, icy blue for Low, and neutral gray for None/Unrated. A numeric score from NVD or a GitHub advisory may be displayed; a text-only advisory severity is not substituted for a numeric CVSS score. CISA KEV means the CVE is listed in that catalog; absence from the catalog is not proof that exploitation has never occurred. GitHub repository-search results are unverified leads, not evidence of a working exploit or exploitation. Review linked source records before making security decisions.

## Feed behavior

The homepage provides the feed, snapshot time, source coverage, and EPSS score-set date. Search matches CVE IDs, descriptions, vendors, products, versions, and source names without reloading the page. Users can filter by severity, select UTC date ranges, sort records, open source-linked details, and load more results. Recent date shards are loaded first; each request reveals up to 24 more cards, and completed older shards are rendered as they arrive. Older-shard loading shows one skeleton per outstanding shard request; search and non-new sorting fetch every shard in the selected range.

While open, the page checks the manifest every two minutes and when it becomes visible. Manifest checks bypass the browser cache; shard URLs include the snapshot version. Per-day SHA-256 fingerprints reveal changes even when record totals stay the same. New CVE IDs are counted when they can be compared with loaded records; other changed data is reported as an update without guessing how many IDs are new. The current list remains visible until the user selects the persistent **View updates** notice; accepted records are applied without a full-page reload.

Initial loading remains visible until the manifest and initial feed data are usable. Failed or delayed requests have timeouts and automatic retries; the startup loader continues through failures rather than ending on a fixed timer, and no fake progress percentage is shown. Later failures preserve usable records, report status, and are retried by subsequent checks or requests.

This is scheduled collection plus browser polling, not a real-time push service. The workflow runs hourly at minute 35 UTC. Upstream publication, API availability, Actions queueing, and Pages/CDN delivery can add delay. FIRST EPSS data is daily and is displayed with its own score-set date.

## Repository layout

- `index.html`, `styles.css`, `app.js` — responsive static interface, accessible controls, feed rendering, polling, and update notices.
- `data/manifest.json` — rolling-window coverage, totals, source health, timestamps, and shard index.
- `data/YYYY-MM-DD.json` — normalized CVE records grouped by UTC activity date.
- `data/epss.json` — optional FIRST EPSS scores and score-set metadata.
- `scripts/update_data.py` — source fetching, retries, CVE-ID normalization/deduplication, enrichment, validation, fingerprinting, and atomic snapshot writing.
- `.github/workflows/update.yml` — scheduled/manual feed generation and publication to `main`.
- `.github/workflows/checks.yml` — Python tests and JavaScript syntax check on pushes and pull requests.
- `tests/` — frontend-contract and feed-pipeline unit tests.

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

The feed generator uses the Python standard library. It uses public NVD, GitHub, CISA, and FIRST endpoints. `GITHUB_TOKEN` or `GH_TOKEN` can be supplied for GitHub API access; GitHub Actions uses its built-in token. `NVD_API_KEY` is optional and can increase NVD request allowance. To refresh only EPSS for an existing snapshot, run `python3 scripts/update_data.py --epss-only`.

## GitHub Pages and Actions

GitHub Pages is configured to publish `/` from the `main` branch. A commit to `main` publishes site changes and triggers the Pages build. **Site and feed checks** runs the Python test suite and `node --check app.js` for pushes and pull requests. **Refresh vulnerability feed** runs hourly and can also be started manually; it requires complete core-source coverage before publishing generated shards and the manifest to `main`. The workflow uses the repository's `GITHUB_TOKEN` with contents-write permission and rebases its commit onto the current branch before a normal push. `NVD_API_KEY` is an optional repository secret.

## Data limitations

Upstream data may be delayed, revised, incomplete, or unavailable. A source's failure or missing field is not treated as proof of absence; product/version coverage depends on source records. CVSS, EPSS, and CISA KEV are distinct signals with different meanings and update schedules. This product uses data from the NVD API but is not endorsed or certified by the NVD.
