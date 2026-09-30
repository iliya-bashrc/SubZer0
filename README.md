<div align="center">

# SUBZER0

### ICE / EMBER · VULNERABILITY INTELLIGENCE

**A focused 30-day CVE radar for RootAccessClub. Four signals, kept separate.**

[![Open the live radar](https://img.shields.io/badge/OPEN%20THE%20RADAR-ICE%20%2F%20EMBER-101820?style=for-the-badge&labelColor=111923)](https://iliya-bashrc.github.io/SubZer0/)
[![Telegram @RootAccessClub](https://img.shields.io/badge/Telegram-%40RootAccessClub-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/RootAccessClub)
[![Source code](https://img.shields.io/badge/SOURCE-GitHub-24292F?style=for-the-badge&logo=github&logoColor=white)](https://github.com/iliya-bashrc/SubZer0)

</div>

SubZer0 is a lightweight static site: GitHub Pages serves the interface and date-sharded feed, while the browser loads public JSON only. No browser-side vulnerability API credentials, UI framework, analytics, or third-party font are required. The original frost-and-ember visual language is made from custom CSS and SVG—not official game artwork or logos.

## Read each signal on its own terms

| Signal | What it says | What it does not say |
| --- | --- | --- |
| **CVSS** | Severity score and severity band, when a numeric score is supplied | Exploit probability, proof of exploitation, or a complete environmental risk score |
| **EPSS** | FIRST's estimated probability that exploitation activity will be observed in the wild in the next 30 days; refreshed daily | Confirmed exploitation. Its percentile is a relative rank, not the probability |
| **CISA KEV** | CISA catalog evidence that a vulnerability is known to have been exploited | CVSS severity or an EPSS forecast |
| **GitHub PoC search** | A convenience search for public repository leads | Verified proof-of-concept code, working exploit, or evidence that a CVE is exploited |

A missing EPSS score is shown as unavailable, never as 0%. A vulnerability without a numeric CVSS score remains **unrated**; advisory labels are not substituted for CVSS. Card colour responds to CVSS severity and score—not to EPSS or PoC search results.

## Data and freshness

The hourly feed job builds a rolling 30-day snapshot from three core sources:

- [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) provides CVE descriptions, CVSS metrics, references, and CPE-based affected-product/version ranges. Pagination continues until the reported result set is covered, with NVD's unauthenticated request pacing respected.
- [GitHub Global Security Advisory Database](https://docs.github.com/en/rest/security-advisories/global-advisories) supplements CVEs with advisory descriptions, package ranges, patched versions, and direct advisory links. The feed follows pagination cursors and uses advisory publication time when that is the activity that brought an older CVE into the window.
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) contributes catalog status, date added, action/due-date details, and vendor/product information. CISA's date-added value has calendar-day precision.

Records are deduplicated by CVE ID and sharded by UTC activity date. NVD publication, GitHub advisory publication, and CISA KEV date-added events retain their own date basis. Three core sources must complete before a new core snapshot is published; optional EPSS enrichment cannot discard or block that coverage.

[FIRST EPSS publishes free daily scores through its API and CSV.](https://www.first.org/epss/data) SubZer0 uses the official compressed daily CSV for its batch update, caches the current-window scores in a separate `data/epss.json` sidecar, and uses small API lookups only for newly surfaced CVEs between daily score-set refreshes. The page shows the score-set date separately from the core snapshot timestamp. EPSS enrichment is optional: if its source is temporarily unavailable, the last available scores are retained and their date remains visible.

GitHub Actions collects the core sources hourly. The page checks for a newer static snapshot every two minutes while open. Scheduled runs can queue, and source/API/deployment time adds latency, so this is a scheduled feed—not a real-time push service. The interface shows the last successful core snapshot, the latest browser check, source coverage, and the EPSS score-set date separately.

## Explore and share

Search CVE IDs, products, vendors, or descriptions across the selected window. Filter by CVSS severity, choose a UTC date range, sort by newest or CVSS severity, and load recent shards first; older shards are fetched only when needed. Open a record for affected-version details, source references, and the independent CVSS, EPSS, CISA KEV, and PoC-search signals. Each card can be shared to Telegram with its source link and signal labels.

Join the channel: [![Telegram @RootAccessClub](https://img.shields.io/badge/Telegram-%40RootAccessClub-26A5E4?logo=telegram&logoColor=white)](https://t.me/RootAccessClub)

## Run locally

```sh
python3 -m unittest discover -s tests -v
node --check app.js
python3 -m http.server 8080
```

Open `http://localhost:8080/`. The feed generator uses only the Python standard library. An optional `NVD_API_KEY` raises NVD request allowance; the GitHub Actions job uses its built-in token for advisory API requests. To update only the optional EPSS score sidecar for a current snapshot, run `python3 scripts/update_data.py --epss-only`.

## Project notes

- GitHub Pages publishes the root of `main`; the existing publishing route is unchanged.
- No commit history rewrite, external frontend runtime, or client-side upstream polling is used.
- Reduced-motion preferences, keyboard focus, accessible filter labels, and narrow-phone layouts are supported.
- CVE IDs and affected versions should be verified with the linked primary/advisory source before taking action.

> This product uses data from the NVD API but is not endorsed or certified by the NVD.
