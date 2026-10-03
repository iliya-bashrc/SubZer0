![SubZer0 — CVE intelligence and vulnerability research, with maintainers @RootAccessClub and @BugCod3](assets/subzero-readme-banner.svg)

# SubZer0

SubZer0 is a static CVE-intelligence browser served by [GitHub Pages](https://iliya-bashrc.github.io/SubZer0/). The browser reads versioned JSON files from the same site; it does not call vulnerability APIs or run a backend.

[![Join @RootAccessClub on Telegram](assets/telegram-rootaccessclub.svg)](https://t.me/RootAccessClub) [![Join @BugCod3 on Telegram](assets/telegram-bugcod3.svg)](https://t.me/BugCod3)

*SubZer0 is independent and is not affiliated with Telegram.*

## Explore

- **Overview** — see counts and the three newest records in the validated snapshot, with links to their CVE details.
- **CVE Center** — search CVE IDs, products and descriptions; filter by CVSS severity or activity date; browse pages and inspect source-linked evidence.
- **Community** — view a terminal-style introduction and optionally open either Telegram destination. The displayed `xdg-open` command is a visual simulation; no shell command is executed.

CVSS, FIRST EPSS and CISA KEV are separate signals. A GitHub repository search is only a lead, not evidence that a proof of concept works. The application does not calculate a combined SubZer0 priority score.

## Static snapshot and refresh

GitHub Actions gathers records from the NVD CVE API, GitHub Security Advisory Database and CISA Known Exploited Vulnerabilities catalog, plus FIRST EPSS scores. A scheduled workflow runs every six hours (UTC) and can also be started manually from the `main` branch. It validates a complete new dataset and exercises the browser against it before committing only `snapshot/` to the GitHub Pages source branch. A core-source failure, incomplete pagination, invalid data, failed test or failed snapshot validation stops publication and retains the previous complete snapshot. EPSS is optional: if its feed is unavailable, retained scores remain explicitly marked stale or unavailable rather than being shown as current.

The browser itself remains offline from those upstream APIs. It fetches the same-origin static manifest and shards on demand, validates their schema and SHA-256 digests, applies byte/record limits, and shows an error rather than an empty or partially verified feed when a request fails. Hashes detect a shard that disagrees with its manifest; they are **not a digital signature**, because both are served from the same origin.

The snapshot currently in this source tree was generated at **2026-10-02 06:00:04 UTC** and contains **15,318 CVE records** across 31 UTC-day shards. Its EPSS data is dated **2026-09-29** and is marked stale. The security-review change adds a validated updater, but the existing data was not refreshed from upstream during that review. Treat these records as a dated snapshot, not a real-time feed. Static hosting provides no accounts, server-side search, push alerts or guarantee of source freshness; an upstream outage leaves the last complete snapshot in place.

See the [snapshot manifest](snapshot/manifest.json), [validation record](snapshot/VALIDATION.json), [source and trust notes](SOURCE-NOTES.md), and [security audit](AUDIT.md).

## Run locally

From the repository root, serve the files over HTTP so the browser can load the JSON snapshot:

```bash
python3 -m http.server 8766 --bind 127.0.0.1
```

Open [Overview](http://127.0.0.1:8766/) or the [CVE Center](http://127.0.0.1:8766/?page=center). Stop the server with `Ctrl+C`.

## Validate changes

Python unit tests use deterministic fixtures and do not call upstream APIs. The browser checks use Playwright and Chromium; the Community suite intercepts every Telegram navigation locally.

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m playwright install --with-deps chromium
node --check app.js
node --check community.js
python3 -m py_compile scripts/*.py tests/*.py verify_full_feed.py verify_preview.py verify_community_ansi_shadow.py
python3 scripts/verify_data_snapshot.py
python3 -m unittest discover -s tests -v
python3 verify_full_feed.py
python3 verify_community_ansi_shadow.py --community-only
```

`verify_community_ansi_shadow.py` without `--community-only` also compares Overview and CVE Center screenshots with `origin/main` (or `SUBZERO_BASELINE_DIR`) and requires Pillow; expected redesign or snapshot changes can produce pixel differences. `scripts/verify_pages.py` is used by the refresh workflow to wait until the public Pages site serves the exact locally validated manifest, every referenced data file, and the checked-in application HTML, JavaScript and stylesheets.

## License

No license file is present in this repository, so no license is declared here.
