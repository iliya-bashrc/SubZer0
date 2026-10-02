![SubZer0 — CVE intelligence and vulnerability research, with maintainers @RootAccessClub and @BugCod3](assets/subzero-readme-banner.svg)

# SubZer0

SubZer0 is an independent static preview for exploring a captured CVE feed from NVD, GitHub Security Advisories, and CISA Known Exploited Vulnerabilities (KEV). Browse the [published snapshot preview](https://iliya-bashrc.github.io/SubZer0/).

[![Join @RootAccessClub on Telegram](assets/telegram-rootaccessclub.svg)](https://t.me/RootAccessClub) [![Join @BugCod3 on Telegram](assets/telegram-bugcod3.svg)](https://t.me/BugCod3)

## Explore

- **Overview** — scan a few records from the snapshot and open each record directly in the CVE Center.
- **CVE Center** — search CVE IDs, products, and descriptions; filter by CVSS severity or activity date; browse paged results and source-linked record details.
- **Community** — view a terminal-style introduction and use either Telegram link. The `xdg-open` command is typed out as a visual simulation; the page never executes a shell command.

## Snapshot and data

This repository bundles **15,318 CVE records** covering **2026-09-02 through 2026-10-02 UTC**, captured at **2026-10-02 06:00:04 UTC**. It is a dated static snapshot, not a live feed, and does not refresh automatically. CVSS severity, FIRST EPSS probability, and CISA KEV membership are separate signals; GitHub repository searches are leads, not proof of a working exploit. The EPSS scores are dated **2026-09-29** and marked stale; a missing score means unscored, not 0%.

See the [snapshot manifest](snapshot/manifest.json), [validation record](snapshot/VALIDATION.json), and [source notes](SOURCE-NOTES.md) for provenance and field semantics.

## Run locally

From the repository root, start a local static server:

```bash
python3 -m http.server 8766 --bind 127.0.0.1
```

Open [Overview](http://127.0.0.1:8766/) or the [CVE Center](http://127.0.0.1:8766/?page=center). Use HTTP rather than opening `index.html` directly so the browser can load the bundled JSON files. Stop the server with `Ctrl+C`.

## Quick checks

```bash
node --check app.js
node --check community.js
python3 -m py_compile \
  capture_snapshot.py \
  verify_full_feed.py \
  verify_preview.py \
  verify_community_ansi_shadow.py
```

Browser regression scripts are also included: `verify_community_ansi_shadow.py` checks Community behavior, and `verify_full_feed.py` checks the captured feed and browsing controls. They require Chromium, Python Playwright, and Pillow; the full-feed suite also uses its comparison baseline from the maintainers' QA environment.

## License

No license file is present in this repository, so no license is declared here.
