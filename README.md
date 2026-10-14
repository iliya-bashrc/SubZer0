<div align="center">

<img src="docs/assets/subzero-readme-banner.svg" alt="SubZer0 — CVE intelligence and vulnerability research" width="600"/>

# ❄️ SubZer0 — CVE Intelligence Platform

**Zero-noise vulnerability radar. Newest CVEs, real exploit signals, verified byte-for-byte.**

<a href="https://iliya-bashrc.github.io/SubZer0/"><img src="docs/assets/telegram-mark.svg" alt="SubZer0 mark" width="72"/></a>

[![Live site](https://img.shields.io/badge/live-iliya--bashrc.github.io%2FSubZer0-0aa1e8?style=flat-square)](https://iliya-bashrc.github.io/SubZer0/)
[![CI](https://img.shields.io/github/actions/workflow/status/iliya-bashrc/SubZer0/checks.yml?branch=main&label=CI&style=flat-square)](https://github.com/iliya-bashrc/SubZer0/actions)
[![Data refresh](https://img.shields.io/badge/data-refresh%20every%206h-7b61ff?style=flat-square)](https://github.com/iliya-bashrc/SubZer0/actions/workflows/update-snapshot.yml)
![License](https://img.shields.io/badge/use-educational%20only-dd3322?style=flat-square)

</div>

## About

SubZer0 is a **fully static, serverless CVE radar** built for the
[@RootAccessClub](https://t.me/RootAccessClub) community. It tracks the newest
publications across five authoritative feeds, enriches every record with
exploit-intelligence signals, and guarantees every byte it shows you is the
byte the pipeline verified — SHA-256 checked in your browser before render.

- **No servers, no database, no tracking** — the entire product is a static
  export on GitHub Pages; GitHub Actions is the only "backend"
- **Fail-closed by design** — a single tampered or mismatched byte aborts the
  page instead of showing unverified data
- **Maintainers:** [@BugCod3](https://t.me/BugCod3) (security research) and
  [@RootAccessClub](https://t.me/RootAccessClub) (community & education)

<div align="center">

<a href="https://t.me/BugCod3"><img src="docs/assets/telegram-bugcod3.svg" alt="BugCod3 on Telegram" width="120"/></a>
<a href="https://t.me/RootAccessClub"><img src="docs/assets/telegram-rootaccessclub.svg" alt="RootAccessClub on Telegram" width="120"/></a>

</div>

---

## What is this?

SubZer0 cuts through CVE noise. Instead of dumping 250,000 advisories at you,
it serves a rolling **30-day window** (~16,000 records) enriched with the
signals that actually matter:

| Signal | Source | Why it matters |
|---|---|---|
| CVSS severity | **NVD CVE API 2.0** | Standard impact scoring |
| Package & ecosystem advisories | **GitHub Advisory Database** | Fastest path for app dependencies |
| KEV flag | **CISA Known Exploited Vulnerabilities** | Exploited in the wild — patch now |
| EPSS probability | **FIRST** | Likelihood of exploitation in 30 days |
| Public PoC / exploit | **Exploit-DB** | Proof-of-concept code exists |

Filter by any combination — e.g. *KEV + PoC + EPSS > 0.5* — and get the handful
of CVEs that genuinely deserve your attention today.

## ⚡ Features

- **🔎 Instant search** — debounced full-text over IDs, titles, vendors and products (`Ctrl/⌘+K` from anywhere)
- **🎚️ Precision filters** — severity, CISA KEV, EPSS threshold, public-PoC, publication date range + presets
- **🗂️ Dossier per CVE** — description, CVSS breakdown, EPSS percentile, exploit intel, affected products, references, related CVEs. Deep-linkable: `/cve/CVE-2026-XXXX-YYYY/`
- **📟 Terminal tab** — a SubZer0 shell with `./info`, `./help`, `./clear` and channel shortcuts
- **📱 Mobile-first** — bottom tab bar, swipeable destinations, virtualized card list (16k+ rows, ~35 DOM nodes)
- **📶 Offline-capable** — service worker caches the shell and snapshot; the last verified data survives a dead connection
- **🎨 Dark terminal aesthetic** — OKLCH color system, severity-calibrated palette, reduced-motion aware

## 🔐 Integrity model (the core idea)

Every data file ships with a **SHA-256 hash published in the manifest**. The
client:

1. Fetches the manifest (no-cache)
2. Fetches each artifact and computes the hash **in the browser**
3. Renders **only if every byte matches** — otherwise it fails closed with an
   explicit integrity error instead of ever showing unverified data

```
manifest.json ──► sha256 ──► search_index.json  ─┐
             ──► sha256 ──► data/YYYY-MM-DD.json ─┼──► all match? render : FAIL CLOSED
             ──► sha256 ──► epss.json             │
             ──► sha256 ──► poc_ids.json          ─┘
```

A cache-buster retry absorbs CDN/browser cache skew between deploys.

## 🔄 Fully autonomous pipeline

```
every 6h ──► fetch NVD + GHSA + CISA KEV + EPSS + Exploit-DB
         ──► validate, normalize, merge (fail-closed: any core feed down = keep last good)
         ──► stage → revalidate → atomic publish
         ──► commit ──► auto-deploy ──► live site
```

No servers, no databases, no secrets — the whole product is a **static export
on GitHub Pages** with GitHub Actions as the backend. Snapshot changes publish
atomically; a failed run never corrupts the live site.

## 🧱 Stack

- **Next.js 15** (App Router, static export) · **React 19**
- **Tailwind CSS v4** · **Swiper 11** · **TanStack Virtual** · **Framer Motion**
- Python 3 pipeline (stdlib-only networking, hash-pinned CI dependencies)

## 🚀 Run locally

```bash
git clone https://github.com/iliya-bashrc/SubZer0.git
cd SubZer0
npm install
npm run dev        # http://localhost:3000
npm run build      # static export → ./out (basePath /SubZer0)
```

Regenerate the data snapshot (optional, ~10 min):

```bash
python scripts/update_data.py --output-dir snapshot          # full refresh
python scripts/verify_data_snapshot.py --root snapshot       # validate
python -m unittest discover -s tests                         # 39 tests
```

## 📁 Repository map

```
├── app/                    # routes (/, /cve/[id], 404)
├── components/
│   ├── shell/              # AppShell, footer, service-worker registrar
│   ├── tabs/               # Briefing · Research · Dossier · Terminal
│   ├── research/           # SearchBar, FilterRail, ResultsTable, DossierPanel
│   ├── briefing/           # hero strip, activity chart, stats
│   ├── dossier/            # shared dossier content + related CVEs
│   └── terminal/           # terminal emulator
├── lib/                    # snapshot loader (SHA-256 verify), search, hotkeys
├── scripts/
│   ├── update_data.py          # 5-source ingestion + validation pipeline
│   ├── verify_data_snapshot.py # offline integrity validator
│   └── migrate_legacy_snapshot.py
├── public/snapshot/        # published data (manifest + shards + index artifacts)
├── tests/                  # 39 pipeline/integrity/workflow-security tests
└── .github/workflows/      # checks.yml · update-snapshot.yml · deploy.yml
```

## 🤝 Contributing

Issues and PRs are welcome. CI runs the full pipeline test-suite plus snapshot
validation on every PR — keep it green. Data files under `public/snapshot/` are
generated; don't edit them by hand.

## ⚠️ Disclaimer

SubZer0 is built for **education and defensive research**. Do not use any
information, exploit reference or technique found here against systems you do
not own or have explicit permission to test.

---

<div align="center">

© 2026 SubZer0 — by @BugCod3 & @RootAccessClub. All rights reserved.
📺 Telegram: [@RootAccessClub](https://t.me/RootAccessClub) · 💬 [@BugCod3](https://t.me/BugCod3)

</div>
