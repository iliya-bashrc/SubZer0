<div align="center">

<a href="https://iliya-bashrc.github.io/SubZer0/">
  <img src="docs/assets/hero.svg" alt="SubZer0 — Noise in. Priority out." width="100%">
</a>

<br>

[![Live](https://img.shields.io/badge/%E2%97%8F-live-7dd3fc?style=for-the-badge&labelColor=0b0f14)](https://iliya-bashrc.github.io/SubZer0/)
[![Checks](https://img.shields.io/github/actions/workflow/status/iliya-bashrc/SubZer0/checks.yml?branch=main&label=checks&style=for-the-badge&labelColor=0b0f14)](https://github.com/iliya-bashrc/SubZer0/actions/workflows/checks.yml)
[![Refresh](https://img.shields.io/badge/refresh-every%206h-f59e0b?style=for-the-badge&labelColor=0b0f14)](https://github.com/iliya-bashrc/SubZer0/actions/workflows/update-snapshot.yml)
[![Integrity](https://img.shields.io/badge/sha--256-verified-22c55e?style=for-the-badge&labelColor=0b0f14)](#-trust-nothing-verify-every-byte)
[![License](https://img.shields.io/badge/license-proprietary-ef4444?style=for-the-badge&labelColor=0b0f14)](LICENSE)

**[Open the radar](https://iliya-bashrc.github.io/SubZer0/)** ·
**[Tour](#-the-tour)** ·
**[Priority rules](#-priority-you-can-explain)** ·
**[Query language](#-query-language)** ·
**[Pipeline](#-the-machine)** ·
**[Telegram](#-community)**

</div>

<br>

> [!NOTE]
> **~17,000 CVEs land every 30 days. Most of them don't matter to you today. A few of them really, really do.**
> SubZer0 pulls every new CVE, cross-checks it against five core feeds and a stack of exploit intel, and hands you a short, explainable list of what to patch first — as a static site that verifies every byte before it shows you a single row.

<table>
<tr>
<td width="25%" align="center"><b>❄️ Serverless</b><br><sub>GitHub Pages + Actions.<br>No servers, no database.</sub></td>
<td width="25%" align="center"><b>🎯 Explainable</b><br><sub>Every priority comes from<br>rules you can read.</sub></td>
<td width="25%" align="center"><b>🔐 Fail-closed</b><br><sub>SHA-256 on every file,<br>checked in your browser.</sub></td>
<td width="25%" align="center"><b>🕶️ Private</b><br><sub>Your stack & watchlist<br>never leave your device.</sub></td>
</tr>
</table>

---

## 🎬 The tour

<div align="center">
<a href="https://iliya-bashrc.github.io/SubZer0/"><img src="docs/assets/screen-briefing.svg" alt="Briefing — the last 30 days, patch queue and live feed" width="100%"></a>
<sub><b>01 · BRIEFING</b> — what got published, what's already being exploited, and a patch queue sorted by real-world risk.</sub>
</div>

<br>

<table>
<tr>
<td width="50%" valign="top">
<img src="docs/assets/screen-research.svg" alt="Research — Weaponized view" width="100%">
<p><b>02 · RESEARCH</b><br><sub>Dig through the whole window with a tiny query language. One click for <i>Patch now</i>, <i>Trending</i>, <i>Weaponized</i> or <i>No patch yet</i>. Export what you see as CSV / JSON or share the exact view as a link.</sub></p>
</td>
<td width="50%" valign="top">
<img src="docs/assets/screen-dossier.svg" alt="Dossier for a single CVE" width="100%">
<p><b>03 · DOSSIER</b><br><sub>One page per CVE: CVSS vector, CWE, EPSS and its trend (live from FIRST), KEV due date, exploit maturity, PoCs, modules, templates, chatter and references. Every CVE has its own URL — <code>/SubZer0/cve/CVE-…</code></sub></p>
</td>
</tr>
<tr>
<td width="50%" valign="top">
<img src="docs/assets/screen-terminal.svg" alt="Terminal" width="100%">
<p><b>04 · TERMINAL</b><br><sub>A real-feeling shell with tab completion and history: <code>cve</code>, <code>search</code>, <code>trending</code>, <code>weaponized</code>, <code>watch</code>, <code>stack add</code>, <code>export</code>, <code>about</code> … and a couple of easter eggs: <code>bugcod3</code>, <code>rootaccessclub</code>.</sub></p>
</td>
<td width="50%" valign="top" align="center">
<img src="docs/assets/screen-mobile.svg" alt="Mobile" width="62%">
<p align="left"><b>📱 IN YOUR POCKET</b><br><sub>Swipe between tabs, drag with the mouse, scroll sideways on a trackpad, or hit <kbd>←</kbd> <kbd>→</kbd> / <kbd>1</kbd>–<kbd>4</kbd>. Works offline with the last verified snapshot.</sub></p>
</td>
</tr>
</table>

---

## 🎯 Priority you can explain

No black-box scores. Four tiers, plain rules — the **same rules** drive the site, the RSS feed and the Telegram alerts.

| Tier | Meaning | A CVE lands here if… |
|:---:|---|---|
| 🟥 **P1** | **Patch now** | on **CISA KEV** · SSVC exploitation = **active** · **weaponized** with CVSS ≥ 7 or EPSS ≥ 10% · public **PoC** with EPSS ≥ 10% |
| 🟧 **P2** | **This week** | CVSS ≥ 9 · CVSS ≥ 7 with a PoC or EPSS ≥ 5% · anything weaponized · automatable **and** total technical impact |
| 🟨 **P3** | **Plan it** | CVSS ≥ 7 |
| ⬜ **P4** | **Track it** | everything else |

### Exploit maturity ladder

```text
   0 ── none ─────────►  1 ── public PoC ─────────►  2 ── weaponized ─────────►  3 ── in the wild
        nothing public        code on GitHub /            Metasploit module or        CISA KEV or
                              Exploit-DB                  Nuclei template             SSVC "active"
```

PoC repos get a sanity check too — forks, bait repos and brand-new accounts are flagged instead of trusted.

---

## ⌨️ Query language

```text
kev:yes poc:yes msf:yes nuclei:yes gh:yes      # has it?
maturity>=2  epss>50  cvss>=9  buzz>20         # numbers
sev:critical  ssvc:active  auto:yes  patch:no  # flags
vendor:fortinet  after:2026-10-01  is:watched  # scope
-wordpress  "remote code execution"            # exclude · exact phrase
```

<details>
<summary><b>Keyboard shortcuts</b></summary>

| Key | Action |
|---|---|
| <kbd>/</kbd> or <kbd>Ctrl</kbd> <kbd>K</kbd> | search |
| <kbd>1</kbd> – <kbd>4</kbd> | Briefing · Research · Dossier · Terminal |
| <kbd>←</kbd> <kbd>→</kbd> | previous / next tab |
| <kbd>?</kbd> | every shortcut |

Decode / typing effects run once per visit and switch off with *reduce motion*.
</details>

---

## 🛰️ Where the signal comes from

| Layer | Source | What it tells you |
|---|---|---|
| Core | **NVD CVE API 2.0** | the CVE itself, CVSS, CWE, affected products |
| Core | **GitHub Advisory Database** | package & ecosystem advisories |
| Core | **CISA KEV** | exploited in the wild — with a due date |
| Core | **FIRST EPSS** | probability of exploitation in the next 30 days |
| Core | **Exploit-DB** | public exploit code |
| Intel | **PoC-in-GitHub** | PoC repos, with fork / bait / fresh-account warnings |
| Intel | **Metasploit · Nuclei** | weaponized: ready-to-fire modules & templates |
| Intel | **CISA Vulnrichment** | SSVC decisions, plus CISA's CVSS when NVD hasn't scored yet |
| Intel | **Bluesky · Mastodon · Reddit · Hacker News** | chatter score — what people are talking about |
| Intel | **References** | whether a fix / patch is linked |

---

## 🔐 Trust nothing. Verify every byte.

Every data file ships with a SHA-256 hash in the manifest. Your browser recomputes each one and renders **only if all of them match** — otherwise it fails closed with a loud integrity error instead of showing data it can't prove.

```mermaid
flowchart LR
    M[manifest.json<br/>no-cache] --> H{{SHA-256<br/>in the browser}}
    A[search_index.json] --> H
    B[data/YYYY-MM-DD.json] --> H
    C[epss.json · intel.json] --> H
    H -- every byte matches --> R([render])
    H -- anything off --> F([FAIL CLOSED])
    style R fill:#0f2a1c,stroke:#22c55e,color:#d1fae5
    style F fill:#2a0f12,stroke:#ef4444,color:#fee2e2
    style H fill:#0b1a24,stroke:#7dd3fc,color:#e0f2fe
```

A cache-busting retry absorbs CDN skew between deploys.

## ⚙️ The machine

```mermaid
flowchart LR
    T((every 6h)) --> F[fetch 5 core feeds]
    F --> V[validate · normalize · merge]
    V --> I[exploit intel + chatter]
    I --> S[stage]
    S --> RV[revalidate]
    RV --> P[atomic publish]
    P --> D[deploy to Pages]
    D --> L([live site · feed.xml · api/latest.json])
    D --> TG([Telegram alert])
    style T fill:#1f1405,stroke:#f59e0b,color:#fef3c7
    style L fill:#0b1a24,stroke:#7dd3fc,color:#e0f2fe
    style TG fill:#0b1a24,stroke:#7dd3fc,color:#e0f2fe
```

- **Fail-closed ingestion** — if a core feed is down, the last good snapshot stays live. A failed intel source keeps its last good data.
- **Atomic publish** — a broken run can never leave the live site half-updated.
- **Feeds** — RSS of *patch now* CVEs at [`/feed.xml`](https://iliya-bashrc.github.io/SubZer0/feed.xml) and a small JSON summary at [`/api/latest.json`](https://iliya-bashrc.github.io/SubZer0/api/latest.json).
- **Telegram alerts** — CVEs that just became *patch now* get posted after each refresh (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` secrets; without them the step is a no-op).
- **Telegram bot** — [@SubZer0Robot](https://t.me/SubZer0Robot) runs on a Cloudflare Worker (`worker/bot.js`): `/cve <id>`, `/top`, and `/watch <product>` for a DM when that product gets a *patch now* CVE. It reads the same published files (`api/cve/<id>.json`, `api/latest.json`), so it never disagrees with the site.
- **Bot in groups** — add [@SubZer0Robot](https://t.me/SubZer0Robot?startgroup=brief) to a team group: admins send `/daily on` for a ☀️ morning brief (the daily channel post, forwarded ~10:00 Tehran, skipped on quiet days) and `/watch <product>` for a shared group watchlist. Everyone can use `/top`, `/check`, `/cve`.
- **Offline** — a service worker keeps the app shell and the last verified snapshot.
- **Privacy** — no cookies, no accounts. Anonymous page counts via GoatCounter (page path only, never search terms).

### Stack

Plain **HTML / CSS / JS** — no framework, no build step, no npm, self-hosted fonts · strict **Content-Security-Policy** (outside calls: FIRST's EPSS API and an anonymous GoatCounter pixel) · **Python 3** stdlib pipeline with hash-pinned CI deps · **GitHub Actions** as the backend, **GitHub Pages** as the host.

---

## 🚀 Run it locally

```bash
git clone https://github.com/iliya-bashrc/SubZer0.git && cd SubZer0
python scripts/build_site.py --out _site/SubZer0     # app + snapshot + feeds
python -m http.server -d _site 8000                  # → http://localhost:8000/SubZer0/
```

<details>
<summary><b>Rebuild the data yourself (~10 min)</b></summary>

```bash
python scripts/update_data.py --output-dir snapshot          # 5-feed refresh
python scripts/enrich_intel.py --snapshot snapshot           # exploit intel (~3 min)
python scripts/verify_data_snapshot.py --root snapshot       # integrity check
python -m unittest discover -s tests                         # tests
```
</details>

<details>
<summary><b>Repository map</b></summary>

```text
├── site/                     the app — index.html, app.js, app.css, sw.js, fonts/
├── public/snapshot/          generated, hash-verified data (don't edit by hand)
├── scripts/
│   ├── update_data.py        5-source ingestion + validation
│   ├── enrich_intel.py       exploit intel + chatter → data/intel.json
│   ├── verify_data_snapshot.py   offline integrity validator
│   ├── build_site.py         assembles _site/, writes feed.xml, api/latest.json, api/cve/<id>.json
│   ├── seo_pages.py          one crawlable page per CVE + sitemap.xml
│   ├── early_warning.py      live layer (live/early.json) between snapshots
│   ├── notify_telegram.py    posts newly urgent CVEs, DMs bot watchlists
│   ├── digest.py             daily digest post + banner (digest_cards.py)
│   ├── deploy_bot.py         uploads worker/bot.js to Cloudflare + sets the webhook
│   └── verify_pages.py       checks the live site serves the exact files
├── worker/bot.js             @SubZer0Robot (Cloudflare Worker)
├── tests/                    pipeline, integrity, intel, bot & workflow-security tests
└── .github/workflows/        checks · update-snapshot · deploy · digest · bot · telegram-test
```
</details>

---

## 📡 Community

<div align="center">

<a href="https://t.me/RootAccessClub"><img src="docs/assets/channel-rootaccessclub.svg" alt="Join @RootAccessClub on Telegram" width="60%"></a>

<sub>Made and maintained by <b>@RootAccessClub</b>. New CVE drops, write-ups and the occasional rant.</sub>

</div>

### 🙏 Special thanks

<div align="center">

<a href="https://t.me/BugCod3"><img src="docs/assets/channel-bugcod3.svg" alt="@BugCod3 on Telegram" width="48%"></a>

<sub>Big thanks to my friend <b>@BugCod3</b> for the help, ideas and testing along the way. Go check out his channel.</sub>

</div>

---

## 🤝 Contributing

Issues and PRs are welcome. CI runs the full pipeline test-suite plus snapshot validation on every PR — keep it green. Files under `public/snapshot/` are generated; please don't edit them by hand.

## ⚡ Early warning: the live layer

Big bugs (php2shell, Log4Shell, React2Shell, …) hit the news and CERT advisories hours or days before NVD publishes a record. The 6-hour snapshot can't see those, so a **fast lane runs every ~15 minutes** (`scripts/early_warning.py`, part of the deploy, no commits):

- **New CVE records** from CVE.org (cvelistV5 delta log) and GitHub advisories that are newer than the snapshot, shown with a `LIVE` tag
- **CISA KEV additions** since the snapshot, applied straight to the patch queue
- **Early warnings**: CERT (CISA, CERT-EU, NCSC-NL, SANS ISC) and security-news feeds, grouped by CVE ID or bug name. An item shows up once **2+ independent sources** (a CERT counts double) report RCE / exploitation / zero-day / no-patch signals. If the CVE isn't published yet, the card says so
- Telegram gets new **P0** early warnings and KEV additions right away
- A **watchdog** restarts the full snapshot refresh if it's overdue (GitHub often delays cron by hours) or if it failed

The live layer is never mixed into the SHA-256 snapshot. It's signed with the same Ed25519 key, and every row from it is labelled.

> Tip: add a free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) as the repo secret `NVD_API_KEY`. The full refresh then gets 10× the NVD rate limit and fails far less often.

## 🛡️ Official site & copying

The only official build is **https://iliya-bashrc.github.io/SubZer0/**. Every published snapshot manifest is signed with an Ed25519 key held only by the maintainers (`snapshot/manifest.sig`); the official site shows **ed25519 signed ✓** in the Briefing header and in the terminal boot log. Copies on any other host are flagged as **unofficial** in the page itself.

This repository is **source-available, not open source**: reading the code is fine, but copying, re-hosting, forking for redistribution or re-branding it requires written permission — see [LICENSE](LICENSE).

## ⚠️ Disclaimer

SubZer0 is built for **education and defensive research**. Don't use any information, exploit reference or technique found here against systems you don't own or don't have explicit permission to test.

<div align="center">
<br>
<sub>© 2026 @RootAccessClub — All Rights Reserved · <a href="LICENSE">Proprietary License</a></sub>
</div>
