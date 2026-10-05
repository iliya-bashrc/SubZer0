# Snapshot and history data contract

This document describes the static files consumed by the browser and written by `scripts/update_data.py`. The checked-in capture and its SHA-256 values in [`snapshot/manifest.json`](snapshot/manifest.json) are authoritative for that capture; this document does not imply a live source check.

## Capture window and timestamps

The manifest describes one **complete, rolling 30-day UTC activity capture**. A record keeps the source's original publication timestamp and source modification/update timestamps. Its `activity_at`, `date_basis` and `window_date` identify the newest eligible source activity in the capture window. NVD last-modified time, GitHub advisory update time and CISA's supplied KEV `dateAdded` are distinct inputs; a CVE's original `published` value is never rewritten to make a recently modified record appear new.

The product displays three different times without substituting one for another:

1. **Source time** — when the source says a record was published, modified, updated, scored or added to KEV.
2. **Observation time** — when the updater ran a complete capture and compared it to the preceding capture.
3. **Capture time** — `manifest.generated_at`, the time of the validated static snapshot that is currently served.

The source-check statuses in the manifest are a captured run record, not telemetry or a live health probe.

## Manifest and sidecars

`manifest.json` uses schema version 2. It declares a bounded path, size, SHA-256, schema and record count for each sidecar and UTC day shard. The browser and the offline verifier reject unlisted paths, unexpected files, invalid counts, unsafe paths, invalid timestamps, hash mismatches and schema inconsistencies before data is displayed.

| File | Purpose | Current contract / upper bound |
|---|---|---|
| `data/overview.json` | At most 50 real feed records, ordered by source activity; backs Overview and Latest | Schema v2; 64 KiB |
| `data/search-index.json` | One structured index row for each full CVE record; backs Explore filtering and search | Schema v2; 16 MiB |
| `data/epss.json` | FIRST score and percentile values, source dates and capture status | Schema v1; 4 MiB |
| `data/history.json` | Bounded complete-capture change events and comparison metadata | Schema v1; 8 MiB |
| `data/YYYY-MM-DD.json` | Complete full-detail records whose activity date is that UTC day | At most 31 shards, 16 MiB each |
| All snapshot JSON | Bounded browser/offline data set | 128 MiB total |

The application also bounds the manifest (512 KiB), record count (50,000), fetch duration (12 seconds), and simultaneous detail-shard fetches (six). The producer stages a full candidate snapshot, validates it offline, and swaps it into place atomically; an incomplete or invalid core-source response does not publish a partial feed.

## Compact search index

Each `search-index.json` row carries a CVE ID, title and at most 320 characters of normalized description summary; CVSS value/severity; EPSS score/percentile; compact KEV evidence; original published/modified timestamps; activity date/basis; source labels; a detail-shard path; up to eight supplied vendor/product labels with version hints limited to 160 characters on the first three; and up to eight validated GitHub advisory IDs.

The index deliberately omits full descriptions, reference lists, CVE configurations/CPE trees and detailed per-source evidence. Those values remain in the corresponding full-record day shard and appear only after that shard's size, SHA-256 and schema are checked. Search is therefore intentionally limited to fields actually available in the compact index; an absent search hit in a long reference or a portion of the full description is not proof that it is absent from the dossier.

The Python validator ties every compact row back to its full-detail record, verifies every summary/provenance value and derived label, and ensures each detail path points at the correct activity shard. The browser repeats the manifest-bound digest and schema checks before rendering.

## Change-history sidecar

`history.json` records observations made when **two complete captures** can be compared. Schema v1 contains:

- `baseline`: the prior complete capture metadata when known; a legacy capture is not assigned a made-up observation time;
- `snapshots`: complete-capture observations, retained for up to 30 days and capped at 800 entries;
- `events`: material differences, retained for 30 days and capped at 10,000 entries;
- `kev_catalog`: a bounded complete CISA KEV comparison state when available, capped at 5,000 records / 4 MiB.

Each event identifies the affected CVE, change type, `observed_at`, `source_time` (a source timestamp, an exact source date, or `null` when the source supplies none), source attribution, and before/after values. The UI exposes event type, observation date and source time independently. Current generated event types include new CVEs, re-observed CVEs, CVSS/title/description/product/version changes, advisory/reference and source-metadata differences, material EPSS differences, CISA KEV additions/changes/removals, and a grouped `CVE_UPDATED` marker.

A new-CVE event requires a source publication timestamp later than the prior complete capture. If a record re-enters the rolling feed with recent source modification but its original publication predates the prior capture and its former details are outside the retained feed, the updater uses `CVE_REOBSERVED` and says that the prior field-level detail cannot be reconstructed. It does not label such a record newly published.

EPSS set membership changes are represented with the score-set's source timestamp when available. To keep the event log useful, score-to-score changes are emitted for an absolute change of at least 0.01 or a twofold move when the larger score is at least 0.05; the complete current EPSS sidecar still contains the raw score set. A score that appears or disappears is also recorded.

The full KEV catalog, not just CVEs that happen to overlap the rolling feed, is compared to detect older-entry modifications and removals. CISA supplies catalog entry dates but no corresponding modification timestamp here, so those changes carry `source_time: null` and retain the actual SubZer0 observation time. **Omission from the rolling CVE feed is never treated as a CVE deletion.**

An initial migrated/legacy capture without comparable retained history is an explicit baseline. It may truthfully show zero observed events; no synthetic “last 30 days” of changes is inferred from source timestamps. Browser tests use explicitly isolated synthetic fixtures to exercise event filters and rendering without writing test events into the production snapshot.

## Offline integrity and trust

The service worker keeps same-origin assets and bounded data. It checks the fresh manifest online before the app accepts a cached index, EPSS sidecar, history file or detail shard; a cache-first payload is only a **candidate** until the application verifies its manifest-declared digest, byte length and schema. An explicit cache reload bypasses that candidate after a hash mismatch. Offline fallback reports the age of the verified capture and refuses an uncached detail rather than rendering a partial dossier.

SHA-256 provides consistency between a resource and the manifest served from the same origin. It is not a digital signature and cannot prove that both values were not replaced together by an attacker controlling that origin. The app renders data strings as text and accepts safe HTTP(S) reference links; a user-activated outbound link is not presented as validated exploit evidence.

## Local validation

```bash
python3 scripts/verify_data_snapshot.py
python3 -m unittest discover -s tests -v
python3 verify_full_feed.py
```

The unit suite uses deterministic mocked sources. The browser suite reads the checked-in capture and test-only intercepted responses; it does not refresh from upstream APIs.
