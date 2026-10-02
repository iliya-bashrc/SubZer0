# Data provenance and trust boundaries

## Source and capture

The snapshot was captured from the current public SubZer0 rolling 30-day feed:

- Manifest: [https://iliya-bashrc.github.io/SubZer0/api/v1/manifest.json](https://iliya-bashrc.github.io/SubZer0/api/v1/manifest.json)
- Shard base: [https://iliya-bashrc.github.io/SubZer0/](https://iliya-bashrc.github.io/SubZer0/)
- Published manifest `generated_at`: **2026-10-02T06:00:04Z**.
- UTC window: **2026-09-02T06:00:04Z through 2026-10-02T06:00:04Z**. The feed window combines NVD CVE publication timestamps, GitHub advisory publication timestamps and CISA KEV date-added entries.
- **15,318 CVE records** across **31 manifest-listed UTC daily shards**, totaling 45 CISA KEV listings.

The snapshot contains the original published JSON bytes in `snapshot/manifest.json` and `snapshot/data/`. `snapshot/VALIDATION.json` is the generated audit record, with every shard's declared row count and SHA-256, the manifest SHA-256, and the EPSS file SHA-256. The capture script checked every listed shard's bytes/hash and row count; each day's severity and KEV counts; cross-shard ID uniqueness; global severity/KEV totals; and EPSS score count. A second local check independently recomputed every bundled day-shard byte hash and count: **31/31 matched**.

Manifest SHA-256: `2caaaa7674afe79af8fe094185b7346c2d5f7c9cdf5c0e266bcfef254449b834`.

## Manifest totals

| Source CVSS category | Count | Center treatment |
|---|---:|---|
| Critical | 1,507 | Critical, red |
| High | 6,361 | High, orange |
| Medium | 4,955 | Medium, gold |
| Low | 949 | Low, icy blue |
| None | 1,527 | Neutral Unrated; source category retained |
| Unknown | 19 | Neutral Unrated; source category retained |
| CISA KEV listings | 45 | Shown as separate catalog evidence |

Unrated is a browsing group only. It does not rewrite the record's `None` or `Unknown` source state. A present numeric CVSS value such as `0.0` is displayed as such, but is not used as a substitute for a missing score.

## EPSS status

The manifest's EPSS section lists 14,760 scores for 15,318 records. The captured FIRST EPSS date is **2026-09-29**, its source timestamp is **2026-09-29T12:00:22Z**, and `source_status` marks FIRST EPSS `ok: false` with the note that the score set is older than 36 hours or has an invalid timestamp. The stale state is shown separately in the CVE center and record detail. **No score entry means unscored, not 0%**; present values (including a genuine score of zero if one existed) are validated before display.

The source signal layers are intentionally distinct:

- CVSS is a severity score and source category from the CVE feed record.
- EPSS is a FIRST probability estimate and percentile, with score-set date/staleness shown.
- CISA KEV is catalog membership with its date, product, due date and supplied catalog fields.
- GitHub advisories attached to a record and user-initiated repository search links are leads; a repository result is not proof of a working PoC or exploitation.

Record descriptions, titles, product fields, labels, reference labels/URLs and catalog text are treated as untrusted input. Data strings are inserted with text nodes (`textContent`), never interpreted as markup. Only parsed HTTPS URLs without credentials are linked, in new tabs with `noopener noreferrer`; unsafe schemes are omitted. The page uses only its bundled files for automatic data requests. A source hyperlink leaves the local preview only after the person activates it.
