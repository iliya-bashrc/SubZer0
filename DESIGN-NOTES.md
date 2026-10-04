# CVE center design and implementation notes

The established SubZer0 black-metal surface remains the base. The CVE center in this independent copy browses the validated rolling snapshot: the full snapshot and KEV totals, a manifest-driven EPSS freshness notice, severity-count tabs, live search, explicit affected-vendor and CISA KEV filters, optional activity-date filtering, user-sized pages, and bounded pagination. The first result page is already populated; this is not a long-term history archive.

`feed.css` is loaded after the inherited `styles.css` and `severity-effects.css`; its layout rules are scoped to the center/page record components. The captured shards are fetched only after the user opens CVE center, avoiding the full local parse cost on the Overview and Community. Their content and Community action flow are retained; global page navigation now updates the shareable route, and the Community wrapper nesting is balanced. The tab controls keep their existing roles and behavior; their wrapper now also hosts the compact Search return action, with only the necessary responsive header styling added to `styles.css`. The regression script continues to compare the preserved sections and styles to the approved preview.

## Record browsing

- Records are sorted by feed activity time, newest first, and shown with original date basis.
- Search covers CVE identifier, title, description, date basis, source labels, explicit affected vendor/product/version/CPE values, KEV vendor/product values, advisory identifiers/URLs, and reference labels/sources/URLs. A complete CVE ID is an exact match; shorter terms search substrings.
- The vendor filter matches only explicit `affected[].vendor` and `kev.vendor` values. It does not infer product ownership or backfill missing source relationships.
- Page, CVE, search, severity, KEV, vendor, activity-date, page-size and one-based page-index state is shareable in query parameters. Page changes create history entries; filter edits replace the current entry, and Back/Forward restores the saved route and filters.
- Severity counts are from the verified manifest. Neutral Unrated combines `None` and `Unknown` only for filtering; detail views show original CVSS state.
- Date filters default to the manifest window. The snapshot-wide count remains visible while result counts and ranges update.
- Pagination mounts only the chosen 24/48/96 page, reducing DOM size and animation work even though the full captured dataset is available to search locally.

## Motion and color

The black-metal palette maps **Critical → red, High → orange, Medium → gold, Low → icy blue, Unrated → neutral**. Each record has three restrained severity-colored flecks. Their `transform`/opacity drift is slow, remains clipped inside the card, does not change card dimensions, and is paused until the row crosses the viewport observer threshold. Off-screen flecks are paused; a visible-row check caught and corrected the `animation` shorthand's default play-state during QA. Reduced-motion preference disables the motion while retaining a subtle still fleck/bloom. These effects are decorative and do not imply attacks or live updates.

## Accessibility and mobile

- Search has an accessible name, `/` shortcut, a visible focus indication, and a header return action while the field is offscreen.
- Native search, date, severity, vendor, KEV, select and button controls remain usable by keyboard and touch. Tab navigation retains arrow/Home/End movement; `Escape` blurs Search without clearing its query, closes the Activity disclosure and returns focus to its summary, or closes CVE details; Back returns focus to the opening record.
- Detail state uses headings, definitions and lists; each score/catalog/advisory source is attributed separately.
- Empty results announce a result status and offer Clear filters. Date-form validation is inline and preserves an explicit From/To ordering.
- Main interaction targets are at least 44 CSS pixels on the Android-like viewports used for QA. Long descriptions and labels wrap rather than creating horizontal overflow.
- Motion is purely cosmetic; no control requires hover or animation to reveal information.

Tested in headless Chromium with Android-like mobile emulation, not a physical handset. The full-feed suite checks widths 320, 360, 375, 390, 414, 768, 1024, 1280 and 1440 CSS pixels. See [`verify_full_feed.py`](verify_full_feed.py) and [`README.md`](README.md) for the exercised cases.

## 2026-10-04 full-update review boundaries

- In the checked-in 2026-10-04 snapshot, **10,783 of 14,903 records have no structured `affected` products**. CPE and product filtering therefore use supplied fields only and cannot be complete for this archive.
- The updater defines `material_change_events()` and `build_change_history()`, but the active `write_snapshot()` path never calls them. No history or facets sidecar is published, and `verify_data_snapshot.py` rejects `history` and `facets` manifest keys. There is no working snapshot-diff or “What Changed?” view.
- Adding a validated, lazy-loaded historical archive needs a new data contract, real retained snapshots, integrity rules, size budgets, eviction/retention behavior and UI tests. It is deferred rather than represented with invented events or metrics. Any future diff must distinguish a rolling-window expiry from a true source removal.
