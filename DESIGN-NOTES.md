# CVE center design and implementation notes

The established SubZer0 black-metal surface remains the base. The CVE center in this independent copy adds a compact first-arrival archive: the full snapshot and KEV totals, a manifest-driven stale-EPSS notice, severity-count tabs, an optional search field, optional activity-date filtering, a user-sized page, and bounded pagination. The first result page is already populated.

`feed.css` is loaded after the inherited `styles.css` and `severity-effects.css`; its layout rules are scoped to the center/page record components. The captured shards are fetched only after the user opens CVE center, avoiding the full local parse cost on the unchanged Overview and Community. The old shared stylesheets, Overview section, page navigation and Community markup were not changed. The regression script compares the preserved sections and styles to the approved preview.

## Record browsing

- Records are sorted by feed activity time, newest first, and shown with original date basis.
- Search covers CVE identifier, title, description, date basis, source labels and affected-product fields. A complete CVE ID is an exact match; shorter terms search substrings.
- Severity counts are from the verified manifest. Neutral Unrated combines `None` and `Unknown` only for filtering; detail views show original CVSS state.
- Date filters default to the manifest window. The snapshot-wide count remains visible while result counts and ranges update.
- Pagination mounts only the chosen 24/48/96 page, reducing DOM size and animation work even though the full captured dataset is available to search locally.

## Motion and color

The black-metal palette maps **Critical → red, High → orange, Medium → gold, Low → icy blue, Unrated → neutral**. Each record has three restrained severity-colored flecks. Their `transform`/opacity drift is slow, remains clipped inside the card, does not change card dimensions, and is paused until the row crosses the viewport observer threshold. Off-screen flecks are paused; a visible-row check caught and corrected the `animation` shorthand's default play-state during QA. Reduced-motion preference disables the motion while retaining a subtle still fleck/bloom. These effects are decorative and do not imply attacks or live updates.

## Accessibility and mobile

- Search has an accessible name, `/` shortcut and a visible focus indication.
- Native search, date, severity, select and button controls remain usable by keyboard and touch. Tab navigation retains arrow/Home/End movement; `Escape` closes details, and Back returns focus to the opening record.
- Detail state uses headings, definitions and lists; each score/catalog/advisory source is attributed separately.
- Empty results announce a result status and offer Clear filters. Date-form validation is inline and preserves an explicit From/To ordering.
- Main interaction targets are at least 44 CSS pixels on the Android-like viewports used for QA. Long descriptions and labels wrap rather than creating horizontal overflow.
- Motion is purely cosmetic; no control requires hover or animation to reveal information.

Tested in headless Chromium with Android-like mobile emulation, not a physical handset. See [`verify_full_feed.py`](verify_full_feed.py) and [`README.md`](README.md) for exact checked widths and cases.
