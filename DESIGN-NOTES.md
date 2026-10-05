# Current product and interface design

SubZer0 keeps its dark steel and black-metal identity while making the vulnerability data the primary visual hierarchy. The current application is a static same-origin HTML/CSS/JavaScript experience; there is no backend, no Cloudflare dependency and no browser-side connection to upstream vulnerability APIs.

## Page architecture

The five primary destinations, in swipe and navigation order, are **Overview**, **Latest**, **Explore** (`page=center` in stable URLs), **Changes**, and **Community**. Archive is not a page or tab: a legacy `?page=archive` bookmark resolves to Explore while preserving valid date filters.

Overview uses the validated manifest and sidecars to show snapshot totals, recorded source checks and capture age, severity distribution, and only source-verified recent changes. Latest displays up to 50 actual records sorted by newest in-window source activity. Changes is a separately hash-verified, searchable 30-day comparison log with type/date filters, URL state and bounded 40-event pages. Events appear only after an actual complete-capture comparison; source dates are not converted into invented observations.

## Explore and search

Explore first validates the current manifest, a deterministic gzip-compressed schema-v3 column-packed search index and its independently hashed EPSS sidecar. Both compressed and expanded index sizes and SHA-256 digests are bounded and checked before JSON parsing; expanded rows stay below 12 MiB and the compressed transfer below 3 MiB. It does not parse every full record shard to show or filter results. Full details are loaded from the selected record's activity-day shard only after the user opens a dossier.

Index search covers the CVE ID, title, a short description summary, source labels, compact product/vendor/version hints, KEV membership and validated GHSA IDs. EPSS remains separate and is joined by CVE ID from its own verified sidecar. Search does not claim to cover every word in full descriptions, references or CPE/configuration trees before a dossier is opened. Native filters and query state are shareable through the URL. Pagination mounts only the selected 24/48/96 rows; virtualization or a third-party search library is not added without evidence that these measured bounds require it.

The single **sticky research toolbar** remains under the global header. Search has no scroll-driven shrink/release state and no synthetic “return to search” button. The `/` shortcut focuses the same search input; query and filter state remain visible/recoverable through browser history. Search/list rendering and initial verified-index rendering are instrumented with bounded Performance API measures; [PERFORMANCE.md](PERFORMANCE.md) records the local Chromium measurements.

## Evidence dossier and history

A dossier separates Summary, Why This Matters, Record, Signals, Affected products, References, Sources and History. CVSS score/severity/vector/version/scoring attribution, FIRST EPSS, CISA KEV and advisory evidence remain separate; supplied CPE/product/version data and source-cited related CVEs retain provenance. Missing values are explicitly missing. Source publication/modification dates and SubZer0's capture/observation dates are not substituted for one another. Full detail is taken from a size-bounded, manifest-hash-verified daily shard before it is rendered.

History events are computed between complete captures. True new publication, re-observation of older modified records, field-level record/CVSS changes, material EPSS changes and full-catalog CISA KEV differences have distinct event meanings. Overview previews are cross-checked against retained history by the offline validator. The rolling-feed omission of a CVE is never treated as deletion, and historical source time is never substituted for observation time.

## Visual system and motion

- **Signal colors:** Critical → restrained red, High → orange, Medium → gold, Low → icy blue. Unrated remains neutral, not a false score.
- **Hierarchy:** stable display headings and readable body copy lead; CVE IDs, score values, timestamps, provenance and source links are visibly distinct secondary facts.
- **Controls:** native inputs/selects/buttons, explicit focus rings, labels and live status regions. The filter/search rail retains its geometry rather than transitioning through scroll states.
- **Responsive layout:** safe-area-aware mobile navigation, compact filter stacking, wrapping long IDs/labels, and touch-sized controls. Detail and list cards do not require hover.
- **Motion:** bounded transition/decorative effects only; `prefers-reduced-motion` retains the same information and navigation without unnecessary motion.

Pointer swipe moves only between adjacent destinations. It follows the finger, has a non-wrapping edge, and excludes buttons, links, inputs, selection gestures and active detail interactions. Vertical scroll and pinch zoom remain native. Keyboard tab navigation and URL/browser history remain the source of truth for page state.

## Offline and integrity behavior

The online manifest is checked before a cached snapshot payload can be trusted. Service-worker CacheStorage may return a same-origin payload candidate, but the app still checks exact size, digest and schema before rendering. An explicit retry bypasses a stale cached candidate after a digest mismatch. Offline fallback states the age of the capture; an uncached full-detail shard yields a clear failure and no partial dossier.

SHA-256 in the manifest detects accidental byte mismatch, not a coordinated replacement of both content and manifest on the same origin. Feed-controlled text is assigned as text, HTTP(S) references reject credentials and active schemes, and external links use `noopener noreferrer`. GitHub Pages does not offer this repository a configurable `frame-ancestors` response header; see the [security and trust notes](SOURCE-NOTES.md).

## Verification boundaries

The full-feed Playwright suite exercises the checked-in records at desktop/mobile viewport sizes, including page navigation, legacy-route migration, keyboard/touch interactions, filters, query state, lazy shard loading, service-worker caching, offline behavior, digest/schema/size failures and captured performance metrics. This is headless browser/device emulation, not a formal screen-reader audit or a physical-device certification. The visual captures are reviewed separately from the automated assertions.
