# SubZer0 — CVE Intelligence Platform

Next.js 15 (App Router) + React 19 + Tailwind v4 + Swiper.js v11.

## Sections implemented
- **Section 5** — AppShell (`components/shell/AppShell.tsx`), canonical Swiper config.
- **Section 6** — Terminal (`components/terminal/Terminal.tsx`), canonical implementation.
- **Section 8 (GO deliverable)** — Research tab: SearchBar (300ms debounce, ⌘K),
  FilterRail (severity/KEV/EPSS/PoC/date), virtualized ResultsTable (TanStack Virtual,
  15k+ rows, ≤~35 DOM rows), DossierPanel (Framer Motion slide-in, Esc + backdrop close).

## Data layer (`lib/snapshot.ts`)
SHA-256-verified snapshot assets (manifest, search_index, day shards, shard_map)
from the existing verified pipeline. Fail-closed: any integrity mismatch aborts
render instead of serving unverified data.

## Run
    npm install
    npm run dev    # http://localhost:3000
    npm run build  # static export to ./out
