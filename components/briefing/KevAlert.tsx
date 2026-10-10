'use client';

import { memo } from 'react';

/**
 * KevAlert — STEP 3: list (not table) inside one card. Row: CVE ID (mono,
 * accent) · vendor · product · severity dot + score · date. First 8 items;
 * the header count keeps the full number visible (nothing hidden — the rest
 * remain reachable via the Research tab filter).
 */
interface KevRow {
  id: string;
  title: string;
  score: number | null;
  sev: string;
  vendor: string | null;
  product: string | null;
  date_added: string | null;
  ransomware: string | null;
}

export const KevAlert = memo(function KevAlert({ items }: { items: KevRow[] }) {
  return (
    <section className="card p-5 sm:p-6">
      <div className="flex items-baseline justify-between gap-4">
        <h3 className="text-[16px] font-semibold text-ink">Recent KEV</h3>
        <span className="text-[13px] text-ink-3">{items.length} in window</span>
      </div>

      {items.length === 0 ? (
        <p className="mt-3 text-[13px] text-ink-3">No CISA KEV records in this window.</p>
      ) : (
        <ul className="mt-2">
          {items.slice(0, 8).map((k) => (
            <li key={k.id}>
              <a
                href={`${process.env.__NEXT_ROUTER_BASEPATH || ''}/cve/${k.id}/`}
                className="group flex items-center gap-3 rounded-md px-2 py-3
                           transition-colors hover:bg-bg-hover"
              >
                <span className="block truncate font-mono text-[13px] text-accent">
                  {k.id}
                </span>
                <span className="min-w-0 flex-1 truncate text-[14px] text-ink">
                  {[k.vendor, k.product].filter(Boolean).join(' · ') || k.title.slice(0, 80)}
                  {k.ransomware === 'Known' ? ' · ransomware' : ''}
                </span>
                <span
                  className={`sev shrink-0 sev--${k.sev || 'low'}`}
                  aria-label={k.sev ? `${k.sev} severity` : undefined}
                >
                  {k.score != null && k.score > 0 ? k.score.toFixed(1) : '—'}
                </span>
                <span className="shrink-0 font-mono text-[12px] text-ink-3">
                  {k.date_added ?? ''}
                </span>
              </a>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
});
