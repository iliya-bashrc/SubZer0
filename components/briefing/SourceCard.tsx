'use client';

import { memo } from 'react';

/**
 * SourceGrid — STEP 3: 4-column provenance grid. Logo mark = monochrome
 * Lucide "database" glyph, name 13px, count mono 16px, green status dot 6px.
 * All data (counts, checked date, notes) preserved — visual only.
 */
interface SourceStatus {
  name: string;
  ok: boolean;
  pages?: number;
  records?: number;
  advisories?: number;
  catalog_records?: number;
  scores?: number;
  score_date?: string;
  checked_at: string;
  note?: string;
}

function metric(s: SourceStatus): { label: string; value: string } | null {
  if (s.records != null) return { label: 'records', value: s.records.toLocaleString('en-US') };
  if (s.advisories != null) return { label: 'advisories', value: s.advisories.toLocaleString('en-US') };
  if (s.catalog_records != null) return { label: 'catalog', value: s.catalog_records.toLocaleString('en-US') };
  if (s.scores != null) return { label: 'scored', value: `${s.scores.toLocaleString('en-US')}${s.score_date ? ` · ${s.score_date}` : ''}` };
  return null;
}

function SourceMark() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
         strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {/* lucide database */}
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v14a9 3 0 0 0 18 0V5" />
      <path d="M3 12a9 3 0 0 0 18 0" />
    </svg>
  );
}

export const SourceGrid = memo(function SourceGrid({ sources }: { sources: SourceStatus[] }) {
  return (
    <section>
      <h3 className="text-[16px] font-semibold text-ink">Sources</h3>
      <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {sources.map((s) => {
          const m = metric(s);
          return (
            <div key={s.name} className="card card-hover p-4">
              <div className="flex items-center gap-2.5 text-ink-2">
                <SourceMark />
                <span className="truncate text-[13px] text-ink">{s.name}</span>
                <span
                  aria-hidden="true"
                  title={s.ok ? 'Succeeded' : 'Failed'}
                  className="ml-auto inline-block h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: s.ok ? 'oklch(0.72 0.17 150)' : 'var(--color-critical)' }}
                />
              </div>
              {m && (
                <div className="mt-2.5 font-mono text-[16px] font-medium tabular-nums text-ink">
                  {m.value}
                  <span className="ml-1.5 font-sans text-[11px] font-normal text-ink-3">{m.label}</span>
                </div>
              )}
              {s.note ? (
                <div className="mt-1 truncate text-[12px] text-ink-3">{s.note}</div>
              ) : (
                <div className="mt-1 font-mono text-[11px] text-ink-3">
                  checked {s.checked_at.slice(0, 10)}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
});
