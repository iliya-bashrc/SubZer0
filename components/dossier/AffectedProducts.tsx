'use client';

import { memo, useMemo, useState } from 'react';
import type { CveAffected } from '@/lib/snapshot';

/**
 * Affected products — STEP 5: plain list inside one card, version strings
 * mono. Collapse toggle kept (ghost chevron). Dedupe unchanged.
 */
const NO_VERSIONS = /(version details not specified|not specified in source|not specified by cisa)/i;

function dedupe(affected: CveAffected[]): { key: string; vendor: string; product: string; versions: string[] }[] {
  const map = new Map<string, { vendor: string; product: string; versions: string[] }>();
  for (const a of affected) {
    const vendor = a.vendor || '(unknown vendor)';
    const product = a.product || '(unknown product)';
    // Case-insensitive grouping key (upstream mixes casing); display keeps the
    // first-seen spelling.
    const key = `${vendor.toLowerCase()} / ${product.toLowerCase()}`;
    const entry = map.get(key) ?? { vendor, product, versions: [] };
    if (a.versions && !NO_VERSIONS.test(a.versions) && !entry.versions.includes(a.versions)) {
      entry.versions.push(a.versions);
    }
    map.set(key, entry);
  }
  return [...map.entries()].map(([key, e]) => ({ key, ...e }));
}

export const AffectedProducts = memo(function AffectedProducts({
  affected,
}: {
  affected: CveAffected[];
}) {
  const rows = useMemo(() => dedupe(affected), [affected]);
  const [open, setOpen] = useState(true);

  if (affected.length === 0) {
    return (
      <section className="space-y-3">
        <h3 className="label-xs">Affected products</h3>
        <div className="text-[12px] text-ink-3">
          No affected-product data published by upstream sources.
        </div>
      </section>
    );
  }

  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between">
        <h3 className="label-xs mb-0">Affected products · {rows.length}</h3>
        <button
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-label={open ? 'Collapse affected products' : 'Expand affected products'}
          className="rounded p-1 text-[11px] text-ink-3 transition-colors hover:bg-bg-hover hover:text-ink"
        >
          {open ? '▾' : '▸'}
        </button>
      </div>
      {open && (
        <ul className="card divide-y divide-line-soft px-4 py-1">
          {rows.map((r) => (
            <li key={r.key} className="py-2 text-[13px]">
              <span className="text-ink">{r.vendor} / {r.product}</span>
              {r.versions.length > 0 && (
                <span className="font-mono text-[12px] text-ink-3"> — {r.versions.join(', ')}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
});
