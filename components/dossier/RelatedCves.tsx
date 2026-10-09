'use client';

import { memo, useMemo } from 'react';
import { toListItem, type CveListItem, type CveRecord, type IndexTuple } from '@/lib/snapshot';

/**
 * Related CVEs — STEP 5: borderless ghost rows (hover bg), mono ONLY on
 * CVE IDs and the similarity percent. Honest empty states preserved
 * verbatim; grouping logic unchanged.
 */
interface RelatedCvesProps {
  record: CveRecord;
  shardRecords: CveRecord[];
  onSelect: (id: string) => void;
}

function tokens(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^a-z0-9\s-]/g, ' ')
      .split(/\s+/)
      .filter((t) => t.length > 3),
  );
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 || b.size === 0) return 0;
  let inter = 0;
  for (const t of a) if (b.has(t)) inter++;
  return inter / (a.size + b.size - inter);
}

export const RelatedCves = memo(function RelatedCves({ record, shardRecords, onSelect }: RelatedCvesProps) {
  const vendorFamily = useMemo(() => {
    const vendors = new Set((record.affected ?? []).map((a) => a.vendor.toLowerCase()).filter(Boolean));
    if (vendors.size === 0) return [];
    return shardRecords
      .filter((r) => r.id !== record.id)
      .filter((r) => (r.affected ?? []).some((a) => vendors.has(a.vendor.toLowerCase())))
      .slice(0, 8);
  }, [record, shardRecords]);

  const similar = useMemo(() => {
    const base = tokens(`${record.title} ${record.desc}`);
    return shardRecords
      .filter((r) => r.id !== record.id)
      .map((r) => ({ r, score: jaccard(base, tokens(`${r.title} ${r.desc}`)) }))
      .filter((x) => x.score >= 0.15)
      .sort((a, b) => b.score - a.score)
      .slice(0, 6);
  }, [record, shardRecords]);

  return (
    <section className="space-y-4">
      <h3 className="label-xs">Related CVEs</h3>

      {/* By CWE — not published upstream */}
      <div>
        <div className="mb-1.5 text-[12px] font-medium text-ink-2">By CWE weakness</div>
        <div className="text-[12px] text-ink-3">
          — CWE classification is not published in the verified feed.
        </div>
      </div>

      {/* By vendor */}
      <div>
        <div className="mb-1.5 text-[12px] font-medium text-ink-2">
          By vendor · same product family {vendorFamily.length > 0 && `(${vendorFamily.length})`}
        </div>
        {vendorFamily.length > 0 ? (
          <ul className="space-y-0.5">
            {vendorFamily.map((r) => (
              <li key={r.id}>
                <button
                  onClick={() => onSelect(r.id)}
                  className="w-full truncate rounded-md px-2 py-1.5 text-left
                             font-mono text-[12px] text-ink-2 transition-colors
                             hover:bg-bg-hover hover:text-accent"
                >
                  {r.id} <span className="text-ink-3">— {r.title.slice(0, 60)}</span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[12px] text-ink-3">—</div>
        )}
      </div>

      {/* By description similarity (lexical) */}
      <div>
        <div className="mb-1.5 text-[12px] font-medium text-ink-2">
          By description similarity {similar.length > 0 && `(top ${similar.length})`}
        </div>
        {similar.length > 0 ? (
          <ul className="space-y-0.5">
            {similar.map(({ r, score }) => (
              <li key={r.id}>
                <button
                  onClick={() => onSelect(r.id)}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5
                             text-left transition-colors hover:bg-bg-hover"
                >
                  <span className="shrink-0 font-mono text-[12px] text-ink-2">{r.id}</span>
                  <span className="min-w-0 flex-1 truncate text-[12px] text-ink-2">{r.title}</span>
                  <span className="shrink-0 font-mono text-[11px] text-ink-3">
                    {(score * 100).toFixed(0)}%
                  </span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-[12px] text-ink-3">—</div>
        )}
      </div>
    </section>
  );
});

export type { CveListItem, IndexTuple };
