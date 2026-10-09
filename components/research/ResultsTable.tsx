'use client';

import { memo, useEffect, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useIsMobile } from '@/lib/useIsMobile';
import type { CveListItem } from '@/lib/snapshot';

/**
 * ResultsTable — STEP 4: Linear-style table. Row height 48px, no vertical
 * borders, row hover bg, severity as dot+text, KEV as text-only marker,
 * PoC as external-link icon, mono ONLY on data values.
 * Virtualization + empty state + focus restore (Section 11) unchanged.
 */

const ROW_H = 48;
const CARD_H = 132;

interface ResultsTableProps {
  rows: CveListItem[];
  /** The second argument is the clicked row, used to restore focus on close (Section 11). */
  onOpen: (id: string, trigger?: HTMLElement | null) => void;
  onResetFilters?: () => void;
}

/** Muted em-dash for missing values — never "UNKNOWN"/"NONE". */
function Dash({ mono = false }: { mono?: boolean }) {
  return <span className={mono ? 'font-mono text-ink-3' : 'text-ink-3'}>—</span>;
}

/** Severity: 6px dot + text. No pill, no border. Missing → em dash. */
function SevCell({ sev }: { sev: string }) {
  if (!sev || sev === 'none' || sev === 'unknown') return <Dash />;
  return (
    <span className={`sev sev--${sev.toLowerCase()}`} aria-label={`${sev} severity`}>
      {sev.charAt(0).toUpperCase() + sev.slice(1)}
    </span>
  );
}

export const ResultsTable = memo(function ResultsTable({ rows, onOpen, onResetFilters }: ResultsTableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const isMobile = useIsMobile();

  // Stable identity + ref so the virtualizer can be re-measured when the
  // breakpoint flips (TanStack caches measured sizes per index).
  const rowHeight = useRef(ROW_H);
  rowHeight.current = isMobile === true ? CARD_H : ROW_H;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight.current,
    overscan: isMobile ? 4 : 8,
  });

  useEffect(() => {
    virtualizer.measure();
  }, [isMobile, virtualizer]);

  if (rows.length === 0) {
    return (
      <div className="flex h-full items-center justify-center px-6">
        <div className="card px-8 py-8 text-center" role="status">
          <svg aria-hidden="true" viewBox="0 0 24 24" className="mx-auto h-10 w-10 text-ink-3" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="11" cy="11" r="7" />
            <path d="m20 20-3.5-3.5" strokeLinecap="round" />
          </svg>
          <div className="mt-3 text-[14px] font-medium text-ink-2">No CVEs match your filters</div>
          <div className="mt-1 text-[13px] text-ink-3">
            Try a different query or clear the active filters.
          </div>
          {onResetFilters && (
            <button
              onClick={onResetFilters}
              className="mt-4 rounded-md px-4 py-1.5 text-[13px] font-medium text-accent
                         transition-colors hover:bg-accent-soft"
            >
              Reset filters
            </button>
          )}
        </div>
      </div>
    );
  }

  const items = virtualizer.getVirtualItems();

  return (
    <div
      ref={scrollRef}
      data-results-table=""
      tabIndex={-1}
      role="region"
      aria-label="CVE results"
      className="h-full overflow-y-auto overscroll-contain outline-none focus-visible:outline-none"
      style={{ touchAction: 'pan-y' }}
    >
      {/* ===== ≥768px: table (not rendered on mobile) ===== */}
      {isMobile === false && (
        <>
          <div className="sticky top-0 z-10 grid grid-cols-[160px_120px_70px_80px_56px_48px_1fr] gap-2
                          border-b border-line bg-bg px-4 py-2.5
                          text-[11px] font-medium uppercase tracking-[0.06em] text-ink-3">
            <span>CVE ID</span>
            <span>Severity</span>
            <span className="text-right">CVSS</span>
            <span className="text-right">EPSS</span>
            <span>KEV</span>
            <span>PoC</span>
            <span className="text-right">Published</span>
          </div>
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
            {items.map((vRow) => {
              const item = rows[vRow.index];
              return (
                <button
                  key={item.id}
                  onClick={(e) => onOpen(item.id, e.currentTarget)}
                  aria-label={`Open dossier for ${item.id}${item.kev ? ', CISA KEV listed' : ''}`}
                  className="group absolute inset-x-0 grid w-full cursor-pointer text-left
                             grid-cols-[160px_120px_70px_80px_56px_48px_1fr] items-center gap-2
                             border-b border-line-soft px-4 transition-colors hover:bg-bg-hover"
                  style={{
                    height: vRow.size,
                    transform: `translateY(${vRow.start}px)`,
                  }}
                >
                  <span className="truncate font-mono text-[13px] text-ink group-hover:text-accent">
                    {item.id}
                  </span>
                  <span><SevCell sev={item.sev} /></span>
                  <span className="text-right font-mono text-[13px] text-ink">
                    {item.score > 0 ? item.score.toFixed(1) : <Dash mono />}
                  </span>
                  <span className="text-right font-mono text-[13px] text-ink">
                    {item.epss != null ? item.epss.toFixed(3) : <Dash mono />}
                  </span>
                  <span className="text-[11px] font-semibold uppercase tracking-[0.04em]">
                    {item.kev ? (
                      <span className="kev-mark">KEV</span>
                    ) : (
                      <span className="text-ink-3">—</span>
                    )}
                  </span>
                  <span aria-hidden="true" className="text-ink-3">
                    {item.kev ? null : '—'}
                  </span>
                  <span className="text-right font-mono text-[12px] text-ink-3">
                    {item.publishedDate}
                  </span>
                </button>
              );
            })}
          </div>
        </>
      )}

      {/* ===== <768px: virtualized card list (virtualization preserved) ===== */}
      {isMobile === true && (
        <div className="px-3 pb-3 pt-3">
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
            {items.map((vRow) => {
              const item = rows[vRow.index];
              return (
                <button
                  key={item.id}
                  onClick={(e) => onOpen(item.id, e.currentTarget)}
                  aria-label={`Open dossier for ${item.id}${item.kev ? ', CISA KEV listed' : ''}`}
                  className="absolute inset-x-0 cursor-pointer rounded-lg border border-line-soft
                             bg-bg-raised p-3.5 text-left transition-colors hover:bg-bg-hover"
                  style={{ height: vRow.size, transform: `translateY(${vRow.start}px)` }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-[13px] text-ink">
                      {item.id}
                    </span>
                    <SevCell sev={item.sev} />
                  </div>
                  <div className="mt-2.5 grid grid-cols-2 gap-2">
                    <div>
                      <div className="text-[10px] font-medium uppercase text-ink-3 tracking-[0.04em]">CVSS</div>
                      <div className="font-mono text-[13px] text-ink">
                        {item.score > 0 ? item.score.toFixed(1) : <Dash mono />}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] font-medium uppercase text-ink-3 tracking-[0.04em]">EPSS</div>
                      <div className="font-mono text-[13px] text-ink">
                        {item.epss != null ? item.epss.toFixed(3) : <Dash mono />}
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 font-mono text-[11px] text-ink-3">{item.publishedDate}</div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
});
