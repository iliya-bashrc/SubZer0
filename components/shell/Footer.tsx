'use client';

import { useState } from 'react';
import { COPYRIGHT, DISCLAIMER, VERSION } from '@/lib/constants';

/**
 * Global footer (Section 12).
 * Never hidden, never a modal backdrop. The copyright line is always
 * selectable/copyable (no select-none) and the disclaimer is never truncated
 * on desktop (max-width 60ch, full text).
 */
interface FooterProps {
  /** Snapshot generated_at / last successful update, ISO 8601 (UTC). */
  lastSync?: string | null;
}

function formatSync(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'unknown';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(
    d.getUTCHours(),
  )}:${pad(d.getUTCMinutes())} UTC`;
}

function isFresh(iso: string): boolean {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return false;
  return Date.now() - d.getTime() <= 24 * 60 * 60 * 1000;
}

export function Footer({ lastSync }: FooterProps) {
  const [disclaimerOpen, setDisclaimerOpen] = useState(false);
  const fresh = lastSync ? isFresh(lastSync) : false;

  return (
    <footer className="border-t border-line-soft bg-transparent px-4 py-6 md:px-8">
      <div className="mx-auto max-w-6xl">
        {/* Desktop: 3-column grid · Mobile: stacked, centered */}
        <div className="hidden gap-6 md:grid md:grid-cols-3 md:items-start">
          <p className="select-text font-mono text-[11px] leading-relaxed text-ink-3 transition-colors hover:text-ink-2">
            {COPYRIGHT.line}
          </p>
          <p className="select-text text-[11px] italic leading-relaxed text-ink-3 transition-colors hover:text-ink-2">
            {DISCLAIMER}
          </p>
          <div className="flex flex-col items-start gap-1 md:items-end">
            <span className="font-mono text-[11px] text-ink-3 transition-colors hover:text-ink-2">
              {VERSION}
            </span>
            {lastSync ? (
              <span className="flex items-center gap-2 font-mono text-[11px] text-ink-3 transition-colors hover:text-ink-2">
                <span
                  aria-hidden="true"
                  className={`inline-block h-1.5 w-1.5 rounded-full ${
                    fresh ? 'sync-dot--live' : ''
                  }`}
                  style={{ background: fresh ? 'var(--color-accent)' : 'var(--color-ink-3)' }}
                />
                Last sync: {formatSync(lastSync)}
              </span>
            ) : (
              <span className="font-mono text-[11px] text-ink-3">Last sync: unavailable</span>
            )}
          </div>
        </div>

        {/* Mobile */}
        <div className="space-y-3 text-center md:hidden">
          <p className="select-text font-mono text-[11px] leading-relaxed text-ink-3">
            {COPYRIGHT.line}
          </p>
          <div>
            <button
              type="button"
              onClick={() => setDisclaimerOpen((v) => !v)}
              aria-expanded={disclaimerOpen}
              aria-controls="footer-disclaimer"
              className="font-mono text-[11px] text-ink-3 transition-colors hover:text-ink-2"
            >
              Disclaimer {disclaimerOpen ? '▾' : '▸'}
            </button>
            {disclaimerOpen && (
              <p
                id="footer-disclaimer"
                className="select-text mx-auto mt-2 max-w-[60ch] text-[11px] italic leading-relaxed text-ink-3"
              >
                {DISCLAIMER}
              </p>
            )}
          </div>
          <div className="flex flex-col items-center gap-1">
            <span className="font-mono text-[11px] text-ink-3">{VERSION}</span>
            {lastSync && (
              <span className="flex items-center gap-2 font-mono text-[11px] text-ink-3">
                <span
                  aria-hidden="true"
                  className={`inline-block h-1.5 w-1.5 rounded-full ${fresh ? 'sync-dot--live' : ''}`}
                  style={{ background: fresh ? 'var(--color-accent)' : 'var(--color-ink-3)' }}
                />
                Last sync: {formatSync(lastSync)}
              </span>
            )}
          </div>
        </div>
      </div>
    </footer>
  );
}
