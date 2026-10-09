'use client';

import { memo, useMemo } from 'react';
import { CountUp } from '@/components/briefing/CountUp';

/**
 * HeroStrip — STEP 3 layout: text-first hero, no card box.
 * "Welcome back" eyebrow → Inter Tight title → verified-records subtitle.
 * Count-up + sync dot (functionality frozen; visuals only).
 */
export const HeroStrip = memo(function HeroStrip({
  total,
  lastSync,
  complete,
}: {
  total: number;
  lastSync: string | null;
  complete: boolean;
}) {
  const synced = useMemo(() => {
    if (!lastSync) return null;
    const d = new Date(lastSync);
    if (Number.isNaN(d.getTime())) return null;
    return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 16)} UTC`;
  }, [lastSync]);

  return (
    <header className="flex flex-wrap items-end justify-between gap-6 pb-10 pt-6">
      <div className="min-w-0">
        <p className="text-[14px] text-ink-2">Welcome back</p>
        <h2 className="mt-1 font-display text-[32px] font-bold leading-tight text-ink">
          CVE Intelligence
        </h2>
        <p className="mt-1.5 text-[13px] text-ink-3" aria-live="polite" aria-atomic="true">
          <CountUp value={total} className="tabular-nums" /> verified records
          {synced && <> · <span className="font-mono text-[12px]">{synced.slice(0, 16)}</span></>}
        </p>
      </div>

      {synced && (
        <div className="flex items-center gap-2 text-[13px] text-ink-3">
          <span
            className={`inline-block h-1.5 w-1.5 rounded-full ${complete ? 'sync-dot--live' : ''}`}
            style={{ background: complete ? 'var(--color-accent)' : 'var(--color-ink-3)' }}
            aria-hidden="true"
          />
          {complete ? 'All sources synced' : 'Partial sync'}
        </div>
      )}
    </header>
  );
});
