'use client';

import { memo, useMemo, useState } from 'react';

/**
 * ActivityChart (Section 7) — dependency-free bar chart. Peak day is
 * highlighted with the accent color; severity mix shown on hover/focus.
 * Caption keeps the data-honesty contract explicit.
 */
interface Day {
  date: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  exploited: number;
}

export const ActivityChart = memo(function ActivityChart({ daily }: { daily: Day[] }) {
  const [hover, setHover] = useState<number | null>(null);

  const { peakIdx, max } = useMemo(() => {
    let peakIdx = 0;
    let max = 0;
    daily.forEach((d, i) => {
      if (d.count > max) {
        max = d.count;
        peakIdx = i;
      }
    });
    return { peakIdx, max };
  }, [daily]);

  if (daily.length === 0) {
    return (
      <div className="card p-6 text-[13px] text-ink-3">No activity data in this window.</div>
    );
  }

  const active = hover != null ? daily[hover] : null;

  return (
    <section className="card p-5 sm:p-6">
      <div className="flex items-baseline justify-between gap-4">
        <h3 className="text-[16px] font-semibold text-ink">Publication activity</h3>
        <span className="text-[13px] text-ink-3">
          Last 30 days
          {active ? ` · ${active.date}: ${active.count}` : ` · peak ${daily[peakIdx].count}`}
        </span>
      </div>

      <div
        className="mt-5 flex h-[200px] items-end gap-[3px]"
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label={`Daily CVE publication counts for ${daily.length} days, peak ${daily[peakIdx].count} on ${daily[peakIdx].date}`}
      >
        {daily.map((d, i) => {
          const h = Math.max(3, Math.round((d.count / max) * 100));
          const isPeak = i === peakIdx;
          return (
            <button
              key={d.date}
              type="button"
              onMouseEnter={() => setHover(i)}
              onFocus={() => setHover(i)}
              aria-label={`${d.date}: ${d.count} CVEs, ${d.critical} critical, ${d.high} high`}
              className="group relative flex-1 rounded-t-[3px] transition-colors"
              style={{
                height: `${h}%`,
                background: isPeak
                  ? 'var(--color-accent)'
                  : 'color-mix(in oklch, var(--color-accent) 16%, transparent)',
              }}
            />
          );
        })}
      </div>

      <div className="mt-2 flex justify-between text-[12px] text-ink-3">
        <span>{daily[0].date}</span>
        <span>{daily[daily.length - 1].date}</span>
      </div>

      {/* severity mix of hovered/peak day — legend with colored dots */}
      <div className="mt-4 flex flex-wrap gap-4">
        {(() => {
          const d = active ?? daily[peakIdx];
          return (
            <>
              <Mix sev="critical" n={d.critical} />
              <Mix sev="high" n={d.high} />
              <Mix sev="medium" n={d.medium} />
              <Mix sev="low" n={d.low} />
              {d.exploited > 0 && <span className="kev-mark">{d.exploited} exploited</span>}
              <span className="ml-auto text-[12px] text-ink-3">
                {active ? 'hovered day' : 'peak day'}
              </span>
            </>
          );
        })()}
      </div>

      <p className="mt-3 text-[12px] text-ink-3">
        Computed only from manifest-verified day shards.
      </p>
    </section>
  );
});

function Mix({ sev, n }: { sev: string; n: number }) {
  return (
    <span className="flex items-center gap-1.5 text-[13px] text-ink-2">
      <span className={`sev-dot sev-dot--${sev}`} aria-hidden="true" />
      <span className="tabular-nums text-ink">{n.toLocaleString('en-US')}</span> {sev}
    </span>
  );
}
