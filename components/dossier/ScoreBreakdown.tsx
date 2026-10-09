'use client';

import { memo } from 'react';

/**
 * Score breakdown — STEP 5: gauges → horizontal bars. CVSS bar colored by
 * severity token, EPSS bar in accent. Mono ONLY on numeric values/vector
 * strings. Honest-data empty states preserved verbatim.
 */
interface ScoreBreakdownProps {
  cvssScore: number | null;
  cvssVector?: string | null;
  cvss30Score?: number | null;
  cvss30Vector?: string | null;
  cvss2Score?: number | null;
  epssScore: number | null;
  epssPercentile: number | null;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown';
}

const SEV_VAR: Record<string, string> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
  none: 'var(--color-ink-3)',
  unknown: 'var(--color-ink-3)',
};

export const ScoreBreakdown = memo(function ScoreBreakdown({
  cvssScore,
  cvssVector,
  cvss30Score,
  cvss30Vector,
  cvss2Score,
  epssScore,
  epssPercentile,
  severity,
}: ScoreBreakdownProps) {
  const barColor = severity ? (SEV_VAR[severity] ?? 'var(--color-ink-3)') : 'var(--color-ink-3)';
  const hasCvss = cvssScore != null && cvssScore > 0;

  return (
    <section className="space-y-3">
      <h3 className="label-xs">Score breakdown</h3>

      <div className="card space-y-4 p-4">
        {/* CVSS bar */}
        <div>
          <div className="flex items-baseline justify-between">
            <span className="text-[13px] font-medium text-ink">CVSS base score</span>
            <span className="font-mono text-[14px] text-ink">
              {hasCvss ? cvssScore!.toFixed(1) : '—'}
              <span className="text-ink-3"> / 10</span>
            </span>
          </div>
          <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-bg-hover">
            {hasCvss && (
              <div
                className="h-full rounded-full transition-[width] duration-500"
                style={{ width: `${(cvssScore! / 10) * 100}%`, background: barColor }}
              />
            )}
          </div>
          {!hasCvss && (
            <div className="mt-1.5 text-[12px] text-ink-3">No CVSS base score in verified sources</div>
          )}
          {/* Vector rows — copy-to-clipboard when present (patch §5a) */}
          {(cvssVector || cvss30Score != null || cvss2Score != null) && (
            <div className="mt-3 space-y-2 border-t border-line pt-3">
              <VectorRow label="v3.1 vector" value={cvssVector} />
              {cvss30Score != null && (
                <VectorRow label="v3.0 score" value={cvss30Vector ?? String(cvss30Score)} fallback={String(cvss30Score)} />
              )}
              {cvss2Score != null && <VectorRow label="v2.0 score" value={String(cvss2Score)} fallback={String(cvss2Score)} />}
            </div>
          )}
        </div>

        {/* EPSS bar */}
        <div className="border-t border-line pt-4">
          <div className="flex items-baseline justify-between">
            <span className="text-[13px] font-medium text-ink">EPSS</span>
            <span className="font-mono text-[14px] text-ink">
              {epssScore != null ? epssScore.toFixed(3) : '—'}
            </span>
          </div>
          <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-bg-hover">
            {epssScore != null && (
              <div
                className="h-full rounded-full bg-accent transition-[width] duration-500"
                style={{ width: `${Math.min(100, epssScore * 100)}%` }}
              />
            )}
          </div>
          <div className="mt-1.5 text-[12px] text-ink-3">
            {epssScore != null
              ? `Exploitation probability · percentile ${((epssPercentile ?? 0) * 100).toFixed(1)}%`
              : 'Not scored by FIRST EPSS'}
          </div>
          {/* 30-day trend: upstream publishes a single score snapshot only */}
          <div className="mt-2 flex items-center justify-between gap-2">
            <span className="text-[12px] text-ink-3">30-day trend</span>
            <span className="text-[12px] text-ink-3">single snapshot — history not published upstream</span>
          </div>
        </div>
      </div>
    </section>
  );
});

function VectorRow({ label, value, fallback }: { label: string; value?: string | null; fallback?: string }) {
  if (value) {
    return (
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="whitespace-nowrap text-[11px] text-ink-3">{label}</div>
          <div className="truncate font-mono text-[11px] text-ink-2">{value}</div>
        </div>
        <CopyButton value={value} label={label} />
      </div>
    );
  }
  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="whitespace-nowrap text-[11px] text-ink-3">{label}</span>
      <span className="text-[11px] text-ink-3">—</span>
    </div>
  );
}

function CopyButton({ value, label }: { value: string; label: string }) {
  return (
    <button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
        } catch {
          /* clipboard unavailable — non-fatal */
        }
      }}
      aria-label={`Copy ${label}`}
      className="rounded px-1.5 py-0.5 text-[11px] text-ink-3
                 transition-colors hover:bg-bg-hover hover:text-ink"
    >
      Copy
    </button>
  );
}

export { CopyButton };
