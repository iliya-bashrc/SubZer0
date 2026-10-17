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
    <section className="space-y-4">
      <h3 className="label-xs">Assessment</h3>

      {/* CINEMATIC v2: editorial numerals sitting directly on the atmosphere —
          no borders, no cards, asymmetric stagger instead of a KPI grid. */}
      <div>
        {/* CVSS — the larger figure, first */}
        <div>
          <div className="label-xs">CVSS BASE SCORE</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className="font-display text-[72px] font-semibold leading-none tracking-[-0.03em]"
              style={{ color: hasCvss ? barColor : 'var(--color-ink-3)' }}
            >
              {hasCvss ? cvssScore!.toFixed(1) : '—'}
            </span>
            <span className="font-mono text-[13px] text-ink-3">/ 10</span>
          </div>
          {!hasCvss && <div className="mt-2 text-[12px] text-ink-3">No CVSS base score in verified sources</div>}
          {(cvssVector || cvss30Score != null || cvss2Score != null) && (
            <div className="mt-3 max-w-md space-y-2 border-t border-line pt-3">
              <VectorRow label="v3.1 vector" value={cvssVector} />
              {cvss30Score != null && (
                <VectorRow label="v3.0 score" value={cvss30Vector ?? String(cvss30Score)} fallback={String(cvss30Score)} />
              )}
              {cvss2Score != null && <VectorRow label="v2.0 score" value={String(cvss2Score)} fallback={String(cvss2Score)} />}
            </div>
          )}
        </div>

        {/* EPSS — offset below and inset, breaking the symmetric grid */}
        <div className="mt-8 ml-[18%] border-t border-line pt-5 sm:ml-[28%]">
          <div className="label-xs" style={{ color: '#6FA8B8' }}>EPSS — EXPLOITATION PROBABILITY</div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-display text-[48px] font-semibold leading-none tracking-[-0.03em] text-ink">
              {epssScore != null ? epssScore.toFixed(3) : '—'}
            </span>
            {epssPercentile != null && (
              <span className="font-mono text-[13px] text-ink-3">p{((epssPercentile ?? 0) * 100).toFixed(1)}</span>
            )}
          </div>
          <div className="mt-2 text-[12px] text-ink-3">
            {epssScore != null
              ? 'Exploitation probability · FIRST EPSS'
              : 'Not scored by FIRST EPSS'}
          </div>
          {/* 30-day trend: upstream publishes a single score snapshot only */}
          <div className="mt-2 text-[12px] text-ink-3">30-day trend: single snapshot — history not published upstream</div>
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
