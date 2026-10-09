'use client';

import { memo, useCallback } from 'react';
import { DEFAULT_FILTERS, type Filters, type IndexTuple } from '@/lib/snapshot';

/**
 * FilterRail — STEP 4: borderless filter controls. Segmented toggles use
 * bg-elevated + ink for active (no border), severity rows are dot+text,
 * presets are ghost chips (hover bg only). All filter behavior unchanged.
 */

const SEVERITIES: { key: IndexTuple[2]; label: string; varName: string }[] = [
  { key: 'critical', label: 'Critical', varName: 'var(--color-critical)' },
  { key: 'high', label: 'High', varName: 'var(--color-high)' },
  { key: 'medium', label: 'Medium', varName: 'var(--color-medium)' },
  { key: 'low', label: 'Low', varName: 'var(--color-low)' },
];

const LABEL = 'mb-2 text-[11px] font-medium uppercase text-ink-3 tracking-[0.05em]';

interface FilterRailProps {
  filters: Filters;
  onChange: (next: Filters) => void;
}

/** Segmented control: active = bg-elevated + ink text; inactive = plain. */
function Segmented<T extends string>({
  value,
  options,
  onPick,
  ariaLabel,
}: {
  value: T;
  options: readonly T[];
  onPick: (v: T) => void;
  ariaLabel: string;
}) {
  return (
    <div className="inline-flex rounded-md bg-bg p-0.5" role="group" aria-label={ariaLabel}>
      {options.map((v) => {
        const active = value === v;
        return (
          <button
            key={v}
            onClick={() => onPick(v)}
            aria-pressed={active}
            className={`rounded-[5px] px-2.5 py-1 text-[12px] transition-colors ${
              active ? 'bg-bg-elevated text-ink' : 'text-ink-3 hover:text-ink-2'
            }`}
          >
            {v}
          </button>
        );
      })}
    </div>
  );
}

/** Left filter rail; collapses to a top drawer on mobile. */
export const FilterRail = memo(function FilterRail({ filters, onChange }: FilterRailProps) {
  const toggleSeverity = useCallback(
    (sev: IndexTuple[2]) => {
      const next = new Set(filters.severities);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      onChange({ ...filters, severities: next });
    },
    [filters, onChange],
  );

  const reset = useCallback(
    () => onChange({ ...DEFAULT_FILTERS, severities: new Set<IndexTuple[2]>() }),
    [onChange],
  );

  /** §9 presets — visible right below Reset, no dead space. */
  const presets = [
    {
      label: 'Critical only',
      apply: () => onChange({ ...DEFAULT_FILTERS, severities: new Set<IndexTuple[2]>(['critical']) }),
    },
    {
      label: 'KEV + PoC',
      apply: () =>
        onChange({ ...DEFAULT_FILTERS, severities: new Set<IndexTuple[2]>(), kev: 'yes', poc: 'yes' }),
    },
    {
      label: 'EPSS > 0.5',
      apply: () => onChange({ ...DEFAULT_FILTERS, severities: new Set<IndexTuple[2]>(), epssMin: 0.5 }),
    },
  ];

  return (
    <aside
      className="swiper-no-swiping w-full shrink-0 space-y-6 px-4 py-4
                 lg:h-full lg:w-60 lg:overflow-y-auto"
      style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}
    >
      {/* Severity — dot + text rows, no pill border */}
      <section>
        <h3 className={LABEL}>Severity</h3>
        <div className="flex flex-wrap gap-1 lg:flex-col lg:items-stretch lg:gap-0.5">
          {SEVERITIES.map(({ key, label, varName }) => {
            const active = filters.severities.has(key);
            return (
              <button
                key={key}
                onClick={() => toggleSeverity(key)}
                aria-pressed={active}
                className={`flex items-center gap-2 rounded-md px-2 py-1.5 text-[13px] transition-colors ${
                  active ? 'bg-bg-elevated text-ink' : 'text-ink-3 hover:bg-bg-hover hover:text-ink-2'
                }`}
              >
                <span
                  aria-hidden="true"
                  className="inline-block h-1.5 w-1.5 rounded-full"
                  style={{ background: varName }}
                />
                {label}
              </button>
            );
          })}
        </div>
      </section>

      {/* CISA KEV */}
      <section>
        <h3 className={LABEL}>CISA KEV</h3>
        <Segmented
          ariaLabel="CISA KEV filter"
          value={filters.kev}
          options={['any', 'yes', 'no'] as const}
          onPick={(v) => onChange({ ...filters, kev: v })}
        />
      </section>

      {/* EPSS — slider + numeric readout §9 */}
      <section className="swiper-no-swiping">
        <div className="mb-2 flex items-baseline justify-between">
          <h3 className={LABEL + ' mb-0'}>EPSS min</h3>
          <span className="font-mono text-[12px] text-ink-2">
            {filters.epssMin.toFixed(2)} / 1.00
          </span>
        </div>
        <input
          type="range"
          min={0}
          max={100}
          value={Math.round(filters.epssMin * 100)}
          onChange={(e) => onChange({ ...filters, epssMin: Number(e.target.value) / 100 })}
          className="w-full accent-accent"
          aria-label="Minimum EPSS score"
        />
      </section>

      {/* Public PoC / Exploit ref */}
      <section>
        <h3 className={LABEL}>Public PoC</h3>
        <Segmented
          ariaLabel="Public PoC filter"
          value={filters.poc}
          options={['any', 'yes', 'no'] as const}
          onPick={(v) => onChange({ ...filters, poc: v })}
        />
      </section>

      {/* Published date range */}
      <section className="swiper-no-swiping">
        <h3 className={LABEL}>Published</h3>
        <div className="space-y-2">
          <input
            type="date"
            value={filters.publishedFrom ?? ''}
            onChange={(e) => onChange({ ...filters, publishedFrom: e.target.value || null })}
            className="w-full rounded-md border border-line bg-bg px-2 py-1.5
                       font-mono text-[12px] text-ink-2 outline-none
                       focus:border-accent"
            aria-label="Published from"
          />
          <input
            type="date"
            value={filters.publishedTo ?? ''}
            onChange={(e) => onChange({ ...filters, publishedTo: e.target.value || null })}
            className="w-full rounded-md border border-line bg-bg px-2 py-1.5
                       font-mono text-[12px] text-ink-2 outline-none
                       focus:border-accent"
            aria-label="Published to"
          />
        </div>
      </section>

      <button
        onClick={reset}
        className="w-full rounded-md px-3 py-1.5 text-[13px] font-medium text-ink-3
                   transition-colors hover:bg-bg-hover hover:text-ink-2"
      >
        Reset filters
      </button>

      {/* §9 preset chips — ghost style */}
      <section>
        <h3 className={LABEL}>Presets</h3>
        <div className="flex flex-wrap gap-1.5">
          {presets.map((p) => (
            <button
              key={p.label}
              onClick={p.apply}
              className="rounded-full px-3 py-1 text-[12px] text-ink-3
                         transition-colors hover:bg-bg-hover hover:text-ink-2"
            >
              {p.label}
            </button>
          ))}
        </div>
      </section>
    </aside>
  );
});
