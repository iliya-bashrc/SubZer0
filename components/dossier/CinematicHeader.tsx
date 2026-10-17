'use client';

/*
 * CINEMATIC DOSSIER PROTOTYPE — branch prototype/cinematic-dossier only.
 *
 * Original visual direction inspired by the described language of the
 * VisionQuest end credits (large composed typography, small rectangular
 * accent labels, atmospheric lighting, editorial negative space). Not a
 * reproduction of any title card. Data is always the real verified record;
 * styling only. Falls back to the standard production panel visually via
 * an environment-free toggle (see CINEMATIC constant below) so the branch
 * stays comparable side-by-side.
 */

import { useEffect, useMemo, useState } from 'react';
import { X } from 'lucide-react';
import type { CveRecord } from '@/lib/snapshot';
import { DossierContent } from '@/components/dossier/DossierContent';

const CINEMATIC = true; // flip to false to render the production drawer look

const SEV_LABEL: Record<string, string> = {
  critical: 'CRITICAL VULNERABILITY',
  high: 'HIGH SEVERITY VULNERABILITY',
  medium: 'MODERATE SEVERITY VULNERABILITY',
  low: 'LOW SEVERITY VULNERABILITY',
  none: 'UNSCORED ADVISORY',
  unknown: 'UNSCORED ADVISORY',
};

/** Atmo: fixed, blurred ambient fields behind the panel content (CSS only,
 *  respects reduced-motion because it never animates — static gradients). */
function Atmo({ sev }: { sev: string }) {
  const hue = sev === 'critical' ? 'var(--color-critical)' : sev === 'high' ? 'var(--color-high)' : 'var(--color-accent)';
  return (
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      <div
        className="absolute -top-40 left-1/2 h-[420px] w-[680px] -translate-x-1/2 rounded-full opacity-[0.10] blur-[120px]"
        style={{ background: hue }}
      />
      <div
        className="absolute -right-32 top-1/3 h-[300px] w-[300px] rounded-full opacity-[0.06] blur-[100px]"
        style={{ background: hue }}
      />
    </div>
  );
}

/** Small rectangular credit-style label. */
function CreditLabel({ children, accent }: { children: string; accent?: boolean }) {
  return (
    <span
      className="inline-block px-2 py-[3px] font-mono text-[10px] tracking-[0.18em] uppercase"
      style={{
        color: accent ? 'var(--color-critical)' : 'var(--color-ink-2)',
        border: `1px solid ${accent ? 'var(--color-critical)' : 'var(--color-line-hi)'}`,
        background: accent ? 'var(--color-critical-soft, rgba(229,72,77,0.08))' : 'transparent',
      }}
    >
      {children}
    </span>
  );
}

function MetaCell({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="label-xs mb-1">{label}</div>
      <div className={`truncate text-[13px] text-ink ${mono ? 'font-mono' : ''}`}>{value}</div>
    </div>
  );
}

export function CinematicHeader({ record, onClose, standalone = false }:
  { record: CveRecord; onClose?: () => void; standalone?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const label = SEV_LABEL[record.sev] ?? SEV_LABEL.unknown;
  const accent = record.sev === 'critical' || record.sev === 'high' || Boolean(record.kev);

  const meta = useMemo(() => {
    const rows: { label: string; value: string }[] = [
      { label: 'Published', value: record.published?.slice(0, 10) ?? '—' },
      { label: 'Last modified', value: record.modified?.slice(0, 10) ?? '—' },
      { label: 'CVSS', value: record.score != null && record.score > 0 ? `v3.1 · ${record.score.toFixed(1)}` : '—' },
      { label: 'KEV catalog', value: record.kev ? `Listed ${record.kev.date_added}` : 'Not listed' },
    ];
    const vendor = record.affected?.[0]?.vendor;
    const product = record.affected?.[0]?.product;
    if (vendor || product) rows.splice(1, 0, { label: 'Affected', value: [vendor, product].filter(Boolean).join(' / ') });
    return rows;
  }, [record]);

  return (
    <header className="relative z-10 border-b border-line px-5 pb-6 pt-5 sm:px-7">
      <Atmo sev={record.sev} />

      {/* eyebrow row: credit-style labels + close */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex flex-wrap items-center gap-2">
          <CreditLabel accent={accent}>{label}</CreditLabel>
          {record.kev ? <CreditLabel>KEV LISTED</CreditLabel> : null}
        </div>
        {onClose ? (
          <button
            onClick={onClose}
            aria-label="Close dossier"
            className="rounded-md p-1.5 text-ink-3 transition-colors hover:bg-bg-hover hover:text-ink"
          >
            <X size={16} strokeWidth={1.5} />
          </button>
        ) : (
          <span aria-hidden="true" className="w-[34px]" />
        )}
      </div>

      {/* the identifier: dominant, editorial, tight tracking */}
      <h2
        className="mt-4 select-text break-words font-display text-[clamp(1.9rem,7vw,2.9rem)] font-semibold leading-[1.02] tracking-[-0.03em] text-ink"
      >
        {record.id}
      </h2>

      {/* metadata strip — editorial hairline grid, LEFT-aligned cells */}
      <div className="mt-5 grid grid-cols-2 gap-x-8 gap-y-3 border-t border-line-soft pt-4 text-left sm:grid-cols-4">
        {meta.map((m) => (
          <MetaCell key={m.label} label={m.label} value={m.value} />
        ))}
      </div>

      {/* supporting statement — clamped teaser; body description hidden until expanded */}
      {record.desc ? (
        <>
          <p className={`mt-3 max-w-md text-[13px] leading-relaxed text-ink-2 ${expanded ? '' : 'line-clamp-2'}`}>
            {record.desc}
          </p>
          {record.desc.length > 180 ? (
            <button
              onClick={() => setExpanded((e) => !e)}
              className="mt-1 font-mono text-[11px] tracking-[0.14em] text-accent hover:text-ink"
              aria-expanded={expanded}
            >
              {expanded ? 'COLLAPSE ▲' : 'READ FULL ADVISORY ▼'}
            </button>
          ) : null}
        </>
      ) : null}
    </header>
  );
}

/** Exported for the drawer: production layout with cinematic header when CINEMATIC. */
export function useCinematic() {
  return CINEMATIC;
}
