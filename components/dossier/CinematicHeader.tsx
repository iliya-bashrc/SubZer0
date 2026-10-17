'use client';

/*
 * CINEMATIC DOSSIER HERO — prototype/cinematic-dossier branch only. v2.
 *
 * Full-bleed editorial composition (NOT a dashboard card): a filled
 * rectangular severity label in oversized contrast to a geometric CVE
 * identifier, set on a layered atmospheric scene — deep blue-black base,
 * teal ambience + severity-colored key light, cool counter-light, film
 * texture, vignette. Visual language inspired by the described VisionQuest
 * end-credit typography; an original composition, not a reproduction.
 * All data comes from the verified record — nothing fabricated.
 */

import { useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import type { CveRecord } from '@/lib/snapshot';

/** Restrained teal for secondary technical info (direction §3). */
const TEAL = '#6FA8B8';

const SEV_LABEL: Record<string, string> = {
  critical: 'CRITICAL VULNERABILITY',
  high: 'HIGH SEVERITY',
  medium: 'MODERATE SEVERITY',
  low: 'LOW SEVERITY',
  none: 'UNSCORED ADVISORY',
  unknown: 'UNSCORED ADVISORY',
};

/** severity → (label fill, label ink, key light color). Red/amber family. */
function sevPalette(sev: string): { fill: string; ink: string; light: string } {
  switch (sev) {
    case 'critical': return { fill: 'var(--color-critical)', ink: '#0B0B0E', light: 'var(--color-critical)' };
    case 'high':     return { fill: 'var(--color-high)',    ink: '#0B0B0E', light: 'var(--color-high)' };
    case 'medium':   return { fill: 'var(--color-medium)',  ink: '#0B0B0E', light: 'var(--color-medium)' };
    case 'low':      return { fill: 'var(--color-low)',     ink: '#0B0B0E', light: 'var(--color-accent)' };
    default:         return { fill: '#2A2F3A',              ink: 'var(--color-ink-2)', light: 'var(--color-accent)' };
  }
}

export function CinematicHeader({ record, onClose, standalone = true }: {
  record: CveRecord; onClose?: () => void; standalone?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const pal = sevPalette(record.sev);
  const label = SEV_LABEL[record.sev] ?? SEV_LABEL.unknown;

  return (
    <section
      className="relative isolate overflow-hidden"
      aria-label={`${record.id} vulnerability dossier`}
      style={{ background: '#05070C' }}
    >
      {/* ── atmospheric scene: layered light, texture, vignette ───────── */}
      <div aria-hidden="true" className="pointer-events-none absolute inset-0">
        {/* deep teal ambience — large soft source, upper left */}
        <div
          className="absolute -left-40 -top-56 h-[80vh] w-[90vw] rounded-full opacity-[0.28] blur-[130px]"
          style={{ background: 'radial-gradient(closest-side, #1E5F74, transparent)' }}
        />
        {/* key light — severity-colored warm source, right of center */}
        <div
          className="absolute right-[8%] top-[22%] h-[46vh] w-[52vw] rounded-full opacity-[0.22] blur-[110px]"
          style={{ background: `radial-gradient(closest-side, ${pal.light}, transparent)` }}
        />
        {/* cool counter-light, bottom left */}
        <div
          className="absolute -bottom-48 left-[15%] h-[38vh] w-[46vw] rounded-full opacity-[0.14] blur-[100px]"
          style={{ background: 'radial-gradient(closest-side, #23425E, transparent)' }}
        />
        {/* fine technical texture: sparse grid + scanline grain */}
        <div
          className="absolute inset-0 opacity-[0.05]"
          style={{
            backgroundImage:
              'linear-gradient(#7A8CA012 1px, transparent 1px), linear-gradient(90deg, #7A8CA012 1px, transparent 1px)',
            backgroundSize: '64px 64px',
          }}
        />
        <div
          className="absolute inset-0 opacity-[0.035]"
          style={{ backgroundImage: 'repeating-linear-gradient(0deg, #FFFFFF14 0 1px, transparent 1px 3px)' }}
        />
        {/* fine noise dither — prevents gradient banding on dark glows */}
        <div
          className="absolute inset-0 opacity-[0.04]"
          style={{
            backgroundImage:
              'url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'120\' height=\'120\'%3E%3Cfilter id=\'n\'%3E%3CfeTurbulence type=\'fractalNoise\' baseFrequency=\'0.9\' numOctaves=\'2\'/%3E%3C/filter%3E%3Crect width=\'120\' height=\'120\' filter=\'url(%23n)\' opacity=\'0.5\'/%3E%3C/svg%3E")',
          }}
        />
        {/* vignette to pull focus into the composition */}
        <div
          className="absolute inset-0"
          style={{ background: 'radial-gradient(120% 90% at 50% 30%, transparent 40%, #05070CE6 100%)' }}
        />
      </div>

      {/* ── composition ───────────────────────────────────────────────── */}
      <motion.div
        initial={useReducedMotion() ? false : { opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
        className="relative z-10 flex min-h-[100vh] supports-[height:100svh]:min-h-[100svh] flex-col
                   px-6 pb-10 pt-24 sm:px-10 sm:pb-14 sm:pt-28 lg:px-20 lg:pb-16 lg:pt-36"
      >
        {/* filled rectangular label — kept in one lockup with the identifier
            (mt-auto pushes the whole lockup down together) */}
        <div className="mt-auto flex flex-wrap items-center gap-3">
          <motion.span
            initial={useReducedMotion() ? false : { opacity: 0, scaleX: 0.6 }}
            animate={{ opacity: 1, scaleX: 1 }}
            transition={{ duration: 0.5, delay: 0.15, ease: [0.16, 1, 0.3, 1] }}
            className="inline-block origin-left px-3 py-[6px] font-mono text-[11px] font-semibold uppercase tracking-[0.16em]"
            style={{ background: pal.fill, color: pal.ink }}
          >
            {record.sev.charAt(0).toUpperCase() + record.sev.slice(1) + ' SEVERITY'}
          </motion.span>
          {record.kev ? (
            <span
              className="inline-block border px-3 py-[6px] font-mono text-[11px] uppercase tracking-[0.16em]"
              style={{ borderColor: pal.light, color: pal.light }}
            >
              CISA KEV LISTED
            </span>
          ) : null}
        </div>

        {/* the identifier — the main visual headline, oversized with deliberate
            negative space; lg pushes it off-left for an asymmetrical title card */}
        <h1
          className="select-text break-words font-display font-semibold leading-[0.92] tracking-[-0.05em] text-ink
                     text-[clamp(3.4rem,12vw,11rem)] lg:-ml-2"
        >
          {/* break only after hyphens — never mid-number (no orphaned digits) */}
          {record.id.split('-').map((part, i, arr) => (
            <span key={i}>
              {part}
              {i < arr.length - 1 ? (
                <>
                  <wbr />-
                </>
              ) : null}
            </span>
          ))}
        </h1>

        {/* short summary — hierarchy C, right after the title */}
        {record.desc ? (
          <div className="mt-6 max-w-xl">
            <p className={`text-[15px] leading-[1.65] text-ink-2 brightness-110 ${expanded ? '' : 'line-clamp-3'}`}>
              {record.desc}
            </p>
            {record.desc.length > 180 ? (
              <button
                onClick={() => setExpanded((e) => !e)}
                aria-expanded={expanded}
                className="mt-2 inline-block font-mono text-[11px] tracking-[0.16em] hover:text-ink"
                style={{ color: TEAL }}
              >
                {expanded ? 'COLLAPSE ▲' : 'READ FULL ADVISORY ▼'}
              </button>
            ) : null}
          </div>
        ) : null}

        {/* editorial meta row — hierarchy D; teal accents on the values' labels */}
        <dl className="mt-8 grid grid-cols-2 gap-x-6 gap-y-4 border-t border-ink/15 pt-5 sm:grid-cols-4">
          {[
            { k: 'PUBLISHED', v: record.published?.slice(0, 10) ?? '—' },
            { k: 'SEVERITY', v: record.sev.charAt(0).toUpperCase() + record.sev.slice(1), sev: pal.fill },
            { k: 'CVSS', v: record.score != null && record.score > 0 ? record.score.toFixed(1) : '—' },
            { k: 'KEV', v: record.kev ? `Listed ${record.kev.date_added}` : 'Not listed' },
          ].map((m, i) => (
            <div key={m.k} className={`min-w-24 ${i === 3 ? "sm:text-right" : ""}`}>
              <dt className="font-mono text-[10px] tracking-[0.18em]" style={{ color: '#8FBFCB' }}>{m.k}</dt>
              <dd className="mt-1 font-mono text-[15px] text-ink" style={m.sev ? { color: m.sev } : undefined}>{m.v}</dd>
            </div>
          ))}
        </dl>

        {/* onClose intentionally not rendered inside the v2 composition: the
            deep-link page has browser navigation, and the drawer's close
            control lives on the panel chrome above this hero. */}
        {onClose ? null : null}
      </motion.div>
    </section>
  );
}
