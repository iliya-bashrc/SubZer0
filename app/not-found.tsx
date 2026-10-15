'use client';

/*
 * 404 — "YOU FOUND NOTHING."
 *
 * SubZer0 treats a missing page like a suspicious incident, produces an
 * inconclusive report, and admits it found absolutely nothing. Probably.
 *
 * Static-export note: Next.js emits this component to out/404.html at the
 * repo root; GitHub Pages serves it for any unknown path. The homepage link
 * below uses the Next Link so basePath (/SubZer0) is applied automatically.
 * Palette here is page-local by design (editorial dark, single red accent).
 */

import Link from 'next/link';
import { useState } from 'react';

const PUNCHLINE = 'Probably.';
const UPDATE = 'UPDATE: Still nothing. Please stop escalating this.';

export default function NotFound() {
  const [escalated, setEscalated] = useState(false);

  return (
    <main
      className="relative flex min-h-dvh flex-col overflow-hidden bg-[#08090B] text-[#E4E4E7]"
      style={{
        fontFamily: 'var(--font-inter), system-ui, sans-serif',
        backgroundImage:
          'linear-gradient(#25272D08 1px, transparent 1px), linear-gradient(90deg, #25272D08 1px, transparent 1px)',
        backgroundSize: '56px 56px',
      }}
    >
      {/* ── top label ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between border-b border-[#25272D] px-5 py-3 sm:px-8">
        <span className="font-mono text-[11px] tracking-[0.18em] text-[#A1A1AA]">
          SUBZER0 / ROUTE ANALYSIS
        </span>
        <span className="flex items-center gap-1.5 font-mono text-[10px] tracking-[0.14em] text-[#A1A1AA]">
          <span className="h-1.5 w-1.5 rounded-full bg-[#E5484D]/70" />
          REPORT INCONCLUSIVE
        </span>
      </div>

      {/* ── main composition ──────────────────────────────────── */}
      <div className="flex flex-1 flex-col items-center justify-center px-6 py-14 text-center sm:px-8">
        <h1
          className="select-none font-display font-semibold leading-none tracking-[-0.04em] text-[#E4E4E7] text-[clamp(7rem,26vw,15rem)]"
          aria-label="404"
        >
          404
        </h1>

        <p className="mt-8 font-display text-lg font-medium tracking-[0.22em] text-[#E4E4E7] sm:text-xl">
          INTERESTING.
        </p>

        <p className="mt-5 max-w-xs text-[15px] leading-relaxed text-[#A1A1AA] sm:max-w-sm sm:text-base">
          You found a page
          <br />
          that doesn&apos;t exist.
        </p>

        <div className="my-9 h-px w-16 bg-[#25272D]" role="presentation" />

        <p className="text-[15px] text-[#A1A1AA] sm:text-base">
          We&apos;ve logged absolutely nothing.
        </p>

        <p className="mt-4">
          <button
            type="button"
            onClick={() => setEscalated((e) => !e)}
            aria-label={
              escalated
                ? 'Restore original incident report conclusion'
                : 'Escalate the incident report conclusion'
            }
            className="cursor-pointer rounded-sm bg-transparent text-lg font-display font-medium italic tracking-wide text-[#E5484D]
                       underline decoration-[#E5484D]/35 decoration-1 underline-offset-[6px]
                       transition-colors duration-150 hover:decoration-[#E5484D]/70
                       focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#E5484D]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-[#08090B]"
          >
            {escalated ? UPDATE : PUNCHLINE}
          </button>
        </p>

        <Link
          href="/"
          className="mt-12 inline-flex items-center gap-2 rounded-md border border-[#25272D] bg-transparent
                     px-6 py-3 font-mono text-[12px] tracking-[0.16em] text-[#E4E4E7]
                     transition-colors duration-150 hover:border-[#3a3d45] hover:bg-[#25272D14]
                     focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#E5484D]/50 focus-visible:ring-offset-2 focus-visible:ring-offset-[#08090B]"
        >
          <span aria-hidden="true" className="text-[#A1A1AA]">←</span>
          RETURN TO BASE
        </Link>
      </div>

      {/* ── metadata ──────────────────────────────────────────── */}
      <div className="border-t border-[#25272D] px-5 py-3 sm:px-8">
        <div className="mx-auto flex max-w-3xl flex-wrap items-center justify-center gap-x-8 gap-y-1 font-mono text-[10px] tracking-[0.14em] text-[#A1A1AA]">
          <span>FINDINGS: NONE</span>
          <span>CONFIDENCE: QUESTIONABLE</span>
        </div>
      </div>

      {/* ── footer signature ──────────────────────────────────── */}
      <footer className="pb-6 text-center">
        <span className="font-mono text-[10px] tracking-[0.3em] text-[#A1A1AA]/60">
          SUBZER0
        </span>
      </footer>
    </main>
  );
}
