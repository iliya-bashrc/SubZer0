'use client';

import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';
import { getCve, fetchVerifiedJson, type CveRecord, type Manifest } from '@/lib/snapshot';
import { DossierContent } from '@/components/dossier/DossierContent';

interface DossierPanelProps {
  open: boolean;
  cveId: string | null;
  manifest: Manifest | null;
  shardMap: Record<string, string>;
  onClose: () => void;
}

/**
 * Research right drawer (Section 8) — STEP 5 restyle: flat elevated panel,
 * text-only header (mono CVE ID + severity dot), ghost close button.
 * Focus trap, Esc, backdrop, verified loader — all behavior unchanged.
 */
export function DossierPanel({ open, cveId, manifest, shardMap, onClose }: DossierPanelProps) {
  const [record, setRecord] = useState<CveRecord | null>(null);
  const [epssPercentile, setEpssPercentile] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const lastId = useRef<string | null>(null);
  const panelRef = useRef<HTMLElement>(null);

  // Esc to close + focus trap + focus move-in (Section 11)
  useEffect(() => {
    if (!open) return;

    const FOCUSABLE =
      'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const root = panelRef.current;
      if (!root) return;
      if (!root.contains(document.activeElement)) {
        e.preventDefault();
        root.querySelector<HTMLElement>(FOCUSABLE)?.focus();
        return;
      }
      const nodes = [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (n) => n.offsetParent !== null || n === document.activeElement,
      );
      if (nodes.length === 0) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      const activeEl = document.activeElement as HTMLElement | null;
      if (!e.shiftKey && activeEl === last) {
        e.preventDefault();
        first.focus();
      } else if (e.shiftKey && (activeEl === first || !root.contains(activeEl))) {
        e.preventDefault();
        last.focus();
      }
    };

    window.addEventListener('keydown', onKey);

    let tries = 0;
    let timer = 0;
    const moveFocus = () => {
      const root = panelRef.current;
      if (root) {
        const first = root.querySelector<HTMLElement>(FOCUSABLE);
        if (first) {
          if (!root.contains(document.activeElement)) first.focus();
          return;
        }
      }
      if (tries++ < 20) timer = window.setTimeout(moveFocus, 100);
    };
    timer = window.setTimeout(moveFocus, 0);

    return () => {
      window.clearTimeout(timer);
      window.removeEventListener('keydown', onKey);
    };
  }, [open, onClose]);

  // Verified record load + EPSS sidecar join (shared loader with the full page).
  useEffect(() => {
    if (!open || !cveId || !manifest) return;
    if (lastId.current === cveId && record) return;
    lastId.current = cveId;
    setError(null);
    setRecord(null);
    setEpssPercentile(null);
    (async () => {
      try {
        const rec = await getCve(manifest, shardMap, cveId);
        try {
          const epss = (await fetchVerifiedJson(
            `/snapshot/${manifest.epss.path}`,
            manifest.epss.sha256,
          )) as { scores?: Record<string, { score: number; percentile: number }> };
          const entry = epss.scores?.[cveId];
          if (entry) {
            rec.epss = entry.score;
            setEpssPercentile(entry.percentile);
          }
        } catch {
          /* score stays null — ScoreBreakdown shows the honest empty state */
        }
        setRecord(rec);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load verified record');
      }
    })();
  }, [open, cveId, manifest, shardMap, record]);

  return (
    <>
      {/* Backdrop: CSS-only fade. Do NOT drive it with AnimatePresence — its exit
          animation stalled and left a full-screen overlay (pointer-blocking)
          mounted forever. Removal is instant; the panel still slides out. */}
      {open && <div className="sz-backdrop fixed inset-0 z-40 bg-black/50" onClick={onClose} />}
      <AnimatePresence>
        {open && (
          <motion.aside
            ref={panelRef}
            key="panel"
            role="dialog"
            aria-label={cveId ? `Dossier for ${cveId}` : 'Dossier'}
            className="swiper-no-swiping fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col
                       border-l border-line bg-bg-elevated"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ duration: 0.4, ease: [0.32, 0.72, 0, 1] }}
          >
            {/* header strip */}
            <div className="flex items-center justify-between border-b border-line px-5 py-4">
              <div className="min-w-0">
                {record ? (
                  <>
                    <div className="truncate font-mono text-[15px] font-semibold text-ink">
                      {record.id}
                    </div>
                    {record.sev && record.sev !== 'none' && record.sev !== 'unknown' ? (
                      <span className={`sev mt-1.5 sev--${record.sev}`} aria-label={`${record.sev} severity`}>
                        {record.sev.charAt(0).toUpperCase() + record.sev.slice(1)}
                        {record.score != null && record.score > 0 ? ` · CVSS ${record.score.toFixed(1)}` : ''}
                      </span>
                    ) : null}
                  </>
                ) : (
                  <div
                    role={error ? 'alert' : 'status'}
                    aria-live="polite"
                    className="text-[13px] text-ink-3"
                  >
                    {error ? 'Verification failed' : 'Loading verified record…'}
                  </div>
                )}
              </div>
              <button
                onClick={onClose}
                aria-label="Close dossier"
                className="rounded-md p-1.5 text-ink-3 transition-colors hover:bg-bg-hover hover:text-ink"
              >
                <X size={16} strokeWidth={1.5} />
              </button>
            </div>

            {/* body — SHARED component */}
            <div
              className="flex-1 space-y-8 overflow-y-auto overscroll-contain px-5 py-6"
              style={{ touchAction: 'pan-y' }}
            >
              {error && (
                <div className="rounded-lg border border-line p-4 text-[13px]" style={{ color: 'var(--color-critical)' }}>
                  {error}
                </div>
              )}
              {record && (
                <DossierContent record={record} epssPercentile={epssPercentile} />
              )}
              {/* Section 12: 1-line disclaimer pinned at the drawer bottom. */}
              <p className="select-text border-t border-line pt-3 text-[11px] leading-relaxed text-ink-3">
                © 2026 SubZer0 — Educational use only. Do not use against systems you do not own.
              </p>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>
    </>
  );
}
