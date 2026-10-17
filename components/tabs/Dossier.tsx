'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useSnapshot } from '@/components/SnapshotProvider';
import { fetchVerifiedJson, getCve, type CveRecord } from '@/lib/snapshot';
import { DossierContent } from '@/components/dossier/DossierContent';
import { CinematicHeader } from '@/components/dossier/CinematicHeader';
import { RelatedCves } from '@/components/dossier/RelatedCves';

const SEV_VAR: Record<string, string | null> = {
  critical: 'var(--color-critical)',
  high: 'var(--color-high)',
  medium: 'var(--color-medium)',
  low: 'var(--color-low)',
  none: null,
  unknown: null, // missing data → render nothing (never the word "UNKNOWN")
};

/**
 * Full-page Dossier tab (Section 9). Directly accessible via /cve/<id>/ in the
 * static export (app/cve/[id]/page.tsx) and used in-app when a CVE is opened
 * as a destination (via ?cve= query). PATCH REQUEST: the body is the SHARED
 * DossierContent component — identical blocks to the Research drawer; this
 * wrapper adds the header strip and Related CVEs slot only. All content
 * derives from SHA-256-verified snapshot data.
 */
export function DossierView({ cveId }: { cveId: string }) {
  const { manifest } = useSnapshot();
  const [record, setRecord] = useState<CveRecord | null>(null);
  const [shardRecords, setShardRecords] = useState<CveRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [epssPercentile, setEpssPercentile] = useState<number | null>(null);

  useEffect(() => {
    if (!manifest || !cveId) return;
    let cancelled = false;
    setError(null);
    setRecord(null);
    setShardRecords([]);
    setEpssPercentile(null);
    (async () => {
      try {
        const shardMap = (await fetchVerifiedJson(
          `${process.env.__NEXT_ROUTER_BASEPATH || ''}/snapshot/${manifest.shard_map.path}`,
          manifest.shard_map.sha256,
        )) as Record<string, string>;
        const rec = await getCve(manifest, shardMap, cveId);
        if (cancelled) return;
        // Join EPSS score from the verified sidecar (not present in shard records).
        try {
          const epss = (await fetchVerifiedJson(
            `${process.env.__NEXT_ROUTER_BASEPATH || ''}/snapshot/${manifest.epss.path}`,
            manifest.epss.sha256,
          )) as { scores?: Record<string, { score: number; percentile: number }> };
          const entry = epss.scores?.[cveId];
          if (entry && !cancelled) {
            rec.epss = entry.score;
            setEpssPercentile(entry.percentile);
          }
        } catch {
          /* score/percentile stay null — ScoreBreakdown shows the honest empty state */
        }
        if (cancelled) return;
        setRecord(rec);
        // Shard records power the "related" sections (verified, same window day).
        const day = manifest.days.find((d) => d.date === rec.window_date);
        if (day) {
          const { loadDayShard } = await import('@/lib/snapshot');
          const recs = await loadDayShard(manifest, day.date);
          if (!cancelled) setShardRecords(recs);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load verified record');
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [manifest, cveId]);

  if (error) {
    return (
      <div className="flex h-full items-center justify-center p-6" style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}>
        <div className="card max-w-md p-6 text-center" role="alert">
          <div className="font-mono text-[13px]" style={{ color: 'var(--color-critical)' }}>
            record unavailable
          </div>
          <p className="mt-2 text-[12px] leading-relaxed text-ink-2">{error}</p>
        </div>
      </div>
    );
  }

  if (!record) {
    return (
      <div className="flex h-full items-center justify-center p-6" style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}>
        <div className="card px-8 py-6 text-center" role="status" aria-live="polite">
          <div className="font-mono text-[13px]" style={{ color: 'var(--color-accent)' }}>
            verifying {cveId}…
          </div>
          <div className="mt-1 text-[12px] text-ink-3">SHA-256 checking shard before display.</div>
        </div>
      </div>
    );
  }

  void SEV_VAR; // severity chips moved to CinematicHeader (branch prototype)

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.32, 0.72, 0, 1] }}
      className="h-full overflow-y-auto overscroll-contain bg-[#05070C]"
      style={{ touchAction: 'pan-y' }}
    >
      {/* 1. Header — cinematic prototype hero (branch-only). Full-bleed:
          negative margins cancel the column padding so the atmosphere owns
          the whole viewport width, like a title card. */}
      <div className="-mx-4 sm:-mx-6">
        <CinematicHeader record={record} onClose={undefined} standalone />
      </div>

      {/* 2..6 — SHARED dossier body (Scores → Exploit intel → Affected → References);
          description lives in the cinematic header teaser on this branch.
          Full-bleed column: hero + body both own the viewport width, with an
          inner prose measure so text stays readable. */}
      <div className="mx-auto max-w-5xl px-6 pb-16 pt-10 sm:px-10 lg:px-16">
        <DossierContent
          record={record}
          epssPercentile={epssPercentile}
          hideDescription
          related={
            /* 7. Related CVEs — full-page-only slot */
            <RelatedCves
              record={record}
              shardRecords={shardRecords}
              onSelect={(id) => {
                window.location.href = `${process.env.__NEXT_ROUTER_BASEPATH || ''}/cve/${id}/`;
              }}
            />
          }
        />
      </div>
    </motion.div>
  );
}

/**
 * In-app destination. Empty state = a real CVE lookup: paste any CVE ID and the
 * verified dossier opens here (plus one-click jump into the newest records).
 * ?cve=CVE-… deep links skip straight to DossierView.
 */
const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

export function Dossier() {
  const [cveId, setCveId] = useState<string | null>(null);
  const { index } = useSnapshot();

  useEffect(() => {
    const read = () => {
      const params = new URLSearchParams(window.location.search);
      setCveId(params.get('cve'));
    };
    read();
    window.addEventListener('popstate', read);
    return () => window.removeEventListener('popstate', read);
  }, []);

  const openCve = (id: string) => {
    const base = process.env.__NEXT_ROUTER_BASEPATH || '';
    window.location.href = `${base}/cve/${encodeURIComponent(id.toUpperCase())}/`;
  };

  const recent = index.slice(0, 6);

  if (!cveId) {
    return (
      <div className="h-full overflow-y-auto overscroll-contain" style={{ touchAction: 'pan-y' }}>
        <div className="mx-auto max-w-md space-y-5 px-4 py-10">
          <div className="card p-6">
            <div className="font-mono text-[13px]" style={{ color: 'var(--color-accent)' }}>Dossier lookup</div>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const data = new FormData(event.currentTarget);
                const value = String(data.get('cve') || '').trim().toUpperCase();
                if (CVE_ID_RE.test(value)) openCve(value);
              }}
              className="mt-4"
            >
              <input
                name="cve"
                required
                title="CVE-YYYY-NNNN+ (digits only after the year)"
                placeholder="CVE-2026-97471"
                aria-label="CVE ID"
                spellCheck={false}
                autoCapitalize="characters"
                className="w-full rounded-lg border border-line bg-bg-raised px-4 py-3 font-mono text-[14px] text-ink
                           placeholder:text-ink-3 focus:border-accent focus:outline-none"
              />
              <button
                type="submit"
                className="mt-3 w-full rounded-lg px-4 py-2.5 text-[13px] font-medium text-bg
                           transition-opacity hover:opacity-90"
                style={{ backgroundColor: 'var(--color-accent)' }}
              >
                Open dossier
              </button>
            </form>
            <p className="mt-3 text-[11px] leading-relaxed text-ink-3">
              Every record is SHA-256 verified before display.
            </p>
          </div>

          {recent.length > 0 && (
            <div className="card p-6">
              <div className="font-mono text-[11px] uppercase tracking-wide text-ink-3">Newest in window</div>
              <ul className="mt-3 space-y-1">
                {recent.map((item) => (
                  <li key={item.id}>
                    <button
                      onClick={() => openCve(item.id)}
                      className="flex w-full items-baseline justify-between gap-3 rounded-md px-2 py-2 text-left
                                 transition-colors hover:bg-bg-hover"
                    >
                      <span className="truncate font-mono text-[12px] text-accent">{item.id}</span>
                      <span className="shrink-0 font-mono text-[11px] text-ink-3">{item.publishedDate}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    );
  }
  return <DossierView cveId={cveId} />;
}
