'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useSnapshot } from '@/components/SnapshotProvider';
import { fetchVerifiedJson, getCve, type CveRecord } from '@/lib/snapshot';
import { DossierContent } from '@/components/dossier/DossierContent';
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
          `/snapshot/${manifest.shard_map.path}`,
          manifest.shard_map.sha256,
        )) as Record<string, string>;
        const rec = await getCve(manifest, shardMap, cveId);
        if (cancelled) return;
        // Join EPSS score from the verified sidecar (not present in shard records).
        try {
          const epss = (await fetchVerifiedJson(
            `/snapshot/${manifest.epss.path}`,
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

  const sevKnown = SEV_VAR[record.sev] != null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.32, 0.72, 0, 1] }}
      className="mx-auto h-full max-w-3xl space-y-8 overflow-y-auto overscroll-contain px-4 py-6 sm:px-6"
      style={{ touchAction: 'pan-y' }}
    >
      {/* 1. Header strip — text-first hero; Critical gets the single allowed pill */}
      <header>
        <h1 className="font-mono text-[28px] font-semibold tracking-[-0.01em] text-ink">
          {record.id}
        </h1>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          {record.sev === 'critical' ? (
            <span className="sev-hero-critical" aria-label="critical severity">Critical</span>
          ) : sevKnown ? (
            <span className={`sev sev--${record.sev}`} aria-label={`${record.sev} severity`}>
              {record.sev.charAt(0).toUpperCase() + record.sev.slice(1)}
            </span>
          ) : null}
          <span className="font-mono text-[12px] text-ink-3">
            published {record.published.slice(0, 10)} · modified {record.modified.slice(0, 10)}
          </span>
          {record.score != null && record.score > 0 && (
            <span className="font-mono text-[12px] text-ink-3">CVSS {record.score.toFixed(1)}</span>
          )}
        </div>
      </header>

      {/* 2..6 — SHARED dossier body (Description → Scores → Exploit intel → Affected → References) */}
      <DossierContent
        record={record}
        epssPercentile={epssPercentile}
        related={
          /* 7. Related CVEs — full-page-only slot */
          <RelatedCves
            record={record}
            shardRecords={shardRecords}
            onSelect={(id) => {
              window.location.href = `/cve/${id}/`;
            }}
          />
        }
      />
    </motion.div>
  );
}

/** In-app destination: ?cve=CVE-… deep link, or the empty guidance state. */
export function Dossier() {
  const [cveId, setCveId] = useState<string | null>(null);

  useEffect(() => {
    const read = () => {
      const params = new URLSearchParams(window.location.search);
      setCveId(params.get('cve'));
    };
    read();
    window.addEventListener('popstate', read);
    return () => window.removeEventListener('popstate', read);
  }, []);

  if (!cveId) {
    return (
      <div className="flex h-full items-center justify-center p-6" style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}>
        <div className="card max-w-md p-6 text-center">
          <div className="font-mono text-[13px]" style={{ color: 'var(--color-accent)' }}>Dossier</div>
          <p className="mt-2 text-[12px] leading-relaxed text-ink-3">
            Open a CVE from Research, or navigate to{' '}
            <code className="font-mono text-ink-2">/cve/CVE-XXXX-YYYY/</code> for a direct deep-dive. Every record
            is SHA-256 verified before display.
          </p>
        </div>
      </div>
    );
  }
  return <DossierView cveId={cveId} />;
}
