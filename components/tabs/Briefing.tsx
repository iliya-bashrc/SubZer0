'use client';

import { useEffect, useState } from 'react';
import { HeroStrip } from '@/components/briefing/HeroStrip';
import { ActivityChart } from '@/components/briefing/ActivityChart';
import { KevAlert } from '@/components/briefing/KevAlert';
import { SourceGrid } from '@/components/briefing/SourceCard';
import { Stat } from '@/components/briefing/CountUp';

/**
 * Briefing (Section 7) — the home dashboard.
 *
 * Data source: /briefing.json, derived at BUILD TIME by
 * scripts/derive_briefing.mjs from the SHA-256-verified snapshot. The client
 * never fetches shards here and never invents numbers; if the derived file is
 * missing, a styled empty state is shown instead of a "waiting" placeholder.
 */
interface BriefingData {
  generated_at: string;
  window: { days: number; start: string; end: string };
  complete: boolean;
  totals: { cves: number; known_exploited: number; critical: number; high: number };
  daily: { date: string; count: number; critical: number; high: number; medium: number; low: number; exploited: number }[];
  kev: {
    id: string; title: string; score: number | null; sev: string;
    vendor: string | null; product: string | null; date_added: string | null;
    due_date: string | null; ransomware: string | null; published: string;
  }[];
  sources: { name: string; ok: boolean; checked_at: string; note?: string }[];
  epss: { scored_cves: number; records: number; score_date: string };
}

export function Briefing() {
  const [data, setData] = useState<BriefingData | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/briefing.json')
      .then((r) => {
        if (!r.ok) throw new Error(`briefing.json ${r.status}`);
        return r.json() as Promise<BriefingData>;
      })
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (failed) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <div className="card max-w-md p-6 text-center" role="alert">
          <div className="text-[13px] font-medium text-ink">Briefing data unavailable</div>
          <p className="mt-1.5 text-[12px] leading-relaxed text-ink-3">
            The derived briefing file could not be loaded. It is regenerated from the verified
            snapshot on every build.
          </p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="mx-auto grid h-full max-w-6xl grid-cols-1 content-center gap-4 px-4 py-6 sm:grid-cols-3" role="status" aria-label="Loading briefing">
        {[0, 1, 2].map((i) => (
          <div key={i} className="skeleton h-40 rounded-[14px] border border-line-soft bg-bg-raised" />
        ))}
      </div>
    );
  }

  const kevWindow = data.kev.filter((k) => {
    if (!k.date_added) return true;
    return k.date_added >= data.window.start.slice(0, 10);
  });

  return (
    <div className="mx-auto h-full max-w-[1200px] space-y-4 overflow-y-auto overscroll-contain px-4 py-6 pb-[calc(1.5rem+2.5rem)] sm:px-6" style={{ touchAction: 'pan-y' }}>
      <HeroStrip
        total={data.totals.cves}
        lastSync={data.generated_at}
        complete={data.complete}
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Total CVEs" value={data.totals.cves.toLocaleString('en-US')} sub="verified records" />
        <Stat label="Critical (30d)" value={data.totals.critical.toLocaleString('en-US')} sub={<span className="whitespace-nowrap">since {data.window.start.slice(0, 10)}</span>} />
        <Stat label="KEV active" value={data.kev.length.toLocaleString('en-US')} sub="CISA KEV catalog" />
        <Stat label="EPSS scored" value={`${data.epss.scored_cves.toLocaleString('en-US')}`} sub={<span className="whitespace-nowrap">of {data.epss.records.toLocaleString('en-US')}</span>} />
      </div>

      <div className="mt-10">
        <ActivityChart daily={data.daily} />
      </div>

      <div className="mt-10">
        <KevAlert items={kevWindow} />
      </div>

      <div className="mt-10">
        <SourceGrid sources={data.sources} />
      </div>

      <p className="pb-2 text-center text-[11px] text-ink-3">
        © 2026 SubZer0 — Educational use only
      </p>
    </div>
  );
}
