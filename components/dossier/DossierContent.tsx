'use client';

import { memo } from 'react';
import type { CveRecord } from '@/lib/snapshot';
import { ScoreBreakdown } from '@/components/dossier/ScoreBreakdown';
import { ExploitIntel } from '@/components/dossier/ExploitIntel';
import { AffectedProducts } from '@/components/dossier/AffectedProducts';
import { ReferenceList } from '@/components/dossier/ReferenceList';

/**
 * Shared dossier body — PATCH REQUEST §5: the Research drawer and the
 * /cve/[id] full-page view are two wrappers around THIS component.
 * Block order: Description → Scores → Exploit intel → Affected (deduped) →
 * References. `related` is an optional slot (full page only).
 */
interface DossierContentProps {
  record: CveRecord;
  epssPercentile: number | null;
  related?: React.ReactNode;
}

export const DossierContent = memo(function DossierContent({
  record,
  epssPercentile,
  related,
}: DossierContentProps) {
  return (
    <>
      {/* Description */}
      <section>
        <h3 className="label-xs mb-2">Description</h3>
        <p className="text-[13px] leading-relaxed text-ink">{record.desc}</p>
      </section>

      {/* Scores (vector string / circular CVSS gauge / EPSS + percentile) */}
      <ScoreBreakdown
        cvssScore={record.score}
        epssScore={record.epss ?? null}
        epssPercentile={epssPercentile}
        severity={record.sev}
      />

      {/* Exploit intelligence (KEV moved here per patch §5b) */}
      <ExploitIntel record={record} checkedAt={record.activity_at ?? record.published ?? null} />

      {/* Affected — deduped by vendor/product (patch §4) */}
      <AffectedProducts affected={record.affected ?? []} />

      {/* References (domain preview rows, patch §6) */}
      <ReferenceList refs={record.refs ?? []} />

      {related}
    </>
  );
});
