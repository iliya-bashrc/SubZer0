import type { Metadata } from 'next';
import { SnapshotProvider } from '@/components/SnapshotProvider';
import { DossierView } from '@/components/tabs/Dossier';
import shardMap from '@/public/snapshot/data/shard_map.json';

interface Props {
  params: Promise<{ id: string }>;
}

/**
 * Static deep-link route for a single CVE dossier (Section 9). The body is the
 * shared DossierView — identical content blocks to the Research drawer
 * (PATCH REQUEST: one DossierContent component, two wrappers).
 *
 * output: 'export' requires every page to exist at build time, so each CVE in
 * the verified manifest is pre-rendered. Extra serialized props stay minimal:
 * the page shell is static and the record itself is fetched client-side from
 * the SHA-256-verified snapshot.
 */
export function generateStaticParams(): { id: string }[] {
  return Object.keys(shardMap).map((id) => ({ id }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  return { title: `${decodeURIComponent(id)} — SubZer0 Dossier` };
}

export default async function CveDossierPage({ params }: Props) {
  const { id } = await params;
  return (
    <SnapshotProvider>
      <DossierView cveId={decodeURIComponent(id)} />
    </SnapshotProvider>
  );
}
