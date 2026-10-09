'use client';

/**
 * Footer integration wrapper (Section 12): binds the presentational Footer to
 * the verified snapshot's last-sync timestamp.
 */
import { Footer } from '@/components/shell/Footer';
import { useSnapshot } from '@/components/SnapshotProvider';

export function SiteFooter() {
  const { manifest } = useSnapshot();
  return <Footer lastSync={manifest?.generated_at ?? null} />;
}
