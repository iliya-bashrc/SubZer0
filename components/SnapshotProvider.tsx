'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import {
  loadManifest,
  loadSearchIndex,
  toListItem,
  type CveListItem,
  type Manifest,
} from '@/lib/snapshot';

interface SnapshotState {
  manifest: Manifest | null;
  index: CveListItem[];
  loading: boolean;
  error: string | null;
}

const SnapshotContext = createContext<SnapshotState>({
  manifest: null,
  index: [],
  loading: true,
  error: null,
});

export function useSnapshot(): SnapshotState {
  return useContext(SnapshotContext);
}

export function SnapshotProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<SnapshotState>({
    manifest: null,
    index: [],
    loading: true,
    error: null,
  });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const manifest = await loadManifest();
        const tuples = await loadSearchIndex(manifest);
        if (cancelled) return;
        setState({ manifest, index: tuples.map(toListItem), loading: false, error: null });
      } catch (err) {
        if (cancelled) return;
        setState({
          manifest: null,
          index: [],
          loading: false,
          error: err instanceof Error ? err.message : 'Snapshot failed integrity verification',
        });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return <SnapshotContext.Provider value={state}>{children}</SnapshotContext.Provider>;
}
