'use client';

import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { SEARCH_FOCUS_EVENT } from '@/lib/hotkeys';
import { useSnapshot } from '@/components/SnapshotProvider';
import { search, DEFAULT_FILTERS, fetchVerifiedJson, type Filters } from '@/lib/snapshot';
import { SearchBar } from '@/components/research/SearchBar';
import { FilterRail } from '@/components/research/FilterRail';
import { ResultsTable } from '@/components/research/ResultsTable';
import { DossierPanel } from '@/components/research/DossierPanel';

/**
 * Public PoC ids are derived at build time from verified shard data — the only
 * records counted are those with a reference explicitly tagged "Exploit" or
 * "PoC" by the upstream sources. Never invented client-side.
 */
function usePocIds(): Set<string> | null {
  const { manifest } = useSnapshot();
  const [pocIds, setPocIds] = useState<Set<string> | null>(null);
  useEffect(() => {
    if (!manifest) return;
    let cancelled = false;
    (async () => {
      // Single compact fetch (~3 KB) — the updater derives the exploit-tagged
      // id list server-side now, so the client no longer downloads all 31 day
      // shards (~6 MB) just to build this set. Cache in module scope.
      const cached = (globalThis as { __szPocIds?: Set<string> }).__szPocIds;
      if (cached) {
        setPocIds(cached);
        return;
      }
      try {
        const { fetchVerifiedJson } = await import('@/lib/snapshot');
        const pocMeta = (manifest as { poc_ids?: { path: string; sha256: string } }).poc_ids;
        if (!pocMeta) throw new Error('manifest has no poc_ids section');
        const ids = (await fetchVerifiedJson(
          `${process.env.__NEXT_ROUTER_BASEPATH || ''}/snapshot/${pocMeta.path}`,
          pocMeta.sha256,
        )) as string[];
        const set = new Set(ids);
        (globalThis as { __szPocIds?: Set<string> }).__szPocIds = set;
        if (!cancelled) setPocIds(set);
      } catch {
        if (!cancelled) setPocIds(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [manifest]);
  return pocIds;
}

export function Research() {
  const { manifest, index, loading, error } = useSnapshot();
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState<Filters>({ ...DEFAULT_FILTERS, severities: new Set() });
  const [railOpen, setRailOpen] = useState(false);
  const [dossierId, setDossierId] = useState<string | null>(null);
  const [dossierOpen, setDossierOpen] = useState(false);
  const [shardMap, setShardMap] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!manifest) return;
    let cancelled = false;
    fetchVerifiedJson(
      `${process.env.__NEXT_ROUTER_BASEPATH || ''}/snapshot/${manifest.shard_map.path}`,
      manifest.shard_map.sha256,
    )
      .then((m) => {
        if (!cancelled) setShardMap(m as Record<string, string>);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [manifest]);

  const deferredQuery = useDeferredValue(query);

  // Section 11: Ctrl/⌘+K from anywhere focuses the search field.
  useEffect(() => {
    const onFocusRequest = () => {
      const input = document.querySelector<HTMLInputElement>(
        "input[aria-label='Search vulnerabilities']",
      );
      input?.focus();
      input?.select();
    };
    window.addEventListener(SEARCH_FOCUS_EVENT, onFocusRequest);
    return () => window.removeEventListener(SEARCH_FOCUS_EVENT, onFocusRequest);
  }, []);
  const pocIds = usePocIds();

  const rows = useMemo(
    () => search(index, deferredQuery, filters, pocIds),
    [index, deferredQuery, filters, pocIds],
  );

  const returnFocusRef = useRef<HTMLElement | null>(null);

  const openDossier = useCallback((id: string, trigger?: HTMLElement | null) => {
    // Section 11: remember the trigger (mouse clicks leave focus on BODY) so focus
    // can be restored to it — or to the results region — on close.
    const active = document.activeElement as HTMLElement | null;
    returnFocusRef.current =
      trigger ?? (active && active !== document.body ? active : null);
    setDossierId(id);
    setDossierOpen(true);
  }, []);

  const closeDossier = useCallback(() => setDossierOpen(false), []);

  // History-aware drawer: opening pushes a history entry so the browser/app Back
  // gesture (Android habit) closes the drawer instead of leaving the app.
  const pushedRef = useRef(false);
  useEffect(() => {
    if (dossierOpen && !pushedRef.current) {
      pushedRef.current = true;
      window.history.pushState({ szDrawer: true }, '');
    } else if (!dossierOpen && pushedRef.current) {
      pushedRef.current = false;
      // We initiated the close (Esc / backdrop / X): consume the pushed entry
      // silently. A popstate-driven close resets the flag before this runs.
      window.history.back();
    }
  }, [dossierOpen]);
  useEffect(() => {
    const onPop = () => {
      if (pushedRef.current) {
        pushedRef.current = false;
        setDossierOpen(false);
      }
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  // Restore focus to the triggering row (or the results region) once closed.
  useEffect(() => {
    if (dossierOpen) return;
    const target = returnFocusRef.current;
    if (!target) return;
    returnFocusRef.current = null;
    const t = window.setTimeout(() => {
      // TanStack Virtual may recycle the row node; fall back to the results region.
      if (target.isConnected) target.focus?.();
      else document.querySelector<HTMLElement>('[data-results-table]')?.focus?.();
    }, 60);
    return () => window.clearTimeout(t);
  }, [dossierOpen]);

  if (error) {
    return (
      <div className="flex h-full items-center justify-center p-6" style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}>
        <div className="max-w-md text-center" role="alert">
          <div className="cine-chip" style={{ background: 'var(--color-critical)', color: '#0B0B0E' }}>INTEGRITY FAILURE</div>
          <p className="mt-2 text-[12px] leading-relaxed text-ink-2">{error}</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center p-6" style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}>
        <div className="px-8 py-6 text-center" role="status" aria-live="polite">
          <div className="cine-label">VERIFYING SNAPSHOT…</div>
          <div className="mt-1 text-[12px] text-ink-3">
            SHA-256 checking manifest, index and shards before display.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col" style={{ touchAction: 'pan-y', overscrollBehavior: 'contain' }}>
      <SearchBar value={query} onChange={setQuery} resultCount={rows.length} totalCount={index.length} />

      <div className="flex min-h-0 flex-1">
        {/* mobile rail toggle */}
        <button
          onClick={() => setRailOpen((v) => !v)}
          aria-label={railOpen ? 'Hide filters' : 'Show filters'}
          aria-expanded={railOpen}
          className="absolute right-3 top-[76px] z-30 mb-2 rounded-md border border-line-soft bg-bg-raised/90 px-3 py-1.5
                     text-[11px] text-ink-2  lg:hidden"
        >
          {railOpen ? 'Hide filters' : 'Filters'}
        </button>

        <div className={`${railOpen ? 'block' : 'hidden'} lg:block`}>
          <FilterRail filters={filters} onChange={setFilters} />
        </div>

        <div className="min-w-0 flex-1">
          {/* mt for mobile only: keep the floating filters chip clear of card 1 */}
          <div className="mt-0 lg:mt-0 max-lg:pt-14 h-full">
            <ResultsTable
              rows={rows}
              onOpen={openDossier}
              onResetFilters={() => setFilters({ ...DEFAULT_FILTERS, severities: new Set() })}
            />
          </div>
        </div>
      </div>

      <DossierPanel
        open={dossierOpen}
        cveId={dossierId}
        manifest={manifest}
        shardMap={shardMap}
        onClose={closeDossier}
      />
    </div>
  );
}
