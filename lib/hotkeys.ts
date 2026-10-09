'use client';

/**
 * Keyboard hotkeys (Section 11).
 *   Ctrl+1..4 → destinations · Ctrl+K → focus search · Escape → handled per component.
 * Uses a native window keydown listener (no extra dependency).
 */
import { useEffect } from 'react';

export function useGlobalHotkeys(opts: {
  onTab: (index: number) => void;
  onSearch?: () => void;
}) {
  const { onTab, onSearch } = opts;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      if (e.key >= '1' && e.key <= '4') {
        e.preventDefault();
        onTab(Number(e.key) - 1);
        return;
      }
      if (e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onSearch?.();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onTab, onSearch]);
}

/** Ctrl+K / ⌘K focus intent shared between AppShell and Research. */
export const SEARCH_FOCUS_EVENT = 'subzero:focus-search';

export function requestSearchFocus() {
  window.dispatchEvent(new CustomEvent(SEARCH_FOCUS_EVENT));
}
