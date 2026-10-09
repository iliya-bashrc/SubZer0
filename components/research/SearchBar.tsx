'use client';

import { memo, useEffect, useRef, useState } from 'react';

interface SearchBarProps {
  value: string;
  onChange: (next: string) => void;
  resultCount: number;
  totalCount: number;
}

/**
 * SearchBar — STEP 4: single bordered input, Inter 13px (no mono except
 * kbd + counts), focus ring = --accent 3px, ghost kbd hint.
 * Debounce 300ms + Ctrl+K focus (Section 8) unchanged.
 */
export const SearchBar = memo(function SearchBar({
  value,
  onChange,
  resultCount,
  totalCount,
}: SearchBarProps) {
  const [local, setLocal] = useState(value);
  const inputRef = useRef<HTMLInputElement>(null);

  // Keep local in sync when the parent resets the query.
  useEffect(() => {
    setLocal(value);
  }, [value]);

  // Debounce 300ms
  useEffect(() => {
    if (local === value) return;
    const t = setTimeout(() => onChange(local), 300);
    return () => clearTimeout(t);
  }, [local, value, onChange]);

  // Command-K to focus
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="sticky top-0 z-20 bg-bg">
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <input
            ref={inputRef}
            value={local}
            onChange={(e) => setLocal(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setLocal('');
                onChange('');
                (e.target as HTMLInputElement).blur();
              }
            }}
            placeholder="Search CVE ID, vendor, product…"
            aria-label="Search vulnerabilities"
            className="w-full rounded-lg border border-line bg-bg px-3.5 py-2 pr-16
                       text-[13px] text-ink placeholder:text-ink-3
                       outline-none transition-shadow duration-200
                       focus-visible:shadow-[0_0_0_3px_oklch(0.78_0.13_230/0.35)]
                       focus-visible:border-accent"
          />
          <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded
                          bg-bg-hover px-1.5 py-0.5 font-mono text-[10px] text-ink-3">
            Ctrl+K
          </kbd>
        </div>
        <div
          role="status"
          aria-live="polite"
          aria-atomic="true"
          className="hidden shrink-0 text-[12px] text-ink-3 sm:block"
        >
          <span className="font-mono text-ink">{resultCount.toLocaleString()}</span>
          <span> / {totalCount.toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
});
