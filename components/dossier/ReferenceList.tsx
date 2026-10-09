'use client';

import { memo } from 'react';
import type { CveRef } from '@/lib/snapshot';

/**
 * Reference list — STEP 5: borderless rows, domain preview (mono, muted),
 * title below, external-link icon on hover, Lucide ExternalLink glyph,
 * source as plain text (no bordered badge). Rows remain full-width
 * clickable + keyboard-focusable.
 */
const EXPLOIT_TAG = /exploit|poc|proof of concept/i;

/** Relative "checked Xh ago" from a verified ISO timestamp. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  const mins = Math.max(0, Math.round((now - t) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function domainOf(url: string): string {
  try {
    const u = new URL(url);
    const path = u.pathname.replace(/\/$/, '');
    return `${u.host}${path.length > 1 ? path.split('/').slice(0, 2).join('/') : ''}`;
  } catch {
    return url;
  }
}

function sourceLabel(source?: string, tags?: string[]): { label: string; exploit: boolean } {
  const exploit = (tags ?? []).some((t) => EXPLOIT_TAG.test(t));
  return { label: source ?? 'Reference', exploit };
}

export const ReferenceList = memo(function ReferenceList({
  refs,
  checkedAt,
}: {
  refs: CveRef[];
  checkedAt?: string | null;
}) {
  const checked = relativeTime(checkedAt);

  if (refs.length === 0) {
    return (
      <section className="space-y-3">
        <h3 className="label-xs">References</h3>
        <div className="text-[12px] text-ink-3">
          No references published by upstream sources.
        </div>
      </section>
    );
  }

  return (
    <section className="space-y-2">
      <h3 className="label-xs">References · {refs.length}</h3>
      <ul className="space-y-0.5">
        {refs.map((ref) => {
          const badge = sourceLabel(ref.source, ref.tags);
          return (
            <li key={ref.url}>
              <a
                href={ref.url}
                target="_blank"
                rel="noopener noreferrer nofollow"
                className="group flex w-full items-start gap-2 rounded-md px-2 py-2 transition-colors hover:bg-bg-hover"
              >
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[11px] text-ink-3">{domainOf(ref.url)}</div>
                  <div className="mt-0.5 truncate text-[13px] text-ink group-hover:text-ink">
                    {ref.label}
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    <span
                      className="shrink-0 text-[11px]"
                      style={badge.exploit ? { color: 'var(--color-critical)' } : undefined}
                    >
                      {badge.label}
                    </span>
                    {(ref.tags ?? []).length > 0 && (
                      <span className="text-[11px] text-ink-3">{(ref.tags ?? []).join(' · ')}</span>
                    )}
                    {checked && <span className="font-mono text-[11px] text-ink-3">{checked}</span>}
                  </div>
                </div>
                <span
                  aria-hidden="true"
                  className="mt-0.5 shrink-0 text-ink-3 opacity-0 transition-opacity group-hover:opacity-100
                             group-focus-visible:opacity-100"
                >
                  <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M14 4h6v6" strokeLinecap="round" />
                    <path d="M20 4 10 14" strokeLinecap="round" />
                    <path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" strokeLinecap="round" />
                  </svg>
                </span>
              </a>
            </li>
          );
        })}
      </ul>
    </section>
  );
});
