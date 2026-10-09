'use client';

import { memo, useEffect, useRef, useState } from 'react';

/**
 * Animated count-up (Section 7): eases to the target, respects
 * prefers-reduced-motion (renders final value instantly), announced
 * via the parent's aria-live region — the number itself is aria-hidden
 * to avoid double-announcement.
 */
export function CountUp({
  value,
  duration = 800,
  className,
}: {
  value: number;
  duration?: number;
  className?: string;
}) {
  const [display, setDisplay] = useState(0);
  const rafRef = useRef(0);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setDisplay(value);
      return;
    }
    const start = performance.now();
    const from = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(Math.round(from + (value - from) * eased));
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [value, duration]);

  return (
    <span aria-hidden="true" className={className}>
      {display.toLocaleString('en-US')}
    </span>
  );
}

export const Stat = memo(function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
}) {
  return (
    <div className="card p-5">
      <div className="label-xs">{label}</div>
      <div className="mt-2 truncate text-[28px] font-semibold leading-none tracking-tight text-ink tabular-nums">
        {value}
      </div>
      {sub && <div className="mt-1.5 text-[12px] text-ink-3">{sub}</div>}
    </div>
  );
});
