'use client';

import { useEffect, useState } from 'react';

/**
 * CSS-breakpoint media query hook. Returns null until measured (avoids SSR
 * hydration mismatch — first client paint renders the neutral variant), then
 * true below the breakpoint. Shared by ResultsTable and Terminal.
 */
export function useIsMobile(breakpoint = '(max-width: 767px)'): boolean | null {
  const [isMobile, setIsMobile] = useState<boolean | null>(null);
  useEffect(() => {
    const mq = window.matchMedia(breakpoint);
    const update = () => setIsMobile(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, [breakpoint]);
  return isMobile;
}
