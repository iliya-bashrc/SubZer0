'use client';

import { useEffect } from 'react';

/**
 * Registers the SubZer0 service worker (public/sw.js) for offline support.
 * Static export → no Next.js built-in SW; this is the same fail-open
 * opportunistic cache model the legacy v1 shipped (bytes only — integrity
 * verification always stays in the app's SHA-256 loader).
 */
export function ServiceWorkerRegistrar() {
  useEffect(() => {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) return;
    if (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') return;
    const register = () => {
      navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => {
        /* offline support is progressive — never blocks the app */
      });
    };
    if (document.readyState === 'complete') register();
    else window.addEventListener('load', register, { once: true });
    return () => window.removeEventListener('load', register);
  }, []);
  return null;
}
