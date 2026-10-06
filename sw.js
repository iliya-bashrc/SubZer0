'use strict';

/*
 * SubZer0 service worker (v2).
 * Shell = cache-first so the app opens offline.
 * Snapshot JSON = network-first with cache fallback, so freshness is never
 * faked from a stale cache when the network is available.
 * Daily shards are cached on demand with an LRU-style date trim.
 */

const CACHE_NAME = 'subzero-offline-v2';
const SCOPE_URL = new URL(self.registration.scope);
const SCOPE_PATH = SCOPE_URL.pathname;
const SHELL_PATHS = [
  '',
  'index.html',
  'app.js',
  'styles.css',
  'assets/telegram-mark.svg',
  'assets/telegram-bugcod3.svg',
  'assets/telegram-rootaccessclub.svg',
];
const SHELL_URLS = SHELL_PATHS.map((path) => new URL(path || './', SCOPE_URL).href);
const MAX_SHARDS_TO_KEEP = 40;

const SHARD_RE = /^snapshot\/data\/\d{4}-\d{2}-\d{2}\.json$/;
const FRESH_JSON_RE = /^snapshot\/(manifest\.json|changes\.json|data\/(search_index|shard_map|epss)\.json)$/;

function relativePath(url) {
  if (!url.pathname.startsWith(SCOPE_PATH)) return '';
  return url.pathname.slice(SCOPE_PATH.length);
}

async function trimOldShards(cache) {
  const keys = await cache.keys();
  const shards = keys.map((request) => {
    const path = relativePath(new URL(request.url));
    const match = path.match(/^snapshot\/data\/(\d{4}-\d{2}-\d{2})\.json$/);
    return match ? { request, date: match[1] } : null;
  }).filter(Boolean).sort((a, b) => a.date.localeCompare(b.date));
  const expired = shards.slice(0, Math.max(0, shards.length - MAX_SHARDS_TO_KEEP));
  await Promise.all(expired.map(({ request }) => cache.delete(request)));
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await Promise.allSettled(SHELL_URLS.map((url) => cache.add(url)));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const path = relativePath(new URL(request.url));
  if (!path) return;

  // Freshness-critical JSON: network first, fall back to cache only offline.
  if (FRESH_JSON_RE.test(path) || SHARD_RE.test(path)) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      try {
        const response = await fetch(request);
        if (response.ok) {
          cache.put(request, response.clone());
          if (SHARD_RE.test(path)) trimOldShards(cache);
        }
        return response;
      } catch (err) {
        const cached = await cache.match(request);
        if (cached) return cached;
        throw err;
      }
    })());
    return;
  }

  // App shell: cache-first, revalidate in the background.
  if (SHELL_PATHS.includes(path)) {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(request);
      const network = fetch(request).then((response) => {
        if (response.ok) cache.put(request, response.clone());
        return response;
      }).catch(() => null);
      return cached || (await network) || Response.error();
    })());
  }
});
