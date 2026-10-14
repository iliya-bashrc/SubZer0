'use strict';

/*
 * SubZer0 (Next.js) service worker — offline shell + opportunistic snapshot cache.
 * Ported from the verified legacy v1 sw.js, adapted to the Next.js static export:
 *  - shell = index.html + /_next/static/* (build-id agnostic: cached at runtime)
 *  - snapshot data files cached with per-type byte limits (fail-closed verify
 *    logic lives in the app, never here — SW only serves bytes).
 * Bump CACHE_NAME whenever the shell layout changes (stale-client rule).
 */

const CACHE_NAME = 'subzero-next-offline-v1';
const CACHE_PREFIX = 'subzero-next-offline-';
const SCOPE_URL = new URL(self.registration.scope);
const SCOPE_PATH = SCOPE_URL.pathname;
const PRECACHE_PATHS = ['index.html', '404.html', 'snapshot/manifest.json'];
const PRECACHE_URLS = PRECACHE_PATHS.map((p) => new URL(p, SCOPE_URL).href);
const MAX_SHARDS_TO_KEEP = 40;

function relativePath(url) {
  if (!url.pathname.startsWith(SCOPE_PATH)) return '';
  return url.pathname.slice(SCOPE_PATH.length);
}

function isStaticAsset(path) {
  return path.startsWith('_next/static/');
}

function snapshotByteLimit(path) {
  if (path === 'snapshot/manifest.json') return 512 * 1024;
  if (path === 'snapshot/data/overview.json') return 64 * 1024;
  if (path === 'snapshot/data/epss.json') return 4 * 1024 * 1024;
  if (path === 'snapshot/data/search_index.json') return 16 * 1024 * 1024;
  if (path === 'snapshot/data/shard_map.json') return 2 * 1024 * 1024;
  if (path === 'snapshot/data/poc_ids.json') return 64 * 1024;
  if (/^snapshot\/data\/\d{4}-\d{2}-\d{2}\.json$/.test(path)) return 16 * 1024 * 1024;
  return 0;
}

function cacheable(request, response, path) {
  if (!response.ok) return false;
  if (isStaticAsset(path)) return true;
  const maximum = snapshotByteLimit(path);
  if (!maximum) return false;
  const header = response.headers.get('content-length');
  if (!header || !/^\d+$/.test(header)) return false;
  const size = Number(header);
  return Number.isSafeInteger(size) && size >= 0 && size <= maximum;
}

async function trimOldShards(cache) {
  const keys = await cache.keys();
  const shards = keys.map((request) => {
    const match = relativePath(new URL(request.url)).match(/^snapshot\/data\/(\d{4}-\d{2}-\d{2})\.json$/);
    return match ? { request, date: match[1] } : null;
  }).filter(Boolean).sort((a, b) => a.date.localeCompare(b.date));
  const expired = shards.slice(0, Math.max(0, shards.length - MAX_SHARDS_TO_KEEP));
  await Promise.all(expired.map(({ request }) => cache.delete(request)));
}

async function cacheNetworkResponse(request, response, path) {
  if (!cacheable(request, response, path)) return;
  try {
    const cache = await caches.open(CACHE_NAME);
    await cache.put(new Request(request.url, { method: 'GET' }), response.clone());
    if (/^snapshot\/data\/\d{4}-\d{2}-\d{2}\.json$/.test(path)) await trimOldShards(cache);
  } catch {
    // Storage is opportunistic; the hash-verified network path remains fully usable.
  }
}

function cachedWithOfflineMarker(response) {
  if (!response) return null;
  const headers = new Headers(response.headers);
  headers.set('X-SubZer0-Cache', 'offline-fallback');
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function serveNavigation(request, event) {
  const indexUrl = new URL('index.html', SCOPE_URL).href;
  if (self.navigator.onLine === false) {
    try {
      const cache = await caches.open(CACHE_NAME);
      return cachedWithOfflineMarker(await cache.match(indexUrl));
    } catch {
      return null;
    }
  }
  try {
    const response = await fetch(request);
    if (response.ok) {
      event.waitUntil(cacheNetworkResponse(new Request(indexUrl), response.clone(), 'index.html'));
      return response;
    }
    if (response.status < 500) return response;
  } catch {
    // Origin unreachable — reuse the cached shell below.
  }
  try {
    const cache = await caches.open(CACHE_NAME);
    return cachedWithOfflineMarker(await cache.match(indexUrl));
  } catch {
    return null;
  }
}

async function serveStaticResource(request, path, event) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      event.waitUntil(cacheNetworkResponse(request, response, path));
      return response;
    }
    if (response.status < 500) return response;
  } catch {
    // Fall back only to previously cached same-origin assets.
  }
  try {
    const cache = await caches.open(CACHE_NAME);
    return cachedWithOfflineMarker(await cache.match(new Request(request.url, { method: 'GET' })));
  } catch {
    return null;
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.addAll(PRECACHE_URLS);
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((name) => name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME)
      .map((name) => caches.delete(name)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(SCOPE_PATH)) return;

  const path = relativePath(url);

  if (request.mode === 'navigate') {
    event.respondWith((async () => (await serveNavigation(request, event))
      || new Response('The last verified SubZer0 app shell is not available offline.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      }))());
    return;
  }

  if (!isStaticAsset(path) && !snapshotByteLimit(path)) return;
  event.respondWith((async () => (await serveStaticResource(request, path, event))
    || new Response('This static snapshot file is not cached. Reconnect to verify the complete capture.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    }))());
});
