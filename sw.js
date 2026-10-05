'use strict';

const CACHE_NAME = 'subzero-offline-v4';
const CACHE_PREFIX = 'subzero-offline-';
const SCOPE_URL = new URL(self.registration.scope);
const SCOPE_PATH = SCOPE_URL.pathname;
const SHELL_PATHS = [
  '',
  'index.html',
  'app.js',
  'community.js',
  'styles.css',
  'feed.css',
  'severity-effects.css',
  'community.css',
  'assets/telegram-mark.svg',
  'assets/telegram-bugcod3.svg',
  'assets/telegram-rootaccessclub.svg',
  'snapshot/manifest.json',
  'snapshot/data/overview.json'
];
const SHELL_URLS = SHELL_PATHS.map((path) => new URL(path || './', SCOPE_URL).href);
const MAX_SHARDS_TO_KEEP = 31;
const MAX_SNAPSHOT_CACHE_BYTES = 128 * 1024 * 1024;

function relativePath(url) {
  if (!url.pathname.startsWith(SCOPE_PATH)) return '';
  return url.pathname.slice(SCOPE_PATH.length);
}

function snapshotByteLimit(path) {
  if (path === 'snapshot/manifest.json') return 512 * 1024;
  if (path === 'snapshot/data/overview.json') return 64 * 1024;
  if (path === 'snapshot/data/search-index.json.gz') return 3 * 1024 * 1024;
  if (path === 'snapshot/data/history.json') return 8 * 1024 * 1024;
  if (path === 'snapshot/data/epss.json') return 4 * 1024 * 1024;
  if (/^snapshot\/data\/\d{4}-\d{2}-\d{2}\.json$/.test(path)) return 16 * 1024 * 1024;
  return 0;
}

function isShellPath(path) {
  return SHELL_PATHS.includes(path);
}

function cacheableSnapshotSize(path, response) {
  const maximum = snapshotByteLimit(path);
  if (!maximum || !response.ok) return false;
  const header = response.headers.get('content-length');
  if (!header || !/^\d+$/.test(header)) return false;
  const size = Number(header);
  return Number.isSafeInteger(size) && size >= 0 && size <= maximum;
}

async function trimOldShards(cache) {
  let keys = await cache.keys();
  let shards = keys.map((request) => {
    const path = relativePath(new URL(request.url));
    const match = path.match(/^snapshot\/data\/(\d{4}-\d{2}-\d{2})\.json$/);
    return match ? { request, date: match[1] } : null;
  }).filter(Boolean).sort((a, b) => a.date.localeCompare(b.date));
  const expired = shards.slice(0, Math.max(0, shards.length - MAX_SHARDS_TO_KEEP));
  await Promise.all(expired.map(({ request }) => cache.delete(request)));

  keys = await cache.keys();
  const snapshotEntries = await Promise.all(keys.map(async (request) => {
    const path = relativePath(new URL(request.url));
    if (!path.startsWith('snapshot/')) return null;
    const response = await cache.match(request);
    const header = response?.headers.get('content-length');
    const bytes = header && /^\d+$/.test(header) ? Number(header) : 0;
    const shard = path.match(/^snapshot\/data\/(\d{4}-\d{2}-\d{2})\.json$/);
    return response ? { request, bytes: Number.isSafeInteger(bytes) ? bytes : 0, date: shard?.[1] || null } : null;
  })).then((entries) => entries.filter(Boolean));
  let totalBytes = snapshotEntries.reduce((total, entry) => total + entry.bytes, 0);
  const oldestShards = snapshotEntries.filter((entry) => entry.date).sort((a, b) => a.date.localeCompare(b.date));
  while (totalBytes > MAX_SNAPSHOT_CACHE_BYTES && oldestShards.length > 1) {
    const oldest = oldestShards.shift();
    if (await cache.delete(oldest.request)) totalBytes -= oldest.bytes;
  }
}

async function cacheNetworkResponse(request, response, path) {
  const shouldCache = isShellPath(path) || cacheableSnapshotSize(path, response);
  if (!shouldCache) return;
  try {
    const cache = await caches.open(CACHE_NAME);
    await cache.put(new Request(request.url, { method: 'GET' }), response.clone());
    if (/^snapshot\/data\/\d{4}-\d{2}-\d{2}\.json$/.test(path)) await trimOldShards(cache);
  } catch {
    // Storage is opportunistic; the hash-verified network path remains fully usable.
  }
}

function makeCacheCompletion(event) {
  let resolve;
  let finished = false;
  const completion = new Promise((done) => { resolve = done; });
  event.waitUntil(completion);
  return (task) => {
    if (finished) return;
    finished = true;
    resolve(task || undefined);
  };
}

function cachedWithOfflineMarker(response) {
  if (!response) return null;
  const headers = new Headers(response.headers);
  headers.set('X-SubZer0-Cache', 'offline-fallback');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

async function serveNavigation(request, event) {
  const indexUrl = new URL('index.html', SCOPE_URL).href;
  const finishCache = makeCacheCompletion(event);
  if (request.headers.get('X-SubZer0-Offline') === 'true' || self.navigator.onLine === false) {
    finishCache();
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
      finishCache(cacheNetworkResponse(new Request(indexUrl), response, 'index.html'));
      return response;
    }
    if (response.status < 500) {
      finishCache();
      return response;
    }
  } catch {
    // Reuse the app shell when the origin is unreachable.
  }
  finishCache();
  try {
    const cache = await caches.open(CACHE_NAME);
    return cachedWithOfflineMarker(await cache.match(indexUrl));
  } catch {
    return null;
  }
}

async function serveStaticResource(request, path, event) {
  const finishCache = makeCacheCompletion(event);
  if (request.headers.get('X-SubZer0-Offline') === 'true' || self.navigator.onLine === false) {
    finishCache();
    try {
      const cache = await caches.open(CACHE_NAME);
      return cachedWithOfflineMarker(await cache.match(new Request(request.url, { method: 'GET' })));
    } catch {
      return null;
    }
  }
  if (path.startsWith('snapshot/data/') && request.cache !== 'reload' && request.cache !== 'no-store' && request.cache !== 'no-cache') {
    try {
      const cache = await caches.open(CACHE_NAME);
      const candidate = await cache.match(new Request(request.url, { method: 'GET' }));
      if (candidate) {
        // The app verifies this candidate against the freshly fetched manifest before using it.
        finishCache();
        return candidate;
      }
    } catch {
      // CacheStorage is opportunistic; continue with the network path.
    }
  }
  try {
    const response = await fetch(request);
    if (response.ok) {
      finishCache(cacheNetworkResponse(request, response, path));
      return response;
    }
    if (response.status < 500) {
      finishCache();
      return response;
    }
  } catch {
    // Fall back only to previously cached same-origin assets.
  }
  finishCache();
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
    await cache.addAll(SHELL_URLS);
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

  if (request.mode === 'navigate') {
    event.respondWith((async () => (await serveNavigation(request, event))
      || new Response('The last verified SubZer0 app shell is not available offline.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      }))());
    return;
  }

  const path = relativePath(url);
  if (!isShellPath(path) && !snapshotByteLimit(path)) return;
  event.respondWith((async () => (await serveStaticResource(request, path, event))
    || new Response('This static snapshot file is not cached. Reconnect to verify the complete capture.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    }))());
});
