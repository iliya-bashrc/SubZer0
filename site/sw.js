/* SubZer0 service worker: network first for everything, cache as the offline fallback. */
const SHELL = 'subzer0-shell-v2';
const DATA = 'subzer0-data-v2';
const ASSETS = ['./', 'index.html', 'app.css', 'app.js', 'icon.svg', 'manifest.webmanifest',
  'fonts/ChakraPetch-500.woff2', 'fonts/ChakraPetch-600.woff2', 'fonts/ChakraPetch-700.woff2',
  'fonts/Inter.woff2', 'fonts/JetBrainsMono.woff2'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(SHELL).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(k => k !== SHELL && k !== DATA).map(k => caches.delete(k))
  )).then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== location.origin) return;
  const scope = new URL(self.registration.scope).pathname;
  const path = url.pathname.slice(scope.length);

  if (path.startsWith('snapshot/')) {
    // Data: always try the network first so the page never shows a stale snapshot when online.
    e.respondWith(fetch(req).then(res => {
      if (res.ok) { const copy = res.clone(); caches.open(DATA).then(c => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req, { ignoreSearch: true }).then(r => r || Response.error())));
    return;
  }

  if (req.mode === 'navigate') {
    // Every route (research, cve/…, terminal) is served by the same shell.
    e.respondWith(fetch(req).catch(() => caches.match('index.html', { ignoreSearch: true })));
    return;
  }

  // Shell: network first so a new deploy is picked up right away; the cache is the offline fallback.
  e.respondWith(fetch(req).then(res => {
    if (res.ok && ASSETS.includes(path)) { const copy = res.clone(); caches.open(SHELL).then(c => c.put(req, copy)); }
    return res;
  }).catch(() => caches.match(req, { ignoreSearch: true }).then(r => r || Response.error())));
});
