const APP_VERSION = '0.2.1';
const CACHE = `meucofre-shell-v${APP_VERSION}`;
const ASSETS = [
  `./index.html?v=${APP_VERSION}`,
  `./styles.css?v=${APP_VERSION}`,
  `./manifest.webmanifest?v=${APP_VERSION}`,
  `./icon-192.png?v=${APP_VERSION}`,
  `./icon-512.png?v=${APP_VERSION}`,
  `./apple-touch-icon.png?v=${APP_VERSION}`,
  `./app.js?v=${APP_VERSION}`,
  `./utils.js?v=${APP_VERSION}`,
  `./storage.js?v=${APP_VERSION}`,
  `./crypto-vault.js?v=${APP_VERSION}`,
  `./webauthn.js?v=${APP_VERSION}`,
  `./totp.js?v=${APP_VERSION}`,
  `./generator.js?v=${APP_VERSION}`,
  // Module imports inside app.js use these stable URLs; pre-cache them too.
  './storage.js',
  './crypto-vault.js',
  './webauthn.js',
  './totp.js',
  './generator.js',
  './utils.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    // Force network revalidation during the repair install so GitHub/iOS HTTP cache
    // cannot seed the new shell with stale JavaScript.
    for (const asset of ASSETS) {
      const response = await fetch(asset, { cache: 'reload' });
      if (!response.ok) throw new Error(`Falha ao preparar ${asset}: ${response.status}`);
      await cache.put(asset, response);
    }
    // Repair release: activate immediately once iOS detects this new worker.
    // Future releases can return to user-confirmed activation.
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys
      .filter((key) => key !== CACHE && key.startsWith('meucofre-shell-'))
      .map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      // Prefer the network while online so a repaired index is visible immediately;
      // fall back to the current versioned shell when offline.
      try {
        const response = await fetch(request, { cache: 'no-store' });
        if (response && response.ok) return response;
      } catch (_) {}
      return (await caches.match(`./index.html?v=${APP_VERSION}`)) || Response.error();
    })());
    return;
  }

  event.respondWith((async () => {
    const cached = await caches.match(request);
    if (cached) return cached;
    try {
      const response = await fetch(request);
      if (response.ok && !url.pathname.endsWith('/version.json')) {
        const clone = response.clone();
        const cache = await caches.open(CACHE);
        cache.put(request, clone).catch(() => {});
      }
      return response;
    } catch (_) {
      return cached || Response.error();
    }
  })());
});
