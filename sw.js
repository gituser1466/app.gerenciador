const APP_VERSION = '1.0.0';
const CACHE = `meucofre-shell-v${APP_VERSION}`;

// Hashes gerados no fechamento da release. O Service Worker recusa uma instalação
// parcial/corrompida. Isso protege contra erro de upload/cache; não substitui a
// segurança da conta/origem de hospedagem, pois quem controla a origem controla o SW.
const ASSET_HASHES = Object.freeze({
  './index.html': 'a5d2193b04f06a34c97708ca0423c546002609f50b7e679dda495364383ab7bb',
  './styles.css': '6652b241b6b1348e2decb74448f298183b02788494b1fb1613f06433ff6a770c',
  './manifest.webmanifest': '890cce41e244dab3c4c0957fb61efccf3d116d2fcc2906f7babd16560527ef6e',
  './icon-192.png': '8dd0fc36a67b996a4586d795b92510d2f7e22a22d9ba8a4bb0b569653a7c2ad0',
  './icon-512.png': '0c81756a3fed05816ba2c236e75092ccbce3a3c08e3edea9c3253b5abeb7e51e',
  './apple-touch-icon.png': '5e0434ff5e6d4b54a376bb72ee9dfca9eb7cf04d152f6fb275bbb7c558e65e6e',
  './app.js': '424e507fc12a0cbf782431fbb7bcab61485efbf8606501d2732436fbd1cb68c7',
  './utils.js': 'fb5a397fda790ba7f596b6eb2ca1e8a72bb67578eaa0c406f466205cafa8a70b',
  './storage.js': '32d16f279aa9f191bae192d8b32403574bb0a6bf7e01da9358d76ef59ab6996f',
  './legacy-vault.js': 'd663a38de94a994c4ba1a713a6934556327b192464fb9867bff145b0826481f3',
  './kdbx.js': '07b95481f72bce2f44178443e83ad5c39e6405298b43257ec3aee4c09a2f340d',
  './webauthn.js': 'a4e9bb9fbea5780f341e034dc64737b6838755a00482c92f0614c59345a59f36',
  './totp.js': '137058587a6d0db77a751f7731b8795baf0cfff3ebb70e550dc6a36144a80679',
  './generator.js': '81197ae74f52857dbcaa61581b462a7a442c4c909d045d9b2708490610582085'
});

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, '0')).join('');
}

async function fetchVerified(asset) {
  const response = await fetch(asset, { cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  if (!response.ok) throw new Error(`Falha ao preparar ${asset}: ${response.status}`);
  const bytes = await response.arrayBuffer();
  const actual = toHex(await crypto.subtle.digest('SHA-256', bytes));
  if (actual !== ASSET_HASHES[asset]) throw new Error(`Integridade da release falhou em ${asset}.`);
  return new Response(bytes, { status: response.status, statusText: response.statusText, headers: response.headers });
}

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const staging = `${CACHE}-staging`;
    await caches.delete(staging);
    const cache = await caches.open(staging);
    try {
      for (const asset of Object.keys(ASSET_HASHES)) await cache.put(asset, await fetchVerified(asset));
      // Copia somente depois que TODOS os arquivos passaram na verificação.
      const finalCache = await caches.open(CACHE);
      for (const request of await cache.keys()) {
        const response = await cache.match(request);
        if (response) await finalCache.put(request, response);
      }
    } finally {
      await caches.delete(staging);
    }
    // Sem skipWaiting automático: o usuário escolhe quando ativar a atualização.
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE && k.startsWith('meucofre-shell-')).map(k => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

function canonicalAssetRequest(request) {
  const url = new URL(request.url);
  url.search = '';
  return new Request(url.href, { method: 'GET', credentials: 'same-origin' });
}

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname.endsWith('/version.json')) {
    event.respondWith(fetch(req, { cache: 'no-store', credentials: 'same-origin', redirect: 'error' }));
    return;
  }

  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      const cached = await caches.match('./index.html');
      if (cached) return cached;
      return fetch(req, { cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
    })());
    return;
  }

  // index/app/css usam ?v=... no HTML. Removemos apenas a query ao procurar no
  // cache para garantir que o navegador receba a cópia que passou pelo SHA-256.
  const canonical = canonicalAssetRequest(req);
  event.respondWith((async () => {
    const cached = await caches.match(canonical);
    if (cached) return cached;
    // Recursos não pertencentes ao shell (por exemplo um arquivo do usuário) não são
    // adicionados ao cache do aplicativo.
    return fetch(req, { cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  })());
});
