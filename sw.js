const APP_VERSION = '1.3.0';
const CACHE = `meucofre-shell-v${APP_VERSION}`;

// Hashes gerados no fechamento da release. O Service Worker recusa uma instalação
// parcial/corrompida. Isso protege contra erro de upload/cache; não substitui a
// segurança da conta/origem de hospedagem, pois quem controla a origem controla o SW.
const ASSET_HASHES = Object.freeze({
  './index.html': '7244d58bc201156fd8a2e5d896d4d46d678862d07f149f3c0062bf178f28e3ec',
  './styles.css': '26b9d86a216317635ca1f27da502b33af94677e9da73f93371440cb1f3a256fd',
  './manifest.webmanifest': '4db57446d82ae0e9e9c5b3a2ee3346a06ad60092f62d0914e0910701e4ac4e62',
  './icon-192.png': '8dd0fc36a67b996a4586d795b92510d2f7e22a22d9ba8a4bb0b569653a7c2ad0',
  './icon-512.png': '0c81756a3fed05816ba2c236e75092ccbce3a3c08e3edea9c3253b5abeb7e51e',
  './apple-touch-icon.png': '5e0434ff5e6d4b54a376bb72ee9dfca9eb7cf04d152f6fb275bbb7c558e65e6e',
  './app.js': 'e10b0244146acc811aad9269d7f85f714026ed633b55a1665b24e6eb0631fa76',
  './utils.js': 'fb5a397fda790ba7f596b6eb2ca1e8a72bb67578eaa0c406f466205cafa8a70b',
  './storage.js': '3cf245ba8b4f6cada59ec97b5b66371780f821a481811fa34bcb26c008e795cc',
  './legacy-vault.js': 'd663a38de94a994c4ba1a713a6934556327b192464fb9867bff145b0826481f3',
  './kdbx.js': 'fd8ef590e8ba0ea16b265523d687ff76b194fd0dd6e70385e083c920f3c31b5f',
  './webauthn.js': 'a4e9bb9fbea5780f341e034dc64737b6838755a00482c92f0614c59345a59f36',
  './totp.js': '137058587a6d0db77a751f7731b8795baf0cfff3ebb70e550dc6a36144a80679',
  './generator.js': '81197ae74f52857dbcaa61581b462a7a442c4c909d045d9b2708490610582085',
  './veracrypt.js': '0ffd969f284baa5d31331cb3f2fdec7837931bf6bc94653c3c65dd2118e3b349',
  './veracrypt-fido.js': 'c689ab02da5beaa1e366d80d87f3bbda1e92ef88ae739ad1ea0e4ebf2d6f960b',
  './filesystem.js': '4bb193f2ad835914a0306eea120821106765d1f0f223f3a8baf874afdde20755',
  './fat.js': '82ea09aacd1360efb5fa6a1ecba33d7ef36e892239c9a517d2fddc5dc870b5b9',
  './exfat.js': '443184ffcc20b2a9f9ff050d5beb6f1cef8fb3435e05c1c18de75d21c6fcdc05'
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
