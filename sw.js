const APP_VERSION = '1.8.1';
const CACHE = `meucofre-shell-v${APP_VERSION}`;

// Hashes gerados no fechamento da release. O Service Worker recusa uma instalação
// parcial/corrompida. Isso protege contra erro de upload/cache; não substitui a
// segurança da conta/origem de hospedagem, pois quem controla a origem controla o SW.
const ASSET_HASHES = Object.freeze({
  './index.html': '6d110116182ee1f95a856e65b340d2c47437a63ea9081a5f60f83634766f2826',
  './styles.css': 'f8e90ad4881797b690caea9fdc70554af0f22b9605c74cba5ec57f1552b31d79',
  './manifest.webmanifest': 'de93d3fb787c8fb0d0d42f4d0dcf88a68900015ca30ae775d88597d824760686',
  './icon-192.png': '8dd0fc36a67b996a4586d795b92510d2f7e22a22d9ba8a4bb0b569653a7c2ad0',
  './icon-512.png': '0c81756a3fed05816ba2c236e75092ccbce3a3c08e3edea9c3253b5abeb7e51e',
  './apple-touch-icon.png': '5e0434ff5e6d4b54a376bb72ee9dfca9eb7cf04d152f6fb275bbb7c558e65e6e',
  './app.js': 'f35e3960cc575ab7dbc4504afee547cb561bd6a6a5c13ef37b24d0d67ef0b5b0',
  './utils.js': 'fb5a397fda790ba7f596b6eb2ca1e8a72bb67578eaa0c406f466205cafa8a70b',
  './storage.js': 'c37814b23abd14e0ac49f56837ec9decbcd74a3657ec30c130a763e1b902da21',
  './legacy-vault.js': 'd663a38de94a994c4ba1a713a6934556327b192464fb9867bff145b0826481f3',
  './kdbx.js': 'c3913bad7408db83664afac4c8c08864f809b2d1d5d595c724a6d820a24eb2ec',
  './webauthn.js': 'a4e9bb9fbea5780f341e034dc64737b6838755a00482c92f0614c59345a59f36',
  './totp.js': '137058587a6d0db77a751f7731b8795baf0cfff3ebb70e550dc6a36144a80679',
  './generator.js': '81197ae74f52857dbcaa61581b462a7a442c4c909d045d9b2708490610582085',
  './veracrypt.js': 'b04ba30f77e909dbe033e82b420318f41c58ebbf1db7bb3537553ce887a69acb',
  './veracrypt-advanced.js': 'b99ef9e85d285f24731942da1a7468d6e0c7fc0d7f212566838c263dfca6576a',
  './veracrypt-fido.js': 'c689ab02da5beaa1e366d80d87f3bbda1e92ef88ae739ad1ea0e4ebf2d6f960b',
  './veracrypt-linked.js': '1fa6747210ee8fa6f37c22653026842d5a2d4f2dad3ebbb3fe6073699f36ae7f',
  './veracrypt-macos-bridge.js': '8274c01bebc7365a339190877fcc7c62774cf4231a82e58c5101ead51d5acdfa',
  './filesystem.js': '4bb193f2ad835914a0306eea120821106765d1f0f223f3a8baf874afdde20755',
  './fat.js': '82ea09aacd1360efb5fa6a1ecba33d7ef36e892239c9a517d2fddc5dc870b5b9',
  './exfat.js': '443184ffcc20b2a9f9ff050d5beb6f1cef8fb3435e05c1c18de75d21c6fcdc05',
  './argon2-kdf.js': '7a496b993062f6b636b41d5fa76a850716d83e10ac9c14bda71977d339d542a5',
  './argon2-kdf.wasm': '9720380a7e99573f7d3df22e884f8dc128200519c6e91ad5886fa5414935a6bf',
  './twofish.js': 'f09082a748e2b6b4b8185325898cd91054431b41196984d380132d284dad0841',
  './MeuCofre-VeraCrypt-macOS.command': 'b5eae1601b027449342dd0a65ddfbced721b5a0f0aceddacf1209e5ff058eeab'
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
