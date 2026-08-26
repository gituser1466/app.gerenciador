const APP_VERSION = '1.9.1';
const CACHE = `meucofre-shell-v${APP_VERSION}`;

// Hashes gerados no fechamento da release. O Service Worker recusa uma instalação
// parcial/corrompida. Isso protege contra erro de upload/cache; não substitui a
// segurança da conta/origem de hospedagem, pois quem controla a origem controla o SW.
const ASSET_HASHES = Object.freeze({
  './index.html': 'a3a68b7c2b8058bbb83bb7f69563d5ddd0a2270b29937769e3ea868bbf2382fb',
  './styles.css': '7a9f09146fd493350efed1ebcf09bcab0c1c79581d61142f082e4b6b049c01aa',
  './manifest.webmanifest': '3ab272c413a7841587d97fbda04a25efa94ca525b499fcea55d2174373145062',
  './icon-192.png': '8dd0fc36a67b996a4586d795b92510d2f7e22a22d9ba8a4bb0b569653a7c2ad0',
  './icon-512.png': '0c81756a3fed05816ba2c236e75092ccbce3a3c08e3edea9c3253b5abeb7e51e',
  './apple-touch-icon.png': '5e0434ff5e6d4b54a376bb72ee9dfca9eb7cf04d152f6fb275bbb7c558e65e6e',
  './appearance.js': 'cc19fec1b5fb556d693d306a4dd18f00c5b00af74ac419fd7cf25bd1a8df0251',
  './app.js': '99d15f8712340dd0e587397b4308c19c5a619df2abf70b29c2ca06884e7976ba',
  './utils.js': 'cd5f41a39ceb207b69bf15d9d1b863e990c39da935bc2d89e0a54bed99e7420c',
  './storage.js': 'c37814b23abd14e0ac49f56837ec9decbcd74a3657ec30c130a763e1b902da21',
  './legacy-vault.js': 'd663a38de94a994c4ba1a713a6934556327b192464fb9867bff145b0826481f3',
  './kdbx.js': '64d8500efd96ce97def690b5cd1d1528ef509b3344113d43c5bcc6eb5bdba9c0',
  './webauthn.js': 'a4e9bb9fbea5780f341e034dc64737b6838755a00482c92f0614c59345a59f36',
  './totp.js': '137058587a6d0db77a751f7731b8795baf0cfff3ebb70e550dc6a36144a80679',
  './generator.js': '81197ae74f52857dbcaa61581b462a7a442c4c909d045d9b2708490610582085',
  './veracrypt.js': 'b9b10842f3c1707bd048bf1aee2d0b57d03903f1e306ac59d3a782787fb269aa',
  './veracrypt-advanced.js': 'b99ef9e85d285f24731942da1a7468d6e0c7fc0d7f212566838c263dfca6576a',
  './veracrypt-fido.js': 'c689ab02da5beaa1e366d80d87f3bbda1e92ef88ae739ad1ea0e4ebf2d6f960b',
  './veracrypt-linked.js': '1fa6747210ee8fa6f37c22653026842d5a2d4f2dad3ebbb3fe6073699f36ae7f',
  './veracrypt-macos-bridge.js': '8274c01bebc7365a339190877fcc7c62774cf4231a82e58c5101ead51d5acdfa',
  './vc-ciphers.js': '90671d2d61053c64f673315a9ba6646dd9a72ccf0dcb5bb3d0d7517ef76a643e',
  './vc-hash.js': '16990bc1c956fd62b6b570061dee91c99ae88c83cbd36e98133c1d12ff15d2c4',
  './filesystem.js': 'fb59009fcb572ab6e228d086bd86ebeb7e9a9c26039fc164d7e08aeb6d7b33e9',
  './fat.js': '860fa2cbcdde3c35d9865576a22b6406ccb35e10e680a21927bd62551cbcd4f7',
  './exfat.js': '443184ffcc20b2a9f9ff050d5beb6f1cef8fb3435e05c1c18de75d21c6fcdc05',
  './hfsplus.js': '8b1d4871ad0ee8775efd1a5c6d2fbb7f334fc52b1131bc655d67b45fa4f5ebaf',
  './argon2-kdf.js': '15b67b65be454f6fe22fd19eae18e47686e3a496440f721bfbdd74ac8a49ecef',
  './argon2-kdf.wasm': '9720380a7e99573f7d3df22e884f8dc128200519c6e91ad5886fa5414935a6bf',
  './twofish.js': '1d8d4e49db11fa149d5df9ec3d73f72b8f9792e4985ba441aba8ce4c7004f8ec',
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
