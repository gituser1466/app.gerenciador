// Funções de hash extras que o VeraCrypt aceita como KDF do cabeçalho e que o
// WebCrypto não oferece: BLAKE2s-256 e Whirlpool. Também exporta o PBKDF2 do
// VeraCrypt já unificado (SHA-512/SHA-256 via WebCrypto, o resto em JS puro).
//
// Streebog e RIPEMD-160 continuam fora: o Streebog depende de tabelas grandes que
// não foram validadas aqui e o RIPEMD-160 foi removido pelo próprio VeraCrypt 1.26.

/* ----------------------------------------------------------- BLAKE2s-256 --- */

const BLAKE2S_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
const BLAKE2S_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
];
const rotr32 = (v, n) => ((v >>> n) | (v << (32 - n))) >>> 0;

class Blake2s {
  constructor(outLength = 32) {
    this.h = BLAKE2S_IV.slice();
    this.h[0] ^= 0x01010000 ^ outLength;
    this.outLength = outLength;
    this.block = new Uint8Array(64);
    this.blockLength = 0;
    this.counter = 0;
    this.m = new Uint32Array(16);
    this.v = new Uint32Array(16);
  }
  _compress(final) {
    const { h, v, m, block } = this;
    for (let i = 0; i < 16; i++) {
      const o = i * 4;
      m[i] = (block[o] | (block[o + 1] << 8) | (block[o + 2] << 16) | (block[o + 3] << 24)) >>> 0;
    }
    for (let i = 0; i < 8; i++) v[i] = h[i];
    for (let i = 0; i < 8; i++) v[8 + i] = BLAKE2S_IV[i];
    v[12] ^= this.counter >>> 0;
    v[13] ^= Math.floor(this.counter / 0x100000000) >>> 0;
    if (final) v[14] = (~v[14]) >>> 0;
    for (let r = 0; r < 10; r++) {
      const s = BLAKE2S_SIGMA[r];
      const g = (a, b, c, d, x, y) => {
        v[a] = (v[a] + v[b] + x) >>> 0; v[d] = rotr32(v[d] ^ v[a], 16);
        v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr32(v[b] ^ v[c], 12);
        v[a] = (v[a] + v[b] + y) >>> 0; v[d] = rotr32(v[d] ^ v[a], 8);
        v[c] = (v[c] + v[d]) >>> 0; v[b] = rotr32(v[b] ^ v[c], 7);
      };
      g(0, 4, 8, 12, m[s[0]], m[s[1]]);
      g(1, 5, 9, 13, m[s[2]], m[s[3]]);
      g(2, 6, 10, 14, m[s[4]], m[s[5]]);
      g(3, 7, 11, 15, m[s[6]], m[s[7]]);
      g(0, 5, 10, 15, m[s[8]], m[s[9]]);
      g(1, 6, 11, 12, m[s[10]], m[s[11]]);
      g(2, 7, 8, 13, m[s[12]], m[s[13]]);
      g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) >>> 0;
  }
  update(bytes) {
    for (let i = 0; i < bytes.length; i++) {
      if (this.blockLength === 64) {
        this.counter += 64;
        this._compress(false);
        this.blockLength = 0;
      }
      this.block[this.blockLength++] = bytes[i];
    }
    return this;
  }
  digest() {
    this.counter += this.blockLength;
    this.block.fill(0, this.blockLength);
    this._compress(true);
    const out = new Uint8Array(this.outLength);
    for (let i = 0; i < this.outLength; i++) out[i] = (this.h[i >> 2] >>> ((i & 3) * 8)) & 0xff;
    this.h.fill(0); this.block.fill(0); this.m.fill(0); this.v.fill(0);
    return out;
  }
}

export function blake2s256(bytes) { return new Blake2s(32).update(bytes).digest(); }

/* -------------------------------------------------------------- Whirlpool -- */
// S-box gerada a partir das mini-boxes E, E^-1 e R, como na implementação de
// referência de Barreto/Rijmen, e as oito tabelas circulantes C0..C7.

let WP = null;
function whirlpoolTables() {
  if (WP) return WP;
  const E = [0x1, 0xb, 0x9, 0xc, 0xd, 0x6, 0xf, 0x3, 0xe, 0x8, 0x7, 0x4, 0xa, 0x2, 0x5, 0x0];
  const R = [0x7, 0xc, 0xb, 0xd, 0xe, 0x4, 0x9, 0xf, 0x6, 0x3, 0x8, 0xa, 0x2, 0x5, 0x1, 0x0];
  const Einv = new Array(16);
  for (let i = 0; i < 16; i++) Einv[E[i]] = i;
  const S = new Uint8Array(256);
  for (let u = 0; u < 16; u++) {
    for (let v = 0; v < 16; v++) {
      const y1 = E[u], y2 = Einv[v];
      const y3 = R[y1 ^ y2];
      const y4 = E[y1 ^ y3], y5 = Einv[y2 ^ y3];
      S[(u << 4) | v] = (y4 << 4) | y5;
    }
  }
  const x2 = (a) => ((a << 1) ^ ((a & 0x80) ? 0x1d : 0)) & 0xff;
  // C0[x] guarda o circulante (1,1,4,1,8,5,2,9) em dois metades de 32 bits.
  const C = [];
  for (let t = 0; t < 8; t++) C.push({ hi: new Uint32Array(256), lo: new Uint32Array(256) });
  for (let x = 0; x < 256; x++) {
    const v1 = S[x], v2 = x2(v1), v4 = x2(v2), v5 = v4 ^ v1, v8 = x2(v4), v9 = v8 ^ v1;
    const bytes = [v1, v1, v4, v1, v8, v5, v2, v9];
    for (let t = 0; t < 8; t++) {
      // Ct[x] = rotação à direita de C0[x] em 8*t bits.
      const rot = [];
      for (let i = 0; i < 8; i++) rot.push(bytes[(i - t + 8) & 7]);
      C[t].hi[x] = ((rot[0] << 24) | (rot[1] << 16) | (rot[2] << 8) | rot[3]) >>> 0;
      C[t].lo[x] = ((rot[4] << 24) | (rot[5] << 16) | (rot[6] << 8) | rot[7]) >>> 0;
    }
  }
  const rcHi = new Uint32Array(11), rcLo = new Uint32Array(11);
  for (let r = 1; r <= 10; r++) {
    const i = 8 * (r - 1);
    rcHi[r] = ((S[i] << 24) | (S[i + 1] << 16) | (S[i + 2] << 8) | S[i + 3]) >>> 0;
    rcLo[r] = ((S[i + 4] << 24) | (S[i + 5] << 16) | (S[i + 6] << 8) | S[i + 7]) >>> 0;
  }
  WP = { S, C, rcHi, rcLo };
  return WP;
}

function wpByte(hi, lo, index) {
  // index 0 = byte mais significativo do valor de 64 bits
  return index < 4 ? (hi >>> ((3 - index) * 8)) & 0xff : (lo >>> ((7 - index) * 8)) & 0xff;
}

class Whirlpool {
  constructor() {
    const t = whirlpoolTables();
    this.C = t.C; this.rcHi = t.rcHi; this.rcLo = t.rcLo;
    this.hHi = new Uint32Array(8); this.hLo = new Uint32Array(8);
    this.block = new Uint8Array(64);
    this.blockLength = 0;
    this.bitLength = 0n;
  }
  _transform() {
    const { C, rcHi, rcLo, hHi, hLo, block } = this;
    const kHi = new Uint32Array(8), kLo = new Uint32Array(8);
    const sHi = new Uint32Array(8), sLo = new Uint32Array(8);
    const lHi = new Uint32Array(8), lLo = new Uint32Array(8);
    const bHi = new Uint32Array(8), bLo = new Uint32Array(8);
    for (let i = 0; i < 8; i++) {
      const o = i * 8;
      bHi[i] = ((block[o] << 24) | (block[o + 1] << 16) | (block[o + 2] << 8) | block[o + 3]) >>> 0;
      bLo[i] = ((block[o + 4] << 24) | (block[o + 5] << 16) | (block[o + 6] << 8) | block[o + 7]) >>> 0;
      kHi[i] = hHi[i]; kLo[i] = hLo[i];
      sHi[i] = (bHi[i] ^ kHi[i]) >>> 0; sLo[i] = (bLo[i] ^ kLo[i]) >>> 0;
    }
    for (let r = 1; r <= 10; r++) {
      // escalonamento da chave
      for (let i = 0; i < 8; i++) {
        let hi = 0, lo = 0;
        for (let t = 0; t < 8; t++) {
          const src = (i - t) & 7;
          const b = wpByte(kHi[src], kLo[src], t);
          hi ^= C[t].hi[b]; lo ^= C[t].lo[b];
        }
        lHi[i] = hi >>> 0; lLo[i] = lo >>> 0;
      }
      lHi[0] = (lHi[0] ^ rcHi[r]) >>> 0; lLo[0] = (lLo[0] ^ rcLo[r]) >>> 0;
      for (let i = 0; i < 8; i++) { kHi[i] = lHi[i]; kLo[i] = lLo[i]; }
      // rodada do cifrador
      for (let i = 0; i < 8; i++) {
        let hi = 0, lo = 0;
        for (let t = 0; t < 8; t++) {
          const src = (i - t) & 7;
          const b = wpByte(sHi[src], sLo[src], t);
          hi ^= C[t].hi[b]; lo ^= C[t].lo[b];
        }
        lHi[i] = (hi ^ kHi[i]) >>> 0; lLo[i] = (lo ^ kLo[i]) >>> 0;
      }
      for (let i = 0; i < 8; i++) { sHi[i] = lHi[i]; sLo[i] = lLo[i]; }
    }
    // Miyaguchi-Preneel
    for (let i = 0; i < 8; i++) {
      hHi[i] = (hHi[i] ^ sHi[i] ^ bHi[i]) >>> 0;
      hLo[i] = (hLo[i] ^ sLo[i] ^ bLo[i]) >>> 0;
    }
    kHi.fill(0); kLo.fill(0); sHi.fill(0); sLo.fill(0); lHi.fill(0); lLo.fill(0);
  }
  update(bytes) {
    for (let i = 0; i < bytes.length; i++) {
      this.block[this.blockLength++] = bytes[i];
      if (this.blockLength === 64) { this._transform(); this.blockLength = 0; }
    }
    this.bitLength += BigInt(bytes.length) * 8n;
    return this;
  }
  digest() {
    const bits = this.bitLength;
    this.block[this.blockLength++] = 0x80;
    if (this.blockLength > 32) {
      this.block.fill(0, this.blockLength);
      this._transform();
      this.blockLength = 0;
    }
    this.block.fill(0, this.blockLength, 32);
    // comprimento em bits, 256 bits big-endian nos últimos 32 bytes
    let n = bits;
    for (let i = 63; i >= 32; i--) { this.block[i] = Number(n & 255n); n >>= 8n; }
    this._transform();
    const out = new Uint8Array(64);
    for (let i = 0; i < 8; i++) {
      const o = i * 8;
      out[o] = (this.hHi[i] >>> 24) & 0xff; out[o + 1] = (this.hHi[i] >>> 16) & 0xff;
      out[o + 2] = (this.hHi[i] >>> 8) & 0xff; out[o + 3] = this.hHi[i] & 0xff;
      out[o + 4] = (this.hLo[i] >>> 24) & 0xff; out[o + 5] = (this.hLo[i] >>> 16) & 0xff;
      out[o + 6] = (this.hLo[i] >>> 8) & 0xff; out[o + 7] = this.hLo[i] & 0xff;
    }
    this.hHi.fill(0); this.hLo.fill(0); this.block.fill(0);
    return out;
  }
}

export function whirlpool(bytes) { return new Whirlpool().update(bytes).digest(); }

/* --------------------------------------------------------- HMAC + PBKDF2 --- */

const JS_HASHES = Object.freeze({
  'BLAKE2s-256': { blockSize: 64, outLength: 32, fn: blake2s256 },
  Whirlpool: { blockSize: 64, outLength: 64, fn: whirlpool }
});

export const VERACRYPT_HASHES = Object.freeze(['SHA-512', 'SHA-256', 'BLAKE2s-256', 'Whirlpool']);
export function isWebCryptoHash(name) { return name === 'SHA-512' || name === 'SHA-256'; }
export function isSupportedVeraCryptHash(name) { return VERACRYPT_HASHES.includes(name); }

function hmacJs(spec, key, data) {
  const { blockSize, fn } = spec;
  let k = key.length > blockSize ? fn(key) : key;
  const padded = new Uint8Array(blockSize);
  padded.set(k);
  const inner = new Uint8Array(blockSize + data.length);
  const outer = new Uint8Array(blockSize + spec.outLength);
  for (let i = 0; i < blockSize; i++) { inner[i] = padded[i] ^ 0x36; outer[i] = padded[i] ^ 0x5c; }
  inner.set(data, blockSize);
  const innerHash = fn(inner);
  outer.set(innerHash, blockSize);
  const out = fn(outer);
  padded.fill(0); inner.fill(0); outer.fill(0); innerHash.fill(0);
  return out;
}

/**
 * PBKDF2 do VeraCrypt. Devolve `length` bytes (o cabeçalho usa 64).
 * `onProgress(fraction)` é opcional e permite ceder o event loop no iOS.
 */
export async function veraCryptPbkdf2(passwordBytes, salt, iterations, hashName, length = 64, onProgress = null) {
  if (isWebCryptoHash(hashName)) {
    const base = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: hashName, salt, iterations }, base, length * 8));
  }
  const spec = JS_HASHES[hashName];
  if (!spec) throw new Error(`Hash de KDF não suportado nesta versão: ${hashName}.`);
  const blocks = Math.ceil(length / spec.outLength);
  const out = new Uint8Array(blocks * spec.outLength);
  const totalWork = blocks * iterations;
  let done = 0, lastYield = 0;
  for (let b = 1; b <= blocks; b++) {
    const seed = new Uint8Array(salt.length + 4);
    seed.set(salt);
    seed[salt.length] = (b >>> 24) & 0xff; seed[salt.length + 1] = (b >>> 16) & 0xff;
    seed[salt.length + 2] = (b >>> 8) & 0xff; seed[salt.length + 3] = b & 0xff;
    let u = hmacJs(spec, passwordBytes, seed);
    const acc = u.slice();
    for (let i = 1; i < iterations; i++) {
      u = hmacJs(spec, passwordBytes, u);
      for (let j = 0; j < acc.length; j++) acc[j] ^= u[j];
      done++;
      if (done - lastYield >= 20000) {
        lastYield = done;
        onProgress?.(done / totalWork);
        // Cede o event loop para o Safari não matar a aba durante o KDF em JS.
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    out.set(acc, (b - 1) * spec.outLength);
    acc.fill(0); u.fill(0); seed.fill(0);
  }
  onProgress?.(1);
  return out.slice(0, length);
}
