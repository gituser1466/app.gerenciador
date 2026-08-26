// Cifradores de bloco de 128 bits e o modo XTS (inclusive em cascata) usados
// pelo VeraCrypt em volumes não-sistema.
//
// Cobertos: AES-256, Serpent-256, Twofish-256 e todas as cascatas do VeraCrypt
// formadas apenas por esses três. Camellia e Kuznyechik ficaram de fora.
//
// Convenção das cascatas, confirmada abrindo containers criados pelo VeraCrypt
// oficial (ver casc-probe no histórico de testes). Para um algoritmo escrito
// como A(B(C)):
//   • `ciphers` = ['A','B','C'] — a mesma ordem do nome, o mais externo primeiro;
//   • a decriptação aplica XTS com A, depois B, depois C (encriptação inverte);
//   • a chave mestra traz as chaves primárias e depois as secundárias, e o
//     bloco de índice 0 pertence ao cifrador MAIS INTERNO (C), o 1 a B, e assim
//     por diante — ou seja, os blocos são atribuídos na ordem inversa do nome.

import { twofishBlockContext, twofishDecryptBlockInto, twofishEncryptBlockInto, twofishFreeContext } from './twofish.js';

const wipeArray = (a) => { if (a && typeof a.fill === 'function') a.fill(0); };

/* ------------------------------------------------------------------ AES --- */

const AES_SBOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);
const AES_INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = i;
const AES_RCON = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

function gfXtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff; }
function gfMul(a, b) {
  let p = 0, x = a, y = b;
  for (let i = 0; i < 8; i++) { if (y & 1) p ^= x; const hi = x & 0x80; x = (x << 1) & 0xff; if (hi) x ^= 0x1b; y >>>= 1; }
  return p;
}

function aesExpand(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('Chave AES-256 inválida.');
  const out = new Uint8Array(240);
  out.set(key);
  const temp = new Uint8Array(4);
  let used = 32, rc = 0;
  while (used < out.length) {
    temp.set(out.subarray(used - 4, used));
    if (used % 32 === 0) {
      const t = temp[0];
      temp[0] = AES_SBOX[temp[1]]; temp[1] = AES_SBOX[temp[2]]; temp[2] = AES_SBOX[temp[3]]; temp[3] = AES_SBOX[t];
      temp[0] ^= AES_RCON[rc++];
    } else if (used % 32 === 16) {
      for (let i = 0; i < 4; i++) temp[i] = AES_SBOX[temp[i]];
    }
    for (let i = 0; i < 4 && used < out.length; i++, used++) out[used] = out[used - 32] ^ temp[i];
  }
  wipeArray(temp);
  return out;
}
function aesEncryptInto(ctx, input, inOff, output, outOff) {
  const s = ctx.state, t = ctx.tmp, exp = ctx.exp;
  for (let i = 0; i < 16; i++) s[i] = input[inOff + i] ^ exp[i];
  for (let round = 1; round <= 13; round++) {
    for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
    t.set(s);
    s[0]=t[0];s[1]=t[5];s[2]=t[10];s[3]=t[15];s[4]=t[4];s[5]=t[9];s[6]=t[14];s[7]=t[3];
    s[8]=t[8];s[9]=t[13];s[10]=t[2];s[11]=t[7];s[12]=t[12];s[13]=t[1];s[14]=t[6];s[15]=t[11];
    for (let c = 0; c < 4; c++) {
      const i = c * 4, a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3], x = a ^ b ^ d ^ e;
      s[i] = a ^ x ^ gfXtime(a ^ b); s[i + 1] = b ^ x ^ gfXtime(b ^ d);
      s[i + 2] = d ^ x ^ gfXtime(d ^ e); s[i + 3] = e ^ x ^ gfXtime(e ^ a);
    }
    const ro = round * 16;
    for (let i = 0; i < 16; i++) s[i] ^= exp[ro + i];
  }
  for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
  t.set(s);
  s[0]=t[0];s[1]=t[5];s[2]=t[10];s[3]=t[15];s[4]=t[4];s[5]=t[9];s[6]=t[14];s[7]=t[3];
  s[8]=t[8];s[9]=t[13];s[10]=t[2];s[11]=t[7];s[12]=t[12];s[13]=t[1];s[14]=t[6];s[15]=t[11];
  for (let i = 0; i < 16; i++) output[outOff + i] = s[i] ^ exp[224 + i];
}
function aesDecryptInto(ctx, input, inOff, output, outOff) {
  const s = ctx.state, t = ctx.tmp, exp = ctx.exp;
  for (let i = 0; i < 16; i++) s[i] = input[inOff + i] ^ exp[224 + i];
  for (let round = 13; round >= 1; round--) {
    t.set(s);
    s[0]=t[0];s[1]=t[13];s[2]=t[10];s[3]=t[7];s[4]=t[4];s[5]=t[1];s[6]=t[14];s[7]=t[11];
    s[8]=t[8];s[9]=t[5];s[10]=t[2];s[11]=t[15];s[12]=t[12];s[13]=t[9];s[14]=t[6];s[15]=t[3];
    for (let i = 0; i < 16; i++) s[i] = AES_INV_SBOX[s[i]];
    const ro = round * 16;
    for (let i = 0; i < 16; i++) s[i] ^= exp[ro + i];
    for (let c = 0; c < 4; c++) {
      const i = c * 4, a = s[i], b = s[i + 1], d = s[i + 2], e = s[i + 3];
      s[i] = gfMul(a, 14) ^ gfMul(b, 11) ^ gfMul(d, 13) ^ gfMul(e, 9);
      s[i + 1] = gfMul(a, 9) ^ gfMul(b, 14) ^ gfMul(d, 11) ^ gfMul(e, 13);
      s[i + 2] = gfMul(a, 13) ^ gfMul(b, 9) ^ gfMul(d, 14) ^ gfMul(e, 11);
      s[i + 3] = gfMul(a, 11) ^ gfMul(b, 13) ^ gfMul(d, 9) ^ gfMul(e, 14);
    }
  }
  t.set(s);
  s[0]=t[0];s[1]=t[13];s[2]=t[10];s[3]=t[7];s[4]=t[4];s[5]=t[1];s[6]=t[14];s[7]=t[11];
  s[8]=t[8];s[9]=t[5];s[10]=t[2];s[11]=t[15];s[12]=t[12];s[13]=t[9];s[14]=t[6];s[15]=t[3];
  for (let i = 0; i < 16; i++) s[i] = AES_INV_SBOX[s[i]];
  for (let i = 0; i < 16; i++) output[outOff + i] = s[i] ^ exp[i];
}

/* -------------------------------------------------------------- Serpent --- */
// Serpent bitsliced: x0..x3 são palavras little-endian e a S-box de 4 bits é
// aplicada a cada "fatia" de bits (bit j de x0..x3 forma um nibble).

const SERPENT_SBOX = [
  [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
  [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
  [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
  [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
  [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
  [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
  [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
  [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]
].map((box) => Uint8Array.from(box));
const SERPENT_INV_SBOX = SERPENT_SBOX.map((box) => {
  const inv = new Uint8Array(16);
  for (let i = 0; i < 16; i++) inv[box[i]] = i;
  return inv;
});
const PHI = 0x9e3779b9;
const rotl32 = (v, n) => ((v << n) | (v >>> (32 - n))) >>> 0;
const rotr32 = (v, n) => ((v >>> n) | (v << (32 - n))) >>> 0;

function applySlice(box, words) {
  let y0 = 0, y1 = 0, y2 = 0, y3 = 0;
  const x0 = words[0], x1 = words[1], x2 = words[2], x3 = words[3];
  for (let j = 0; j < 32; j++) {
    const nibble = ((x0 >>> j) & 1) | (((x1 >>> j) & 1) << 1) | (((x2 >>> j) & 1) << 2) | (((x3 >>> j) & 1) << 3);
    const out = box[nibble];
    y0 |= (out & 1) << j;
    y1 |= ((out >>> 1) & 1) << j;
    y2 |= ((out >>> 2) & 1) << j;
    y3 |= ((out >>> 3) & 1) << j;
  }
  words[0] = y0 >>> 0; words[1] = y1 >>> 0; words[2] = y2 >>> 0; words[3] = y3 >>> 0;
}
function serpentLinear(w) {
  let x0 = w[0], x1 = w[1], x2 = w[2], x3 = w[3];
  x0 = rotl32(x0, 13); x2 = rotl32(x2, 3);
  x1 = (x1 ^ x0 ^ x2) >>> 0;
  x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
  x1 = rotl32(x1, 1); x3 = rotl32(x3, 7);
  x0 = (x0 ^ x1 ^ x3) >>> 0;
  x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
  x0 = rotl32(x0, 5); x2 = rotl32(x2, 22);
  w[0] = x0; w[1] = x1; w[2] = x2; w[3] = x3;
}
function serpentInvLinear(w) {
  let x0 = w[0], x1 = w[1], x2 = w[2], x3 = w[3];
  x2 = rotr32(x2, 22); x0 = rotr32(x0, 5);
  x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
  x0 = (x0 ^ x1 ^ x3) >>> 0;
  x3 = rotr32(x3, 7); x1 = rotr32(x1, 1);
  x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
  x1 = (x1 ^ x0 ^ x2) >>> 0;
  x2 = rotr32(x2, 3); x0 = rotr32(x0, 13);
  w[0] = x0; w[1] = x1; w[2] = x2; w[3] = x3;
}
function serpentSchedule(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('Chave Serpent-256 inválida.');
  const w = new Uint32Array(140);
  for (let i = 0; i < 8; i++) {
    const o = i * 4;
    w[i] = (key[o] | (key[o + 1] << 8) | (key[o + 2] << 16) | (key[o + 3] << 24)) >>> 0;
  }
  for (let i = 8; i < 140; i++) {
    w[i] = rotl32((w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (i - 8)) >>> 0, 11);
  }
  const k = new Uint32Array(132);
  const tmp = new Uint32Array(4);
  for (let i = 0; i <= 32; i++) {
    const box = SERPENT_SBOX[((3 - i) % 8 + 8) % 8];
    for (let j = 0; j < 4; j++) tmp[j] = w[8 + i * 4 + j];
    applySlice(box, tmp);
    for (let j = 0; j < 4; j++) k[i * 4 + j] = tmp[j];
  }
  wipeArray(w); wipeArray(tmp);
  return k;
}
function serpentEncryptInto(ctx, input, inOff, output, outOff) {
  const w = ctx.words, k = ctx.k;
  for (let i = 0; i < 4; i++) {
    const o = inOff + i * 4;
    w[i] = (input[o] | (input[o + 1] << 8) | (input[o + 2] << 16) | (input[o + 3] << 24)) >>> 0;
  }
  for (let r = 0; r < 31; r++) {
    for (let i = 0; i < 4; i++) w[i] = (w[i] ^ k[r * 4 + i]) >>> 0;
    applySlice(SERPENT_SBOX[r & 7], w);
    serpentLinear(w);
  }
  for (let i = 0; i < 4; i++) w[i] = (w[i] ^ k[31 * 4 + i]) >>> 0;
  applySlice(SERPENT_SBOX[7], w);
  for (let i = 0; i < 4; i++) w[i] = (w[i] ^ k[32 * 4 + i]) >>> 0;
  for (let i = 0; i < 4; i++) {
    const o = outOff + i * 4, v = w[i];
    output[o] = v & 0xff; output[o + 1] = (v >>> 8) & 0xff; output[o + 2] = (v >>> 16) & 0xff; output[o + 3] = (v >>> 24) & 0xff;
  }
}
function serpentDecryptInto(ctx, input, inOff, output, outOff) {
  const w = ctx.words, k = ctx.k;
  for (let i = 0; i < 4; i++) {
    const o = inOff + i * 4;
    w[i] = (input[o] | (input[o + 1] << 8) | (input[o + 2] << 16) | (input[o + 3] << 24)) >>> 0;
  }
  for (let i = 0; i < 4; i++) w[i] = (w[i] ^ k[32 * 4 + i]) >>> 0;
  applySlice(SERPENT_INV_SBOX[7], w);
  for (let i = 0; i < 4; i++) w[i] = (w[i] ^ k[31 * 4 + i]) >>> 0;
  for (let r = 30; r >= 0; r--) {
    serpentInvLinear(w);
    applySlice(SERPENT_INV_SBOX[r & 7], w);
    for (let i = 0; i < 4; i++) w[i] = (w[i] ^ k[r * 4 + i]) >>> 0;
  }
  for (let i = 0; i < 4; i++) {
    const o = outOff + i * 4, v = w[i];
    output[o] = v & 0xff; output[o + 1] = (v >>> 8) & 0xff; output[o + 2] = (v >>> 16) & 0xff; output[o + 3] = (v >>> 24) & 0xff;
  }
}

/* ------------------------------------------------------ registro/cascatas -- */

export const CIPHERS = Object.freeze({
  AES: {
    keySize: 32,
    schedule: (key) => ({ exp: aesExpand(key), state: new Uint8Array(16), tmp: new Uint8Array(16) }),
    encrypt: aesEncryptInto,
    decrypt: aesDecryptInto,
    free: (ctx) => { wipeArray(ctx.exp); wipeArray(ctx.state); wipeArray(ctx.tmp); }
  },
  Serpent: {
    keySize: 32,
    schedule: (key) => ({ k: serpentSchedule(key), words: new Uint32Array(4) }),
    encrypt: serpentEncryptInto,
    decrypt: serpentDecryptInto,
    free: (ctx) => { wipeArray(ctx.k); wipeArray(ctx.words); }
  },
  Twofish: {
    keySize: 32,
    schedule: (key) => twofishBlockContext(key),
    encrypt: twofishEncryptBlockInto,
    decrypt: twofishDecryptBlockInto,
    free: (ctx) => twofishFreeContext(ctx)
  }
});

/**
 * Algoritmos de criptografia do VeraCrypt cobertos por esta versão.
 * `ciphers` está na ordem interna do VeraCrypt (índice 0 = primeiro da lista).
 */
export const ENCRYPTION_ALGORITHMS = Object.freeze([
  { name: 'AES', ciphers: ['AES'] },
  { name: 'Serpent', ciphers: ['Serpent'] },
  { name: 'Twofish', ciphers: ['Twofish'] },
  { name: 'AES(Twofish)', ciphers: ['AES', 'Twofish'] },
  { name: 'AES(Twofish(Serpent))', ciphers: ['AES', 'Twofish', 'Serpent'] },
  { name: 'Serpent(AES)', ciphers: ['Serpent', 'AES'] },
  { name: 'Serpent(Twofish(AES))', ciphers: ['Serpent', 'Twofish', 'AES'] },
  { name: 'Twofish(Serpent)', ciphers: ['Twofish', 'Serpent'] }
]);

/** Algoritmos que o VeraCrypt oferece mas que esta versão ainda não lê. */
export const UNSUPPORTED_ENCRYPTION_ALGORITHMS = Object.freeze([
  'Camellia', 'Kuznyechik', 'Camellia(Kuznyechik)', 'Camellia(Serpent)',
  'Kuznyechik(AES)', 'Kuznyechik(Serpent(Camellia))', 'Kuznyechik(Twofish)'
]);

export function algorithmByName(name) {
  return ENCRYPTION_ALGORITHMS.find((a) => a.name === name) || null;
}
export function algorithmKeySize(algorithm) {
  return algorithm.ciphers.reduce((sum, c) => sum + CIPHERS[c].keySize, 0) * 2;
}

/** Cadeia XTS pronta para uso, com as chaves já expandidas. */
export class XtsChain {
  /**
   * `masterKey` = chaves primárias seguidas das secundárias. O bloco de índice 0
   * é do cifrador mais interno, então percorremos a cascata de trás para frente
   * ao fatiar a chave.
   */
  constructor(algorithm, masterKey) {
    this.name = algorithm.name;
    this.algorithm = algorithm;
    const half = algorithm.ciphers.reduce((sum, c) => sum + CIPHERS[c].keySize, 0);
    if (masterKey.length < half * 2) throw new Error('Área de chaves insuficiente para este algoritmo.');
    const slices = [];
    let offset = 0;
    for (let i = algorithm.ciphers.length - 1; i >= 0; i--) {
      const spec = CIPHERS[algorithm.ciphers[i]];
      slices[i] = { spec, primary: masterKey.subarray(offset, offset + spec.keySize), secondary: masterKey.subarray(half + offset, half + offset + spec.keySize) };
      offset += spec.keySize;
    }
    this.units = [];
    for (const slice of slices) {
      this.units.push({ spec: slice.spec, data: slice.spec.schedule(slice.primary), tweak: slice.spec.schedule(slice.secondary) });
    }
    this.block = new Uint8Array(16);
    this.tweakBlock = new Uint8Array(16);
    this.unitBytes = new Uint8Array(16);
  }
  _pass(unit, data, startDataUnitNo, decrypt, startCipherBlockNo) {
    const { spec } = unit;
    const tweak = this.tweakBlock, unitBytes = this.unitBytes, tmp = this.block;
    let pos = 0, dataUnit = BigInt(startDataUnitNo), firstBlock = startCipherBlockNo;
    while (pos < data.length) {
      let n = dataUnit;
      for (let i = 0; i < 8; i++) { unitBytes[i] = Number(n & 255n); n >>= 8n; }
      unitBytes.fill(0, 8);
      spec.encrypt(unit.tweak, unitBytes, 0, tweak, 0);
      for (let j = 0; j < firstBlock; j++) mulAlpha(tweak);
      let block = firstBlock;
      while (block < 32 && pos < data.length) {
        for (let i = 0; i < 16; i++) tmp[i] = data[pos + i] ^ tweak[i];
        if (decrypt) spec.decrypt(unit.data, tmp, 0, tmp, 0);
        else spec.encrypt(unit.data, tmp, 0, tmp, 0);
        for (let i = 0; i < 16; i++) data[pos + i] = tmp[i] ^ tweak[i];
        mulAlpha(tweak);
        pos += 16; block++;
      }
      dataUnit++; firstBlock = 0;
    }
  }
  /** Decripta `data` no lugar: o cifrador mais externo sai primeiro. */
  decrypt(data, startDataUnitNo = 0, startCipherBlockNo = 0) {
    validateXtsInput(data, startDataUnitNo, startCipherBlockNo);
    for (let i = 0; i < this.units.length; i++) this._pass(this.units[i], data, startDataUnitNo, true, startCipherBlockNo);
    return data;
  }
  /** Encripta `data` no lugar: o mais interno entra primeiro. */
  encrypt(data, startDataUnitNo = 0, startCipherBlockNo = 0) {
    validateXtsInput(data, startDataUnitNo, startCipherBlockNo);
    for (let i = this.units.length - 1; i >= 0; i--) this._pass(this.units[i], data, startDataUnitNo, false, startCipherBlockNo);
    return data;
  }
  destroy() {
    for (const unit of this.units) { unit.spec.free(unit.data); unit.spec.free(unit.tweak); }
    this.units = [];
    wipeArray(this.block); wipeArray(this.tweakBlock); wipeArray(this.unitBytes);
  }
}

function validateXtsInput(data, startDataUnitNo, startCipherBlockNo) {
  if (!(data instanceof Uint8Array) || data.length % 16) throw new Error('XTS exige blocos de 16 bytes.');
  if (!Number.isSafeInteger(Number(startDataUnitNo)) || Number(startDataUnitNo) < 0) throw new Error('Número de unidade XTS inválido.');
  if (!Number.isInteger(startCipherBlockNo) || startCipherBlockNo < 0 || startCipherBlockNo >= 32) throw new Error('Bloco inicial XTS inválido.');
}
function mulAlpha(t) {
  let carry = 0;
  for (let i = 0; i < 16; i++) { const next = (t[i] >>> 7) & 1; t[i] = ((t[i] << 1) & 0xff) | carry; carry = next; }
  if (carry) t[0] ^= 0x87;
}

/** Encripta/decripta uma cópia, sem alterar a entrada. Usado nos testes. */
export function xtsTransformCopy(data, algorithmName, masterKey, startDataUnitNo = 0, decrypt = false, startCipherBlockNo = 0) {
  const algorithm = algorithmByName(algorithmName);
  if (!algorithm) throw new Error(`Algoritmo VeraCrypt não suportado: ${algorithmName}.`);
  const chain = new XtsChain(algorithm, masterKey);
  try {
    const out = data.slice();
    return decrypt ? chain.decrypt(out, startDataUnitNo, startCipherBlockNo) : chain.encrypt(out, startDataUnitNo, startCipherBlockNo);
  } finally { chain.destroy(); }
}
