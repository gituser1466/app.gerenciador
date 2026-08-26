import { concatBytes, randomBytes, wipe } from './utils.js';
import { algorithmByName, ENCRYPTION_ALGORITHMS, UNSUPPORTED_ENCRYPTION_ALGORITHMS, XtsChain } from './vc-ciphers.js';
import { isSupportedVeraCryptHash, isWebCryptoHash, VERACRYPT_HASHES, veraCryptPbkdf2 } from './vc-hash.js';

// Leitor de containers VeraCrypt (arquivos, não volumes de sistema).
//
// 1.9.1: além do AES-256-XTS/PBKDF2-SHA-512/SHA-256 originais, entende
// Serpent, Twofish e as cascatas formadas por esses três, mais PBKDF2 com
// Whirlpool e BLAKE2s-256. Camellia, Kuznyechik e Streebog seguem fora.

const HEADER_SIZE = 512;
const SALT_SIZE = 64;
const ENCRYPTED_HEADER_SIZE = 448;
const HIDDEN_HEADER_OFFSET = 64 * 1024;
const DATA_UNIT = 512;
const MAX_KEYFILE_BYTES = 1024 * 1024;
const MAX_PASSWORD_BYTES = 128;
const MAX_KEYFILES = 32;
const MAX_PIM = 20000;
const MAX_HEADER_KEY_BYTES = 192; // maior cascata coberta: 3 cifradores x 32 x 2
const MAGIC = new Uint8Array([0x56, 0x45, 0x52, 0x41]); // VERA

export { ENCRYPTION_ALGORITHMS, UNSUPPORTED_ENCRYPTION_ALGORITHMS, VERACRYPT_HASHES };
export const ENCRYPTION_ALGORITHM_NAMES = Object.freeze(ENCRYPTION_ALGORITHMS.map((a) => a.name));

/**
 * Compatibilidade com a suíte de testes: XTS de AES-256 com duas chaves de 32
 * bytes, o formato usado antes de existirem cascatas.
 */
export function aesXtsTransformForTest(data, key1, key2, startDataUnitNo = 0, decrypt = false, startCipherBlockNo = 0) {
  const chain = new XtsChain(algorithmByName('AES'), concatBytes(key1, key2));
  try {
    const out = data.slice();
    return decrypt ? chain.decrypt(out, startDataUnitNo, startCipherBlockNo) : chain.encrypt(out, startDataUnitNo, startCipherBlockNo);
  } finally { chain.destroy(); }
}

/* ------------------------------------------------------------------ CRC --- */
let CRC_TABLE = null;
function crcTable() {
  if (CRC_TABLE) return CRC_TABLE;
  CRC_TABLE = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1); CRC_TABLE[n] = c >>> 0; }
  return CRC_TABLE;
}
function crcUpdate(state, byte) { return (crcTable()[(state ^ byte) & 255] ^ (state >>> 8)) >>> 0; }
function crc32(bytes) { let c = 0xffffffff; for (const b of bytes) c = crcUpdate(c, b); return (c ^ 0xffffffff) >>> 0; }

/* ------------------------------------------------------- senha+keyfiles --- */
async function applyKeyfiles(password, keyfiles) {
  const pass = new TextEncoder().encode(String(password ?? ''));
  if (pass.length > MAX_PASSWORD_BYTES) { wipe(pass); throw new Error('A senha excede 128 bytes em UTF-8, limite desta compatibilidade VeraCrypt.'); }
  if (!keyfiles?.length) return pass;
  if (keyfiles.length > MAX_KEYFILES) { wipe(pass); throw new Error(`Use no máximo ${MAX_KEYFILES} keyfiles por abertura.`); }
  const poolSize = pass.length <= 64 ? 64 : 128;
  const pool = new Uint8Array(poolSize);
  pool.set(pass); wipe(pass);
  for (const file of keyfiles) {
    let bytes;
    if (file instanceof Uint8Array) {
      if (file.length < 1) throw new Error('Keyfile vazio não é aceito.');
      bytes = file.slice(0, MAX_KEYFILE_BYTES);
    } else {
      if (!file || typeof file.slice !== 'function') throw new Error('Keyfile inválido.');
      const len = Math.min(Number(file.size) || 0, MAX_KEYFILE_BYTES);
      if (len < 1) throw new Error('Keyfile vazio não é aceito.');
      bytes = new Uint8Array(await file.slice(0, len).arrayBuffer());
    }
    let state = 0xffffffff, pos = 0;
    try {
      for (const b of bytes) {
        state = crcUpdate(state, b);
        const v = [state >>> 24, (state >>> 16) & 255, (state >>> 8) & 255, state & 255];
        for (const x of v) { pool[pos] = (pool[pos] + x) & 255; pos++; if (pos >= pool.length) pos = 0; }
      }
    } finally { wipe(bytes); }
  }
  return pool;
}

function iterationsFor(pim) {
  const iterations = pim > 0 ? 15000 + (pim * 1000) : 500000;
  if (!Number.isSafeInteger(iterations) || iterations < 16000 || iterations > 100000000) throw new Error('PIM produz uma contagem de iterações inválida/excessiva.');
  return iterations;
}

/* --------------------------------------------------------- cabeçalho ----- */
function be16(b, o) { return (b[o] << 8) | b[o + 1]; }
function be32(b, o) { return ((b[o] * 0x1000000) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3]) >>> 0; }
function be64(b, o) { let n = 0n; for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(b[o + i]); if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Campo de 64 bits grande demais para este navegador.'); return Number(n); }
function equal4(a, b) { return a[0] === b[0] && a[1] === b[1] && a[2] === b[2] && a[3] === b[3]; }

function parseDecryptedHeader(dec, fileSize, hash, pim, headerOffset, algorithm) {
  if (!equal4(dec, MAGIC)) return null;
  const headerVersion = be16(dec, 4);
  const keyAreaCrc = be32(dec, 8);
  const headerCrc = be32(dec, 188);
  if (headerVersion < 4 || headerVersion > 5) return null;
  if (crc32(dec.subarray(0, 188)) !== headerCrc) return null;
  if (crc32(dec.subarray(192, 448)) !== keyAreaCrc) return null;
  const sectorSize = be32(dec, 64);
  const encryptedAreaStart = be64(dec, 44);
  const encryptedAreaLength = be64(dec, 52);
  if (![512, 1024, 2048, 4096].includes(sectorSize)) throw new Error('Tamanho de setor VeraCrypt não suportado.');
  if (encryptedAreaStart < 0 || encryptedAreaLength <= 0 || encryptedAreaStart + encryptedAreaLength > fileSize) throw new Error('Cabeçalho VeraCrypt contém limites de volume inválidos.');
  const keyBytes = algorithm.ciphers.length * 32;
  const primaryKey = dec.slice(192, 192 + keyBytes);
  const secondaryKey = dec.slice(192 + keyBytes, 192 + keyBytes * 2);
  let same = true;
  for (let i = 0; i < keyBytes; i++) if (primaryKey[i] !== secondaryKey[i]) { same = false; break; }
  if (same) { wipe(primaryKey); wipe(secondaryKey); throw new Error('Volume rejeitado: chaves XTS primária e secundária são idênticas.'); }
  const single = algorithm.ciphers.length === 1;
  return {
    // Mantém o formato histórico "AES-256-XTS" para cifrador único.
    cipher: single ? `${algorithm.name}-256-XTS` : `${algorithm.name}-XTS`,
    cipherDetail: single
      ? `${algorithm.name}-256-XTS`
      : `${algorithm.name}-XTS · cascata de ${algorithm.ciphers.length} cifradores (${algorithm.ciphers.join(' → ')})`,
    algorithmName: algorithm.name,
    hash, pim,
    iterations: iterationsFor(pim),
    headerVersion,
    requiredVersion: be16(dec, 6),
    hiddenVolumeSize: be64(dec, 28),
    volumeSize: be64(dec, 36),
    encryptedAreaStart, encryptedAreaLength,
    flags: be32(dec, 60),
    sectorSize,
    headerOffset,
    primaryKey, secondaryKey
  };
}

function candidateAlgorithms(cipherOption) {
  if (!cipherOption || cipherOption === 'auto') return ENCRYPTION_ALGORITHMS;
  const found = algorithmByName(cipherOption);
  if (!found) throw new Error(`Cifrador não suportado nesta versão: ${cipherOption}. Cobertos: ${ENCRYPTION_ALGORITHM_NAMES.join(', ')}.`);
  return [found];
}
// 'auto' fica só nos hashes acelerados pelo WebCrypto: BLAKE2s e Whirlpool
// rodam em JS puro (~5 s e ~11 s por tentativa num Mac, mais no iPhone) e
// tornariam insuportável a espera por uma senha errada. 'todos' força a série
// completa quando o usuário sabe que o volume usa um deles.
function candidateHashes(hashOption) {
  const value = String(hashOption || 'auto');
  if (value === 'auto') return VERACRYPT_HASHES.filter(isWebCryptoHash);
  if (value === 'todos' || value === 'all') return VERACRYPT_HASHES;
  if (!isSupportedVeraCryptHash(value)) throw new Error(`Hash de KDF não suportado nesta versão: ${value}. Cobertos: ${VERACRYPT_HASHES.join(', ')}.`);
  return [value];
}

/**
 * Tenta abrir um cabeçalho em `offset` com todas as combinações pedidas.
 * Devolve `{info, decryptedHeader}` ou null.
 */
async function readHeaderMaterial(file, passwordBytes, { pim = 0, hashes, algorithms, offset = 0, source = 'primário', onStatus = null } = {}) {
  if (offset < 0 || file.size < offset + HEADER_SIZE) return null;
  const raw = new Uint8Array(await file.slice(offset, offset + HEADER_SIZE).arrayBuffer());
  const salt = raw.slice(0, SALT_SIZE);
  const encrypted = raw.subarray(SALT_SIZE);
  const iterations = iterationsFor(pim);
  try {
    for (const hash of hashes) {
      onStatus?.(`Derivando a chave do cabeçalho com PBKDF2-${hash} (${iterations.toLocaleString('pt-BR')} iterações)…`);
      // Deriva 64 bytes primeiro (cifrador único) e só amplia para cascatas.
      let derived = await veraCryptPbkdf2(passwordBytes, salt, iterations, hash, 64);
      let derivedLength = 64;
      try {
        for (const pass of [1, 2]) {
          const wanted = pass === 1 ? 64 : MAX_HEADER_KEY_BYTES;
          const group = algorithms.filter((a) => a.ciphers.length * 64 === wanted || (pass === 2 && a.ciphers.length * 64 > 64));
          if (!group.length) continue;
          if (wanted > derivedLength) {
            wipe(derived);
            derived = await veraCryptPbkdf2(passwordBytes, salt, iterations, hash, wanted);
            derivedLength = wanted;
          }
          for (const algorithm of group) {
            const keyBytes = algorithm.ciphers.length * 32;
            if (derivedLength < keyBytes * 2) continue;
            const chain = new XtsChain(algorithm, derived.subarray(0, keyBytes * 2));
            const dec = encrypted.slice();
            try {
              chain.decrypt(dec, 0, 0);
              const info = parseDecryptedHeader(dec, file.size, hash, pim, offset, algorithm);
              if (info) { info.headerSource = source; return { info, decryptedHeader: dec.slice() }; }
            } finally { chain.destroy(); wipe(dec); }
          }
        }
      } finally { wipe(derived); }
    }
    return null;
  } finally { wipe(raw); wipe(salt); }
}

function headerOffsets(fileSize, hidden) {
  return hidden
    ? { primary: HIDDEN_HEADER_OFFSET, backup: fileSize - HIDDEN_HEADER_OFFSET }
    : { primary: 0, backup: fileSize - (2 * HIDDEN_HEADER_OFFSET) };
}

export async function openVeraCryptFile(file, { password = '', pim = 0, keyfiles = [], hash = 'auto', cipher = 'auto', hidden = false, onStatus = null } = {}) {
  if (!file || typeof file.slice !== 'function') throw new Error('Selecione um arquivo-container VeraCrypt.');
  if (file.size < 262144) throw new Error('O arquivo é pequeno demais para um volume VeraCrypt moderno.');
  pim = Number.parseInt(String(pim || 0), 10) || 0;
  if (pim < 0 || pim > MAX_PIM) throw new Error(`PIM inválido ou acima do limite defensivo desta versão (${MAX_PIM}).`);
  const hashes = candidateHashes(hash);
  const algorithms = candidateAlgorithms(cipher);
  const pass = await applyKeyfiles(password, keyfiles);
  const offsets = headerOffsets(file.size, !!hidden);
  try {
    for (const source of [{ offset: offsets.primary, label: 'primário' }, { offset: offsets.backup, label: 'backup embutido' }]) {
      const material = await readHeaderMaterial(file, pass, { pim, hashes, algorithms, offset: source.offset, source: source.label, onStatus });
      if (material) {
        wipe(material.decryptedHeader);
        material.info.hidden = !!hidden;
        return new VeraCryptVolume(file, material.info);
      }
    }
    const triedHashes = hashes.join(', ');
    const hint = hashes.length < VERACRYPT_HASHES.length
      ? ` Foram testados apenas ${triedHashes}: se o volume usa Whirlpool ou BLAKE2s-256, escolha o hash em “Hash do KDF” (a derivação deles roda em JavaScript e leva dezenas de segundos).`
      : '';
    throw new Error(`Não foi possível abrir o cabeçalho primário nem o backup embutido. Verifique senha, PIM, keyfiles e volume normal/oculto.${hint} Cifradores cobertos: ${ENCRYPTION_ALGORITHM_NAMES.join(', ')}. Camellia, Kuznyechik e Streebog ainda não são lidos.`);
  } finally { wipe(pass); }
}

async function findHeaderMaterial(file, passwordBytes, { pim = 0, hash = 'auto', cipher = 'auto', hidden = false, source = 'any' } = {}) {
  const offsets = headerOffsets(file.size, !!hidden);
  const hashes = candidateHashes(hash);
  const algorithms = candidateAlgorithms(cipher);
  const candidates = source === 'backup'
    ? [{ offset: offsets.backup, label: 'backup embutido' }]
    : source === 'primary'
      ? [{ offset: offsets.primary, label: 'primário' }]
      : [{ offset: offsets.primary, label: 'primário' }, { offset: offsets.backup, label: 'backup embutido' }];
  for (const candidate of candidates) {
    const material = await readHeaderMaterial(file, passwordBytes, { pim, hashes, algorithms, offset: candidate.offset, source: candidate.label });
    if (material) { material.info.hidden = !!hidden; return material; }
  }
  return null;
}

async function encryptHeaderMaterial(decryptedHeader, passwordBytes, { pim = 0, hash = 'SHA-512', algorithmName = 'AES' } = {}) {
  if (!(decryptedHeader instanceof Uint8Array) || decryptedHeader.length !== ENCRYPTED_HEADER_SIZE) throw new Error('Cabeçalho descriptografado inválido.');
  if (!isSupportedVeraCryptHash(hash)) throw new Error('Hash de KDF de destino não suportado.');
  const algorithm = algorithmByName(algorithmName);
  if (!algorithm) throw new Error('Cifrador de destino não suportado.');
  const keyBytes = algorithm.ciphers.length * 32;
  const salt = randomBytes(SALT_SIZE);
  let derived = null, chain = null, enc = null;
  try {
    derived = await veraCryptPbkdf2(passwordBytes, salt, iterationsFor(pim), hash, keyBytes * 2);
    chain = new XtsChain(algorithm, derived);
    enc = decryptedHeader.slice();
    chain.encrypt(enc, 0, 0);
    return concatBytes(salt, enc);
  } finally { wipe(salt); derived && wipe(derived); chain?.destroy(); enc && wipe(enc); }
}

function patchedBlob(file, patches) {
  const sorted = [...patches].sort((a, b) => a.offset - b.offset);
  const parts = []; let cursor = 0;
  for (const patch of sorted) {
    if (!Number.isSafeInteger(patch.offset) || patch.offset < cursor || patch.offset + patch.bytes.length > file.size) throw new Error('Patch de cabeçalho fora dos limites.');
    if (patch.offset > cursor) parts.push(file.slice(cursor, patch.offset));
    parts.push(patch.bytes.slice()); cursor = patch.offset + patch.bytes.length;
  }
  if (cursor < file.size) parts.push(file.slice(cursor));
  return new Blob(parts, { type: 'application/octet-stream' });
}

export async function reencryptVeraCryptHeaders(file, current = {}, next = {}) {
  if (!file || typeof file.slice !== 'function') throw new Error('Selecione um container VeraCrypt.');
  const currentPim = Number.parseInt(String(current.pim || 0), 10) || 0;
  const nextPim = Number.parseInt(String(next.pim ?? currentPim), 10) || 0;
  if (currentPim < 0 || currentPim > MAX_PIM || nextPim < 0 || nextPim > MAX_PIM) throw new Error('PIM inválido.');
  const currentPass = await applyKeyfiles(current.password || '', current.keyfiles || []);
  let nextPass = null, material = null, primary = null, backup = null;
  try {
    material = await findHeaderMaterial(file, currentPass, { pim: currentPim, hash: current.hash || 'auto', cipher: current.cipher || 'auto', hidden: !!current.hidden, source: 'any' });
    if (!material) throw new Error('Credenciais atuais não abriram o cabeçalho VeraCrypt.');
    const targetHash = (next.hash === 'same' || !next.hash || next.hash === 'auto') ? material.info.hash : next.hash;
    const algorithmName = material.info.algorithmName;
    nextPass = await applyKeyfiles(next.password ?? current.password ?? '', next.keyfiles ?? current.keyfiles ?? []);
    primary = await encryptHeaderMaterial(material.decryptedHeader, nextPass, { pim: nextPim, hash: targetHash, algorithmName });
    backup = await encryptHeaderMaterial(material.decryptedHeader, nextPass, { pim: nextPim, hash: targetHash, algorithmName });
    const offsets = headerOffsets(file.size, !!current.hidden);
    const blob = patchedBlob(file, [{ offset: offsets.primary, bytes: primary }, { offset: offsets.backup, bytes: backup }]);
    return { blob, info: { ...material.info, hash: targetHash, pim: nextPim, iterations: iterationsFor(nextPim), headerSource: 'novo primário' } };
  } finally {
    wipe(currentPass); nextPass && wipe(nextPass);
    material?.decryptedHeader && wipe(material.decryptedHeader);
    material?.info?.primaryKey && wipe(material.info.primaryKey);
    material?.info?.secondaryKey && wipe(material.info.secondaryKey);
    primary && wipe(primary); backup && wipe(backup);
  }
}

export async function repairVeraCryptPrimaryHeader(file, credentials = {}) {
  if (!file || typeof file.slice !== 'function') throw new Error('Selecione um container VeraCrypt.');
  const pim = Number.parseInt(String(credentials.pim || 0), 10) || 0;
  if (pim < 0 || pim > MAX_PIM) throw new Error('PIM inválido.');
  const pass = await applyKeyfiles(credentials.password || '', credentials.keyfiles || []);
  let material = null, fresh = null;
  try {
    material = await findHeaderMaterial(file, pass, { pim, hash: credentials.hash || 'auto', cipher: credentials.cipher || 'auto', hidden: !!credentials.hidden, source: 'backup' });
    if (!material) throw new Error('O backup embutido não pôde ser aberto com as credenciais informadas.');
    fresh = await encryptHeaderMaterial(material.decryptedHeader, pass, { pim, hash: material.info.hash, algorithmName: material.info.algorithmName });
    const offsets = headerOffsets(file.size, !!credentials.hidden);
    return { blob: patchedBlob(file, [{ offset: offsets.primary, bytes: fresh }]), info: { ...material.info, headerSource: 'primário reparado' } };
  } finally {
    wipe(pass);
    material?.decryptedHeader && wipe(material.decryptedHeader);
    material?.info?.primaryKey && wipe(material.info.primaryKey);
    material?.info?.secondaryKey && wipe(material.info.secondaryKey);
    fresh && wipe(fresh);
  }
}

/**
 * Volume aberto.
 *
 * O número da unidade de dados XTS é ABSOLUTO: conta setores de 512 bytes desde
 * o início do arquivo-container, não desde a área criptografada. Isso foi
 * confirmado abrindo um container FAT criado pelo VeraCrypt oficial — com base
 * relativa (0) o setor de boot sai como lixo. `dataUnitBase` fica configurável
 * para que o app possa provar a outra convenção antes de desistir do volume.
 */
export class VeraCryptVolume {
  constructor(file, info) {
    this.file = file;
    this.info = info;
    this.closed = false;
    this.dataUnitBase = Math.floor(info.encryptedAreaStart / DATA_UNIT);
    this._chain = new XtsChain(algorithmByName(info.algorithmName), concatBytes(info.primaryKey, info.secondaryKey));
    this._cache = new Map();
    this._cacheLimit = 96;
  }
  get size() { return this.info.encryptedAreaLength; }
  /** Convenções de numeração XTS a tentar quando o sistema de arquivos não é reconhecido. */
  candidateDataUnitBases() {
    const absolute = Math.floor(this.info.encryptedAreaStart / DATA_UNIT);
    return absolute ? [absolute, 0] : [0];
  }
  setDataUnitBase(base) {
    if (this.dataUnitBase === base) return;
    this.dataUnitBase = base;
    this.clearCache();
  }
  async read(offset, length) {
    if (this.closed) throw new Error('Volume VeraCrypt fechado.');
    offset = Number(offset); length = Number(length);
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > this.info.encryptedAreaLength) throw new Error('Leitura fora dos limites do volume.');
    if (length === 0) return new Uint8Array(0);
    const first = Math.floor(offset / DATA_UNIT), last = Math.floor((offset + length - 1) / DATA_UNIT);
    const out = new Uint8Array(length);
    let outPos = 0;
    for (let unit = first; unit <= last; unit++) {
      let plain = this._cache.get(unit);
      if (!plain) {
        const absolute = this.info.encryptedAreaStart + unit * DATA_UNIT;
        const cipherBytes = new Uint8Array(await this.file.slice(absolute, absolute + DATA_UNIT).arrayBuffer());
        if (cipherBytes.length !== DATA_UNIT) throw new Error('Container truncado durante leitura.');
        plain = this._chain.decrypt(cipherBytes, this.dataUnitBase + unit, 0);
        this._cache.set(unit, plain);
        if (this._cache.size > this._cacheLimit) {
          const k = this._cache.keys().next().value;
          const old = this._cache.get(k);
          old && wipe(old);
          this._cache.delete(k);
        }
      }
      const unitStart = unit * DATA_UNIT;
      const a = Math.max(offset, unitStart) - unitStart;
      const b = Math.min(offset + length, unitStart + DATA_UNIT) - unitStart;
      const chunk = plain.subarray(a, b);
      out.set(chunk, outPos); outPos += chunk.length;
    }
    return out;
  }
  clearCache() { for (const b of this._cache.values()) wipe(b); this._cache.clear(); }
  close() {
    if (this.closed) return;
    this.clearCache();
    this._chain?.destroy();
    this._chain = null;
    wipe(this.info.primaryKey); wipe(this.info.secondaryKey);
    this.file = null; this.closed = true;
  }
}
