import { bytesToBase64, base64ToBytes, randomBytes, wipe } from './utils.js';

const REGION_SIZE = 128 * 1024;
const MAGIC = new TextEncoder().encode('MCVCHEADER1');
const HEADER_PREFIX = 32;
const CHECKSUM_SIZE = 32;
const FORMAT_VERSION = 1;

function ensureFile(file, label = 'arquivo') {
  if (!file || typeof file.slice !== 'function' || typeof file.arrayBuffer !== 'function') throw new Error(`Selecione um ${label} válido.`);
}

function writeU64LE(view, offset, value) {
  let n = BigInt(value);
  for (let i = 0; i < 8; i += 1) {
    view.setUint8(offset + i, Number(n & 255n));
    n >>= 8n;
  }
}

function readU64LE(view, offset) {
  let n = 0n;
  for (let i = 7; i >= 0; i -= 1) n = (n << 8n) | BigInt(view.getUint8(offset + i));
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Tamanho do container excede o limite seguro deste navegador.');
  return Number(n);
}

function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function makeHeader(fileSize) {
  const header = new Uint8Array(HEADER_PREFIX);
  header.set(MAGIC, 0);
  const view = new DataView(header.buffer);
  view.setUint32(12, FORMAT_VERSION, true);
  writeU64LE(view, 16, fileSize);
  view.setUint32(24, REGION_SIZE, true);
  return header;
}

export async function createVeraCryptHeaderBackup(file) {
  ensureFile(file, 'container VeraCrypt');
  if (file.size < REGION_SIZE * 2) throw new Error('Container pequeno demais para o formato moderno de headers VeraCrypt.');
  const first = new Uint8Array(await file.slice(0, REGION_SIZE).arrayBuffer());
  const last = new Uint8Array(await file.slice(file.size - REGION_SIZE, file.size).arrayBuffer());
  const header = makeHeader(file.size);
  const payload = new Uint8Array(header.length + first.length + last.length);
  payload.set(header, 0); payload.set(first, header.length); payload.set(last, header.length + first.length);
  const digest = await sha256(payload);
  const blob = new Blob([payload, digest], { type: 'application/octet-stream' });
  wipe(first); wipe(last); wipe(header); wipe(payload); wipe(digest);
  return blob;
}

export async function restoreVeraCryptHeaderBackup(containerFile, backupFile) {
  ensureFile(containerFile, 'container VeraCrypt');
  ensureFile(backupFile, 'backup de headers');
  const expectedSize = HEADER_PREFIX + REGION_SIZE * 2 + CHECKSUM_SIZE;
  if (backupFile.size !== expectedSize) throw new Error('Backup .vcheader possui tamanho inesperado.');
  const raw = new Uint8Array(await backupFile.arrayBuffer());
  const body = raw.subarray(0, raw.length - CHECKSUM_SIZE);
  const checksum = raw.subarray(raw.length - CHECKSUM_SIZE);
  const actual = await sha256(body);
  try {
    if (!constantTimeEqual(checksum, actual)) throw new Error('Backup .vcheader corrompido ou adulterado.');
    for (let i = 0; i < MAGIC.length; i += 1) if (body[i] !== MAGIC[i]) throw new Error('Formato de backup .vcheader desconhecido.');
    const view = new DataView(body.buffer, body.byteOffset, HEADER_PREFIX);
    if (view.getUint32(12, true) !== FORMAT_VERSION || view.getUint32(24, true) !== REGION_SIZE) throw new Error('Versão de backup .vcheader não suportada.');
    const originalSize = readU64LE(view, 16);
    if (originalSize !== containerFile.size) throw new Error('O backup de headers pertence a um container de tamanho diferente.');
    const first = body.slice(HEADER_PREFIX, HEADER_PREFIX + REGION_SIZE);
    const last = body.slice(HEADER_PREFIX + REGION_SIZE, HEADER_PREFIX + REGION_SIZE * 2);
    const blob = new Blob([
      first,
      containerFile.slice(REGION_SIZE, containerFile.size - REGION_SIZE),
      last
    ], { type: 'application/octet-stream' });
    wipe(first); wipe(last);
    return blob;
  } finally {
    wipe(raw); wipe(actual);
  }
}

export function generateVeraCryptKeyfile(length = 64) {
  const n = Number(length);
  if (![64, 128, 256, 512, 1024].includes(n)) throw new Error('Escolha um keyfile entre 64 e 1024 bytes nas opções disponíveis.');
  return randomBytes(n);
}

export async function keyfileSha256(value) {
  let bytes;
  if (value instanceof Uint8Array) bytes = value.slice();
  else {
    ensureFile(value, 'keyfile');
    if (value.size < 1 || value.size > 1024 * 1024) throw new Error('Keyfile vazio ou acima do limite de 1 MiB.');
    bytes = new Uint8Array(await value.arrayBuffer());
  }
  try {
    const digest = await sha256(bytes);
    const hex = [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
    wipe(digest);
    return hex;
  } finally { wipe(bytes); }
}

export function encodeHeaderBackupForTest(bytes) {
  return bytesToBase64(bytes);
}

export function decodeHeaderBackupForTest(value) {
  return base64ToBytes(value);
}
