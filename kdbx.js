import {
  base64ToBytes,
  bytesToBase64,
  concatBytes,
  randomBytes,
  text,
  utf8,
  uuid,
  wipe
} from './utils.js';
import { argon2Kdf } from './argon2-kdf.js';
import { twofishCbcDecrypt, twofishCbcEncrypt } from './twofish.js';

export const KDBX_RECORD_FORMAT = 'meucofre-kdbx-v1';
export const KDBX_VERSION = 0x00040001;
export const PROTECTION_MODES = Object.freeze({
  PASSWORD: 'password',
  YUBIKEY: 'yubikey',
  PASSWORD_YUBIKEY: 'password-yubikey',
  EXTERNAL: 'external'
});

const SIG1 = 0x9AA2D903;
const SIG2 = 0xB54BFB67;
const CIPHER_AES = hex('31C1F2E6BF714350BE5805216AFC5AFF');
const CIPHER_CHACHA20 = hex('D6038A2B8B6F4CB5A524339A31DBB59A');
const CIPHER_TWOFISH = hex('AD68F29F576F4BB9A36AD47AF965346C');
const KDF_AES = hex('C9D9F39A628A4460BF740D08C18A4FEA');
const KDF_ARGON2D = hex('EF636DDF8C29444B91F7A9A403E30A0C');
const KDF_ARGON2ID = hex('9E298B1956DB4773B23DFC3EC6F0A1E6');
const ZERO_UUID = new Uint8Array(16);
const EPOCH_0001_TO_1970 = 62135596800n;
const PUBLIC_SCHEMA = 1;
const APP_VERSION = '1.8.1';
const BLOCK_SIZE = 1024 * 1024;
const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_XML_BYTES = 128 * 1024 * 1024;
const MAX_HEADER_FIELD_BYTES = 4 * 1024 * 1024;
const MAX_PUBLIC_SLOTS = 24;
const DEFAULT_AES_ROUNDS = 180000;
const MIN_AES_ROUNDS = 50000;
const MAX_AES_ROUNDS_CREATE = 2000000;
const AES_KDF_YIELD_EVERY = 25000;
const AAD_PREFIX = 'MeuCofre-KDBX-v1';

function hex(value) {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function sameBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function u16(value) {
  const b = new Uint8Array(2);
  new DataView(b.buffer).setUint16(0, Number(value), true);
  return b;
}
function u32(value) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, Number(value) >>> 0, true);
  return b;
}
function i32(value) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setInt32(0, Number(value), true);
  return b;
}
function u64(value) {
  let n = BigInt(value);
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) { b[i] = Number(n & 255n); n >>= 8n; }
  return b;
}
function readU16(bytes, offset) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(offset, true); }
function readU32(bytes, offset) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true); }
function readI32(bytes, offset) { return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getInt32(offset, true); }
function readU64(bytes, offset) {
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) | BigInt(bytes[offset + i]);
  return n;
}

function ensureBytes(value, length, name) {
  if (!(value instanceof Uint8Array) || (length != null && value.length !== length)) throw new Error(`${name} inválido.`);
  return value;
}

async function digest(name, bytes) {
  return new Uint8Array(await crypto.subtle.digest(name, bytes));
}
async function sha256(bytes) { return digest('SHA-256', bytes); }
async function sha512(bytes) { return digest('SHA-512', bytes); }
async function hmacSha256(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}

export async function passwordComponent(password) {
  const bytes = utf8(String(password));
  try { return await sha256(bytes); } finally { wipe(bytes); }
}

export function randomKeyFileComponent() { return randomBytes(32); }

function hexToBytesStrict(value) {
  const clean=String(value||'').replace(/\s+/g,'');
  if(!/^[0-9a-f]+$/i.test(clean)||clean.length%2) throw new Error('Conteúdo hexadecimal inválido.');
  return hex(clean);
}

function decodeXmlEntities(value) {
  return String(value||'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&');
}

// KeePass/KeePassXC key-file semantics: XML v1/v2, raw 32-byte,
// 64 hexadecimal characters, or SHA-256 of any other file.
export async function keyFileComponent(fileBytes) {
  ensureBytes(fileBytes,null,'Arquivo de chave');
  if(fileBytes.length===32) return fileBytes.slice();
  if(fileBytes.length===64) {
    let ascii=''; try{ascii=text(fileBytes);}catch{}
    if(/^[0-9a-fA-F]{64}$/.test(ascii)) return hex(ascii);
  }
  let xml='';
  try { xml=text(fileBytes); } catch {}
  if(/^\s*(?:<\?xml[^>]*>\s*)?<KeyFile(?:\s|>)/i.test(xml)) {
    if(/<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error('DTD/entidades não são permitidos em key files XML.');
    const versionMatch=xml.match(/<Version\b[^>]*>([\s\S]*?)<\/Version>/i);
    const dataMatch=xml.match(/<Data\b([^>]*)>([\s\S]*?)<\/Data>/i);
    if(!dataMatch) throw new Error('Key file XML sem campo Data.');
    const version=decodeXmlEntities(versionMatch?.[1]||'1.0').trim();
    const rawText=decodeXmlEntities(dataMatch[2]).replace(/\s+/g,'');
    let key;
    if(/^2(?:\.|$)/.test(version)) key=hexToBytesStrict(rawText);
    else {
      try { key=base64ToBytes(rawText); } catch { throw new Error('Key file XML v1 inválido.'); }
    }
    if(key.length!==32) { wipe(key); throw new Error('Key file XML deve conter exatamente 32 bytes de chave.'); }
    const hm=dataMatch[1].match(/\bHash\s*=\s*["']([0-9a-fA-F]{8})["']/i);
    if(hm) {
      const actual=await sha256(key); const prefix=Array.from(actual.slice(0,4),b=>b.toString(16).padStart(2,'0')).join('').toUpperCase(); wipe(actual);
      if(prefix!==hm[1].toUpperCase()) { wipe(key); throw new Error('Hash de integridade do key file XML não confere.'); }
    }
    return key;
  }
  return sha256(fileBytes);
}

function xmlEscape(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&apos;');
}

function uuidBytesFromString(value) {
  const clean = String(value || '').replace(/-/g, '');
  if (/^[0-9a-f]{32}$/i.test(clean)) return hex(clean);
  return randomBytes(16);
}

function isoToKdbxTime(iso) {
  const ms = Date.parse(iso || '') || Date.now();
  const seconds = BigInt(Math.floor(ms / 1000)) + EPOCH_0001_TO_1970;
  return bytesToBase64(u64(seconds));
}
function kdbxTimeToIso(value) {
  const raw=String(value||'').trim();
  if (/^\d{4}-\d{2}-\d{2}T/.test(raw)) { const ms=Date.parse(raw); if(Number.isFinite(ms)) return new Date(ms).toISOString(); }
  try {
    const bytes = base64ToBytes(raw);
    if (bytes.length !== 8) return new Date().toISOString();
    const sec = readU64(bytes, 0) - EPOCH_0001_TO_1970;
    const ms = Number(sec) * 1000;
    if (!Number.isFinite(ms)) return new Date().toISOString();
    return new Date(ms).toISOString();
  } catch { return new Date().toISOString(); }
}

function writeHeaderField(id, value) { return concatBytes(new Uint8Array([id]), i32(value.length), value); }
function writeInnerField(id, value) { return concatBytes(new Uint8Array([id]), i32(value.length), value); }

function variantDict(items) {
  const parts = [u16(0x0100)];
  for (const item of items) {
    const name = utf8(item.name);
    let value;
    if (item.type === 0x04) value = u32(item.value);
    else if (item.type === 0x05) value = u64(item.value);
    else if (item.type === 0x08) value = new Uint8Array([item.value ? 1 : 0]);
    else if (item.type === 0x0c) value = i32(item.value);
    else if (item.type === 0x0d) value = u64(BigInt(item.value));
    else if (item.type === 0x18) value = utf8(item.value);
    else if (item.type === 0x42) value = item.value;
    else throw new Error('Tipo VariantDictionary não suportado.');
    parts.push(new Uint8Array([item.type]), i32(name.length), name, i32(value.length), value);
  }
  parts.push(new Uint8Array([0]));
  return concatBytes(...parts);
}

function parseVariantDict(bytes) {
  if (bytes.length < 3) throw new Error('VariantDictionary truncado.');
  const version = readU16(bytes, 0);
  if ((version >>> 8) !== 1) throw new Error('Versão de VariantDictionary não suportada.');
  const map = new Map();
  let p = 2, terminated = false;
  while (p < bytes.length) {
    const type = bytes[p++];
    if (type === 0) { terminated = true; break; }
    if (p + 4 > bytes.length) throw new Error('VariantDictionary truncado.');
    const nameLen = readI32(bytes, p); p += 4;
    if (nameLen < 0 || p + nameLen + 4 > bytes.length) throw new Error('VariantDictionary inválido.');
    const name = text(bytes.slice(p, p + nameLen)); p += nameLen;
    const valueLen = readI32(bytes, p); p += 4;
    if (valueLen < 0 || p + valueLen > bytes.length) throw new Error('VariantDictionary inválido.');
    const raw = bytes.slice(p, p + valueLen); p += valueLen;
    let value = raw;
    if (type === 0x04 && raw.length === 4) value = readU32(raw, 0);
    else if (type === 0x05 && raw.length === 8) value = readU64(raw, 0);
    else if (type === 0x08 && raw.length === 1) value = raw[0] !== 0;
    else if (type === 0x0c && raw.length === 4) value = readI32(raw, 0);
    else if (type === 0x0d && raw.length === 8) value = readU64(raw, 0);
    else if (type === 0x18) value = text(raw);
    if (map.has(name)) throw new Error('VariantDictionary contém chave duplicada.');
    map.set(name, { type, value, raw });
  }
  if (!terminated) throw new Error('VariantDictionary sem marcador final.');
  if (p !== bytes.length) throw new Error('VariantDictionary contém dados extras após o marcador final.');
  return map;
}

// Minimal, constant-table-free AES-256 implementation used only for the KeePass AES-KDF.
// Outer database encryption is handled by WebCrypto AES-CBC.
const SBOX = new Uint8Array([
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
const RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]);
function aesExpandKey(key) {
  ensureBytes(key, 32, 'Chave AES-KDF');
  const out = new Uint8Array(240); out.set(key);
  let bytes = 32, rcon = 0;
  const temp = new Uint8Array(4);
  while (bytes < 240) {
    temp.set(out.slice(bytes - 4, bytes));
    if (bytes % 32 === 0) {
      const t = temp[0]; temp[0]=SBOX[temp[1]]; temp[1]=SBOX[temp[2]]; temp[2]=SBOX[temp[3]]; temp[3]=SBOX[t]; temp[0] ^= RCON[rcon++];
    } else if (bytes % 32 === 16) {
      for (let i=0;i<4;i++) temp[i]=SBOX[temp[i]];
    }
    for (let i=0;i<4 && bytes<240;i++,bytes++) out[bytes]=out[bytes-32]^temp[i];
  }
  wipe(temp); return out;
}
function xtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 255; }
function aesEncryptBlockInPlace(s, expanded, t) {
  for (let i=0;i<16;i++) s[i]^=expanded[i];
  for (let round=1; round<=13; round++) {
    for (let i=0;i<16;i++) s[i]=SBOX[s[i]];
    t.set(s);
    s[0]=t[0];s[1]=t[5];s[2]=t[10];s[3]=t[15];s[4]=t[4];s[5]=t[9];s[6]=t[14];s[7]=t[3];
    s[8]=t[8];s[9]=t[13];s[10]=t[2];s[11]=t[7];s[12]=t[12];s[13]=t[1];s[14]=t[6];s[15]=t[11];
    for (let c=0;c<4;c++) {
      const i=c*4, a=s[i],b=s[i+1],d=s[i+2],e=s[i+3], x=a^b^d^e;
      s[i]=a^x^xtime(a^b); s[i+1]=b^x^xtime(b^d); s[i+2]=d^x^xtime(d^e); s[i+3]=e^x^xtime(e^a);
    }
    const ro=round*16; for (let i=0;i<16;i++) s[i]^=expanded[ro+i];
  }
  for (let i=0;i<16;i++) s[i]=SBOX[s[i]];
  t.set(s);
  s[0]=t[0];s[1]=t[5];s[2]=t[10];s[3]=t[15];s[4]=t[4];s[5]=t[9];s[6]=t[14];s[7]=t[3];
  s[8]=t[8];s[9]=t[13];s[10]=t[2];s[11]=t[7];s[12]=t[12];s[13]=t[1];s[14]=t[6];s[15]=t[11];
  for (let i=0;i<16;i++) s[i]^=expanded[224+i];
}
function aesEncryptBlock(block, expanded) {
  const s=new Uint8Array(block), t=new Uint8Array(16);
  aesEncryptBlockInPlace(s,expanded,t); wipe(t); return s;
}

export function aes256BlockForTest(key, block) { const e=aesExpandKey(key); try{return aesEncryptBlock(block,e);}finally{wipe(e);} }

async function aesKdf(composite, seed, rounds) {
  rounds = Number(rounds);
  if (!Number.isSafeInteger(rounds) || rounds < 1) throw new Error('Quantidade de rodadas AES-KDF inválida.');
  const expanded = aesExpandKey(seed);
  const a = composite.slice(0,16), b = composite.slice(16,32), temp = new Uint8Array(16);
  try {
    for (let i=0;i<rounds;i++) {
      aesEncryptBlockInPlace(a,expanded,temp); aesEncryptBlockInPlace(b,expanded,temp);
      if (i && i % AES_KDF_YIELD_EVERY === 0) await new Promise(resolve => setTimeout(resolve, 0));
    }
    return await sha256(concatBytes(a,b));
  } finally { wipe(expanded); wipe(a); wipe(b); wipe(temp); }
}

export async function calibrateAesKdf(targetMs = 1000) {
  const seed = randomBytes(32), c=randomBytes(32); const probe=3000; const start=performance.now();
  try { await aesKdf(c,seed,probe); } finally { wipe(seed); wipe(c); }
  const elapsed=Math.max(10,performance.now()-start);
  const estimate=Math.round(probe*(targetMs/elapsed));
  return Math.max(MIN_AES_ROUNDS,Math.min(MAX_AES_ROUNDS_CREATE,estimate));
}

async function compositeKey(components) {
  if (!Array.isArray(components) || !components.length) throw new Error('Componente de chave ausente.');
  for (const c of components) ensureBytes(c,32,'Componente da chave mestra');
  return sha256(concatBytes(...components));
}

async function computeKeys(components, masterSeed, kdf) {
  const comp = await compositeKey(components);
  let transformed;
  try {
    if (sameBytes(kdf.uuid, KDF_AES)) transformed = await aesKdf(comp,kdf.seed,kdf.rounds);
    else if (sameBytes(kdf.uuid,KDF_ARGON2D) || sameBytes(kdf.uuid,KDF_ARGON2ID)) {
      transformed = await argon2Kdf({
        type: sameBytes(kdf.uuid,KDF_ARGON2ID) ? 'argon2id' : 'argon2d',
        version: kdf.version,
        iterations: kdf.iterations,
        memoryBytes: kdf.memoryBytes,
        parallelism: kdf.parallelism,
        password: comp,
        salt: kdf.salt,
        secret: kdf.secret,
        associatedData: kdf.associatedData,
        length: 32
      });
    } else throw new Error('KDF do KDBX não suportado.');
    const encryptionKey = await sha256(concatBytes(masterSeed, transformed));
    const hmacBase = await sha512(concatBytes(masterSeed, transformed, new Uint8Array([1])));
    const headerHmacKey = await sha512(concatBytes(new Uint8Array([255,255,255,255,255,255,255,255]), hmacBase));
    return { encryptionKey, hmacBase, headerHmacKey };
  } finally { wipe(comp); if(transformed) wipe(transformed); }
}

async function blockHmacKey(hmacBase,index) { return sha512(concatBytes(u64(index),hmacBase)); }

async function aesCbcEncrypt(keyBytes, iv, plaintext) {
  const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-CBC'},false,['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv},key,plaintext));
}
async function aesCbcDecrypt(keyBytes, iv, ciphertext) {
  const key=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-CBC'},false,['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CBC',iv},key,ciphertext));
}

function chacha20Crypt(keyBytes, nonce, input) {
  const stream=new ChaCha20Stream(keyBytes,nonce,0);
  try{return stream.xor(input);}finally{stream.destroy();}
}
async function outerDecrypt(cipherName,keyBytes,iv,ciphertext){
  if(cipherName==='AES-256-CBC')return aesCbcDecrypt(keyBytes,iv,ciphertext);
  if(cipherName==='ChaCha20')return chacha20Crypt(keyBytes,iv,ciphertext);
  if(cipherName==='Twofish-256-CBC')return twofishCbcDecrypt(keyBytes,iv,ciphertext);
  throw new Error('Cifrador KDBX não suportado.');
}

async function outerEncrypt(cipherName,keyBytes,iv,plaintext){
  if(cipherName==='AES-256-CBC')return aesCbcEncrypt(keyBytes,iv,plaintext);
  if(cipherName==='ChaCha20')return chacha20Crypt(keyBytes,iv,plaintext);
  if(cipherName==='Twofish-256-CBC')return twofishCbcEncrypt(keyBytes,iv,plaintext);
  throw new Error('Cifrador KDBX não suportado para gravação.');
}

function rotl32(v,n){return ((v<<n)|(v>>>(32-n)))>>>0;}
class ChaCha20Stream {
  constructor(key,nonce,counter=0){ensureBytes(key,32,'Chave ChaCha20');ensureBytes(nonce,12,'Nonce ChaCha20');this.key=key.slice();this.nonce=nonce.slice();this.counter=counter>>>0;this.buffer=new Uint8Array(0);this.offset=0;}
  block(){
    const c=new Uint32Array(16), x=new Uint32Array(16), dvk=new DataView(this.key.buffer,this.key.byteOffset,this.key.byteLength), dvn=new DataView(this.nonce.buffer,this.nonce.byteOffset,this.nonce.byteLength);
    c[0]=0x61707865;c[1]=0x3320646e;c[2]=0x79622d32;c[3]=0x6b206574;
    for(let i=0;i<8;i++)c[4+i]=dvk.getUint32(i*4,true);c[12]=this.counter++;c[13]=dvn.getUint32(0,true);c[14]=dvn.getUint32(4,true);c[15]=dvn.getUint32(8,true);x.set(c);
    const qr=(a,b,d,e)=>{x[a]=(x[a]+x[b])>>>0;x[e]^=x[a];x[e]=rotl32(x[e],16);x[d]=(x[d]+x[e])>>>0;x[b]^=x[d];x[b]=rotl32(x[b],12);x[a]=(x[a]+x[b])>>>0;x[e]^=x[a];x[e]=rotl32(x[e],8);x[d]=(x[d]+x[e])>>>0;x[b]^=x[d];x[b]=rotl32(x[b],7);};
    for(let i=0;i<10;i++){qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15);qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14);}
    const out=new Uint8Array(64), dv=new DataView(out.buffer);for(let i=0;i<16;i++)dv.setUint32(i*4,(x[i]+c[i])>>>0,true);return out;
  }
  take(n){const out=new Uint8Array(n);let p=0;while(p<n){if(this.offset>=this.buffer.length){this.buffer=this.block();this.offset=0;}const m=Math.min(n-p,this.buffer.length-this.offset);out.set(this.buffer.subarray(this.offset,this.offset+m),p);this.offset+=m;p+=m;}return out;}
  xor(bytes){const ks=this.take(bytes.length),out=new Uint8Array(bytes.length);for(let i=0;i<bytes.length;i++)out[i]=bytes[i]^ks[i];wipe(ks);return out;}
  destroy(){wipe(this.key);wipe(this.nonce);wipe(this.buffer);}
}

async function innerChaCha(innerKey) { const h=await sha512(innerKey); const s=new ChaCha20Stream(h.slice(0,32),h.slice(32,44)); wipe(h); return s; }

function salsaRotl(v,n){return ((v<<n)|(v>>>(32-n)))>>>0;}
class Salsa20Stream {
  constructor(key,nonce){ensureBytes(key,32,'Chave Salsa20');ensureBytes(nonce,8,'Nonce Salsa20');this.key=key.slice();this.nonce=nonce.slice();this.lo=0;this.hi=0;this.buffer=new Uint8Array(0);this.offset=0;}
  block(){
    const st=new Uint32Array(16),x=new Uint32Array(16),dk=new DataView(this.key.buffer,this.key.byteOffset,this.key.byteLength),dn=new DataView(this.nonce.buffer,this.nonce.byteOffset,this.nonce.byteLength);
    st[0]=0x61707865;st[5]=0x3320646e;st[10]=0x79622d32;st[15]=0x6b206574;
    st[1]=dk.getUint32(0,true);st[2]=dk.getUint32(4,true);st[3]=dk.getUint32(8,true);st[4]=dk.getUint32(12,true);
    st[11]=dk.getUint32(16,true);st[12]=dk.getUint32(20,true);st[13]=dk.getUint32(24,true);st[14]=dk.getUint32(28,true);
    st[6]=dn.getUint32(0,true);st[7]=dn.getUint32(4,true);st[8]=this.lo;st[9]=this.hi;
    this.lo=(this.lo+1)>>>0;if(this.lo===0)this.hi=(this.hi+1)>>>0;x.set(st);
    for(let i=0;i<10;i++){
      x[4]^=salsaRotl((x[0]+x[12])>>>0,7);x[8]^=salsaRotl((x[4]+x[0])>>>0,9);x[12]^=salsaRotl((x[8]+x[4])>>>0,13);x[0]^=salsaRotl((x[12]+x[8])>>>0,18);
      x[9]^=salsaRotl((x[5]+x[1])>>>0,7);x[13]^=salsaRotl((x[9]+x[5])>>>0,9);x[1]^=salsaRotl((x[13]+x[9])>>>0,13);x[5]^=salsaRotl((x[1]+x[13])>>>0,18);
      x[14]^=salsaRotl((x[10]+x[6])>>>0,7);x[2]^=salsaRotl((x[14]+x[10])>>>0,9);x[6]^=salsaRotl((x[2]+x[14])>>>0,13);x[10]^=salsaRotl((x[6]+x[2])>>>0,18);
      x[3]^=salsaRotl((x[15]+x[11])>>>0,7);x[7]^=salsaRotl((x[3]+x[15])>>>0,9);x[11]^=salsaRotl((x[7]+x[3])>>>0,13);x[15]^=salsaRotl((x[11]+x[7])>>>0,18);
      x[1]^=salsaRotl((x[0]+x[3])>>>0,7);x[2]^=salsaRotl((x[1]+x[0])>>>0,9);x[3]^=salsaRotl((x[2]+x[1])>>>0,13);x[0]^=salsaRotl((x[3]+x[2])>>>0,18);
      x[6]^=salsaRotl((x[5]+x[4])>>>0,7);x[7]^=salsaRotl((x[6]+x[5])>>>0,9);x[4]^=salsaRotl((x[7]+x[6])>>>0,13);x[5]^=salsaRotl((x[4]+x[7])>>>0,18);
      x[11]^=salsaRotl((x[10]+x[9])>>>0,7);x[8]^=salsaRotl((x[11]+x[10])>>>0,9);x[9]^=salsaRotl((x[8]+x[11])>>>0,13);x[10]^=salsaRotl((x[9]+x[8])>>>0,18);
      x[12]^=salsaRotl((x[15]+x[14])>>>0,7);x[13]^=salsaRotl((x[12]+x[15])>>>0,9);x[14]^=salsaRotl((x[13]+x[12])>>>0,13);x[15]^=salsaRotl((x[14]+x[13])>>>0,18);
    }
    const out=new Uint8Array(64),dv=new DataView(out.buffer);for(let i=0;i<16;i++)dv.setUint32(i*4,(x[i]+st[i])>>>0,true);return out;
  }
  take(n){const out=new Uint8Array(n);let p=0;while(p<n){if(this.offset>=this.buffer.length){this.buffer=this.block();this.offset=0;}const m=Math.min(n-p,this.buffer.length-this.offset);out.set(this.buffer.subarray(this.offset,this.offset+m),p);this.offset+=m;p+=m;}return out;}
  xor(bytes){const ks=this.take(bytes.length),out=new Uint8Array(bytes.length);for(let i=0;i<bytes.length;i++)out[i]=bytes[i]^ks[i];wipe(ks);return out;}
  destroy(){wipe(this.key);wipe(this.nonce);wipe(this.buffer);}
}
async function innerSalsa(innerKey){const k=await sha256(innerKey),nonce=new Uint8Array([0xE8,0x30,0x09,0x4B,0x97,0x20,0x5D,0x2A]);const s=new Salsa20Stream(k,nonce);wipe(k);wipe(nonce);return s;}

function protectedXmlValue(value, stream) {
  const raw=utf8(value||''); const enc=stream.xor(raw); wipe(raw); const b64=bytesToBase64(enc); wipe(enc); return `<Value Protected="True">${b64}</Value>`;
}

function timesXml(created,modified) {
  const c=isoToKdbxTime(created),m=isoToKdbxTime(modified||created),now=isoToKdbxTime(new Date().toISOString());
  return `<Times><CreationTime>${c}</CreationTime><LastModificationTime>${m}</LastModificationTime><LastAccessTime>${now}</LastAccessTime><ExpiryTime>${now}</ExpiryTime><Expires>False</Expires><UsageCount>0</UsageCount><LocationChanged>${m}</LocationChanged></Times>`;
}

function entryXml(entry,stream){
  const id=entry.kdbxUuidBytes?base64ToBytes(entry.kdbxUuidBytes):uuidBytesFromString(entry.id); entry.kdbxUuidBytes=bytesToBase64(id);
  const strings=[];
  const plain=(k,v)=>strings.push(`<String><Key>${xmlEscape(k)}</Key><Value>${xmlEscape(v||'')}</Value></String>`);
  const prot=(k,v)=>strings.push(`<String><Key>${xmlEscape(k)}</Key>${protectedXmlValue(v||'',stream)}</String>`);
  plain('Title',entry.title);plain('UserName',entry.username);prot('Password',entry.password);plain('URL',entry.url);plain('Notes',entry.notes);
  if(entry.totpSecret){prot('TimeOtp-Secret-Base32',entry.totpSecret);plain('TimeOtp-Length','6');plain('TimeOtp-Period','30');plain('TimeOtp-Algorithm','HMAC-SHA-1');}
  if(entry.favorite) plain('MeuCofre-Favorite','True');
  return `<Entry><UUID>${bytesToBase64(id)}</UUID><IconID>0</IconID><ForegroundColor></ForegroundColor><BackgroundColor></BackgroundColor><OverrideURL></OverrideURL><Tags>${xmlEscape((entry.tags||[]).join(';'))}</Tags>${timesXml(entry.createdAt,entry.updatedAt)}${strings.join('')}<AutoType><Enabled>True</Enabled><DataTransferObfuscation>0</DataTransferObfuscation></AutoType></Entry>`;
}

function buildVaultXml(vault,stream){
  const now=new Date().toISOString();
  if(!vault.rootGroupUuid) vault.rootGroupUuid=bytesToBase64(randomBytes(16));
  const rootUuid=base64ToBytes(vault.rootGroupUuid);
  const customSettings=bytesToBase64(utf8(JSON.stringify(vault.settings||{})));
  const entries=(vault.entries||[]).map(e=>entryXml(e,stream)).join('');
  return `<?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta><Generator>Meu Cofre ${APP_VERSION}</Generator><DatabaseName>${xmlEscape(vault.name||'Meu Cofre')}</DatabaseName><DatabaseNameChanged>${isoToKdbxTime(vault.updatedAt||now)}</DatabaseNameChanged><MaintenanceHistoryDays>365</MaintenanceHistoryDays><MemoryProtection><ProtectTitle>False</ProtectTitle><ProtectUserName>False</ProtectUserName><ProtectPassword>True</ProtectPassword><ProtectURL>False</ProtectURL><ProtectNotes>False</ProtectNotes></MemoryProtection><RecycleBinEnabled>False</RecycleBinEnabled><EntryTemplatesGroup>${bytesToBase64(ZERO_UUID)}</EntryTemplatesGroup><EntryTemplatesGroupChanged>${isoToKdbxTime(now)}</EntryTemplatesGroupChanged><LastSelectedGroup>${bytesToBase64(rootUuid)}</LastSelectedGroup><LastTopVisibleGroup>${bytesToBase64(rootUuid)}</LastTopVisibleGroup><CustomData><Item><Key>MeuCofre.Settings</Key><Value>${customSettings}</Value><LastModificationTime>${isoToKdbxTime(vault.updatedAt||now)}</LastModificationTime></Item></CustomData></Meta><Root><Group><UUID>${bytesToBase64(rootUuid)}</UUID><Name>${xmlEscape(vault.name||'Meu Cofre')}</Name><Notes></Notes><IconID>48</IconID>${timesXml(vault.createdAt||now,vault.updatedAt||now)}<IsExpanded>True</IsExpanded><DefaultAutoTypeSequence></DefaultAutoTypeSequence><EnableAutoType>null</EnableAutoType><EnableSearching>null</EnableSearching><LastTopVisibleEntry>${bytesToBase64(ZERO_UUID)}</LastTopVisibleEntry>${entries}</Group><DeletedObjects></DeletedObjects></Root></KeePassFile>`;
}

function readElementText(parent,selector,def=''){const el=parent.querySelector(selector);return el?.textContent??def;}
function directChild(parent,name){return Array.from(parent.children||[]).find(el=>el.tagName===name)||null;}
function directChildren(parent,name){return Array.from(parent.children||[]).filter(el=>el.tagName===name);}

function totpSecretFromValues(vals){
  const direct=vals['TimeOtp-Secret-Base32']||'';if(direct)return String(direct).replace(/\s+/g,'').toUpperCase();
  const otp=String(vals.otp||'').trim();if(!otp)return '';
  if(/^otpauth:\/\//i.test(otp)){try{return String(new URL(otp).searchParams.get('secret')||'').replace(/\s+/g,'').toUpperCase();}catch{return '';}}
  return /^[A-Z2-7]+=*$/i.test(otp.replace(/\s+/g,''))?otp.replace(/\s+/g,'').replace(/=+$/,'').toUpperCase():'';
}

async function parseVaultXml(xmlBytes,innerAlg,innerKey,expectedHeaderHash=null){
  if(xmlBytes.length>MAX_XML_BYTES) throw new Error('XML KDBX excessivamente grande.');
  const xmlText=text(xmlBytes);
  if(/<!DOCTYPE|<!ENTITY/i.test(xmlText)) throw new Error('DTD/entidades não são permitidos em KDBX importado.');
  const doc=new DOMParser().parseFromString(xmlText,'application/xml');
  if(doc.querySelector('parsererror')) throw new Error('XML interno do KDBX inválido.');
  if(expectedHeaderHash){const stored=doc.querySelector('KeePassFile > Meta > HeaderHash')?.textContent?.trim()||'';if(stored){let b;try{b=base64ToBytes(stored);}catch{throw new Error('HeaderHash KDBX 3.1 inválido.');}const ok=sameBytes(b,expectedHeaderHash);wipe(b);if(!ok)throw new Error('Integridade do cabeçalho KDBX 3.1 falhou.');}}
  let stream=null;
  if(innerAlg===0) stream=null; else if(innerAlg===2) stream=await innerSalsa(innerKey); else if(innerAlg===3) stream=await innerChaCha(innerKey); else throw new Error('Algoritmo de proteção interna KDBX não suportado (ArcFourVariant legado não é aceito).');
  try{
    const protectedValues=Array.from(doc.querySelectorAll('Value[Protected="True"]'));
    if(protectedValues.length&&!stream) throw new Error('O KDBX contém valores protegidos, mas não declara stream interno.');
    for(const el of protectedValues){const enc=base64ToBytes(el.textContent||'');const dec=stream.xor(enc);el.textContent=text(dec);el.removeAttribute('Protected');wipe(enc);wipe(dec);}
    const rootGroup=doc.querySelector('KeePassFile > Root > Group'); if(!rootGroup) throw new Error('KDBX sem grupo raiz.');
    const meta=doc.querySelector('KeePassFile > Meta');
    const name=readElementText(meta,'DatabaseName',readElementText(rootGroup,':scope > Name','Meu Cofre'));
    let settings={idleLockMinutes:5,backgroundLockSeconds:0,clipboardClearSeconds:20};
    const items=meta?Array.from(meta.querySelectorAll(':scope > CustomData > Item')):[];
    for(const item of items){if(readElementText(item,':scope > Key')==='MeuCofre.Settings'){try{settings={...settings,...JSON.parse(text(base64ToBytes(readElementText(item,':scope > Value'))))};}catch{}}}
    const entries=[];
    const walkGroup=(group)=>{
      for(const entryEl of directChildren(group,'Entry')){
        const vals={}; for(const stringEl of directChildren(entryEl,'String')){const k=readElementText(stringEl,':scope > Key');const v=readElementText(stringEl,':scope > Value');vals[k]=v;}
        const times=directChild(entryEl,'Times');const tags=(readElementText(entryEl,':scope > Tags')||'').split(';').map(s=>s.trim()).filter(Boolean);
        const uuidB64=readElementText(entryEl,':scope > UUID');
        entries.push({
          id: uuid(), kdbxUuidBytes: uuidB64,
          title:vals.Title||'',username:vals.UserName||'',password:vals.Password||'',url:vals.URL||'',notes:vals.Notes||'',tags,
          totpSecret:totpSecretFromValues(vals),favorite:String(vals['MeuCofre-Favorite']||'').toLowerCase()==='true',
          createdAt:kdbxTimeToIso(readElementText(times,':scope > CreationTime')),
          updatedAt:kdbxTimeToIso(readElementText(times,':scope > LastModificationTime'))
        });
      }
      for(const child of directChildren(group,'Group')) walkGroup(child);
    }; walkGroup(rootGroup);
    const now=new Date().toISOString();
    return {schema:2,id:uuid(),name,createdAt:now,updatedAt:now,rootGroupUuid:readElementText(rootGroup,':scope > UUID')||bytesToBase64(randomBytes(16)),entries,settings};
  }finally{stream?.destroy();}
}

function publicMetaToDict(meta){
  return variantDict([
    {name:'MeuCofre.Schema',type:0x04,value:PUBLIC_SCHEMA},
    {name:'MeuCofre.AppVersion',type:0x18,value:APP_VERSION},
    {name:'MeuCofre.Mode',type:0x18,value:meta.mode||PROTECTION_MODES.PASSWORD},
    {name:'MeuCofre.WebAuthnUserId',type:0x18,value:meta.webauthnUserId||bytesToBase64(randomBytes(32))},
    {name:'MeuCofre.Slots',type:0x18,value:JSON.stringify(meta.slots||[])},
    {name:'MeuCofre.RecoveryKeyRequired',type:0x08,value:Boolean(meta.recoveryKeyRequired)}
  ]);
}
function dictToPublicMeta(bytes){
  if(!bytes?.length) return {schema:0,mode:null,webauthnUserId:null,slots:[],recoveryKeyRequired:false};
  if(bytes.length>MAX_HEADER_FIELD_BYTES) throw new Error('Metadados públicos KDBX excessivamente grandes.');
  const d=parseVariantDict(bytes); let slots=[];
  try{slots=JSON.parse(d.get('MeuCofre.Slots')?.value||'[]');}catch{slots=[];}
  if(!Array.isArray(slots)) slots=[];
  const seenSlotIds=new Set();
  slots=slots.slice(0,MAX_PUBLIC_SLOTS).filter((slot)=>{
    if(!slot||typeof slot!=='object') return false;
    const strings=['id','type','kind','label','credentialId','prfSalt','hkdfSalt','iv','wrapped','role'];
    if(!strings.every(k=>slot[k]==null||(typeof slot[k]==='string'&&slot[k].length<=8192))) return false;
    if(!slot.id||seenSlotIds.has(slot.id)) return false;
    seenSlotIds.add(slot.id); return true;
  }).map(slot=>({...slot,transports:Array.isArray(slot.transports)?slot.transports.filter(x=>typeof x==='string').slice(0,8):[]}));
  const mode=d.get('MeuCofre.Mode')?.value||null;
  return {schema:Number(d.get('MeuCofre.Schema')?.value||0),appVersion:String(d.get('MeuCofre.AppVersion')?.value||'').slice(0,64),mode:Object.values(PROTECTION_MODES).includes(mode)?mode:null,webauthnUserId:String(d.get('MeuCofre.WebAuthnUserId')?.value||'').slice(0,256)||null,slots,recoveryKeyRequired:Boolean(d.get('MeuCofre.RecoveryKeyRequired')?.value)};
}

function kdfToDict(seed,rounds){return variantDict([{name:'$UUID',type:0x42,value:KDF_AES},{name:'S',type:0x42,value:seed},{name:'R',type:0x05,value:BigInt(rounds)}]);}
function parseKdf(bytes){
  const d=parseVariantDict(bytes);const uuid=d.get('$UUID')?.raw;
  if(!uuid||uuid.length!==16)throw new Error('KDBX sem UUID válido da KDF.');
  if(sameBytes(uuid,KDF_AES)){
    const seed=d.get('S')?.raw, rounds=d.get('R')?.value;
    if(!seed||seed.length!==32||typeof rounds!=='bigint'||rounds<1n||rounds>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Parâmetros AES-KDF inválidos.');
    return{uuid,seed,rounds:Number(rounds),name:'AES-KDF'};
  }
  if(sameBytes(uuid,KDF_ARGON2ID)||sameBytes(uuid,KDF_ARGON2D)){
    const salt=d.get('S')?.raw, iterations=d.get('I')?.value, memory=d.get('M')?.value, parallelism=d.get('P')?.value, version=d.get('V')?.value;
    const secret=d.get('K')?.raw||new Uint8Array(0), associatedData=d.get('A')?.raw||new Uint8Array(0);
    if(!salt||salt.length<8||typeof iterations!=='bigint'||iterations<1n||iterations>BigInt(Number.MAX_SAFE_INTEGER)||typeof memory!=='bigint'||memory<8192n||memory>2147000000n||!Number.isInteger(parallelism)||parallelism<1||parallelism>0xffffff||![0x10,0x13].includes(Number(version)))throw new Error('Parâmetros Argon2 inválidos ou acima da memória suportada pelo navegador.');
    return{uuid,name:sameBytes(uuid,KDF_ARGON2ID)?'Argon2id':'Argon2d',salt,iterations:Number(iterations),memoryBytes:Number(memory),parallelism:Number(parallelism),version:Number(version),secret,associatedData};
  }
  return{uuid,name:'Desconhecida'};
}

function cipherInfo(cipher,iv) {
  const cipherName=sameBytes(cipher,CIPHER_AES)?'AES-256-CBC':sameBytes(cipher,CIPHER_CHACHA20)?'ChaCha20':sameBytes(cipher,CIPHER_TWOFISH)?'Twofish-256-CBC':null;
  if(!cipherName)throw new Error('Cifrador KDBX desconhecido.');
  if((cipherName==='AES-256-CBC'||cipherName==='Twofish-256-CBC')&&iv.length!==16)throw new Error('IV do cifrador KDBX inválido.');
  if(cipherName==='ChaCha20'&&iv.length!==12)throw new Error('Nonce ChaCha20 KDBX inválido.');
  return cipherName;
}

function parseHeaderV4(bytes,version){
  let p=12; const fields=new Map();
  while(p+5<=bytes.length){const id=bytes[p++];const len=readI32(bytes,p);p+=4;if(len<0||len>MAX_HEADER_FIELD_BYTES||p+len>bytes.length)throw new Error('Cabeçalho KDBX truncado ou excessivo.');if(fields.has(id))throw new Error('Campo duplicado no cabeçalho KDBX.');const value=bytes.slice(p,p+len);p+=len;fields.set(id,value);if(id===0){if(!sameBytes(value,new Uint8Array([13,10,13,10])))throw new Error('Marcador final do cabeçalho KDBX inválido.');break;}}
  if(!fields.has(0)||p+64>bytes.length) throw new Error('Cabeçalho KDBX incompleto.');
  const cipher=fields.get(2),compression=fields.get(3),masterSeed=fields.get(4),iv=fields.get(7),kdfBytes=fields.get(11);
  if(!cipher||!compression||!masterSeed||!iv||!kdfBytes)throw new Error('Campos obrigatórios do KDBX ausentes.');
  if(cipher.length!==16||compression.length!==4||masterSeed.length!==32)throw new Error('Tamanho inválido em campo obrigatório do cabeçalho KDBX.');
  const cipherName=cipherInfo(cipher,iv),comp=readU32(compression,0);if(comp!==0&&comp!==1)throw new Error('Compressão KDBX não suportada.');
  const headerBytes=bytes.slice(0,p),storedHash=bytes.slice(p,p+32),storedHmac=bytes.slice(p+32,p+64);
  return{major:4,version,headerEnd:p,bodyOffset:p+64,headerBytes,storedHash,storedHmac,cipher,cipherName,compression:comp,masterSeed,iv,kdfBytes,kdf:parseKdf(kdfBytes),publicMeta:dictToPublicMeta(fields.get(12)||new Uint8Array(0))};
}

function parseHeaderV3(bytes,version){
  let p=12; const fields=new Map();
  while(p+3<=bytes.length){const id=bytes[p++],len=readU16(bytes,p);p+=2;if(len>MAX_HEADER_FIELD_BYTES||p+len>bytes.length)throw new Error('Cabeçalho KDBX 3.1 truncado ou excessivo.');if(fields.has(id))throw new Error('Campo duplicado no cabeçalho KDBX 3.1.');const value=bytes.slice(p,p+len);p+=len;fields.set(id,value);if(id===0)break;}
  if(!fields.has(0))throw new Error('Cabeçalho KDBX 3.1 incompleto.');
  const cipher=fields.get(2),compression=fields.get(3),masterSeed=fields.get(4),transformSeed=fields.get(5),transformRounds=fields.get(6),iv=fields.get(7),protectedStreamKey=fields.get(8),streamStartBytes=fields.get(9),innerRandomStream=fields.get(10);
  if(!cipher||!compression||!masterSeed||!transformSeed||!transformRounds||!iv||!protectedStreamKey||!streamStartBytes||!innerRandomStream)throw new Error('Campos obrigatórios do KDBX 3.1 ausentes.');
  if(cipher.length!==16||compression.length!==4||masterSeed.length!==32||transformSeed.length!==32||transformRounds.length!==8||innerRandomStream.length!==4||streamStartBytes.length<16)throw new Error('Tamanho inválido em campo obrigatório do cabeçalho KDBX 3.1.');
  const cipherName=cipherInfo(cipher,iv);if(cipherName==='ChaCha20')throw new Error('ChaCha20 requer KDBX 4; cabeçalho KDBX 3.1 incompatível.');
  const comp=readU32(compression,0);if(comp!==0&&comp!==1)throw new Error('Compressão KDBX 3.1 não suportada.');
  const rounds=readU64(transformRounds,0);if(rounds<1n||rounds>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Parâmetros AES-KDF KDBX 3.1 inválidos.');
  const innerAlg=readU32(innerRandomStream,0);if(![0,1,2].includes(innerAlg))throw new Error('Stream interno KDBX 3.1 desconhecido.');
  return{major:3,version,headerEnd:p,bodyOffset:p,headerBytes:bytes.slice(0,p),cipher,cipherName,compression:comp,masterSeed,iv,kdf:{uuid:KDF_AES,seed:transformSeed,rounds:Number(rounds),name:'AES-KDF'},protectedStreamKey,streamStartBytes,innerAlg,publicMeta:{schema:0,mode:null,webauthnUserId:null,slots:[],recoveryKeyRequired:false}};
}

function parseHeader(bytes){
  if(bytes.length<24||bytes.length>MAX_FILE_BYTES) throw new Error('Arquivo KDBX inválido ou grande demais.');
  if(readU32(bytes,0)!==SIG1||readU32(bytes,4)!==SIG2) throw new Error('Assinatura KDBX inválida.');
  const version=readU32(bytes,8),major=version>>>16;
  if(major===4)return parseHeaderV4(bytes,version);
  if(major===3)return parseHeaderV3(bytes,version);
  throw new Error(`KDBX ${major} não suportado.`);
}

export function inspectKdbx(bytes){const h=parseHeader(bytes);return{version:`${h.version>>>16}.${h.version&0xffff}`,cipher:h.cipherName,compression:h.compression?'GZip':'Nenhuma',kdf:h.kdf.name,rounds:h.kdf.rounds||null,memoryBytes:h.kdf.memoryBytes||null,iterations:h.kdf.iterations||null,parallelism:h.kdf.parallelism||null,publicMeta:h.publicMeta,externalCompatible:true};}

async function hmacBlockStream(encrypted,hmacBase){
  const parts=[];let index=0n;
  for(let p=0;p<encrypted.length;p+=BLOCK_SIZE){const block=encrypted.slice(p,Math.min(encrypted.length,p+BLOCK_SIZE)),size=i32(block.length),key=await blockHmacKey(hmacBase,index),mac=await hmacSha256(key,concatBytes(u64(index),size,block));wipe(key);parts.push(mac,size,block);index++;}
  const size=i32(0),key=await blockHmacKey(hmacBase,index),mac=await hmacSha256(key,concatBytes(u64(index),size));wipe(key);parts.push(mac,size);return concatBytes(...parts);
}
async function verifyBlockStream(bytes,offset,hmacBase){
  const blocks=[];let p=offset,index=0n,total=0;
  while(true){if(p+36>bytes.length)throw new Error('Fluxo HMAC do KDBX truncado.');const stored=bytes.slice(p,p+32);p+=32;const size=readI32(bytes,p);p+=4;if(size<0||p+size>bytes.length)throw new Error('Bloco KDBX inválido.');const block=bytes.slice(p,p+size);p+=size;const key=await blockHmacKey(hmacBase,index),actual=await hmacSha256(key,concatBytes(u64(index),i32(size),block));wipe(key);if(!sameBytes(stored,actual))throw new Error('Integridade HMAC do KDBX falhou.');if(size===0){if(p!==bytes.length)throw new Error('Dados extras após o fim do fluxo KDBX.');break;}total+=size;if(total>MAX_FILE_BYTES)throw new Error('Conteúdo KDBX excessivamente grande.');blocks.push(block);index++;}
  return concatBytes(...blocks);
}

async function verifyHashedBlockStreamV3(bytes,offset){
  const blocks=[];let p=offset,expected=0,total=0;
  while(true){if(p+40>bytes.length)throw new Error('Fluxo de blocos KDBX 3.1 truncado.');const index=readU32(bytes,p);p+=4;const stored=bytes.slice(p,p+32);p+=32;const size=readU32(bytes,p);p+=4;if(index!==expected)throw new Error('Sequência de blocos KDBX 3.1 inválida.');if(p+size>bytes.length)throw new Error('Bloco KDBX 3.1 truncado.');const block=bytes.slice(p,p+size);p+=size;if(size===0){if(p!==bytes.length)throw new Error('Dados extras após o fim do KDBX 3.1.');break;}const actual=await sha256(block);if(!sameBytes(stored,actual))throw new Error('Hash de bloco KDBX 3.1 inválido.');wipe(actual);total+=size;if(total>MAX_FILE_BYTES)throw new Error('Conteúdo KDBX 3.1 excessivamente grande.');blocks.push(block);expected++;}
  return concatBytes(...blocks);
}

async function maybeDecompress(bytes,compression){
  if(!compression)return bytes;
  if(typeof DecompressionStream==='undefined')throw new Error('Este navegador não consegue descompactar este KDBX GZip.');
  const reader=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip')).getReader();
  const chunks=[];let total=0;
  try{while(true){const {value,done}=await reader.read();if(done)break;total+=value.byteLength;if(total>MAX_XML_BYTES+4*1024*1024){await reader.cancel();throw new Error('KDBX GZip descompactado excede o limite seguro.');}chunks.push(new Uint8Array(value));}}finally{reader.releaseLock?.();}
  return concatBytes(...chunks);
}

async function maybeCompress(bytes,compression){
  if(!compression)return bytes;
  if(typeof CompressionStream==='undefined')throw new Error('Este navegador não consegue gravar KDBX com compressão GZip.');
  const reader=new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip')).getReader();
  const chunks=[];let total=0;
  try{while(true){const {value,done}=await reader.read();if(done)break;total+=value.byteLength;if(total>MAX_FILE_BYTES){await reader.cancel();throw new Error('KDBX GZip excede o limite seguro.');}chunks.push(new Uint8Array(value));}}finally{reader.releaseLock?.();}
  return concatBytes(...chunks);
}

async function hashedBlockStreamV3(data){
  const parts=[];let index=0,total=0;
  for(let p=0;p<data.length;p+=BLOCK_SIZE){const block=data.slice(p,Math.min(data.length,p+BLOCK_SIZE)),hash=await sha256(block);parts.push(u32(index),hash,u32(block.length),block);total+=block.length;if(total>MAX_FILE_BYTES)throw new Error('Conteúdo KDBX 3.1 excessivamente grande.');index++;}
  parts.push(u32(index),new Uint8Array(32),u32(0));return concatBytes(...parts);
}

function parseInnerHeader(bytes){let p=0,innerAlg=null,innerKey=null;while(p+5<=bytes.length){const id=bytes[p++],len=readI32(bytes,p);p+=4;if(len<0||p+len>bytes.length)throw new Error('Cabeçalho interno KDBX inválido.');const value=bytes.slice(p,p+len);p+=len;if(id===0){if(len!==0)throw new Error('Final do cabeçalho interno inválido.');return{innerAlg,innerKey,xmlOffset:p,headerBytes:bytes.slice(0,p)};}if(id===1){if(len!==4)throw new Error('Algoritmo interno inválido.');innerAlg=readI32(value,0);}else if(id===2)innerKey=value;}throw new Error('Cabeçalho interno KDBX incompleto.');}

function rewriteHeaderV4(headerBytes,replacements){
  const parts=[headerBytes.slice(0,12)];let p=12;
  while(p+5<=headerBytes.length){const id=headerBytes[p++],len=readI32(headerBytes,p);p+=4;if(len<0||p+len>headerBytes.length)throw new Error('Cabeçalho KDBX inválido durante gravação.');let value=headerBytes.slice(p,p+len);p+=len;if(replacements.has(id))value=replacements.get(id);parts.push(new Uint8Array([id]),i32(value.length),value);if(id===0)break;}
  return concatBytes(...parts);
}
function rewriteHeaderV3(headerBytes,replacements){
  const parts=[headerBytes.slice(0,12)];let p=12;
  while(p+3<=headerBytes.length){const id=headerBytes[p++],len=readU16(headerBytes,p);p+=2;if(p+len>headerBytes.length)throw new Error('Cabeçalho KDBX 3.1 inválido durante gravação.');let value=headerBytes.slice(p,p+len);p+=len;if(replacements.has(id))value=replacements.get(id);if(value.length>0xffff)throw new Error('Campo KDBX 3.1 grande demais.');parts.push(new Uint8Array([id]),u16(value.length),value);if(id===0)break;}
  return concatBytes(...parts);
}
function rewriteInnerHeader(headerBytes,newKey){
  const parts=[];let p=0,seenKey=false;
  while(p+5<=headerBytes.length){const id=headerBytes[p++],len=readI32(headerBytes,p);p+=4;if(len<0||p+len>headerBytes.length)throw new Error('Cabeçalho interno KDBX inválido durante gravação.');let value=headerBytes.slice(p,p+len);p+=len;if(id===2){value=newKey;seenKey=true;}parts.push(new Uint8Array([id]),i32(value.length),value);if(id===0)break;}
  if(!seenKey)throw new Error('Cabeçalho interno KDBX sem chave de proteção.');return concatBytes(...parts);
}
function rewriteVariantDictRaw(bytes,replacements){
  if(bytes.length<3)throw new Error('VariantDictionary truncado.');const parts=[bytes.slice(0,2)];let p=2,ended=false;
  while(p<bytes.length){const type=bytes[p++];if(type===0){parts.push(new Uint8Array([0]));ended=true;break;}if(p+4>bytes.length)throw new Error('VariantDictionary truncado.');const nameLen=readI32(bytes,p),nameLenBytes=bytes.slice(p,p+4);p+=4;if(nameLen<0||p+nameLen+4>bytes.length)throw new Error('VariantDictionary inválido.');const nameBytes=bytes.slice(p,p+nameLen),name=text(nameBytes);p+=nameLen;const valueLen=readI32(bytes,p);p+=4;if(valueLen<0||p+valueLen>bytes.length)throw new Error('VariantDictionary inválido.');let value=bytes.slice(p,p+valueLen);p+=valueLen;if(replacements.has(name))value=replacements.get(name);parts.push(new Uint8Array([type]),nameLenBytes,nameBytes,i32(value.length),value);}
  if(!ended)throw new Error('VariantDictionary sem marcador final.');return concatBytes(...parts);
}
async function editableXmlDocument(xmlBytes,innerAlg,innerKey,expectedHeaderHash=null){
  if(xmlBytes.length>MAX_XML_BYTES)throw new Error('XML KDBX excessivamente grande.');const xmlText=text(xmlBytes);if(/<!DOCTYPE|<!ENTITY/i.test(xmlText))throw new Error('DTD/entidades não são permitidos em KDBX importado.');const doc=new DOMParser().parseFromString(xmlText,'application/xml');if(doc.querySelector('parsererror'))throw new Error('XML interno do KDBX inválido.');
  if(expectedHeaderHash){const stored=doc.querySelector('KeePassFile > Meta > HeaderHash')?.textContent?.trim()||'';if(stored){let b;try{b=base64ToBytes(stored);}catch{throw new Error('HeaderHash KDBX 3.1 inválido.');}const ok=sameBytes(b,expectedHeaderHash);wipe(b);if(!ok)throw new Error('Integridade do cabeçalho KDBX 3.1 falhou.');}}
  let stream=null;if(innerAlg===0)stream=null;else if(innerAlg===2)stream=await innerSalsa(innerKey);else if(innerAlg===3)stream=await innerChaCha(innerKey);else throw new Error('Algoritmo de proteção interna KDBX não suportado para edição.');
  const protectedSet=new Set();try{const protectedValues=Array.from(doc.querySelectorAll('Value[Protected="True"]'));if(protectedValues.length&&!stream)throw new Error('KDBX contém valores protegidos sem stream interno.');for(const el of protectedValues){const enc=base64ToBytes(el.textContent||''),dec=stream.xor(enc);el.textContent=text(dec);el.removeAttribute('Protected');protectedSet.add(el);wipe(enc);wipe(dec);}return{doc,protectedSet};}finally{stream?.destroy();}
}
function kdbxTimeForMajor(iso,major){if(major>=4)return isoToKdbxTime(iso);const d=new Date(Date.parse(iso||'')||Date.now());return d.toISOString().replace('.000Z','Z');}
function setDirectChildText(parent,name,value){let el=directChild(parent,name);if(!el){el=parent.ownerDocument.createElement(name);parent.append(el);}el.textContent=String(value??'');return el;}
function directString(entry,key){return directChildren(entry,'String').find(s=>readElementText(s,':scope > Key')===key)||null;}
function setStringValue(entry,key,value,protectedSet,{protect=false,removeEmpty=false}={}){let node=directString(entry,key);if(removeEmpty&&!value){if(node){for(const v of node.querySelectorAll('Value'))protectedSet.delete(v);node.remove();}return null;}if(!node){node=entry.ownerDocument.createElement('String');const k=entry.ownerDocument.createElement('Key'),v=entry.ownerDocument.createElement('Value');k.textContent=key;node.append(k,v);const auto=directChild(entry,'AutoType');if(auto)entry.insertBefore(node,auto);else entry.append(node);}let val=directChild(node,'Value');if(!val){val=entry.ownerDocument.createElement('Value');node.append(val);}val.textContent=String(value??'');if(protect)protectedSet.add(val);return node;}
function cloneEntryForHistory(entry,protectedSet){for(const v of entry.querySelectorAll('Value'))if(protectedSet.has(v))v.setAttribute('MCProtected','1');const clone=entry.cloneNode(true);for(const v of entry.querySelectorAll('Value[MCProtected="1"]'))v.removeAttribute('MCProtected');for(const v of clone.querySelectorAll('Value[MCProtected="1"]')){v.removeAttribute('MCProtected');protectedSet.add(v);}const nested=directChild(clone,'History');nested?.remove();return clone;}
function setTotpValue(entry,secret,protectedSet){const otpNode=directString(entry,'otp');if(otpNode){if(!secret){for(const v of otpNode.querySelectorAll('Value'))protectedSet.delete(v);otpNode.remove();return;}const old=readElementText(otpNode,':scope > Value');let next=secret;if(/^otpauth:\/\//i.test(old)){try{const u=new URL(old);u.searchParams.set('secret',secret);next=u.toString();}catch{next=secret;}}setStringValue(entry,'otp',next,protectedSet,{protect:true});return;}setStringValue(entry,'TimeOtp-Secret-Base32',secret,protectedSet,{protect:true,removeEmpty:true});if(secret){setStringValue(entry,'TimeOtp-Length','6',protectedSet);setStringValue(entry,'TimeOtp-Period','30',protectedSet);setStringValue(entry,'TimeOtp-Algorithm','HMAC-SHA-1',protectedSet);}else{for(const k of ['TimeOtp-Length','TimeOtp-Period','TimeOtp-Algorithm'])setStringValue(entry,k,'',protectedSet,{removeEmpty:true});}}
function entryChanged(entryEl,e){const vals={};for(const s of directChildren(entryEl,'String'))vals[readElementText(s,':scope > Key')]=readElementText(s,':scope > Value');const tags=(readElementText(entryEl,':scope > Tags')||'').split(';').map(x=>x.trim()).filter(Boolean);return (vals.Title||'')!==(e.title||'')||(vals.UserName||'')!==(e.username||'')||(vals.Password||'')!==(e.password||'')||(vals.URL||'')!==(e.url||'')||(vals.Notes||'')!==(e.notes||'')||tags.join(';')!==(e.tags||[]).join(';')||totpSecretFromValues(vals)!==(e.totpSecret||'')||(String(vals['MeuCofre-Favorite']||'').toLowerCase()==='true')!==Boolean(e.favorite);}
function ensureHistory(entry){let h=directChild(entry,'History');if(!h){h=entry.ownerDocument.createElement('History');entry.append(h);}return h;}
function createNewEntryElement(doc,e,major,protectedSet){const entry=doc.createElement('Entry'),id=randomBytes(16);e.kdbxUuidBytes=bytesToBase64(id);setDirectChildText(entry,'UUID',e.kdbxUuidBytes);setDirectChildText(entry,'IconID','0');setDirectChildText(entry,'ForegroundColor','');setDirectChildText(entry,'BackgroundColor','');setDirectChildText(entry,'OverrideURL','');setDirectChildText(entry,'Tags',(e.tags||[]).join(';'));const times=doc.createElement('Times'),now=e.createdAt||new Date().toISOString();for(const [n,v] of [['CreationTime',now],['LastModificationTime',e.updatedAt||now],['LastAccessTime',e.updatedAt||now],['ExpiryTime',e.updatedAt||now]])setDirectChildText(times,n,kdbxTimeForMajor(v,major));setDirectChildText(times,'Expires','False');setDirectChildText(times,'UsageCount','0');setDirectChildText(times,'LocationChanged',kdbxTimeForMajor(e.updatedAt||now,major));entry.append(times);setStringValue(entry,'Title',e.title,protectedSet);setStringValue(entry,'UserName',e.username,protectedSet);setStringValue(entry,'Password',e.password,protectedSet,{protect:true});setStringValue(entry,'URL',e.url,protectedSet);setStringValue(entry,'Notes',e.notes,protectedSet);if(e.totpSecret)setTotpValue(entry,e.totpSecret,protectedSet);if(e.favorite)setStringValue(entry,'MeuCofre-Favorite','True',protectedSet);const at=doc.createElement('AutoType');setDirectChildText(at,'Enabled','True');setDirectChildText(at,'DataTransferObfuscation','0');entry.append(at);wipe(id);return entry;}
function addDeletedObject(doc,uuidB64,major){let deleted=doc.querySelector('KeePassFile > Root > DeletedObjects');if(!deleted){deleted=doc.createElement('DeletedObjects');doc.querySelector('KeePassFile > Root')?.append(deleted);}if(!deleted)return;const d=doc.createElement('DeletedObject');setDirectChildText(d,'UUID',uuidB64);setDirectChildText(d,'DeletionTime',kdbxTimeForMajor(new Date().toISOString(),major));deleted.append(d);}
function patchDocumentFromVault(doc,vault,major,protectedSet){const current=new Map();for(const e of vault.entries||[]){if(e.kdbxUuidBytes)current.set(e.kdbxUuidBytes,e);}const live=Array.from(doc.querySelectorAll('Entry')).filter(e=>e.parentElement?.tagName==='Group');for(const entryEl of live){const uuidB64=readElementText(entryEl,':scope > UUID');const e=current.get(uuidB64);if(!e){addDeletedObject(doc,uuidB64,major);entryEl.remove();continue;}current.delete(uuidB64);if(entryChanged(entryEl,e))ensureHistory(entryEl).append(cloneEntryForHistory(entryEl,protectedSet));setStringValue(entryEl,'Title',e.title,protectedSet);setStringValue(entryEl,'UserName',e.username,protectedSet);setStringValue(entryEl,'Password',e.password,protectedSet,{protect:true});setStringValue(entryEl,'URL',e.url,protectedSet);setStringValue(entryEl,'Notes',e.notes,protectedSet);setDirectChildText(entryEl,'Tags',(e.tags||[]).join(';'));setTotpValue(entryEl,e.totpSecret,protectedSet);setStringValue(entryEl,'MeuCofre-Favorite',e.favorite?'True':'',protectedSet,{removeEmpty:true});const times=directChild(entryEl,'Times');if(times)setDirectChildText(times,'LastModificationTime',kdbxTimeForMajor(e.updatedAt||new Date().toISOString(),major));}
  const rootGroup=doc.querySelector('KeePassFile > Root > Group');if(!rootGroup)throw new Error('KDBX sem grupo raiz.');for(const e of current.values())rootGroup.append(createNewEntryElement(doc,e,major,protectedSet));
}
async function protectXmlDocument(doc,protectedSet,innerAlg,innerKey){let stream=null;if(innerAlg===0){if(protectedSet.size)throw new Error('Não é possível gravar valores protegidos sem stream interno.');}else if(innerAlg===2)stream=await innerSalsa(innerKey);else if(innerAlg===3)stream=await innerChaCha(innerKey);else throw new Error('Stream interno não suportado para gravação.');try{for(const el of Array.from(doc.querySelectorAll('Value'))){el.removeAttribute('MCProtected');if(!protectedSet.has(el))continue;const raw=utf8(el.textContent||''),enc=stream.xor(raw);el.textContent=bytesToBase64(enc);el.setAttribute('Protected','True');wipe(raw);wipe(enc);}}finally{stream?.destroy();}}
function serializeXmlDocument(doc){let xml=new XMLSerializer().serializeToString(doc);if(!/^<\?xml/i.test(xml))xml='<?xml version="1.0" encoding="utf-8"?>'+xml;return utf8(xml);}

export async function writeKdbx(vault,components,publicMeta={},options={}){
  const rounds=Math.max(MIN_AES_ROUNDS,Math.min(MAX_AES_ROUNDS_CREATE,Number(options.rounds||DEFAULT_AES_ROUNDS)));
  const masterSeed=randomBytes(32),transformSeed=randomBytes(32),iv=randomBytes(16),innerKey=randomBytes(64);
  const kdf={uuid:KDF_AES,seed:transformSeed,rounds,name:'AES-KDF'};
  const keys=await computeKeys(components,masterSeed,kdf);
  let innerStream,xmlBytes,plaintext,encrypted,blocks;
  try{
    innerStream=await innerChaCha(innerKey);
    const xml=buildVaultXml(vault,innerStream); xmlBytes=utf8(xml);
    const innerHeader=concatBytes(writeInnerField(1,i32(3)),writeInnerField(2,innerKey),writeInnerField(0,new Uint8Array(0)));
    plaintext=concatBytes(innerHeader,xmlBytes);
    encrypted=await aesCbcEncrypt(keys.encryptionKey,iv,plaintext);
    blocks=await hmacBlockStream(encrypted,keys.hmacBase);
    const header=concatBytes(u32(SIG1),u32(SIG2),u32(KDBX_VERSION),writeHeaderField(2,CIPHER_AES),writeHeaderField(3,u32(0)),writeHeaderField(4,masterSeed),writeHeaderField(7,iv),writeHeaderField(11,kdfToDict(transformSeed,rounds)),writeHeaderField(12,publicMetaToDict(publicMeta)),writeHeaderField(0,new Uint8Array([13,10,13,10])));
    const headerHash=await sha256(header),headerHmac=await hmacSha256(keys.headerHmacKey,header);
    return concatBytes(header,headerHash,headerHmac,blocks);
  } finally {
    innerStream?.destroy();[masterSeed,transformSeed,iv,innerKey,xmlBytes,plaintext,encrypted,blocks,keys.encryptionKey,keys.hmacBase,keys.headerHmacKey].forEach(x=>x&&wipe(x));
  }
}

export async function readKdbx(bytes,components){
  ensureBytes(bytes,null,'Arquivo KDBX');const h=parseHeader(bytes);const keys=await computeKeys(components,h.masterSeed,h.kdf);let encrypted,plain,decompressed,headerHash;
  try{
    if(h.major===4){
      const actualHash=await sha256(h.headerBytes);if(!sameBytes(actualHash,h.storedHash))throw new Error('Hash do cabeçalho KDBX inválido.');wipe(actualHash);
      const actualHeaderHmac=await hmacSha256(keys.headerHmacKey,h.headerBytes);if(!sameBytes(actualHeaderHmac,h.storedHmac))throw new Error('Senha/chave incorreta ou cabeçalho KDBX adulterado.');wipe(actualHeaderHmac);
      encrypted=await verifyBlockStream(bytes,h.bodyOffset,keys.hmacBase);
      try{plain=await outerDecrypt(h.cipherName,keys.encryptionKey,h.iv,encrypted);}catch(e){throw new Error(e?.message?.includes('Twofish')?e.message:'Senha/chave incorreta ou conteúdo KDBX danificado.');}
      decompressed=await maybeDecompress(plain,h.compression);
      const inner=parseInnerHeader(decompressed);if(!inner.innerKey||inner.innerAlg==null)throw new Error('Proteção interna KDBX ausente.');
      const vault=await parseVaultXml(decompressed.slice(inner.xmlOffset),inner.innerAlg,inner.innerKey);
      return{vault,publicMeta:h.publicMeta,info:{version:`${h.version>>>16}.${h.version&0xffff}`,cipher:h.cipherName,kdf:h.kdf.name,rounds:h.kdf.rounds||null,memoryBytes:h.kdf.memoryBytes||null,iterations:h.kdf.iterations||null,parallelism:h.kdf.parallelism||null,compression:h.compression?'GZip':'Nenhuma'}};
    }
    // KDBX 3.1: decrypt first, verify StreamStartBytes, then SHA-256 block stream.
    const cipherText=bytes.slice(h.bodyOffset);
    try{plain=await outerDecrypt(h.cipherName,keys.encryptionKey,h.iv,cipherText);}catch{throw new Error('Senha/chave incorreta ou conteúdo KDBX 3.1 danificado.');}
    if(plain.length<h.streamStartBytes.length||!sameBytes(plain.slice(0,h.streamStartBytes.length),h.streamStartBytes))throw new Error('Senha/chave incorreta (StreamStartBytes KDBX 3.1 não confere).');
    const blockData=await verifyHashedBlockStreamV3(plain,h.streamStartBytes.length);
    decompressed=await maybeDecompress(blockData,h.compression);wipe(blockData);
    headerHash=await sha256(h.headerBytes);
    const vault=await parseVaultXml(decompressed,h.innerAlg,h.protectedStreamKey,headerHash);
    return{vault,publicMeta:h.publicMeta,info:{version:`${h.version>>>16}.${h.version&0xffff}`,cipher:h.cipherName,kdf:'AES-KDF',rounds:h.kdf.rounds,compression:h.compression?'GZip':'Nenhuma'}};
  } finally {[keys.encryptionKey,keys.hmacBase,keys.headerHmacKey,encrypted,plain,decompressed,headerHash].forEach(x=>x&&wipe(x));}
}

export function makeStoredRecord(kdbxBytes,options={}){return{format:KDBX_RECORD_FORMAT,version:1,fileName:String(options.fileName||'MeuCofre.kdbx').slice(0,240),kdbx:bytesToBase64(kdbxBytes),external:Boolean(options.external),sidecarMeta:options.sidecarMeta||null,sidecarPrefs:options.sidecarPrefs||null,updatedAt:new Date().toISOString()};}
export function storedRecordBytes(record){if(record?.format!==KDBX_RECORD_FORMAT||record.version!==1||!record.kdbx)throw new Error('Registro KDBX local inválido.');return base64ToBytes(record.kdbx);}
export function isKdbxRecord(record){return record?.format===KDBX_RECORD_FORMAT&&record.version===1&&typeof record.kdbx==='string';}

export function defaultKdbxVault(name='Meu Cofre'){
  const now=new Date().toISOString();return{schema:2,id:uuid(),name,createdAt:now,updatedAt:now,rootGroupUuid:bytesToBase64(randomBytes(16)),entries:[],settings:{idleLockMinutes:5,backgroundLockSeconds:0,clipboardClearSeconds:20}};
}

function slotAad(slot){return utf8(`${AAD_PREFIX}:${slot.id}:${slot.role||'component'}:${slot.kind||'security-key'}`);}
async function prfWrapKey(secret,salt,slot){const material=await crypto.subtle.importKey('raw',secret,'HKDF',false,['deriveKey']);return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:utf8(`${AAD_PREFIX}:${slot.kind||'security-key'}:component-wrap`)},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}

export async function createPrfComponentSlot(component,registration,prfSecret,role='keyfile'){
  ensureBytes(component,null,'Componente KDBX');if(component.length<32||component.length%32!==0||component.length>128)throw new Error('Pacote de componentes KDBX inválido.');ensureBytes(prfSecret,32,'Segredo PRF');const id=uuid(),hkdfSalt=randomBytes(32),iv=randomBytes(12);
  const base={id,type:'webauthn-prf',kind:registration.kind,label:registration.label,credentialId:registration.credentialId,transports:registration.transports||[],prfSalt:registration.prfSalt,role,componentCount:component.length/32,createdAt:new Date().toISOString()};
  const key=await prfWrapKey(prfSecret,hkdfSalt,base);const aad=slotAad(base);const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},key,component));wipe(aad);
  return{...base,hkdfSalt:bytesToBase64(hkdfSalt),iv:bytesToBase64(iv),wrapped:bytesToBase64(ct)};
}
export async function unwrapPrfComponent(slot,prfSecret){
  ensureBytes(prfSecret,32,'Segredo PRF');const salt=base64ToBytes(slot.hkdfSalt),iv=base64ToBytes(slot.iv),ct=base64ToBytes(slot.wrapped),key=await prfWrapKey(prfSecret,salt,slot),aad=slotAad(slot);
  try{const plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad},key,ct));const expected=Math.max(1,Math.min(4,Number(slot.componentCount||1)))*32;if(plain.length!==expected)throw new Error();return plain;}catch{throw new Error('Esta YubiKey/chave de acesso não conseguiu liberar o componente KDBX.');}finally{wipe(salt);wipe(iv);wipe(ct);wipe(aad);}
}

function sanitizeSidecarMeta(meta){
  const m=(meta&&typeof meta==='object')?structuredClone(meta):{};if(!Array.isArray(m.slots))m.slots=[];m.slots=m.slots.slice(0,MAX_PUBLIC_SLOTS).filter(x=>x&&typeof x==='object'&&x.type==='webauthn-prf'&&typeof x.id==='string');
  return{schema:PUBLIC_SCHEMA,appVersion:APP_VERSION,mode:PROTECTION_MODES.EXTERNAL,webauthnUserId:String(m.webauthnUserId||bytesToBase64(randomBytes(32))),slots:m.slots,requiresPassword:m.requiresPassword===true?true:m.requiresPassword===false?false:null,requiresKeyFile:m.requiresKeyFile===true?true:m.requiresKeyFile===false?false:null,recoveryKeyRequired:false,external:true};
}
export function publicMetaForRecord(record){
  if(record?.external)return sanitizeSidecarMeta(record.sidecarMeta);
  const bytes=storedRecordBytes(record);try{return parseHeader(bytes).publicMeta;}finally{wipe(bytes);}
}
function externalMetaAfterUnlock(record,passwordUsed,keyUsed){const m=sanitizeSidecarMeta(record.sidecarMeta);m.requiresPassword=Boolean(passwordUsed);m.requiresKeyFile=Boolean(keyUsed);return m;}


export function newPublicMeta(mode,webauthnUserId=null){return{schema:PUBLIC_SCHEMA,appVersion:APP_VERSION,mode,webauthnUserId:webauthnUserId||bytesToBase64(randomBytes(32)),slots:[],recoveryKeyRequired:mode!==PROTECTION_MODES.PASSWORD};}

export async function createKdbxRecord({vault,mode,password=null,registration=null,prfSecret=null,rounds=null,webauthnUserId=null}){
  if(!Object.values(PROTECTION_MODES).includes(mode))throw new Error('Modo de proteção KDBX inválido.');
  const meta=newPublicMeta(mode,webauthnUserId);const components=[];let keyFileComponent=null,passwordHash=null;
  try{
    if(mode===PROTECTION_MODES.PASSWORD||mode===PROTECTION_MODES.PASSWORD_YUBIKEY){if(!password)throw new Error('Senha mestra obrigatória.');passwordHash=await passwordComponent(password);components.push(passwordHash);}
    if(mode===PROTECTION_MODES.YUBIKEY||mode===PROTECTION_MODES.PASSWORD_YUBIKEY){if(!registration||!prfSecret)throw new Error('YubiKey PRF obrigatória para este modo.');keyFileComponent=randomKeyFileComponent();components.push(keyFileComponent);meta.slots.push(await createPrfComponentSlot(keyFileComponent,registration,prfSecret,'keyfile'));}
    const actualRounds=rounds||await calibrateAesKdf(1000);const bytes=await writeKdbx(vault,components,meta,{rounds:actualRounds});
    return{record:makeStoredRecord(bytes),vault,components:components.map(c=>c.slice()),publicMeta:meta,kdbxInfo:{version:'4.1',cipher:'AES-256-CBC',kdf:'AES-KDF',rounds:actualRounds,compression:'Nenhuma'},recoveryKey:keyFileComponent?.slice()||null};
  }finally{passwordHash&&wipe(passwordHash);keyFileComponent&&wipe(keyFileComponent);}
}

export async function openStoredKdbxWithPassword(record,password){
  const bytes=storedRecordBytes(record),header=parseHeader(bytes),meta=record.external?sanitizeSidecarMeta(record.sidecarMeta):header.publicMeta,mode=meta.mode;if(!record.external&&mode===PROTECTION_MODES.YUBIKEY)throw new Error('Este cofre exige YubiKey ou chave de recuperação.');if(!record.external&&mode===PROTECTION_MODES.PASSWORD_YUBIKEY)throw new Error('Este cofre exige senha + YubiKey/chave de recuperação.');const pc=await passwordComponent(password);try{const opened=await readKdbx(bytes,[pc]);const publicMeta=record.external?externalMetaAfterUnlock(record,true,false):opened.publicMeta;return{...opened,publicMeta,components:[pc.slice()],external:Boolean(record.external)};}finally{wipe(pc);wipe(bytes);}
}

export async function openStoredKdbxWithPrf(record,slot,prfSecret,password=null){
  const bytes=storedRecordBytes(record),header=parseHeader(bytes),meta=record.external?sanitizeSidecarMeta(record.sidecarMeta):header.publicMeta,mode=meta.mode;const component=await unwrapPrfComponent(slot,prfSecret);let pc=null;
  try{
    let components=[];
    if(record.external&&slot.role==='component-bundle'){for(let p=0;p<component.length;p+=32)components.push(component.slice(p,p+32));}
    else {if(mode===PROTECTION_MODES.PASSWORD_YUBIKEY){if(!password)throw new Error('Digite a senha mestra.');pc=await passwordComponent(password);components.push(pc);}components.push(component);}
    const opened=await readKdbx(bytes,components);const publicMeta=record.external?meta:opened.publicMeta;return{...opened,publicMeta,components:components.map(c=>c.slice()),external:Boolean(record.external)};
  }finally{wipe(component);pc&&wipe(pc);wipe(bytes);}
}

export async function openStoredKdbxWithRecoveryKey(record,keyBytes,password=null){
  ensureBytes(keyBytes,32,'Chave de recuperação');if(record.external)return openStoredKdbxGeneric(record,password,keyBytes);const bytes=storedRecordBytes(record),h=parseHeader(bytes),mode=h.publicMeta.mode;let pc=null;try{const components=[];if(mode===PROTECTION_MODES.PASSWORD_YUBIKEY){if(!password)throw new Error('Este cofre exige a senha mestra junto com a chave de recuperação.');pc=await passwordComponent(password);components.push(pc);}else if(mode===PROTECTION_MODES.PASSWORD)throw new Error('Este cofre usa senha mestra, não chave de recuperação.');components.push(keyBytes);const opened=await readKdbx(bytes,components);return{...opened,components:components.map(c=>c.slice()),external:false};}finally{pc&&wipe(pc);wipe(bytes);}
}

async function rewriteExternalKdbx(record,vault,components){
  const bytes=storedRecordBytes(record),h=parseHeader(bytes);let oldKeys=null,newKeys=null,encrypted=null,plain=null,decompressed=null,xmlBytes=null,payload=null,compressed=null,newEncrypted=null,blocks=null,newHeader=null,newKdfBytes=null,newMasterSeed=null,newIv=null,newInnerKey=null,newStreamKey=null,newStreamStart=null,newTransformSeed=null;
  try{
    oldKeys=await computeKeys(components,h.masterSeed,h.kdf);
    if(h.major===4){
      const actualHash=await sha256(h.headerBytes);if(!sameBytes(actualHash,h.storedHash)){wipe(actualHash);throw new Error('Hash do cabeçalho KDBX inválido.');}wipe(actualHash);const actualHmac=await hmacSha256(oldKeys.headerHmacKey,h.headerBytes);if(!sameBytes(actualHmac,h.storedHmac)){wipe(actualHmac);throw new Error('Credenciais KDBX não conferem para gravação.');}wipe(actualHmac);
      encrypted=await verifyBlockStream(bytes,h.bodyOffset,oldKeys.hmacBase);plain=await outerDecrypt(h.cipherName,oldKeys.encryptionKey,h.iv,encrypted);decompressed=await maybeDecompress(plain,h.compression);const inner=parseInnerHeader(decompressed);const opened=await editableXmlDocument(decompressed.slice(inner.xmlOffset),inner.innerAlg,inner.innerKey);patchDocumentFromVault(opened.doc,vault,4,opened.protectedSet);
      newInnerKey=randomBytes(inner.innerKey.length);await protectXmlDocument(opened.doc,opened.protectedSet,inner.innerAlg,newInnerKey);xmlBytes=serializeXmlDocument(opened.doc);const newInnerHeader=rewriteInnerHeader(inner.headerBytes,newInnerKey);payload=concatBytes(newInnerHeader,xmlBytes);compressed=await maybeCompress(payload,h.compression);
      const oldSalt=h.kdf.name==='AES-KDF'?h.kdf.seed:h.kdf.salt,newSalt=randomBytes(oldSalt.length);newKdfBytes=rewriteVariantDictRaw(h.kdfBytes,new Map([['S',newSalt]]));wipe(newSalt);const newKdf=parseKdf(newKdfBytes);newMasterSeed=randomBytes(32);newIv=randomBytes(h.iv.length);newHeader=rewriteHeaderV4(h.headerBytes,new Map([[4,newMasterSeed],[7,newIv],[11,newKdfBytes]]));newKeys=await computeKeys(components,newMasterSeed,newKdf);newEncrypted=await outerEncrypt(h.cipherName,newKeys.encryptionKey,newIv,compressed);blocks=await hmacBlockStream(newEncrypted,newKeys.hmacBase);const hh=await sha256(newHeader),hm=await hmacSha256(newKeys.headerHmacKey,newHeader);const out=concatBytes(newHeader,hh,hm,blocks);wipe(hh);wipe(hm);return out;
    }
    const cipherText=bytes.slice(h.bodyOffset);plain=await outerDecrypt(h.cipherName,oldKeys.encryptionKey,h.iv,cipherText);if(plain.length<h.streamStartBytes.length||!sameBytes(plain.slice(0,h.streamStartBytes.length),h.streamStartBytes))throw new Error('Credenciais KDBX 3.1 não conferem para gravação.');const blockData=await verifyHashedBlockStreamV3(plain,h.streamStartBytes.length);decompressed=await maybeDecompress(blockData,h.compression);wipe(blockData);const oldHeaderHash=await sha256(h.headerBytes);const opened=await editableXmlDocument(decompressed,h.innerAlg,h.protectedStreamKey,oldHeaderHash);wipe(oldHeaderHash);patchDocumentFromVault(opened.doc,vault,3,opened.protectedSet);
    newMasterSeed=randomBytes(32);newTransformSeed=randomBytes(32);newIv=randomBytes(h.iv.length);newStreamKey=randomBytes(h.protectedStreamKey.length);newStreamStart=randomBytes(h.streamStartBytes.length);newHeader=rewriteHeaderV3(h.headerBytes,new Map([[4,newMasterSeed],[5,newTransformSeed],[7,newIv],[8,newStreamKey],[9,newStreamStart]]));const meta=opened.doc.querySelector('KeePassFile > Meta');if(meta){const hh=await sha256(newHeader);setDirectChildText(meta,'HeaderHash',bytesToBase64(hh));wipe(hh);}await protectXmlDocument(opened.doc,opened.protectedSet,h.innerAlg,newStreamKey);xmlBytes=serializeXmlDocument(opened.doc);compressed=await maybeCompress(xmlBytes,h.compression);blocks=await hashedBlockStreamV3(compressed);payload=concatBytes(newStreamStart,blocks);const newKdf={...h.kdf,seed:newTransformSeed};newKeys=await computeKeys(components,newMasterSeed,newKdf);newEncrypted=await outerEncrypt(h.cipherName,newKeys.encryptionKey,newIv,payload);return concatBytes(newHeader,newEncrypted);
  }finally{
    [bytes,encrypted,plain,decompressed,xmlBytes,payload,compressed,newEncrypted,blocks,newHeader,newKdfBytes,newMasterSeed,newIv,newInnerKey,newStreamKey,newStreamStart,newTransformSeed,oldKeys?.encryptionKey,oldKeys?.hmacBase,oldKeys?.headerHmacKey,newKeys?.encryptionKey,newKeys?.hmacBase,newKeys?.headerHmacKey].forEach(x=>x&&wipe(x));
  }
}

export async function saveStoredKdbx(record,vault,components,publicMeta,rounds=null){
  if(record?.external){const bytes=await rewriteExternalKdbx(record,vault,components);try{return makeStoredRecord(bytes,{external:true,fileName:record.fileName,sidecarMeta:record.sidecarMeta,sidecarPrefs:record.sidecarPrefs});}finally{wipe(bytes);}}
  const current=inspectKdbx(storedRecordBytes(record));const bytes=await writeKdbx(vault,components,publicMeta,{rounds:rounds||current.rounds||DEFAULT_AES_ROUNDS});try{return makeStoredRecord(bytes);}finally{wipe(bytes);}
}

export async function addPrfSlotToKdbx(record,session,registration,prfSecret){
  if(record?.external){const bundle=concatBytes(...session.components);try{const slot=await createPrfComponentSlot(bundle,registration,prfSecret,'component-bundle');const meta=sanitizeSidecarMeta(session.publicMeta||record.sidecarMeta);meta.slots.push(slot);const next={...record,sidecarMeta:meta,updatedAt:new Date().toISOString()};return{record:next,publicMeta:meta,slot};}finally{wipe(bundle);}}
  const mode=session.publicMeta.mode;let component;if(mode===PROTECTION_MODES.PASSWORD){component=session.components[0];}else component=session.components[session.components.length-1];
  const slot=await createPrfComponentSlot(component,registration,prfSecret,mode===PROTECTION_MODES.PASSWORD?'password-component':'keyfile');
  const meta=structuredClone(session.publicMeta);meta.slots.push(slot);const next=await saveStoredKdbx(record,session.vault,session.components,meta,session.kdbxInfo?.rounds);return{record:next,publicMeta:meta,slot};
}

export async function removePrfSlotFromKdbx(record,session,slotId){const meta=record?.external?sanitizeSidecarMeta(session.publicMeta||record.sidecarMeta):structuredClone(session.publicMeta);const slot=meta.slots.find(s=>s.id===slotId);if(!slot)return{record,publicMeta:meta};if(!record.external&&meta.mode!==PROTECTION_MODES.PASSWORD&&meta.slots.filter(s=>s.type==='webauthn-prf'&&s.id!==slotId).length===0)throw new Error('Não remova a última YubiKey antes de exportar/confirmar a chave de recuperação ou cadastrar outra chave.');meta.slots=meta.slots.filter(s=>s.id!==slotId);if(record.external)return{record:{...record,sidecarMeta:meta,updatedAt:new Date().toISOString()},publicMeta:meta};const next=await saveStoredKdbx(record,session.vault,session.components,meta,session.kdbxInfo?.rounds);return{record:next,publicMeta:meta};}

export function exportRecoveryKeyBytes(session){if(session?.external)throw new Error('O key file original de um KDBX externo não é armazenado pelo Meu Cofre. Use o backup original do KeePassXC.');if(session?.publicMeta?.mode===PROTECTION_MODES.PASSWORD)throw new Error('Este cofre não usa chave de recuperação separada.');const key=session?.components?.[session.components.length-1];ensureBytes(key,32,'Chave de recuperação');return key.slice();}

export async function openStoredKdbxGeneric(record,password=null,keyBytes=null){
  const bytes=storedRecordBytes(record);const components=[];let pc=null;
  try{
    if(password){pc=await passwordComponent(password);components.push(pc);}
    if(keyBytes){ensureBytes(keyBytes,32,'Componente do arquivo de chave');components.push(keyBytes);}
    if(!components.length)throw new Error('Informe a senha e/ou um arquivo de chave KeePass/KeePassXC.');
    const opened=await readKdbx(bytes,components);
    const meta=record.external?externalMetaAfterUnlock(record,Boolean(password),Boolean(keyBytes)):(opened.publicMeta?.schema===PUBLIC_SCHEMA?opened.publicMeta:newPublicMeta(keyBytes?(password?PROTECTION_MODES.PASSWORD_YUBIKEY:PROTECTION_MODES.YUBIKEY):PROTECTION_MODES.PASSWORD));
    return{...opened,publicMeta:meta,components:components.map(c=>c.slice()),external:Boolean(record.external)};
  }finally{pc&&wipe(pc);wipe(bytes);}
}

export async function changeKdbxMasterPassword(record,session,newPassword){
  if(record?.external)throw new Error('Altere a senha no KeePassXC e reimporte o arquivo. O Meu Cofre não regrava KDBX externo para evitar perda de dados avançados.');
  const mode=session?.publicMeta?.mode;
  if(mode===PROTECTION_MODES.YUBIKEY) throw new Error('Este cofre não usa senha mestra.');
  if(mode===PROTECTION_MODES.PASSWORD && (session.publicMeta.slots||[]).length) throw new Error('Remova temporariamente as YubiKeys/chaves de acesso antes de trocar a senha neste modo e cadastre-as novamente depois.');
  const pc=await passwordComponent(newPassword);
  const components=mode===PROTECTION_MODES.PASSWORD ? [pc] : [pc,session.components[session.components.length-1]];
  try{const next=await saveStoredKdbx(record,session.vault,components,session.publicMeta,session.kdbxInfo?.rounds);return {record:next,components:components.map(c=>c.slice())};} finally { wipe(pc); }
}

export function migrateLegacyVaultData(legacyVault){const now=new Date().toISOString();return{schema:2,id:legacyVault.id||uuid(),name:legacyVault.name||'Meu Cofre',createdAt:legacyVault.createdAt||now,updatedAt:now,rootGroupUuid:bytesToBase64(randomBytes(16)),entries:(legacyVault.entries||[]).map(e=>({...e,id:e.id||uuid(),kdbxUuidBytes:bytesToBase64(randomBytes(16))})),settings:{idleLockMinutes:legacyVault.settings?.idleLockMinutes??5,backgroundLockSeconds:legacyVault.settings?.backgroundLockSeconds??0,clipboardClearSeconds:legacyVault.settings?.clipboardClearSeconds??20}};}
