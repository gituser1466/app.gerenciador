import { base64ToBytes, bytesToBase64, randomBytes, utf8, uuid, wipe } from './utils.js';

export const VC_LINKED_FORMAT = 'meucofre-veracrypt-linked-v1';
export const VC_LINKED_VERSION = 1;
export const VC_LINKED_EXPORT_EXT = '.vcprofile';
const MAX_SLOTS = 8;
const MAX_KEYFILES = 32;
const MAX_KEYFILE_BYTES = 1024 * 1024;
const MAX_TOTAL_KEYFILE_BYTES = 8 * 1024 * 1024;
const DEFAULT_RECOVERY_ITERATIONS = 900000;
const MAX_RECOVERY_ITERATIONS = 4000000;
const AAD_PREFIX = 'MeuCofre-VeraCrypt-Linked-v1';

function ensureBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || (length != null && value.length !== length)) throw new Error(`${label} inválido.`);
}

function ensureProfileShape(profile) {
  if (profile?.format !== VC_LINKED_FORMAT || profile.version !== VC_LINKED_VERSION) throw new Error('Perfil VeraCrypt vinculado desconhecido.');
  if (!profile.id || typeof profile.name !== 'string' || !profile.name.trim()) throw new Error('Metadados do perfil VeraCrypt inválidos.');
  if (!profile.credentials?.ciphertext || !profile.credentials?.iv) throw new Error('Credenciais cifradas ausentes.');
  if (!Array.isArray(profile.slots) || profile.slots.length < 1 || profile.slots.length > MAX_SLOTS) throw new Error('Lista de YubiKeys inválida.');
  for (const slot of profile.slots) {
    if (!slot?.id || slot.type !== 'webauthn-prf' || !slot.credentialId || !slot.prfSalt || !slot.hkdfSalt || !slot.iv || !slot.wrappedKey) throw new Error('Slot FIDO2 inválido.');
  }
  if (!profile.recovery?.salt || !profile.recovery?.iv || !profile.recovery?.wrappedKey) throw new Error('Recuperação por senha ausente.');
  const iterations = Number(profile.recovery.iterations);
  if (!Number.isSafeInteger(iterations) || iterations < 300000 || iterations > MAX_RECOVERY_ITERATIONS) throw new Error('KDF de recuperação inválido.');
  return true;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function bytesFingerprint(bytes) {
  ensureBytes(bytes, null, 'Dados');
  const digest = await sha256(bytes);
  try { return [...digest].map((b) => b.toString(16).padStart(2, '0')).join(''); }
  finally { wipe(digest); }
}

export async function containerFingerprint(file, hidden = false) {
  if (!file || typeof file.slice !== 'function') throw new Error('Selecione o container VeraCrypt.');
  const offset = hidden ? 64 * 1024 : 0;
  if (file.size < offset + 512) throw new Error('Container pequeno demais para fingerprint do header.');
  const header = new Uint8Array(await file.slice(offset, offset + 512).arrayBuffer());
  const sizeBytes = utf8(String(file.size));
  const combined = new Uint8Array(header.length + 1 + sizeBytes.length);
  combined.set(header, 0); combined[header.length] = 0; combined.set(sizeBytes, header.length + 1);
  try { return await bytesFingerprint(combined); }
  finally { wipe(header); wipe(sizeBytes); wipe(combined); }
}

function profileAad(profileId) { return utf8(`${AAD_PREFIX}:credentials:${profileId}`); }
function slotAad(profileId, slot) { return utf8(`${AAD_PREFIX}:slot:${profileId}:${slot.id}:${slot.credentialId}`); }
function recoveryAad(profileId) { return utf8(`${AAD_PREFIX}:recovery:${profileId}`); }

async function derivePrfWrappingKey(prfSecret, hkdfSalt) {
  ensureBytes(prfSecret, 32, 'Segredo PRF');
  ensureBytes(hkdfSalt, 32, 'Salt HKDF');
  const material = await crypto.subtle.importKey('raw', prfSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info: utf8(`${AAD_PREFIX}:slot-wrap`) },
    material,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function deriveRecoveryKey(password, salt, iterations) {
  const encoded = utf8(String(password || ''));
  if (encoded.length < 12) { wipe(encoded); throw new Error('Use uma senha de recuperação com pelo menos 12 caracteres.'); }
  try {
    const material = await crypto.subtle.importKey('raw', encoded, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  } finally { wipe(encoded); }
}

async function wrapDekForRegistration(profileId, dek, registration, prfSecret, label = null) {
  ensureBytes(dek, 32, 'Chave do perfil');
  ensureBytes(prfSecret, 32, 'Segredo PRF');
  if (!registration?.credentialId || !registration?.prfSalt) throw new Error('Credencial FIDO2/PRF inválida.');
  const hkdfSalt = randomBytes(32), iv = randomBytes(12);
  const slot = {
    id: uuid(), type: 'webauthn-prf', kind: 'security-key',
    label: label || registration.label || 'YubiKey FIDO2',
    credentialId: registration.credentialId, transports: registration.transports || [],
    prfSalt: registration.prfSalt, createdAt: new Date().toISOString(), lastTestedAt: new Date().toISOString()
  };
  const aad = slotAad(profileId, slot);
  try {
    const key = await derivePrfWrappingKey(prfSecret, hkdfSalt);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, dek));
    return { ...slot, hkdfSalt: bytesToBase64(hkdfSalt), iv: bytesToBase64(iv), wrappedKey: bytesToBase64(wrapped) };
  } finally { wipe(hkdfSalt); wipe(iv); wipe(aad); }
}

export async function unwrapDekFromSlot(profile, slot, prfSecret) {
  validateLinkedProfile(profile);
  ensureBytes(prfSecret, 32, 'Segredo PRF');
  if (!slot || !profile.slots.some((s) => s.id === slot.id)) throw new Error('YubiKey não pertence a este perfil.');
  const hkdfSalt = base64ToBytes(slot.hkdfSalt), iv = base64ToBytes(slot.iv), wrapped = base64ToBytes(slot.wrappedKey), aad = slotAad(profile.id, slot);
  try {
    const key = await derivePrfWrappingKey(prfSecret, hkdfSalt);
    const dek = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, wrapped));
    ensureBytes(dek, 32, 'Chave do perfil');
    return dek;
  } catch { throw new Error('Esta YubiKey não conseguiu liberar as credenciais deste vault.'); }
  finally { wipe(hkdfSalt); wipe(iv); wipe(wrapped); wipe(aad); }
}

async function wrapDekForRecovery(profileId, dek, password, iterations = DEFAULT_RECOVERY_ITERATIONS) {
  if (!Number.isSafeInteger(iterations) || iterations < 300000 || iterations > MAX_RECOVERY_ITERATIONS) throw new Error('Parâmetro de KDF inválido.');
  const salt = randomBytes(32), iv = randomBytes(12), aad = recoveryAad(profileId);
  try {
    const key = await deriveRecoveryKey(password, salt, iterations);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, dek));
    return { kdf: 'PBKDF2-SHA-256', iterations, salt: bytesToBase64(salt), cipher: 'AES-256-GCM', iv: bytesToBase64(iv), wrappedKey: bytesToBase64(wrapped) };
  } finally { wipe(salt); wipe(iv); wipe(aad); }
}

export async function unwrapDekFromRecovery(profile, password) {
  validateLinkedProfile(profile);
  const r = profile.recovery, salt = base64ToBytes(r.salt), iv = base64ToBytes(r.iv), wrapped = base64ToBytes(r.wrappedKey), aad = recoveryAad(profile.id);
  try {
    const key = await deriveRecoveryKey(password, salt, Number(r.iterations));
    const dek = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, wrapped));
    ensureBytes(dek, 32, 'Chave do perfil');
    return dek;
  } catch { throw new Error('Senha de recuperação incorreta ou perfil danificado.'); }
  finally { wipe(salt); wipe(iv); wipe(wrapped); wipe(aad); }
}

async function serializeKeyfiles(files) {
  if (!Array.isArray(files)) return [];
  if (files.length > MAX_KEYFILES) throw new Error(`Use no máximo ${MAX_KEYFILES} keyfiles.`);
  const out = []; let total = 0;
  for (let i = 0; i < files.length; i++) {
    const file = files[i]; let bytes;
    if (file instanceof Uint8Array) bytes = file.slice(0, MAX_KEYFILE_BYTES);
    else {
      if (!file || typeof file.slice !== 'function') throw new Error('Keyfile inválido.');
      if (Number(file.size) < 1) throw new Error('Keyfile vazio não é aceito.');
      bytes = new Uint8Array(await file.slice(0, Math.min(Number(file.size), MAX_KEYFILE_BYTES)).arrayBuffer());
    }
    if (!bytes.length) throw new Error('Keyfile vazio não é aceito.');
    total += bytes.length;
    if (total > MAX_TOTAL_KEYFILE_BYTES) { wipe(bytes); throw new Error('Keyfiles excedem 8 MB no total, limite defensivo para armazenamento local.'); }
    out.push({ name: String(file?.name || `keyfile-${i + 1}`).slice(0, 180), size: bytes.length, data: bytesToBase64(bytes), sha256: await bytesFingerprint(bytes) });
    wipe(bytes);
  }
  return out;
}

function validateBundle(bundle) {
  if (bundle?.format !== 'meucofre-veracrypt-credentials-v1' || bundle.version !== 1) throw new Error('Pacote de credenciais VeraCrypt desconhecido.');
  if (typeof bundle.password !== 'string') throw new Error('Senha VeraCrypt inválida no pacote.');
  const pim = Number(bundle.pim || 0); if (!Number.isInteger(pim) || pim < 0 || pim > 20000) throw new Error('PIM inválido no pacote.');
  if (!['auto','SHA-512','SHA-256'].includes(bundle.hash)) throw new Error('KDF inválido no pacote.');
  if (typeof bundle.hidden !== 'boolean') throw new Error('Tipo de volume inválido no pacote.');
  if (!Array.isArray(bundle.keyfiles) || bundle.keyfiles.length > MAX_KEYFILES) throw new Error('Keyfiles inválidos no pacote.');
  let total = 0;
  for (const k of bundle.keyfiles) {
    if (!k || typeof k.data !== 'string') throw new Error('Keyfile inválido no pacote.');
    const b = base64ToBytes(k.data); total += b.length;
    if (!b.length || b.length > MAX_KEYFILE_BYTES || total > MAX_TOTAL_KEYFILE_BYTES) { wipe(b); throw new Error('Keyfile fora dos limites permitidos.'); }
    wipe(b);
  }
  return true;
}

export async function buildCredentialBundle({ password = '', pim = 0, hash = 'auto', hidden = false, keyfiles = [] } = {}) {
  const serialized = await serializeKeyfiles(keyfiles);
  return { format: 'meucofre-veracrypt-credentials-v1', version: 1, password: String(password ?? ''), pim: Number.parseInt(String(pim || 0), 10) || 0, hash, hidden: !!hidden, keyfiles: serialized, createdAt: new Date().toISOString() };
}

function encodeBundle(bundle) {
  validateBundle(bundle);
  return utf8(JSON.stringify(bundle));
}

export function materializeBundleCredentials(bundle) {
  validateBundle(bundle);
  const keyfiles = bundle.keyfiles.map((k) => base64ToBytes(k.data));
  return { password: bundle.password, pim: bundle.pim, hash: bundle.hash, hidden: bundle.hidden, keyfiles };
}

export function wipeMaterializedCredentials(credentials) {
  for (const k of credentials?.keyfiles || []) wipe(k);
  if (credentials) credentials.password = '';
}

async function encryptBundle(profileId, bundle, dek) {
  const plain = encodeBundle(bundle), iv = randomBytes(12), aad = profileAad(profileId);
  try {
    const key = await crypto.subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plain));
    return { cipher: 'AES-256-GCM', iv: bytesToBase64(iv), ciphertext: bytesToBase64(ciphertext) };
  } finally { wipe(plain); wipe(iv); wipe(aad); }
}

export async function decryptBundle(profile, dek) {
  validateLinkedProfile(profile); ensureBytes(dek, 32, 'Chave do perfil');
  const iv = base64ToBytes(profile.credentials.iv), ciphertext = base64ToBytes(profile.credentials.ciphertext), aad = profileAad(profile.id);
  try {
    const key = await crypto.subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext));
    try { const bundle = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)); validateBundle(bundle); return bundle; }
    finally { wipe(plain); }
  } catch (e) {
    if (String(e?.message || e).includes('pacote') || String(e?.message || e).includes('Keyfile') || String(e?.message || e).includes('PIM') || String(e?.message || e).includes('KDF')) throw e;
    throw new Error('As credenciais cifradas do vault não puderam ser abertas.');
  } finally { wipe(iv); wipe(ciphertext); wipe(aad); }
}

export async function createLinkedProfile({ name, file, bundle, registration, prfSecret, recoveryPassword } = {}) {
  if (!String(name || '').trim()) throw new Error('Dê um nome ao vault.');
  validateBundle(bundle);
  const profileId = uuid(), dek = randomBytes(32);
  try {
    const profile = {
      format: VC_LINKED_FORMAT, version: VC_LINKED_VERSION, id: profileId,
      name: String(name).trim().slice(0, 100), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      container: { name: String(file?.name || 'container').slice(0, 220), size: Number(file?.size || 0), hidden: !!bundle.hidden, headerFingerprint: await containerFingerprint(file, !!bundle.hidden) },
      credentials: await encryptBundle(profileId, bundle, dek), slots: [],
      recovery: await wrapDekForRecovery(profileId, dek, recoveryPassword),
      lastVerifiedAt: new Date().toISOString()
    };
    profile.slots.push(await wrapDekForRegistration(profileId, dek, registration, prfSecret, 'YubiKey 1'));
    return profile;
  } finally { wipe(dek); }
}

export async function addLinkedProfileSlot(profile, dek, registration, prfSecret, label = null) {
  validateLinkedProfile(profile); ensureBytes(dek, 32, 'Chave do perfil');
  if (profile.slots.length >= MAX_SLOTS) throw new Error(`Limite de ${MAX_SLOTS} YubiKeys atingido.`);
  if (profile.slots.some((s) => s.credentialId === registration.credentialId)) throw new Error('Esta credencial já está cadastrada.');
  const next = structuredClone(profile);
  next.slots.push(await wrapDekForRegistration(profile.id, dek, registration, prfSecret, label || `YubiKey ${profile.slots.length + 1}`));
  next.updatedAt = new Date().toISOString();
  return next;
}

export function removeLinkedProfileSlot(profile, slotId) {
  validateLinkedProfile(profile);
  if (profile.slots.length <= 1) throw new Error('Mantenha pelo menos uma YubiKey cadastrada.');
  const next = structuredClone(profile), before = next.slots.length;
  next.slots = next.slots.filter((s) => s.id !== slotId);
  if (next.slots.length === before) throw new Error('YubiKey não encontrada.');
  next.updatedAt = new Date().toISOString();
  return next;
}

export async function changeRecoveryPassword(profile, dek, newPassword) {
  validateLinkedProfile(profile); ensureBytes(dek, 32, 'Chave do perfil');
  const next = structuredClone(profile); next.recovery = await wrapDekForRecovery(profile.id, dek, newPassword); next.updatedAt = new Date().toISOString(); return next;
}

export function validateLinkedProfile(profile) { return ensureProfileShape(profile); }

export function profileToBlob(profile) {
  validateLinkedProfile(profile);
  return new Blob([JSON.stringify(profile, null, 2) + '\n'], { type: 'application/json' });
}

export async function profileFromFile(file) {
  if (!file || typeof file.text !== 'function') throw new Error('Selecione um arquivo .vcprofile.');
  if (file.size > 16 * 1024 * 1024) throw new Error('Perfil VeraCrypt grande demais.');
  let parsed; try { parsed = JSON.parse(await file.text()); } catch { throw new Error('Arquivo .vcprofile inválido.'); }
  validateLinkedProfile(parsed); return parsed;
}

export async function verifyContainerAgainstProfile(profile, file) {
  validateLinkedProfile(profile);
  if (!file) throw new Error('Selecione o container VeraCrypt.');
  const fingerprint = await containerFingerprint(file, !!profile.container.hidden);
  const sameHeader = fingerprint === profile.container.headerFingerprint;
  const sameSize = Number(file.size) === Number(profile.container.size);
  return { ok: sameHeader && sameSize, sameHeader, sameSize, fingerprint };
}
