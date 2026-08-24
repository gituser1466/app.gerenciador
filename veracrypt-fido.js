import { base64ToBytes, bytesToBase64, randomBytes, utf8, uuid, wipe } from './utils.js';

export const VC_FIDO_FORMAT = 'meucofre-veracrypt-fido-v1';
export const VC_RECOVERY_FORMAT = 'meucofre-veracrypt-fido-recovery-v1';
export const VC_FIDO_VERSION = 1;
export const VC_SECRET_BYTES = 64;
const DEFAULT_RECOVERY_ITERATIONS = 900000;
const MAX_RECOVERY_ITERATIONS = 4000000;
const AAD_PREFIX = 'MeuCofre-VeraCrypt-FIDO-v1';

function ensureBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || (length != null && value.length !== length)) {
    throw new Error(`${label} inválido.`);
  }
}

function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export async function secretFingerprint(secret) {
  ensureBytes(secret, VC_SECRET_BYTES, 'Segredo VeraCrypt');
  const digest = await sha256(secret);
  try {
    return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
  } finally {
    wipe(digest);
  }
}

function slotAad(profileId, slot) {
  return utf8(`${AAD_PREFIX}:slot:${profileId}:${slot.id}:${slot.credentialId}`);
}

async function derivePrfWrappingKey(prfSecret, hkdfSalt) {
  ensureBytes(prfSecret, 32, 'Segredo PRF');
  ensureBytes(hkdfSalt, 32, 'Salt HKDF');
  const material = await crypto.subtle.importKey('raw', prfSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info: utf8(`${AAD_PREFIX}:slot-wrap`) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrapSecretForRegistration(profileId, secret, registration, prfSecret, label = null) {
  ensureBytes(secret, VC_SECRET_BYTES, 'Segredo VeraCrypt');
  ensureBytes(prfSecret, 32, 'Segredo PRF');
  if (!registration?.credentialId || !registration?.prfSalt) throw new Error('Credencial FIDO2/PRF inválida.');
  const hkdfSalt = randomBytes(32);
  const iv = randomBytes(12);
  const base = {
    id: uuid(),
    type: 'webauthn-prf',
    kind: 'security-key',
    label: label || registration.label || 'YubiKey FIDO2',
    credentialId: registration.credentialId,
    transports: registration.transports || [],
    prfSalt: registration.prfSalt,
    createdAt: new Date().toISOString()
  };
  const aad = slotAad(profileId, base);
  try {
    const key = await derivePrfWrappingKey(prfSecret, hkdfSalt);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, secret));
    return {
      ...base,
      hkdfSalt: bytesToBase64(hkdfSalt),
      iv: bytesToBase64(iv),
      wrapped: bytesToBase64(wrapped)
    };
  } finally {
    wipe(hkdfSalt);
    wipe(iv);
    wipe(aad);
  }
}

export async function unwrapSecretFromSlot(profile, slot, prfSecret) {
  validateProfile(profile);
  ensureBytes(prfSecret, 32, 'Segredo PRF');
  if (!slot || !profile.slots.some((item) => item.id === slot.id)) throw new Error('YubiKey não pertence a esta configuração VeraCrypt.');
  const hkdfSalt = base64ToBytes(slot.hkdfSalt);
  const iv = base64ToBytes(slot.iv);
  const ciphertext = base64ToBytes(slot.wrapped);
  const aad = slotAad(profile.id, slot);
  try {
    const key = await derivePrfWrappingKey(prfSecret, hkdfSalt);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext));
    ensureBytes(plain, VC_SECRET_BYTES, 'Segredo VeraCrypt');
    const fingerprint = await secretFingerprint(plain);
    if (fingerprint !== profile.fingerprint) {
      wipe(plain);
      throw new Error('A YubiKey liberou uma chave que não corresponde a esta configuração.');
    }
    return plain;
  } catch (error) {
    if (error?.message?.includes('não corresponde')) throw error;
    throw new Error('Esta YubiKey não conseguiu liberar a chave VeraCrypt compartilhada.');
  } finally {
    wipe(hkdfSalt);
    wipe(iv);
    wipe(ciphertext);
    wipe(aad);
  }
}

async function deriveRecoveryKey(password, salt, iterations) {
  const encoded = utf8(password);
  if (encoded.length < 12) {
    wipe(encoded);
    throw new Error('Use uma senha de recuperação com pelo menos 12 caracteres.');
  }
  try {
    const material = await crypto.subtle.importKey('raw', encoded, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    wipe(encoded);
  }
}

function recoveryAad(recovery) {
  return utf8(`${AAD_PREFIX}:recovery:${recovery.id}:${recovery.fingerprint}`);
}

export async function createRecoveryVault(secret, password, { iterations = DEFAULT_RECOVERY_ITERATIONS } = {}) {
  ensureBytes(secret, VC_SECRET_BYTES, 'Segredo VeraCrypt');
  if (!Number.isSafeInteger(iterations) || iterations < 300000 || iterations > MAX_RECOVERY_ITERATIONS) throw new Error('Parâmetro de KDF de recuperação inválido.');
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const recovery = {
    format: VC_RECOVERY_FORMAT,
    version: 1,
    id: uuid(),
    fingerprint: await secretFingerprint(secret),
    createdAt: new Date().toISOString(),
    kdf: { name: 'PBKDF2-SHA-256', iterations, salt: bytesToBase64(salt) },
    cipher: { name: 'AES-256-GCM', iv: bytesToBase64(iv) },
    ciphertext: ''
  };
  const aad = recoveryAad(recovery);
  try {
    const key = await deriveRecoveryKey(password, salt, iterations);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, secret));
    recovery.ciphertext = bytesToBase64(ciphertext);
    wipe(ciphertext);
    return recovery;
  } finally {
    wipe(salt);
    wipe(iv);
    wipe(aad);
  }
}

export function validateRecoveryVault(recovery) {
  if (recovery?.format !== VC_RECOVERY_FORMAT || recovery.version !== 1) throw new Error('Cofre de recuperação VeraCrypt desconhecido.');
  if (!recovery.id || !/^[0-9a-f]{64}$/i.test(String(recovery.fingerprint || ''))) throw new Error('Metadados do cofre de recuperação inválidos.');
  const iterations = Number(recovery.kdf?.iterations);
  if (recovery.kdf?.name !== 'PBKDF2-SHA-256' || !Number.isSafeInteger(iterations) || iterations < 300000 || iterations > MAX_RECOVERY_ITERATIONS) throw new Error('KDF do cofre de recuperação inválido.');
  if (recovery.cipher?.name !== 'AES-256-GCM' || typeof recovery.kdf?.salt !== 'string' || typeof recovery.cipher?.iv !== 'string' || typeof recovery.ciphertext !== 'string') throw new Error('Cifra do cofre de recuperação inválida.');
  return true;
}

export async function openRecoveryVault(recovery, password) {
  validateRecoveryVault(recovery);
  const salt = base64ToBytes(recovery.kdf.salt);
  const iv = base64ToBytes(recovery.cipher.iv);
  const ciphertext = base64ToBytes(recovery.ciphertext);
  const aad = recoveryAad(recovery);
  try {
    if (salt.length !== 32 || iv.length !== 12 || ciphertext.length !== VC_SECRET_BYTES + 16) throw new Error('Cofre de recuperação corrompido.');
    const key = await deriveRecoveryKey(password, salt, recovery.kdf.iterations);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext));
    ensureBytes(plain, VC_SECRET_BYTES, 'Segredo VeraCrypt');
    const expected = new TextEncoder().encode(recovery.fingerprint);
    const actual = new TextEncoder().encode(await secretFingerprint(plain));
    const ok = constantTimeEqual(expected, actual);
    wipe(expected); wipe(actual);
    if (!ok) { wipe(plain); throw new Error('Cofre de recuperação não corresponde à chave VeraCrypt esperada.'); }
    return plain;
  } catch (error) {
    if (error?.message?.includes('corrompido') || error?.message?.includes('não corresponde')) throw error;
    throw new Error('Senha de recuperação incorreta ou cofre de recuperação danificado.');
  } finally {
    wipe(salt);
    wipe(iv);
    wipe(ciphertext);
    wipe(aad);
  }
}

export async function createProfile(registration, prfSecret, recoveryPassword) {
  const secret = randomBytes(VC_SECRET_BYTES);
  const profile = {
    format: VC_FIDO_FORMAT,
    version: VC_FIDO_VERSION,
    id: uuid(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    fingerprint: await secretFingerprint(secret),
    slots: [],
    recovery: null
  };
  try {
    profile.slots.push(await wrapSecretForRegistration(profile.id, secret, registration, prfSecret, 'YubiKey 1'));
    profile.recovery = await createRecoveryVault(secret, recoveryPassword);
    return { profile, secret: secret.slice() };
  } finally {
    wipe(secret);
  }
}

export async function addSlot(profile, secret, registration, prfSecret, label = null) {
  validateProfile(profile);
  ensureBytes(secret, VC_SECRET_BYTES, 'Segredo VeraCrypt');
  const fingerprint = await secretFingerprint(secret);
  if (fingerprint !== profile.fingerprint) throw new Error('A chave em memória não pertence a esta configuração VeraCrypt.');
  if (profile.slots.length >= 8) throw new Error('Limite de 8 YubiKeys por configuração atingido.');
  if (profile.slots.some((slot) => slot.credentialId === registration.credentialId)) throw new Error('Esta credencial FIDO2 já está cadastrada.');
  const next = structuredClone(profile);
  next.slots.push(await wrapSecretForRegistration(profile.id, secret, registration, prfSecret, label || `YubiKey ${profile.slots.length + 1}`));
  next.updatedAt = new Date().toISOString();
  return next;
}

export function validateProfile(profile) {
  if (profile?.format !== VC_FIDO_FORMAT || profile.version !== VC_FIDO_VERSION) throw new Error('Configuração VeraCrypt FIDO2 desconhecida.');
  if (!profile.id || !/^[0-9a-f]{64}$/i.test(String(profile.fingerprint || ''))) throw new Error('Configuração VeraCrypt FIDO2 inválida.');
  if (!Array.isArray(profile.slots) || profile.slots.length < 1 || profile.slots.length > 8) throw new Error('Lista de YubiKeys VeraCrypt inválida.');
  for (const slot of profile.slots) {
    if (!slot?.id || slot.type !== 'webauthn-prf' || !slot.credentialId || !slot.prfSalt || !slot.hkdfSalt || !slot.iv || !slot.wrapped) throw new Error('Slot FIDO2 VeraCrypt inválido.');
  }
  if (profile.recovery) validateRecoveryVault(profile.recovery);
  return true;
}

export function recoveryToBlob(recovery) {
  validateRecoveryVault(recovery);
  return new Blob([JSON.stringify(recovery, null, 2) + '\n'], { type: 'application/json' });
}

export async function recoveryFromFile(file) {
  if (!file || typeof file.text !== 'function') throw new Error('Selecione um arquivo .vcrecovery.');
  if (file.size > 1024 * 1024) throw new Error('Arquivo de recuperação grande demais.');
  let parsed;
  try { parsed = JSON.parse(await file.text()); } catch { throw new Error('Arquivo de recuperação não é JSON válido.'); }
  validateRecoveryVault(parsed);
  return parsed;
}

export function rawKeyfileBlob(secret) {
  ensureBytes(secret, VC_SECRET_BYTES, 'Segredo VeraCrypt');
  return new Blob([secret.slice()], { type: 'application/octet-stream' });
}
