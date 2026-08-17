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

export const FORMAT = 'meucofre-local-v1';
export const VERSION = 1;
export const PASSWORD_ITERATIONS = 600000;
export const UNLOCK_POLICIES = Object.freeze({
  ANY: 'any',
  YUBIKEY: 'yubikey',
  PASSWORD_YUBIKEY: 'password-yubikey'
});
const AAD_VAULT = utf8(`${FORMAT}:vault`);

async function importAesKey(raw, extractable = false) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);
}

function normalizedPasswordBytes(password) {
  return utf8(String(password).normalize('NFKC'));
}

async function derivePasswordKey(password, salt, iterations = PASSWORD_ITERATIONS) {
  const passwordBytes = normalizedPasswordBytes(password);
  try {
    const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    wipe(passwordBytes);
  }
}

async function derivePasswordBytes(password, salt, iterations = PASSWORD_ITERATIONS) {
  const passwordBytes = normalizedPasswordBytes(password);
  try {
    const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      256
    );
    return new Uint8Array(bits);
  } finally {
    wipe(passwordBytes);
  }
}

async function derivePrfKey(prfSecret, salt, info) {
  const material = await crypto.subtle.importKey('raw', prfSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8(info) },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function derivePasswordPrfKey(password, prfSecret, passwordSalt, iterations, hkdfSalt, info) {
  const passwordPart = await derivePasswordBytes(password, passwordSalt, iterations);
  const combined = concatBytes(passwordPart, prfSecret);
  wipe(passwordPart);
  try {
    const material = await crypto.subtle.importKey('raw', combined, 'HKDF', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: hkdfSalt, info: utf8(info) },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  } finally {
    wipe(combined);
  }
}

async function encryptRaw(key, bytes, aad) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, bytes);
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptRaw(key, wrapped, aad) {
  const iv = base64ToBytes(wrapped.iv);
  const ciphertext = base64ToBytes(wrapped.ciphertext);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ciphertext);
  return new Uint8Array(plain);
}

async function encryptVaultData(vaultKeyBytes, vault) {
  const key = await importAesKey(vaultKeyBytes);
  const json = utf8(JSON.stringify(vault));
  const encrypted = await encryptRaw(key, json, AAD_VAULT);
  wipe(json);
  return encrypted;
}

async function decryptVaultData(vaultKeyBytes, encrypted) {
  const key = await importAesKey(vaultKeyBytes);
  const json = await decryptRaw(key, encrypted, AAD_VAULT);
  try {
    const parsed = JSON.parse(text(json));
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.entries)) throw new Error('Estrutura do cofre inválida.');
    return parsed;
  } finally {
    wipe(json);
  }
}

function slotAad(slotId) {
  return utf8(`${FORMAT}:slot:${slotId}`);
}

async function makePasswordSlot(vaultKeyBytes, password, label = 'Senha mestra') {
  const slotId = uuid();
  const salt = randomBytes(32);
  const key = await derivePasswordKey(password, salt, PASSWORD_ITERATIONS);
  const wrapped = await encryptRaw(key, vaultKeyBytes, slotAad(slotId));
  return {
    id: slotId,
    type: 'password',
    label,
    createdAt: new Date().toISOString(),
    kdf: {
      name: 'PBKDF2-SHA-256',
      iterations: PASSWORD_ITERATIONS,
      salt: bytesToBase64(salt)
    },
    wrapped
  };
}

function hasStandaloneYubiKey(record) {
  return record.slots.some((slot) => slot.type === 'webauthn-prf' && slot.kind === 'security-key');
}

function hasCombinedYubiKey(record) {
  return record.slots.some((slot) => slot.type === 'password-webauthn-prf' && slot.kind === 'security-key');
}

export function defaultVault(name = 'Meu Cofre') {
  const now = new Date().toISOString();
  return {
    schema: 1,
    id: uuid(),
    name,
    createdAt: now,
    updatedAt: now,
    entries: [],
    settings: {
      idleLockMinutes: 5,
      backgroundLockSeconds: 30,
      clipboardClearSeconds: 30
    }
  };
}

export async function createRecord(password, name = 'Meu Cofre') {
  const vaultKey = randomBytes(32);
  const vault = defaultVault(name);
  const passwordSlot = await makePasswordSlot(vaultKey, password);
  const record = {
    format: FORMAT,
    version: VERSION,
    createdAt: vault.createdAt,
    updatedAt: vault.updatedAt,
    unlockPolicy: UNLOCK_POLICIES.ANY,
    webauthnUserId: bytesToBase64(randomBytes(32)),
    slots: [passwordSlot],
    vault: await encryptVaultData(vaultKey, vault)
  };
  return { record, vault, vaultKey };
}

export function validateRecord(record) {
  if (!record || record.format !== FORMAT || record.version !== VERSION) throw new Error('Arquivo de cofre incompatível.');
  if (!record.vault?.iv || !record.vault?.ciphertext || !Array.isArray(record.slots)) throw new Error('Arquivo de cofre incompleto.');
  if (!record.slots.some((slot) => slot.type === 'password')) throw new Error('O cofre não possui método de recuperação por senha mestra.');
  return true;
}

export function getUnlockPolicy(record) {
  const policy = record?.unlockPolicy;
  if (policy === UNLOCK_POLICIES.YUBIKEY && hasStandaloneYubiKey(record)) return policy;
  if (policy === UNLOCK_POLICIES.PASSWORD_YUBIKEY && hasCombinedYubiKey(record)) return policy;
  return UNLOCK_POLICIES.ANY;
}

export function setUnlockPolicy(record, policy) {
  validateRecord(record);
  if (!Object.values(UNLOCK_POLICIES).includes(policy)) throw new Error('Política de desbloqueio inválida.');
  if (policy === UNLOCK_POLICIES.YUBIKEY && !hasStandaloneYubiKey(record)) {
    throw new Error('Cadastre ao menos uma YubiKey antes de selecionar esse modo.');
  }
  if (policy === UNLOCK_POLICIES.PASSWORD_YUBIKEY && !hasCombinedYubiKey(record)) {
    throw new Error('Crie primeiro um método criptográfico Senha + YubiKey.');
  }
  const next = structuredClone(record);
  next.unlockPolicy = policy;
  next.updatedAt = new Date().toISOString();
  return next;
}

export async function unlockPassword(record, password) {
  validateRecord(record);
  const slot = record.slots.find((item) => item.type === 'password');
  if (!slot) throw new Error('Senha mestra não configurada.');
  const salt = base64ToBytes(slot.kdf.salt);
  const iterations = Number(slot.kdf.iterations) || PASSWORD_ITERATIONS;
  const key = await derivePasswordKey(password, salt, iterations);
  let vaultKey;
  try {
    vaultKey = await decryptRaw(key, slot.wrapped, slotAad(slot.id));
    const vault = await decryptVaultData(vaultKey, record.vault);
    return { vaultKey, vault };
  } catch {
    if (vaultKey) wipe(vaultKey);
    throw new Error('Senha mestra incorreta ou cofre danificado.');
  }
}

export async function saveRecord(record, vaultKey, vault) {
  vault.updatedAt = new Date().toISOString();
  const next = structuredClone(record);
  next.updatedAt = vault.updatedAt;
  next.vault = await encryptVaultData(vaultKey, vault);
  return next;
}

export async function changeMasterPassword(record, vaultKey, newPassword) {
  if (record.slots.some((slot) => slot.type === 'password-webauthn-prf')) {
    throw new Error('Remova temporariamente os métodos “Senha + YubiKey” antes de trocar a senha mestra e cadastre-os novamente depois.');
  }
  const next = structuredClone(record);
  const oldIndex = next.slots.findIndex((slot) => slot.type === 'password');
  const newSlot = await makePasswordSlot(vaultKey, newPassword);
  if (oldIndex >= 0) next.slots.splice(oldIndex, 1, newSlot);
  else next.slots.unshift(newSlot);
  next.updatedAt = new Date().toISOString();
  return next;
}

export async function createPrfSlot(record, vaultKey, registration, prfSecret) {
  const slotId = uuid();
  const hkdfSalt = randomBytes(32);
  const info = `${FORMAT}:${registration.kind}:wrap`;
  const key = await derivePrfKey(prfSecret, hkdfSalt, info);
  const wrapped = await encryptRaw(key, vaultKey, slotAad(slotId));
  return {
    id: slotId,
    type: 'webauthn-prf',
    kind: registration.kind,
    label: registration.label,
    credentialId: registration.credentialId,
    transports: registration.transports || [],
    prfSalt: registration.prfSalt,
    hkdfSalt: bytesToBase64(hkdfSalt),
    createdAt: new Date().toISOString(),
    wrapped
  };
}

export async function unlockPrf(record, slot, prfSecret) {
  validateRecord(record);
  const hkdfSalt = base64ToBytes(slot.hkdfSalt);
  const info = `${FORMAT}:${slot.kind}:wrap`;
  const key = await derivePrfKey(prfSecret, hkdfSalt, info);
  let vaultKey;
  try {
    vaultKey = await decryptRaw(key, slot.wrapped, slotAad(slot.id));
    const vault = await decryptVaultData(vaultKey, record.vault);
    return { vaultKey, vault };
  } catch {
    if (vaultKey) wipe(vaultKey);
    throw new Error('Não foi possível desbloquear o cofre com este autenticador.');
  }
}

export async function createPasswordPrfSlot(record, vaultKey, registration, prfSecret, password) {
  const slotId = uuid();
  const passwordSalt = randomBytes(32);
  const hkdfSalt = randomBytes(32);
  const info = `${FORMAT}:${registration.kind}:password-prf:wrap`;
  const key = await derivePasswordPrfKey(
    password,
    prfSecret,
    passwordSalt,
    PASSWORD_ITERATIONS,
    hkdfSalt,
    info
  );
  const wrapped = await encryptRaw(key, vaultKey, slotAad(slotId));
  return {
    id: slotId,
    type: 'password-webauthn-prf',
    kind: registration.kind,
    label: `Senha + ${registration.label}`,
    credentialId: registration.credentialId,
    transports: registration.transports || [],
    prfSalt: registration.prfSalt,
    passwordKdf: {
      name: 'PBKDF2-SHA-256',
      iterations: PASSWORD_ITERATIONS,
      salt: bytesToBase64(passwordSalt)
    },
    hkdfSalt: bytesToBase64(hkdfSalt),
    createdAt: new Date().toISOString(),
    wrapped
  };
}

export async function unlockPasswordPrf(record, slot, password, prfSecret) {
  validateRecord(record);
  if (slot?.type !== 'password-webauthn-prf') throw new Error('Método de dois fatores inválido.');
  const passwordSalt = base64ToBytes(slot.passwordKdf?.salt || '');
  const hkdfSalt = base64ToBytes(slot.hkdfSalt);
  const iterations = Number(slot.passwordKdf?.iterations) || PASSWORD_ITERATIONS;
  const info = `${FORMAT}:${slot.kind}:password-prf:wrap`;
  const key = await derivePasswordPrfKey(password, prfSecret, passwordSalt, iterations, hkdfSalt, info);
  let vaultKey;
  try {
    vaultKey = await decryptRaw(key, slot.wrapped, slotAad(slot.id));
    const vault = await decryptVaultData(vaultKey, record.vault);
    return { vaultKey, vault };
  } catch {
    if (vaultKey) wipe(vaultKey);
    throw new Error('Senha ou YubiKey incorreta, ou cofre danificado.');
  }
}

export function removeSlot(record, slotId) {
  const next = structuredClone(record);
  const slot = next.slots.find((item) => item.id === slotId);
  if (!slot) return next;
  if (slot.type === 'password') throw new Error('A senha mestra é o método de recuperação e não pode ser removida.');
  next.slots = next.slots.filter((item) => item.id !== slotId);
  if (next.unlockPolicy === UNLOCK_POLICIES.PASSWORD_YUBIKEY && !hasCombinedYubiKey(next)) {
    next.unlockPolicy = hasStandaloneYubiKey(next) ? UNLOCK_POLICIES.YUBIKEY : UNLOCK_POLICIES.ANY;
  }
  if (next.unlockPolicy === UNLOCK_POLICIES.YUBIKEY && !hasStandaloneYubiKey(next)) {
    next.unlockPolicy = UNLOCK_POLICIES.ANY;
  }
  next.updatedAt = new Date().toISOString();
  return next;
}
