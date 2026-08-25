import { base64ToBytes, bytesToBase64, concatBytes, randomBytes, utf8, wipe } from './utils.js';

export const VC_MAC_PAIR_FORMAT = 'meucofre-veracrypt-macos-pair-v1';
export const VC_MAC_MOUNT_FORMAT = 'meucofre-veracrypt-macos-mount-v1';
export const VC_MAC_PAIR_VERSION = 1;
export const VC_MAC_MOUNT_VERSION = 1;
const PBKDF2_ITERATIONS = 200000;
const PACKAGE_TTL_SECONDS = 180;
const MAX_PAIR_FILE_BYTES = 32 * 1024;
const MAX_MOUNT_PLAINTEXT_BYTES = 9 * 1024 * 1024;
const MAC_DOMAIN = utf8('MeuCofreVeraCryptBridge-MAC-v1\0');

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function pemToDer(pem) {
  const text = String(pem || '').trim();
  const match = text.match(/-----BEGIN PUBLIC KEY-----([\s\S]+?)-----END PUBLIC KEY-----/);
  if (!match) throw new Error('Arquivo de pareamento não contém uma chave pública SPKI válida.');
  return base64ToBytes(match[1].replace(/\s+/g, ''));
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function importRsaPublicKey(pem) {
  const der = pemToDer(pem);
  try {
    const key = await crypto.subtle.importKey('spki', der, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const bits = Number(key.algorithm?.modulusLength || 0);
    if (bits < 3072) throw new Error('A chave pública do helper deve ter pelo menos RSA-3072.');
    return key;
  } finally { wipe(der); }
}

export async function pairingFingerprint(publicKeyPem) {
  const der = pemToDer(publicKeyPem);
  try { return toHex(await sha256(der)); }
  finally { wipe(der); }
}

export async function parseMacPairingFile(file) {
  if (!file || typeof file.text !== 'function') throw new Error('Selecione o arquivo .mcpair gerado pelo helper do Mac.');
  if (file.size > MAX_PAIR_FILE_BYTES) throw new Error('Arquivo de pareamento grande demais.');
  const raw = (await file.text()).trim();
  let publicKeyPem = raw;
  let helperVersion = null;
  if (raw.startsWith('{')) {
    let parsed;
    try { parsed = JSON.parse(raw); } catch { throw new Error('Arquivo .mcpair inválido.'); }
    if (parsed?.format !== VC_MAC_PAIR_FORMAT || parsed.version !== VC_MAC_PAIR_VERSION) throw new Error('Formato de pareamento macOS desconhecido.');
    publicKeyPem = String(parsed.publicKeyPem || '');
    helperVersion = parsed.helperVersion || null;
  }
  const key = await importRsaPublicKey(publicKeyPem);
  const fingerprint = await pairingFingerprint(publicKeyPem);
  return {
    format: VC_MAC_PAIR_FORMAT,
    version: VC_MAC_PAIR_VERSION,
    publicKeyPem,
    fingerprint,
    helperVersion,
    pairedAt: new Date().toISOString(),
    modulusLength: Number(key.algorithm?.modulusLength || 0)
  };
}

export function validateMacPairing(pairing) {
  if (pairing?.format !== VC_MAC_PAIR_FORMAT || pairing.version !== VC_MAC_PAIR_VERSION) throw new Error('Pareamento do helper macOS ausente ou inválido.');
  if (typeof pairing.publicKeyPem !== 'string' || !pairing.publicKeyPem.includes('BEGIN PUBLIC KEY')) throw new Error('Chave pública do helper macOS ausente.');
  if (!/^[0-9a-f]{64}$/i.test(String(pairing.fingerprint || ''))) throw new Error('Fingerprint do helper macOS inválido.');
  return true;
}

function canonicalMacData(pkg) {
  return utf8([
    pkg.format,
    String(pkg.version),
    pkg.profileId,
    pkg.headerFingerprint,
    String(pkg.containerSize),
    String(pkg.expiresUnix),
    String(pkg.kdfIterations),
    pkg.salt,
    pkg.encryptedSecret,
    pkg.ciphertext
  ].join('\n'));
}

async function deriveOpenSslKeyIv(secretHex, salt, iterations) {
  const passBytes = utf8(secretHex);
  try {
    const material = await crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material, 384));
    return { keyBytes: bits.slice(0, 32), ivBytes: bits.slice(32, 48), all: bits };
  } finally { wipe(passBytes); }
}

async function deriveMacKey(secretHex) {
  const secret = utf8(secretHex);
  const material = concatBytes(MAC_DOMAIN, secret);
  try { return await sha256(material); }
  finally { wipe(secret); wipe(material); }
}

function minimalMountPayload(profile, bundle) {
  const keyfiles = (bundle.keyfiles || []).map((k, index) => ({
    name: `keyfile-${index + 1}.bin`,
    data: String(k.data || '')
  }));
  return {
    format: 'meucofre-veracrypt-mount-credentials-v1',
    version: 1,
    profileId: profile.id,
    password: String(bundle.password ?? ''),
    pim: Number.parseInt(String(bundle.pim || 0), 10) || 0,
    hash: String(bundle.hash || 'auto'),
    hidden: !!bundle.hidden,
    keyfileCount: keyfiles.length,
    keyfiles
  };
}

export async function createMacMountPackage(profile, bundle, pairing) {
  validateMacPairing(pairing);
  if (!profile?.id || !profile?.container?.headerFingerprint) throw new Error('Perfil VeraCrypt vinculado inválido.');
  const publicKey = await importRsaPublicKey(pairing.publicKeyPem);
  const payload = utf8(JSON.stringify(minimalMountPayload(profile, bundle)));
  if (payload.length > MAX_MOUNT_PLAINTEXT_BYTES) { wipe(payload); throw new Error('As credenciais/keyfiles são grandes demais para o bridge macOS.'); }
  const random = randomBytes(32), salt = randomBytes(8);
  const secretHex = toHex(random);
  const now = Math.floor(Date.now() / 1000);
  let derived = null, ciphertext = null, encryptedSecret = null, macKey = null, canonical = null, mac = null;
  try {
    derived = await deriveOpenSslKeyIv(secretHex, salt, PBKDF2_ITERATIONS);
    const aesKey = await crypto.subtle.importKey('raw', derived.keyBytes, { name: 'AES-CBC' }, false, ['encrypt']);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: derived.ivBytes }, aesKey, payload));
    encryptedSecret = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, utf8(secretHex)));
    const pkg = {
      format: VC_MAC_MOUNT_FORMAT,
      version: VC_MAC_MOUNT_VERSION,
      profileId: profile.id,
      containerName: String(profile.container.name || 'VeraCrypt.hc'),
      containerSize: Number(profile.container.size),
      headerFingerprint: String(profile.container.headerFingerprint),
      hidden: !!profile.container.hidden,
      createdUnix: now,
      expiresUnix: now + PACKAGE_TTL_SECONDS,
      kdf: 'PBKDF2-HMAC-SHA-256/OpenSSL-compatible',
      kdfIterations: PBKDF2_ITERATIONS,
      salt: bytesToBase64(salt),
      encryptedSecret: bytesToBase64(encryptedSecret),
      ciphertext: bytesToBase64(ciphertext),
      mac: '',
      helperFingerprint: pairing.fingerprint
    };
    canonical = canonicalMacData(pkg);
    macKey = await deriveMacKey(secretHex);
    const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, canonical));
    pkg.mac = bytesToBase64(mac);
    return pkg;
  } finally {
    wipe(payload); wipe(random); wipe(salt);
    if (derived) { wipe(derived.keyBytes); wipe(derived.ivBytes); wipe(derived.all); }
    ciphertext && wipe(ciphertext); encryptedSecret && wipe(encryptedSecret); macKey && wipe(macKey); canonical && wipe(canonical); mac && wipe(mac);
  }
}

export function macMountPackageBlob(pkg) {
  if (pkg?.format !== VC_MAC_MOUNT_FORMAT || pkg.version !== VC_MAC_MOUNT_VERSION || !pkg.mac) throw new Error('Pacote de montagem macOS inválido.');
  return new Blob([JSON.stringify(pkg) + '\n'], { type: 'application/vnd.meucofre.vcmount+json' });
}

export function macMountFilename(profile) {
  const safe = String(profile?.name || 'Vault').replace(/[^a-z0-9._-]+/gi, '_').slice(0, 70) || 'Vault';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `MeuCofre-Mount-${safe}-${stamp}.vcmount`;
}
