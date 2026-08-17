import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  randomBytes
} from './utils.js';

function ensureSupport() {
  if (!window.isSecureContext) throw new Error('Chaves de acesso e YubiKey exigem HTTPS (contexto seguro).');
  if (!('PublicKeyCredential' in window) || !navigator.credentials) throw new Error('WebAuthn não está disponível neste navegador.');
}

export async function platformAuthenticatorAvailable() {
  if (!window.isSecureContext || !window.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export async function registerPrfCredential(record, kind) {
  ensureSupport();
  const isPlatform = kind === 'platform';
  if (!isPlatform && kind !== 'security-key') throw new Error('Tipo de autenticador inválido.');

  const prfSalt = randomBytes(32);
  const challenge = randomBytes(32);
  const userId = record.webauthnUserId ? base64ToBytes(record.webauthnUserId) : randomBytes(32);

  const publicKey = {
    challenge,
    rp: { name: 'Meu Cofre' },
    user: {
      id: userId,
      name: 'cofre-local',
      displayName: 'Cofre local'
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 }
    ],
    timeout: 90000,
    attestation: 'none',
    authenticatorSelection: {
      authenticatorAttachment: isPlatform ? 'platform' : 'cross-platform',
      residentKey: isPlatform ? 'preferred' : 'discouraged',
      requireResidentKey: false,
      userVerification: 'required'
    },
    extensions: {
      prf: { eval: { first: prfSalt } }
    }
  };

  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey });
  } catch (error) {
    if (error?.name === 'NotAllowedError') throw new Error('Cadastro cancelado ou não autorizado pelo iPhone/chave de segurança.');
    throw new Error(`Falha ao cadastrar autenticador: ${error?.message || error}`);
  }
  if (!credential) throw new Error('O navegador não retornou uma credencial WebAuthn.');

  const ext = credential.getClientExtensionResults?.() || {};
  if (ext.prf?.enabled === false) throw new Error('Este autenticador não oferece a extensão WebAuthn PRF necessária para proteger o cofre.');

  const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));
  const transports = credential.response?.getTransports?.() || [];
  const registration = {
    kind,
    label: isPlatform ? 'Este iPhone / chave de acesso' : 'YubiKey / chave FIDO2',
    credentialId,
    transports,
    prfSalt: bytesToBase64(prfSalt)
  };

  const prfSecret = await evaluatePrf(registration);
  return { registration, prfSecret };
}

export async function evaluatePrf(slotLike) {
  ensureSupport();
  const credentialId = base64UrlToBytes(slotLike.credentialId);
  const prfSalt = base64ToBytes(slotLike.prfSalt);
  const descriptor = { type: 'public-key', id: credentialId };
  // Não envia hints de transporte no get(): o credentialId já restringe a credencial e
  // omitir transports evita incompatibilidades específicas de Safari/NFC.

  let assertion;
  try {
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        timeout: 90000,
        userVerification: 'required',
        allowCredentials: [descriptor],
        extensions: {
          prf: { eval: { first: prfSalt } }
        }
      }
    });
  } catch (error) {
    if (error?.name === 'NotAllowedError') throw new Error('Autenticação cancelada, expirada ou não autorizada.');
    throw new Error(`Falha na autenticação WebAuthn: ${error?.message || error}`);
  }

  const ext = assertion?.getClientExtensionResults?.() || {};
  const first = ext.prf?.results?.first;
  if (!first) throw new Error('O navegador/autenticador não retornou o segredo PRF. Atualize o iOS/Safari ou use a senha mestra.');
  return new Uint8Array(first);
}
