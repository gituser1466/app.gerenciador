const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function normalizeBase32(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

export function decodeBase32(value) {
  const input = normalizeBase32(value);
  if (!input) throw new Error('Segredo TOTP vazio.');
  let bits = 0;
  let buffer = 0;
  const bytes = [];
  for (const char of input) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error('Segredo TOTP inválido.');
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

export async function totp(secret, timestamp = Date.now(), digits = 6, period = 30) {
  const keyBytes = decodeBase32(secret);
  const counter = Math.floor(timestamp / 1000 / period);
  const counterBytes = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i -= 1) {
    counterBytes[i] = value & 0xff;
    value = Math.floor(value / 256);
  }
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary = ((signature[offset] & 0x7f) << 24)
    | ((signature[offset + 1] & 0xff) << 16)
    | ((signature[offset + 2] & 0xff) << 8)
    | (signature[offset + 3] & 0xff);
  const code = String(binary % (10 ** digits)).padStart(digits, '0');
  const remaining = period - (Math.floor(timestamp / 1000) % period);
  return { code, remaining, period };
}
