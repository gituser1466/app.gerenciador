const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(text) {
  return encoder.encode(String(text));
}

export function text(bytes) {
  return decoder.decode(bytes);
}

export function randomBytes(length) {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
}

export function base64UrlToBytes(value) {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return base64ToBytes(padded);
}

export function concatBytes(...parts) {
  const arrays = parts.map((part) => part instanceof Uint8Array ? part : new Uint8Array(part));
  const total = arrays.reduce((sum, item) => sum + item.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

export function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

export function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function safeHttpUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  try {
    const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(raw) ? raw : `https://${raw}`;
    const url = new URL(candidate);
    return ['https:', 'http:'].includes(url.protocol) ? url : null;
  } catch {
    return null;
  }
}

export function formatDateTime(iso) {
  if (!iso) return '';
  try {
    return new Intl.DateTimeFormat('pt-BR', {
      dateStyle: 'short',
      timeStyle: 'short'
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

export function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

/**
 * Entrega um arquivo ao usuário. No iPhone/iPad a folha de compartilhamento do
 * iOS ("Salvar em Arquivos") é bem mais confiável que um <a download> dentro de
 * uma PWA em modo standalone; no macOS o download normal é o comportamento
 * esperado. Qualquer falha cai de volta no download.
 */
export async function saveBlob(blob, filename) {
  const touch = typeof matchMedia === 'function' && matchMedia('(hover: none) and (pointer: coarse)').matches;
  if (touch && typeof File === 'function' && navigator.canShare) {
    try {
      const file = new File([blob], filename, { type: blob.type || 'application/octet-stream' });
      if (navigator.canShare({ files: [file] })) {
        await navigator.share({ files: [file], title: filename });
        return 'share';
      }
    } catch (error) {
      if (error?.name === 'AbortError') return 'cancel';
    }
  }
  downloadBlob(blob, filename);
  return 'download';
}

/** Tamanho legível para anexos e containers. */
export function formatBytes(value) {
  const n = Number(value) || 0;
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}
