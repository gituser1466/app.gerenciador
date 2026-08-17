const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const DIGITS = '23456789';
const SYMBOLS = '!@#$%&*+-_=?:.,';

function randomIndex(max) {
  if (max <= 0 || max > 256) throw new Error('Intervalo inválido.');
  const limit = 256 - (256 % max);
  const b = new Uint8Array(1);
  do crypto.getRandomValues(b); while (b[0] >= limit);
  return b[0] % max;
}

function pick(chars) {
  return chars[randomIndex(chars.length)];
}

function shuffle(chars) {
  const arr = [...chars];
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const j = randomIndex(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

export function generatePassword({ length = 24, lower = true, upper = true, digits = true, symbols = true } = {}) {
  const groups = [];
  if (lower) groups.push(LOWER);
  if (upper) groups.push(UPPER);
  if (digits) groups.push(DIGITS);
  if (symbols) groups.push(SYMBOLS);
  if (!groups.length) throw new Error('Selecione pelo menos um conjunto de caracteres.');
  const n = Math.max(groups.length, Math.min(128, Number(length) || 24));
  const all = groups.join('');
  const out = groups.map((group) => pick(group));
  while (out.length < n) out.push(pick(all));
  return shuffle(out);
}
