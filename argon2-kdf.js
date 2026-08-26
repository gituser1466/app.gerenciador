import { wipe } from './utils.js';

let wasmPromise = null;
let queue = Promise.resolve();

function align(value, alignment = 16) {
  return Math.ceil(value / alignment) * alignment;
}

async function loadWasm() {
  if (!wasmPromise) {
    wasmPromise = (async () => {
      // Resolve pelo próprio módulo, não pela URL da página: assim funciona também
      // quando o importador está em outra pasta (páginas de teste, subrotas).
      const wasmUrl = new URL('./argon2-kdf.wasm', import.meta.url);
      const response = await fetch(wasmUrl, { cache: 'no-store' });
      if (!response.ok) throw new Error(`Não foi possível carregar Argon2 (${response.status}).`);
      const bytes = await response.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(bytes, {});
      const exp = instance.exports;
      if (!(exp.memory instanceof WebAssembly.Memory) || typeof exp.argon2_kdf !== 'function') {
        throw new Error('Módulo Argon2 local inválido.');
      }
      return exp;
    })();
  }
  return wasmPromise;
}

function runExclusive(fn) {
  const run = queue.then(fn, fn);
  queue = run.catch(() => {});
  return run;
}

export async function argon2Kdf({
  type,
  version,
  iterations,
  memoryBytes,
  parallelism,
  password,
  salt,
  secret = null,
  associatedData = null,
  length = 32
}) {
  return runExclusive(async () => {
    const exp = await loadWasm();
    const pwd = password instanceof Uint8Array ? password : new Uint8Array(password || 0);
    const s = salt instanceof Uint8Array ? salt : new Uint8Array(salt || 0);
    const sec = secret instanceof Uint8Array ? secret : new Uint8Array(secret || 0);
    const ad = associatedData instanceof Uint8Array ? associatedData : new Uint8Array(associatedData || 0);
    const t = type === 'argon2d' || type === 0 ? 0 : type === 'argon2id' || type === 2 ? 2 : -1;
    const ver = Number(version);
    const passes = Number(iterations);
    const lanes = Number(parallelism);
    const memBytes = Number(memoryBytes);
    const outLen = Number(length);
    if (t < 0 || ![0x10, 0x13].includes(ver)) throw new Error('Versão/tipo Argon2 do KDBX não suportado.');
    if (!Number.isSafeInteger(passes) || passes < 1 || !Number.isSafeInteger(lanes) || lanes < 1) throw new Error('Parâmetros Argon2 inválidos.');
    if (!Number.isSafeInteger(memBytes) || memBytes < 8 * lanes * 1024 || memBytes % 1024 !== 0) throw new Error('Memória Argon2 inválida no KDBX.');
    if (!Number.isSafeInteger(outLen) || outLen < 4 || outLen > 1024) throw new Error('Tamanho de saída Argon2 inválido.');
    if (s.length < 8) throw new Error('Salt Argon2 inválido.');

    const memoryKiB = memBytes / 1024;
    const segmentLength = Math.floor(memoryKiB / (lanes * 4));
    const blocks = segmentLength * lanes * 4;
    if (segmentLength < 2) throw new Error('Memória Argon2 insuficiente.');

    let ptr = align(Number(exp.__heap_base.value), 1024);
    const pwdPtr = ptr; ptr = align(ptr + pwd.length);
    const saltPtr = ptr; ptr = align(ptr + s.length);
    const secPtr = ptr; ptr = align(ptr + sec.length);
    const adPtr = ptr; ptr = align(ptr + ad.length);
    const outPtr = ptr; ptr = align(ptr + outLen);
    const memPtr = align(ptr, 1024);
    const required = memPtr + blocks * 1024;
    const maxBytes = 2147483648;
    if (required > maxBytes) {
      throw new Error(`Este KDBX exige ${(memBytes / 1048576).toFixed(0)} MiB de Argon2, acima do limite de memória WebAssembly desta versão.`);
    }
    try {
      if (exp.memory.buffer.byteLength < required) {
        const pages = Math.ceil((required - exp.memory.buffer.byteLength) / 65536);
        try { exp.memory.grow(pages); }
        catch { throw new Error(`Não há memória suficiente neste navegador para Argon2 (${(memBytes / 1048576).toFixed(0)} MiB).`); }
      }
      let heap = new Uint8Array(exp.memory.buffer);
      heap.set(pwd, pwdPtr); heap.set(s, saltPtr);
      if (sec.length) heap.set(sec, secPtr);
      if (ad.length) heap.set(ad, adPtr);
      heap.fill(0, outPtr, outPtr + outLen);
      // Do not pre-zero the whole Argon2 region: every block is written before use.
      const rc = exp.argon2_kdf(
        t, ver, passes, memoryKiB, lanes,
        pwdPtr, pwd.length, saltPtr, s.length,
        sec.length ? secPtr : 0, sec.length,
        ad.length ? adPtr : 0, ad.length,
        outPtr, outLen, memPtr, blocks
      );
      if (rc !== 0) throw new Error(`Argon2 recusou os parâmetros do KDBX (código ${rc}).`);
      heap = new Uint8Array(exp.memory.buffer);
      return heap.slice(outPtr, outPtr + outLen);
    } finally {
      // Best-effort cleanup. JavaScript/WebAssembly do not provide a hard zeroization guarantee.
      try {
        const heap = new Uint8Array(exp.memory.buffer);
        heap.fill(0, pwdPtr, pwdPtr + pwd.length);
        heap.fill(0, saltPtr, saltPtr + s.length);
        if (sec.length) heap.fill(0, secPtr, secPtr + sec.length);
        if (ad.length) heap.fill(0, adPtr, adPtr + ad.length);
        heap.fill(0, outPtr, outPtr + outLen);
        heap.fill(0, memPtr, Math.min(required, heap.length));
      } catch {}
    }
  });
}
