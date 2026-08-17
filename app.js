import { getVaultRecord, putVaultRecord } from './storage.js';
import {
  changeMasterPassword,
  createPrfSlot,
  createRecord,
  removeSlot,
  saveRecord,
  unlockPassword,
  unlockPrf,
  validateRecord
} from './crypto-vault.js';
import { evaluatePrf, platformAuthenticatorAvailable, registerPrfCredential } from './webauthn.js';
import { generatePassword } from './generator.js';
import { totp } from './totp.js';
import {
  clampInt,
  downloadBlob,
  formatDateTime,
  safeHttpUrl,
  uuid,
  wipe
} from './utils.js';

const $ = (id) => document.getElementById(id);
let record = null;
let session = null;
let editingId = null;
let totpTimer = null;
let idleTimer = null;
let backgroundTimer = null;
let toastTimer = null;
let clipboardTimer = null;
let waitingWorker = null;

function showToast(message, type = '') {
  const el = $('toast');
  el.textContent = message;
  el.className = `toast ${type}`;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 3200);
}

function setPublicScreen(name) {
  $('screen-setup').hidden = name !== 'setup';
  $('screen-unlock').hidden = name !== 'unlock';
  $('screen-app').hidden = name !== 'app';
  $('public-brand').hidden = name === 'app';
}

function passwordQuality(value) {
  const p = String(value || '');
  let score = 0;
  if (p.length >= 8) score += 1;
  if (p.length >= 14) score += 1;
  if (p.length >= 20) score += 1;
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score += 1;
  if (/\d/.test(p) || /[^A-Za-z0-9]/.test(p)) score += 1;
  return score;
}

function updateSetupStrength() {
  const p = $('setup-password').value;
  const el = $('setup-strength');
  const score = passwordQuality(p);
  const labels = ['Muito curta', 'Fraca', 'Razoável', 'Boa', 'Forte', 'Muito forte'];
  el.textContent = p ? `${labels[score]}. Para um cofre de senhas, prefira uma frase longa e exclusiva.` : 'Use de preferência uma frase longa e exclusiva.';
  el.className = score >= 4 ? 'hint success' : score <= 1 && p ? 'hint warning' : 'hint';
}

async function init() {
  registerServiceWorker();
  wireEvents();
  record = await getVaultRecord();
  if (record) {
    try {
      validateRecord(record);
      renderUnlockMethods();
      setPublicScreen('unlock');
    } catch (error) {
      setPublicScreen('setup');
      showToast(error.message, 'error');
    }
  } else {
    setPublicScreen('setup');
  }
  generateNewPassword();
}

function wireEvents() {
  $('setup-password').addEventListener('input', updateSetupStrength);
  $('setup-create').addEventListener('click', createVaultFromSetup);
  $('setup-import').addEventListener('click', () => $('setup-import-file').click());
  $('setup-import-file').addEventListener('change', (event) => importBackupFile(event.target.files?.[0], false));
  $('unlock-password-btn').addEventListener('click', unlockWithPassword);
  $('unlock-password').addEventListener('keydown', (event) => { if (event.key === 'Enter') unlockWithPassword(); });
  $('unlock-import').addEventListener('click', () => $('unlock-import-file').click());
  $('unlock-import-file').addEventListener('change', (event) => importBackupFile(event.target.files?.[0], false));
  $('lock-btn').addEventListener('click', () => lockVault('Cofre bloqueado.'));
  $('search').addEventListener('input', renderEntries);
  $('add-entry').addEventListener('click', () => openEntryModal());
  $('entry-close').addEventListener('click', closeEntryModal);
  $('entry-modal').addEventListener('click', (event) => { if (event.target === $('entry-modal')) closeEntryModal(); });
  $('entry-form').addEventListener('submit', saveEntryFromForm);
  $('entry-delete').addEventListener('click', deleteCurrentEntry);
  $('entry-show-password').addEventListener('click', toggleEntryPassword);
  $('entry-generate-password').addEventListener('click', () => { $('entry-password').value = generatePassword({ length: 24 }); });
  $('entry-copy-user').addEventListener('click', () => copyText($('entry-username').value, 'Usuário copiado.'));
  $('entry-copy-pass').addEventListener('click', () => copyText($('entry-password').value, 'Senha copiada.'));
  $('entry-open-url').addEventListener('click', openCurrentUrl);
  $('entry-copy-totp').addEventListener('click', () => copyText($('entry-totp-code').textContent, 'Código TOTP copiado.'));
  $('entry-totp').addEventListener('input', updateTotpBox);

  document.querySelectorAll('[data-nav]').forEach((button) => button.addEventListener('click', () => navigate(button.dataset.nav)));
  ['gen-length', 'gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols'].forEach((id) => $(id).addEventListener('change', generateNewPassword));
  $('generate-btn').addEventListener('click', generateNewPassword);
  $('copy-generated').addEventListener('click', () => copyText($('generated-password').textContent, 'Senha gerada copiada.'));

  $('add-faceid').addEventListener('click', () => addWebAuthnMethod('platform'));
  $('add-yubikey').addEventListener('click', () => addWebAuthnMethod('security-key'));
  $('change-master').addEventListener('click', changeMaster);
  $('export-backup').addEventListener('click', exportBackup);
  $('restore-backup').addEventListener('click', () => $('restore-backup-file').click());
  $('restore-backup-file').addEventListener('change', (event) => importBackupFile(event.target.files?.[0], true));
  $('save-settings').addEventListener('click', saveSettings);

  $('apply-update').addEventListener('click', () => waitingWorker?.postMessage({ type: 'SKIP_WAITING' }));
  $('dismiss-update').addEventListener('click', () => { $('update-banner').hidden = true; });

  ['pointerdown', 'keydown', 'touchstart'].forEach((eventName) => window.addEventListener(eventName, resetIdleTimer, { passive: true }));
  document.addEventListener('visibilitychange', handleVisibility);
  window.addEventListener('pagehide', clearSessionMemory);
}

async function createVaultFromSetup() {
  const password = $('setup-password').value;
  const repeat = $('setup-password2').value;
  const name = $('setup-name').value.trim() || 'Meu Cofre';
  if (password.length < 8) return showToast('Use pelo menos 8 caracteres na senha mestra.', 'error');
  if (password !== repeat) return showToast('As senhas não coincidem.', 'error');
  const button = $('setup-create');
  button.disabled = true;
  button.textContent = 'Criando...';
  try {
    const created = await createRecord(password, name);
    record = created.record;
    await putVaultRecord(record);
    session = { vault: created.vault, vaultKey: created.vaultKey };
    $('setup-password').value = '';
    $('setup-password2').value = '';
    enterApp();
    showToast('Cofre criado. Faça um backup criptografado em seguida.', 'success');
  } catch (error) {
    showToast(error.message || String(error), 'error');
  } finally {
    button.disabled = false;
    button.textContent = 'Criar cofre criptografado';
  }
}

async function unlockWithPassword() {
  const password = $('unlock-password').value;
  if (!password) return;
  const btn = $('unlock-password-btn');
  btn.disabled = true;
  btn.textContent = 'Desbloqueando...';
  $('unlock-error').textContent = '';
  try {
    const unlocked = await unlockPassword(record, password);
    session = unlocked;
    $('unlock-password').value = '';
    enterApp();
  } catch (error) {
    $('unlock-error').textContent = error.message || String(error);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Desbloquear com senha';
  }
}

function renderUnlockMethods() {
  const box = $('unlock-prf-buttons');
  box.replaceChildren();
  for (const slot of record?.slots || []) {
    if (slot.type !== 'webauthn-prf') continue;
    const btn = document.createElement('button');
    btn.className = slot.kind === 'platform' ? 'btn secondary' : 'btn ghost';
    btn.textContent = slot.kind === 'platform' ? 'Desbloquear com Face ID / dispositivo' : 'Desbloquear com YubiKey / chave FIDO2';
    btn.addEventListener('click', () => unlockWithPrfSlot(slot, btn));
    box.append(btn);
  }
}

async function unlockWithPrfSlot(slot, button) {
  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Aguardando autenticação...';
  $('unlock-error').textContent = '';
  try {
    const secret = await evaluatePrf(slot);
    try {
      session = await unlockPrf(record, slot, secret);
    } finally {
      wipe(secret);
    }
    enterApp();
  } catch (error) {
    $('unlock-error').textContent = error.message || String(error);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function enterApp() {
  if (!session) return;
  setPublicScreen('app');
  $('app-vault-name').textContent = session.vault.name || 'Meu Cofre';
  $('search').value = '';
  renderEntries();
  renderSecurity();
  renderSettings();
  navigate('vault');
  resetIdleTimer();
}

function clearSessionMemory() {
  if (session?.vaultKey) wipe(session.vaultKey);
  session = null;
  editingId = null;
  clearTimeout(idleTimer);
  clearTimeout(backgroundTimer);
  clearTimeout(clipboardTimer);
  stopTotpTimer();
}

function lockVault(message) {
  clearSessionMemory();
  closeEntryModal();
  renderUnlockMethods();
  setPublicScreen('unlock');
  if (message) showToast(message);
}

function resetIdleTimer() {
  if (!session) return;
  clearTimeout(idleTimer);
  const minutes = clampInt(session.vault.settings?.idleLockMinutes, 1, 120, 5);
  idleTimer = setTimeout(() => lockVault('Bloqueado por inatividade.'), minutes * 60 * 1000);
}

function handleVisibility() {
  if (!session) return;
  clearTimeout(backgroundTimer);
  if (document.hidden) {
    const seconds = clampInt(session.vault.settings?.backgroundLockSeconds, 0, 300, 30);
    if (seconds === 0) lockVault('Bloqueado ao sair do aplicativo.');
    else backgroundTimer = setTimeout(() => lockVault('Bloqueado em segundo plano.'), seconds * 1000);
  }
}

function navigate(view) {
  document.querySelectorAll('.view').forEach((el) => el.classList.toggle('active', el.dataset.view === view));
  document.querySelectorAll('[data-nav]').forEach((el) => el.classList.toggle('active', el.dataset.nav === view));
  if (view === 'security') renderSecurity();
  if (view === 'settings') renderSettings();
}

function entryMatches(entry, term) {
  if (!term) return true;
  const hay = [entry.title, entry.username, entry.url, ...(entry.tags || [])].join(' ').toLocaleLowerCase('pt-BR');
  return hay.includes(term);
}

function renderEntries() {
  if (!session) return;
  const list = $('entry-list');
  list.replaceChildren();
  const term = $('search').value.trim().toLocaleLowerCase('pt-BR');
  const entries = [...session.vault.entries]
    .filter((entry) => entryMatches(entry, term))
    .sort((a, b) => Number(Boolean(b.favorite)) - Number(Boolean(a.favorite)) || String(a.title).localeCompare(String(b.title), 'pt-BR'));
  $('app-count').textContent = `${session.vault.entries.length} ${session.vault.entries.length === 1 ? 'item' : 'itens'}`;
  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.textContent = term ? 'Nenhum item encontrado.' : 'Seu cofre está vazio. Toque em + para adicionar a primeira senha.';
    list.append(empty);
    return;
  }
  for (const entry of entries) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'entry';
    item.addEventListener('click', () => openEntryModal(entry.id));
    const icon = document.createElement('div');
    icon.className = 'entry-icon';
    icon.textContent = (entry.title || '?').trim().slice(0, 1).toUpperCase();
    const main = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'entry-title';
    title.textContent = entry.title || 'Sem título';
    const meta = document.createElement('div');
    meta.className = 'entry-meta';
    meta.textContent = entry.username || entry.url || (entry.tags || []).join(', ') || 'Credencial';
    main.append(title, meta);
    const fav = document.createElement('div');
    fav.className = 'favorite';
    fav.textContent = entry.favorite ? '★' : '';
    item.append(icon, main, fav);
    list.append(item);
  }
}

function openEntryModal(id = null) {
  if (!session) return;
  editingId = id;
  const entry = id ? session.vault.entries.find((item) => item.id === id) : null;
  $('entry-modal-title').textContent = entry ? 'Editar item' : 'Novo item';
  $('entry-id').value = entry?.id || '';
  $('entry-title').value = entry?.title || '';
  $('entry-username').value = entry?.username || '';
  $('entry-password').value = entry?.password || '';
  $('entry-password').type = 'password';
  $('entry-show-password').textContent = 'Mostrar';
  $('entry-url').value = entry?.url || '';
  $('entry-tags').value = (entry?.tags || []).join(', ');
  $('entry-totp').value = entry?.totpSecret || '';
  $('entry-notes').value = entry?.notes || '';
  $('entry-favorite').checked = Boolean(entry?.favorite);
  $('entry-delete').hidden = !entry;
  $('entry-quick-actions').hidden = !entry;
  $('entry-modal').hidden = false;
  updateTotpBox();
  setTimeout(() => $('entry-title').focus(), 80);
}

function closeEntryModal() {
  $('entry-modal').hidden = true;
  editingId = null;
  stopTotpTimer();
  $('entry-form').reset();
  $('entry-totp-box').hidden = true;
}

async function saveEntryFromForm(event) {
  event.preventDefault();
  if (!session) return;
  const title = $('entry-title').value.trim();
  if (!title) return showToast('Informe um título.', 'error');
  const now = new Date().toISOString();
  const existing = editingId ? session.vault.entries.find((item) => item.id === editingId) : null;
  const entry = {
    id: existing?.id || uuid(),
    title,
    username: $('entry-username').value,
    password: $('entry-password').value,
    url: $('entry-url').value.trim(),
    tags: $('entry-tags').value.split(',').map((tag) => tag.trim()).filter(Boolean).slice(0, 30),
    totpSecret: $('entry-totp').value.trim().replace(/\s+/g, ''),
    notes: $('entry-notes').value,
    favorite: $('entry-favorite').checked,
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
  if (existing) Object.assign(existing, entry);
  else session.vault.entries.push(entry);
  await persistVault();
  closeEntryModal();
  renderEntries();
  showToast('Item salvo.', 'success');
}

async function deleteCurrentEntry() {
  if (!session || !editingId) return;
  const entry = session.vault.entries.find((item) => item.id === editingId);
  if (!confirm(`Excluir “${entry?.title || 'este item'}”? Esta ação será gravada imediatamente.`)) return;
  session.vault.entries = session.vault.entries.filter((item) => item.id !== editingId);
  await persistVault();
  closeEntryModal();
  renderEntries();
  showToast('Item excluído.');
}

function toggleEntryPassword() {
  const input = $('entry-password');
  input.type = input.type === 'password' ? 'text' : 'password';
  $('entry-show-password').textContent = input.type === 'password' ? 'Mostrar' : 'Ocultar';
}

async function updateTotpBox() {
  stopTotpTimer();
  const secret = $('entry-totp').value.trim();
  if (!secret) {
    $('entry-totp-box').hidden = true;
    return;
  }
  $('entry-totp-box').hidden = false;
  const update = async () => {
    try {
      const result = await totp(secret);
      $('entry-totp-code').textContent = result.code;
      $('entry-totp-remaining').textContent = `${result.remaining}s`;
    } catch {
      $('entry-totp-code').textContent = 'inválido';
      $('entry-totp-remaining').textContent = '';
    }
  };
  await update();
  totpTimer = setInterval(update, 1000);
}

function stopTotpTimer() {
  clearInterval(totpTimer);
  totpTimer = null;
}

function openCurrentUrl() {
  const url = safeHttpUrl($('entry-url').value);
  if (!url) return showToast('URL inválida ou não permitida.', 'error');
  window.open(url.href, '_blank', 'noopener,noreferrer');
}

async function copyText(value, message) {
  if (!value) return showToast('Nada para copiar.', 'error');
  try {
    await navigator.clipboard.writeText(value);
    showToast(message, 'success');
    clearTimeout(clipboardTimer);
    const seconds = clampInt(session?.vault?.settings?.clipboardClearSeconds, 0, 300, 30);
    if (seconds > 0) {
      clipboardTimer = setTimeout(async () => {
        if (document.visibilityState !== 'visible') return;
        try { await navigator.clipboard.writeText(''); } catch { /* best effort */ }
      }, seconds * 1000);
    }
  } catch {
    showToast('O navegador não permitiu acesso à área de transferência.', 'error');
  }
}

function generateNewPassword() {
  try {
    const password = generatePassword({
      length: clampInt($('gen-length').value, 8, 128, 24),
      lower: $('gen-lower').checked,
      upper: $('gen-upper').checked,
      digits: $('gen-digits').checked,
      symbols: $('gen-symbols').checked
    });
    $('generated-password').textContent = password;
  } catch (error) {
    $('generated-password').textContent = error.message;
  }
}

async function persistVault() {
  if (!session) return;
  const next = await saveRecord(record, session.vaultKey, session.vault);
  record = next;
  await putVaultRecord(record);
  resetIdleTimer();
}

async function addWebAuthnMethod(kind) {
  if (!session) return;
  const label = kind === 'platform' ? 'Face ID / dispositivo' : 'YubiKey / chave FIDO2';
  if (record.slots.some((slot) => slot.type === 'webauthn-prf' && slot.kind === kind)) {
    return showToast(`${label} já está cadastrado. Remova o método antigo antes de criar outro.`, 'error');
  }
  if (!confirm(`Cadastrar ${label}? Este método ficará vinculado ao domínio HTTPS onde o app está instalado. Mantenha a senha mestra e um backup criptografado.`)) return;
  const button = kind === 'platform' ? $('add-faceid') : $('add-yubikey');
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Aguardando autenticação...';
  try {
    const { registration, prfSecret } = await registerPrfCredential(record, kind);
    try {
      const slot = await createPrfSlot(record, session.vaultKey, registration, prfSecret);
      const next = structuredClone(record);
      next.slots.push(slot);
      next.updatedAt = new Date().toISOString();
      record = next;
      await putVaultRecord(record);
    } finally {
      wipe(prfSecret);
    }
    renderSecurity();
    renderUnlockMethods();
    showToast(`${label} cadastrado.`, 'success');
  } catch (error) {
    showToast(error.message || String(error), 'error');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function removeAuthSlot(slotId) {
  if (!confirm('Remover este método de desbloqueio? A senha mestra continuará funcionando.')) return;
  try {
    record = removeSlot(record, slotId);
    await putVaultRecord(record);
    renderSecurity();
    renderUnlockMethods();
    showToast('Método removido.');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function renderSecurity() {
  if (!session) return;
  const box = $('auth-slots');
  box.replaceChildren();
  for (const slot of record.slots) {
    const row = document.createElement('div');
    row.className = 'row';
    const main = document.createElement('div');
    main.className = 'row-main';
    const title = document.createElement('div');
    title.className = 'row-title';
    title.textContent = slot.type === 'password' ? 'Senha mestra' : slot.label || 'WebAuthn';
    const sub = document.createElement('div');
    sub.className = 'row-sub';
    sub.textContent = slot.type === 'password'
      ? `PBKDF2-SHA-256 · ${Number(slot.kdf?.iterations || 0).toLocaleString('pt-BR')} iterações`
      : `WebAuthn PRF · cadastrado em ${formatDateTime(slot.createdAt)}`;
    main.append(title, sub);
    row.append(main);
    if (slot.type !== 'password') {
      const remove = document.createElement('button');
      remove.className = 'btn danger small';
      remove.textContent = 'Remover';
      remove.addEventListener('click', () => removeAuthSlot(slot.id));
      row.append(remove);
    } else {
      const pill = document.createElement('span');
      pill.className = 'pill ok';
      pill.textContent = 'Recuperação';
      row.append(pill);
    }
    box.append(row);
  }

  const diagnostics = $('security-diagnostics');
  diagnostics.replaceChildren();
  const items = [
    ['HTTPS / contexto seguro', window.isSecureContext],
    ['WebCrypto', Boolean(window.crypto?.subtle)],
    ['WebAuthn', Boolean(window.PublicKeyCredential && navigator.credentials)],
    ['Service Worker / offline', 'serviceWorker' in navigator],
    ['Instalado como app', window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true]
  ];
  items.push(['Autenticador do dispositivo', await platformAuthenticatorAvailable()]);
  for (const [label, ok] of items) {
    const row = document.createElement('div');
    row.className = 'row';
    const main = document.createElement('div');
    main.className = 'row-title';
    main.textContent = label;
    const pill = document.createElement('span');
    pill.className = `pill ${ok ? 'ok' : 'bad'}`;
    pill.textContent = ok ? 'OK' : 'Indisponível';
    row.append(main, pill);
    diagnostics.append(row);
  }
}

async function changeMaster() {
  if (!session) return;
  const p1 = $('new-master').value;
  const p2 = $('new-master2').value;
  if (p1.length < 8) return showToast('Use pelo menos 8 caracteres.', 'error');
  if (p1 !== p2) return showToast('As novas senhas não coincidem.', 'error');
  const btn = $('change-master');
  btn.disabled = true;
  btn.textContent = 'Alterando...';
  try {
    record = await changeMasterPassword(record, session.vaultKey, p1);
    await putVaultRecord(record);
    $('new-master').value = '';
    $('new-master2').value = '';
    renderSecurity();
    showToast('Senha mestra alterada. Exporte um novo backup.', 'success');
  } catch (error) {
    showToast(error.message || String(error), 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Trocar senha mestra';
  }
}

function exportBackup() {
  validateRecord(record);
  const pretty = JSON.stringify(record, null, 2);
  const stamp = new Date().toISOString().slice(0, 10);
  downloadBlob(new Blob([pretty], { type: 'application/json' }), `MeuCofre-${stamp}.mcvault`);
  showToast('Backup criptografado exportado.', 'success');
}

async function importBackupFile(file, fromUnlockedApp) {
  if (!file) return;
  try {
    const parsed = JSON.parse(await file.text());
    validateRecord(parsed);
    if (!confirm('Restaurar este backup substituirá o cofre armazenado neste aparelho. Continuar?')) return;
    record = parsed;
    await putVaultRecord(record);
    clearSessionMemory();
    renderUnlockMethods();
    setPublicScreen('unlock');
    showToast('Backup restaurado. Desbloqueie com a senha ou autenticador correspondente.', 'success');
  } catch (error) {
    showToast(`Backup inválido: ${error.message || error}`, 'error');
  } finally {
    if (fromUnlockedApp) $('restore-backup-file').value = '';
    $('setup-import-file').value = '';
    $('unlock-import-file').value = '';
  }
}

function renderSettings() {
  if (!session) return;
  $('setting-idle').value = clampInt(session.vault.settings?.idleLockMinutes, 1, 120, 5);
  $('setting-background').value = clampInt(session.vault.settings?.backgroundLockSeconds, 0, 300, 30);
  $('setting-clipboard').value = clampInt(session.vault.settings?.clipboardClearSeconds, 0, 300, 30);
}

async function saveSettings() {
  if (!session) return;
  session.vault.settings = {
    ...session.vault.settings,
    idleLockMinutes: clampInt($('setting-idle').value, 1, 120, 5),
    backgroundLockSeconds: clampInt($('setting-background').value, 0, 300, 30),
    clipboardClearSeconds: clampInt($('setting-clipboard').value, 0, 300, 30)
  };
  await persistVault();
  showToast('Configurações salvas.', 'success');
}

async function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  try {
    const registration = await navigator.serviceWorker.register('./sw.js', { scope: './' });
    if (registration.waiting && navigator.serviceWorker.controller) showUpdate(registration.waiting);
    registration.addEventListener('updatefound', () => {
      const worker = registration.installing;
      if (!worker) return;
      worker.addEventListener('statechange', () => {
        if (worker.state === 'installed' && navigator.serviceWorker.controller) showUpdate(worker);
      });
    });
    navigator.serviceWorker.addEventListener('controllerchange', () => location.reload());
  } catch (error) {
    console.warn('Service Worker indisponível:', error);
  }
}

function showUpdate(worker) {
  waitingWorker = worker;
  $('update-banner').hidden = false;
}

init().catch((error) => {
  console.error(error);
  document.body.textContent = `Falha ao iniciar Meu Cofre: ${error.message || error}`;
});
