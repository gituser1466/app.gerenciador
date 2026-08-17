import { getVaultRecord, putVaultRecord } from './storage.js';
import {
  changeMasterPassword,
  createPasswordPrfSlot,
  createPrfSlot,
  createRecord,
  getUnlockPolicy,
  removeSlot,
  saveRecord,
  setUnlockPolicy,
  UNLOCK_POLICIES,
  unlockPassword,
  unlockPasswordPrf,
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

const APP_VERSION = '0.2.1';
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
  $('unlock-recovery-password-btn').addEventListener('click', unlockWithRecoveryPassword);
  $('unlock-recovery-password').addEventListener('keydown', (event) => { if (event.key === 'Enter') unlockWithRecoveryPassword(); });
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
  $('save-unlock-policy').addEventListener('click', saveUnlockPolicy);
  $('create-twofactor').addEventListener('click', createTwoFactorMethod);
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

function authButtonLabel(slot) {
  if (slot.type === 'password-webauthn-prf') return slot.label || 'Senha + YubiKey';
  if (slot.kind === 'platform') return slot.label || 'Este iPhone / chave de acesso';
  return slot.label || 'YubiKey / chave FIDO2';
}

function appendPrfButton(container, slot, alternative = false) {
  const btn = document.createElement('button');
  btn.className = alternative ? 'btn ghost' : (slot.kind === 'security-key' ? 'btn' : 'btn secondary');
  btn.textContent = `Desbloquear com ${authButtonLabel(slot)}`;
  btn.addEventListener('click', () => unlockWithPrfSlot(slot, btn));
  container.append(btn);
}

function appendTwoFactorButton(container, slot) {
  const btn = document.createElement('button');
  btn.className = 'btn';
  btn.textContent = `Desbloquear com ${authButtonLabel(slot)}`;
  btn.addEventListener('click', () => unlockWithPasswordPrfSlot(slot, btn));
  container.append(btn);
}

function renderUnlockMethods() {
  const normal = $('unlock-prf-buttons');
  const alternatives = $('unlock-alternative-buttons');
  const twoFactor = $('unlock-twofactor-buttons');
  normal.replaceChildren();
  alternatives.replaceChildren();
  twoFactor.replaceChildren();

  const policy = getUnlockPolicy(record);
  $('unlock-any-area').hidden = policy === UNLOCK_POLICIES.PASSWORD_YUBIKEY;
  $('unlock-twofactor-area').hidden = policy !== UNLOCK_POLICIES.PASSWORD_YUBIKEY;
  $('unlock-password-area').hidden = policy === UNLOCK_POLICIES.YUBIKEY;
  $('unlock-recovery').hidden = policy === UNLOCK_POLICIES.ANY;

  if (policy === UNLOCK_POLICIES.ANY) {
    $('unlock-policy-note').textContent = 'Você pode abrir com a senha mestra, uma YubiKey cadastrada ou a chave de acesso deste iPhone.';
  } else if (policy === UNLOCK_POLICIES.YUBIKEY) {
    $('unlock-policy-note').textContent = 'Acesso normal pela YubiKey. A senha mestra fica disponível somente na área de recuperação.';
  } else {
    $('unlock-policy-note').textContent = 'Acesso normal exige a senha mestra e uma YubiKey. A senha de recuperação continua disponível em emergência.';
  }

  const standalone = (record?.slots || []).filter((slot) => slot.type === 'webauthn-prf');
  const combined = (record?.slots || []).filter((slot) => slot.type === 'password-webauthn-prf');

  if (policy === UNLOCK_POLICIES.ANY) {
    standalone.forEach((slot) => appendPrfButton(normal, slot));
  } else if (policy === UNLOCK_POLICIES.YUBIKEY) {
    standalone.filter((slot) => slot.kind === 'security-key').forEach((slot) => appendPrfButton(normal, slot));
    standalone.filter((slot) => slot.kind !== 'security-key').forEach((slot) => appendPrfButton(alternatives, slot, true));
  } else {
    combined.filter((slot) => slot.kind === 'security-key').forEach((slot) => appendTwoFactorButton(twoFactor, slot));
    standalone.forEach((slot) => appendPrfButton(alternatives, slot, true));
  }
}

async function unlockWithRecoveryPassword() {
  const password = $('unlock-recovery-password').value;
  if (!password) return;
  const btn = $('unlock-recovery-password-btn');
  btn.disabled = true;
  btn.textContent = 'Verificando recuperação...';
  $('unlock-error').textContent = '';
  try {
    session = await unlockPassword(record, password);
    $('unlock-recovery-password').value = '';
    enterApp();
    showToast('Cofre aberto pela recuperação com senha mestra.', 'success');
  } catch (error) {
    $('unlock-error').textContent = error.message || String(error);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Usar senha de recuperação';
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

async function unlockWithPasswordPrfSlot(slot, button) {
  const password = $('unlock-2fa-password').value;
  if (!password) {
    $('unlock-error').textContent = 'Digite a senha mestra antes de tocar na YubiKey.';
    return;
  }
  button.disabled = true;
  const original = button.textContent;
  button.textContent = 'Aguardando YubiKey...';
  $('unlock-error').textContent = '';
  try {
    const secret = await evaluatePrf(slot);
    try {
      session = await unlockPasswordPrf(record, slot, password, secret);
    } finally {
      wipe(secret);
    }
    $('unlock-2fa-password').value = '';
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
  ['unlock-password', 'unlock-recovery-password', 'unlock-2fa-password'].forEach((id) => { if ($(id)) $(id).value = ''; });
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
  const baseLabel = kind === 'platform' ? 'este iPhone / chave de acesso' : 'YubiKey / chave FIDO2';
  if (kind === 'platform' && record.slots.some((slot) => slot.type === 'webauthn-prf' && slot.kind === 'platform')) {
    return showToast('Este iPhone / chave de acesso já está cadastrado. Remova o método antigo antes de criar outro.', 'error');
  }
  if (!confirm(`Cadastrar ${baseLabel}? O método ficará vinculado ao domínio HTTPS atual. Mantenha a senha mestra e um backup criptografado.`)) return;
  const button = kind === 'platform' ? $('add-faceid') : $('add-yubikey');
  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'Aguardando autenticação...';
  try {
    let requestedLabel = 'Este iPhone / chave de acesso';
    if (kind === 'security-key') {
      const keyNumber = record.slots.filter((slot) => slot.type === 'webauthn-prf' && slot.kind === 'security-key').length + 1;
      const chosen = prompt('Nome para identificar esta chave:', `YubiKey ${keyNumber}`);
      requestedLabel = (chosen || '').trim().slice(0, 80) || `YubiKey ${keyNumber}`;
    }
    const { registration, prfSecret } = await registerPrfCredential(record, kind);
    registration.label = requestedLabel;
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
    showToast(`${registration.label} cadastrada com sucesso.`, 'success');
  } catch (error) {
    showToast(error.message || String(error), 'error');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function createTwoFactorMethod() {
  if (!session) return;
  const slotId = $('twofactor-yubikey-select').value;
  const password = $('twofactor-master-password').value;
  const source = record.slots.find((slot) => slot.id === slotId && slot.type === 'webauthn-prf' && slot.kind === 'security-key');
  if (!source) return showToast('Cadastre ou selecione uma YubiKey primeiro.', 'error');
  if (!password) return showToast('Informe a senha mestra atual.', 'error');
  if (record.slots.some((slot) => slot.type === 'password-webauthn-prf' && slot.credentialId === source.credentialId)) {
    return showToast('Já existe um método Senha + YubiKey para essa chave.', 'error');
  }
  const button = $('create-twofactor');
  button.disabled = true;
  button.textContent = 'Verificando senha...';
  let verified = null;
  try {
    verified = await unlockPassword(record, password);
    if (verified?.vaultKey) wipe(verified.vaultKey);
    verified = null;
    button.textContent = 'Aguardando YubiKey...';
    const secret = await evaluatePrf(source);
    try {
      const registration = {
        kind: source.kind,
        label: source.label || 'YubiKey',
        credentialId: source.credentialId,
        transports: source.transports || [],
        prfSalt: source.prfSalt
      };
      const combined = await createPasswordPrfSlot(record, session.vaultKey, registration, secret, password);
      let next = structuredClone(record);
      next.slots.push(combined);
      next.updatedAt = new Date().toISOString();
      next = setUnlockPolicy(next, UNLOCK_POLICIES.PASSWORD_YUBIKEY);
      record = next;
      await putVaultRecord(record);
    } finally {
      wipe(secret);
    }
    $('twofactor-master-password').value = '';
    renderSecurity();
    renderUnlockMethods();
    showToast('Senha + YubiKey ativado como acesso normal.', 'success');
  } catch (error) {
    if (verified?.vaultKey) wipe(verified.vaultKey);
    showToast(error.message || String(error), 'error');
  } finally {
    $('twofactor-master-password').value = '';
    button.disabled = false;
    button.textContent = 'Criar método de dois fatores';
  }
}

async function saveUnlockPolicy() {
  if (!session) return;
  const policy = $('unlock-policy-select').value;
  const names = {
    [UNLOCK_POLICIES.ANY]: 'Senha, YubiKey ou este iPhone',
    [UNLOCK_POLICIES.YUBIKEY]: 'YubiKey principal',
    [UNLOCK_POLICIES.PASSWORD_YUBIKEY]: 'Senha + YubiKey'
  };
  if (!confirm(`Aplicar o modo “${names[policy] || policy}”? A senha mestra continuará disponível como recuperação de emergência.`)) return;
  try {
    record = setUnlockPolicy(record, policy);
    await putVaultRecord(record);
    renderSecurity();
    renderUnlockMethods();
    showToast('Política de desbloqueio atualizada.', 'success');
  } catch (error) {
    showToast(error.message || String(error), 'error');
    renderSecurity();
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
    if (slot.type === 'password') title.textContent = 'Senha mestra';
    else title.textContent = slot.label || (slot.kind === 'platform' ? 'Este iPhone / chave de acesso' : 'YubiKey');
    const sub = document.createElement('div');
    sub.className = 'row-sub';
    if (slot.type === 'password') {
      sub.textContent = `PBKDF2-SHA-256 · ${Number(slot.kdf?.iterations || 0).toLocaleString('pt-BR')} iterações · recuperação`;
    } else if (slot.type === 'password-webauthn-prf') {
      sub.textContent = `Dois fatores criptográficos · PBKDF2 + WebAuthn PRF/HKDF · ${formatDateTime(slot.createdAt)}`;
    } else {
      sub.textContent = `WebAuthn PRF/HKDF · cadastrado em ${formatDateTime(slot.createdAt)}`;
    }
    main.append(title, sub);
    row.append(main);
    if (slot.type !== 'password') {
      const tag = document.createElement('span');
      tag.className = 'pill ok';
      tag.textContent = slot.type === 'password-webauthn-prf' ? '2 fatores' : (slot.kind === 'security-key' ? 'YubiKey' : 'iPhone');
      row.append(tag);
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

  $('unlock-policy-select').value = getUnlockPolicy(record);

  const twoFactorSelect = $('twofactor-yubikey-select');
  twoFactorSelect.replaceChildren();
  const used = new Set(record.slots.filter((slot) => slot.type === 'password-webauthn-prf').map((slot) => slot.credentialId));
  const keys = record.slots.filter((slot) => slot.type === 'webauthn-prf' && slot.kind === 'security-key' && !used.has(slot.credentialId));
  if (!keys.length) {
    const option = document.createElement('option');
    option.value = '';
    option.textContent = 'Nenhuma YubiKey disponível';
    twoFactorSelect.append(option);
    $('create-twofactor').disabled = true;
  } else {
    for (const slot of keys) {
      const option = document.createElement('option');
      option.value = slot.id;
      option.textContent = slot.label || 'YubiKey';
      twoFactorSelect.append(option);
    }
    $('create-twofactor').disabled = false;
  }

  const backup = $('backup-status');
  backup.textContent = record.lastBackupAt
    ? `Último backup registrado: ${formatDateTime(record.lastBackupAt)}.`
    : 'Nenhum backup exportado foi registrado nesta instalação.';

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

async function exportBackup() {
  try {
    validateRecord(record);
    const next = structuredClone(record);
    next.lastBackupAt = new Date().toISOString();
    record = next;
    await putVaultRecord(record);
    const pretty = JSON.stringify(record, null, 2);
    const stamp = new Date().toISOString().slice(0, 10);
    downloadBlob(new Blob([pretty], { type: 'application/json' }), `MeuCofre-${stamp}.mcvault`);
    renderSecurity();
    showToast('Backup criptografado exportado.', 'success');
  } catch (error) {
    showToast(`Falha ao exportar backup: ${error.message || error}`, 'error');
  }
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
    // updateViaCache:none is important on iOS/GitHub Pages: never reuse an HTTP-cached SW script.
    const registration = await navigator.serviceWorker.register(`./sw.js?v=${APP_VERSION}`, {
      scope: './',
      updateViaCache: 'none'
    });

    const inspectRegistration = () => {
      if (registration.waiting && navigator.serviceWorker.controller) showUpdate(registration.waiting);
    };
    inspectRegistration();

    registration.addEventListener('updatefound', () => {
      const worker = registration.installing;
      if (!worker) return;
      worker.addEventListener('statechange', () => {
        if (worker.state === 'installed' && navigator.serviceWorker.controller) showUpdate(worker);
      });
    });

    navigator.serviceWorker.addEventListener('controllerchange', () => location.reload());

    // Explicitly ask for a network update on launch. This avoids the long iOS SW refresh delay.
    registration.update().catch(() => {});
    setTimeout(() => registration.update().catch(() => {}), 1800);

    // Future releases publish version.json. Unique query prevents the current SW cache from hiding it.
    const checkRemoteVersion = async () => {
      try {
        const response = await fetch(`./version.json?t=${Date.now()}`, { cache: 'no-store' });
        if (!response.ok) return;
        const info = await response.json();
        if (info?.version && info.version !== APP_VERSION) {
          await registration.update().catch(() => {});
          inspectRegistration();
        }
      } catch (_) {
        // Offline is a supported state; no warning is necessary.
      }
    };
    checkRemoteVersion();
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) checkRemoteVersion();
    });
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
