import { getVaultRecord, putVaultRecord } from './storage.js';
import {
  FORMAT as LEGACY_FORMAT,
  getUnlockPolicy as legacyGetUnlockPolicy,
  saveRecord as legacySaveRecord,
  UNLOCK_POLICIES as LEGACY_POLICIES,
  unlockPassword as legacyUnlockPassword,
  unlockPasswordPrf as legacyUnlockPasswordPrf,
  unlockPrf as legacyUnlockPrf,
  validateRecord as validateLegacyRecord
} from './legacy-vault.js';
import {
  addPrfSlotToKdbx,
  changeKdbxMasterPassword,
  createKdbxRecord,
  defaultKdbxVault,
  exportRecoveryKeyBytes,
  inspectKdbx,
  isKdbxRecord,
  makeStoredRecord,
  migrateLegacyVaultData,
  openStoredKdbxGeneric,
  openStoredKdbxWithPassword,
  openStoredKdbxWithPrf,
  openStoredKdbxWithRecoveryKey,
  PROTECTION_MODES,
  removePrfSlotFromKdbx,
  saveStoredKdbx,
  storedRecordBytes
} from './kdbx.js';
import { evaluatePrf, platformAuthenticatorAvailable, registerPrfCredential } from './webauthn.js';
import { generatePassword } from './generator.js';
import { totp } from './totp.js';
import { base64ToBytes, bytesToBase64, clampInt, downloadBlob, formatDateTime, safeHttpUrl, uuid, wipe } from './utils.js';

const APP_VERSION = '1.0.0';
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

function isLegacyRecord(value) { return value?.format === LEGACY_FORMAT; }
function isLegacySession() { return session?.kind === 'legacy'; }
function isKdbxSession() { return session?.kind === 'kdbx'; }

function showToast(message, type = '') {
  const el = $('toast'); el.textContent = message; el.className = `toast ${type}`; el.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 4200);
}
function setPublicScreen(name) {
  for (const id of ['setup','unlock','app']) $(`screen-${id}`).hidden = id !== name;
  $('public-brand').hidden = name === 'app';
}
function clearSecretInputs() {
  document.querySelectorAll('input[type="password"]').forEach((el) => { el.value = ''; });
}
function modeLabel(mode) {
  return ({password:'Senha mestra',yubikey:'YubiKey', 'password-yubikey':'Senha + YubiKey'})[mode] || 'KDBX externo';
}
function requireStrongEnough(password) {
  if (String(password).length < 12) throw new Error('Use pelo menos 12 caracteres na senha mestra. Uma frase longa é recomendada.');
}

async function init() {
  if (window.top !== window.self) throw new Error('Por segurança, Meu Cofre não funciona dentro de frames. Abra o endereço diretamente.');
  if (!window.isSecureContext) throw new Error('Meu Cofre exige HTTPS/contexto seguro.');
  bindEvents();
  $('public-version').textContent = `v${APP_VERSION}`;
  record = await getVaultRecord();
  if (!record) setPublicScreen('setup');
  else {
    if (!isLegacyRecord(record) && !isKdbxRecord(record)) throw new Error('Formato local desconhecido. Restaure um backup válido.');
    renderUnlockMethods(); setPublicScreen('unlock');
  }
  generateNewPassword();
  await updatePersistentStatus();
  registerServiceWorker();
}

function bindEvents() {
  $('setup-mode').addEventListener('change', renderSetupMode);
  $('setup-create').addEventListener('click', createVaultFromSetup);
  $('setup-import-kdbx').addEventListener('click', () => $('setup-import-kdbx-file').click());
  $('setup-import-kdbx-file').addEventListener('change', (e) => importKdbxFile(e.target.files?.[0], false));
  $('setup-import-legacy').addEventListener('click', () => $('setup-import-legacy-file').click());
  $('setup-import-legacy-file').addEventListener('change', (e) => importLegacyBackup(e.target.files?.[0]));
  $('unlock-password-btn').addEventListener('click', unlockWithPassword);
  $('unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') unlockWithPassword(); });
  $('unlock-2fa-password').addEventListener('keydown', e => { if (e.key === 'Enter') $('unlock-twofactor-buttons').querySelector('button')?.click(); });
  $('choose-recovery-key').addEventListener('click', () => $('unlock-recovery-key-file').click());
  $('unlock-recovery-key-file').addEventListener('change', e => unlockWithRecoveryFile(e.target.files?.[0]));
  $('unlock-import-kdbx').addEventListener('click', () => $('unlock-import-kdbx-file').click());
  $('unlock-import-kdbx-file').addEventListener('change', e => importKdbxFile(e.target.files?.[0], true));
  $('lock-btn').addEventListener('click', () => lockVault('Cofre bloqueado.'));
  $('search').addEventListener('input', renderEntries);
  $('add-entry').addEventListener('click', () => openEntryModal());
  $('entry-close').addEventListener('click', closeEntryModal);
  $('entry-modal').addEventListener('click', e => { if (e.target === $('entry-modal')) closeEntryModal(); });
  $('entry-form').addEventListener('submit', saveEntryFromForm);
  $('entry-delete').addEventListener('click', deleteCurrentEntry);
  $('entry-show-password').addEventListener('click', toggleEntryPassword);
  $('entry-generate-password').addEventListener('click', () => { $('entry-password').value = generatePassword({ length: 28 }); });
  $('entry-copy-user').addEventListener('click', () => copyText($('entry-username').value, 'Usuário copiado.'));
  $('entry-copy-pass').addEventListener('click', () => copyText($('entry-password').value, 'Senha copiada.'));
  $('entry-open-url').addEventListener('click', openCurrentUrl);
  $('entry-copy-totp').addEventListener('click', () => copyText($('entry-totp-code').textContent, 'Código TOTP copiado.'));
  $('entry-totp').addEventListener('input', updateTotpBox);
  document.querySelectorAll('[data-nav]').forEach(b => b.addEventListener('click', () => navigate(b.dataset.nav)));
  ['gen-length','gen-lower','gen-upper','gen-digits','gen-symbols'].forEach(id => $(id).addEventListener('change', generateNewPassword));
  $('generate-btn').addEventListener('click', generateNewPassword); $('copy-generated').addEventListener('click', () => copyText($('generated-password').textContent, 'Senha gerada copiada.'));
  $('add-yubikey').addEventListener('click', () => addWebAuthnMethod('security-key'));
  $('add-passkey').addEventListener('click', () => addWebAuthnMethod('platform'));
  $('export-recovery-key').addEventListener('click', exportRecoveryKey);
  $('change-master').addEventListener('click', changeMaster);
  $('export-kdbx').addEventListener('click', exportKdbx);
  $('restore-kdbx').addEventListener('click', () => $('restore-kdbx-file').click());
  $('restore-kdbx-file').addEventListener('change', e => importKdbxFile(e.target.files?.[0], true));
  $('migration-mode').addEventListener('change', renderMigrationMode);
  $('migrate-kdbx').addEventListener('click', migrateLegacyToKdbx);
  $('save-settings').addEventListener('click', saveSettings);
  $('request-persistent').addEventListener('click', requestPersistentStorage);
  $('apply-update').addEventListener('click', () => waitingWorker?.postMessage({type:'SKIP_WAITING'}));
  $('dismiss-update').addEventListener('click', () => { $('update-banner').hidden = true; });
  ['pointerdown','keydown','touchstart'].forEach(n => window.addEventListener(n, resetIdleTimer, {passive:true}));
  document.addEventListener('visibilitychange', handleVisibility);
  window.addEventListener('pagehide', clearSessionMemory);
  renderSetupMode(); renderMigrationMode();
}

function renderSetupMode() {
  const mode = $('setup-mode').value;
  $('setup-password-fields').hidden = mode === PROTECTION_MODES.YUBIKEY;
  $('setup-yubikey-note').hidden = mode === PROTECTION_MODES.PASSWORD;
}
function renderMigrationMode() {
  const mode = $('migration-mode').value;
  $('migration-password-fields').hidden = mode === PROTECTION_MODES.YUBIKEY;
  $('migration-key-label').hidden = mode === PROTECTION_MODES.PASSWORD;
}

async function createVaultFromSetup() {
  const mode = $('setup-mode').value, name = $('setup-name').value.trim() || 'Meu Cofre';
  const password = $('setup-password').value, repeat = $('setup-password2').value;
  if (mode !== PROTECTION_MODES.YUBIKEY) { try { requireStrongEnough(password); } catch(e){ return showToast(e.message,'error'); } if (password !== repeat) return showToast('As senhas não coincidem.','error'); }
  const btn=$('setup-create');btn.disabled=true;btn.textContent='Preparando KDBX...';
  let secret=null, created=null;
  try {
    const vault=defaultKdbxVault(name); let registration=null, webauthnUserId=null;
    if (mode !== PROTECTION_MODES.PASSWORD) {
      webauthnUserId=bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
      btn.textContent='Aguardando YubiKey...';
      const reg=await registerPrfCredential({webauthnUserId},'security-key'); registration=reg.registration; secret=reg.prfSecret;
    }
    btn.textContent='Derivando chaves e criando KDBX...';
    created=await createKdbxRecord({vault,mode,password:mode===PROTECTION_MODES.YUBIKEY?null:password,registration,prfSecret:secret,webauthnUserId});
    record=created.record; await putVaultRecord(record);
    session={kind:'kdbx',vault:created.vault,components:created.components,publicMeta:created.publicMeta,kdbxInfo:created.kdbxInfo};
    clearSecretInputs(); enterApp();
    if (created.recoveryKey) { downloadRecoveryKey(created.recoveryKey); wipe(created.recoveryKey); showToast('Cofre criado. A chave de recuperação foi baixada: guarde-a separadamente.','success'); }
    else showToast('Cofre KDBX criado. Exporte um backup .kdbx.','success');
  } catch(e){ showToast(e.message||String(e),'error'); }
  finally { secret&&wipe(secret); btn.disabled=false;btn.textContent='Criar KDBX 4.1'; }
}

function getKdbxHeaderInfo() { try { return inspectKdbx(storedRecordBytes(record)); } catch { return null; } }

function renderUnlockMethods() {
  $('unlock-error').textContent=''; $('unlock-prf-buttons').replaceChildren(); $('unlock-twofactor-buttons').replaceChildren();
  $('unlock-password-area').hidden=true; $('unlock-twofactor-area').hidden=true; $('unlock-recovery').hidden=true;
  if (isLegacyRecord(record)) return renderLegacyUnlock();
  const info=getKdbxHeaderInfo(); const meta=info?.publicMeta||{}; const mode=meta.mode;
  $('unlock-subtitle').textContent='O KDBX é autenticado por HMAC antes da descriptografia.';
  if (!mode || mode===PROTECTION_MODES.PASSWORD) {
    $('unlock-password-area').hidden=false;
    $('unlock-policy-note').textContent=meta.schema ? 'KDBX 4.1 protegido por senha mestra. YubiKeys cadastradas podem ser usadas como desbloqueio alternativo.' : 'KDBX externo: tente a senha mestra. Se ele usar também um key file de 32 bytes, abra “Recuperação com arquivo de chave”. Argon2/cifradores ainda não suportados serão recusados sem alterar o original.';
    if(!meta.schema){$('unlock-recovery').hidden=false;$('recovery-password-label').hidden=false;}
    (meta.slots||[]).forEach(slot => appendKdbxPrfButton(slot,false));
  } else if (mode===PROTECTION_MODES.YUBIKEY) {
    $('unlock-policy-note').textContent='KDBX 4.1 protegido por um componente aleatório liberado pela YubiKey. A recuperação usa o arquivo .key de 32 bytes.';
    (meta.slots||[]).forEach(slot => appendKdbxPrfButton(slot,false)); $('unlock-recovery').hidden=false;
  } else {
    $('unlock-policy-note').textContent='KDBX 4.1 com dois componentes: senha mestra + chave liberada pela YubiKey. Ambos são necessários no acesso normal.';
    $('unlock-twofactor-area').hidden=false; (meta.slots||[]).forEach(slot => appendKdbxPrfButton(slot,true)); $('unlock-recovery').hidden=false; $('recovery-password-label').hidden=false;
  }
}

function appendKdbxPrfButton(slot,twoFactor) {
  const btn=document.createElement('button');btn.className=slot.kind==='security-key'?'btn':'btn secondary';
  const label=slot.label||(slot.kind==='platform'?'Este iPhone / chave de acesso':'YubiKey'); btn.textContent=twoFactor?`Senha + ${label}`:`Desbloquear com ${label}`;
  btn.addEventListener('click',()=>unlockKdbxPrf(slot,btn,twoFactor)); (twoFactor?$('unlock-twofactor-buttons'):$('unlock-prf-buttons')).append(btn);
}

function renderLegacyUnlock() {
  $('unlock-subtitle').textContent='Formato antigo .mcvault detectado. Desbloqueie para migrar para KDBX 4.1.';
  const policy=legacyGetUnlockPolicy(record); $('unlock-password-area').hidden=false;
  $('unlock-twofactor-area').hidden=policy!==LEGACY_POLICIES.PASSWORD_YUBIKEY;
  $('unlock-policy-note').textContent='Cofre legado: seus dados permanecem intactos até você concluir a migração KDBX.';
  for(const slot of record.slots||[]){
    if(slot.type==='webauthn-prf') {const b=document.createElement('button');b.className='btn';b.textContent=`Desbloquear com ${slot.label||'YubiKey'}`;b.addEventListener('click',()=>unlockLegacyPrf(slot,b,false));$('unlock-prf-buttons').append(b);}
    if(slot.type==='password-webauthn-prf') {const b=document.createElement('button');b.className='btn';b.textContent=slot.label||'Senha + YubiKey';b.addEventListener('click',()=>unlockLegacyPrf(slot,b,true));$('unlock-twofactor-buttons').append(b);}
  }
  if(policy!==LEGACY_POLICIES.ANY) $('unlock-password-btn').textContent='Usar senha mestra de recuperação';
  else $('unlock-password-btn').textContent='Desbloquear com senha';
}

async function unlockWithPassword() {
  const password=$('unlock-password').value;if(!password)return;const btn=$('unlock-password-btn');btn.disabled=true;btn.textContent='Desbloqueando...';
  try {
    if(isLegacyRecord(record)){const u=await legacyUnlockPassword(record,password);session={kind:'legacy',vault:u.vault,vaultKey:u.vaultKey};}
    else {const u=await openStoredKdbxWithPassword(record,password);session={kind:'kdbx',vault:u.vault,components:u.components,publicMeta:u.publicMeta,kdbxInfo:u.info};}
    $('unlock-password').value='';enterApp();
  } catch(e){$('unlock-error').textContent=e.message||String(e);} finally{btn.disabled=false;btn.textContent='Desbloquear com senha';}
}

async function unlockKdbxPrf(slot,button,twoFactor) {
  const password=twoFactor?$('unlock-2fa-password').value:null;if(twoFactor&&!password){$('unlock-error').textContent='Digite a senha mestra.';return;}
  button.disabled=true;const old=button.textContent;button.textContent='Aguardando autenticação...';let secret=null;
  try{secret=await evaluatePrf(slot);const u=await openStoredKdbxWithPrf(record,slot,secret,password);session={kind:'kdbx',vault:u.vault,components:u.components,publicMeta:u.publicMeta,kdbxInfo:u.info};clearSecretInputs();enterApp();}
  catch(e){$('unlock-error').textContent=e.message||String(e);}finally{secret&&wipe(secret);button.disabled=false;button.textContent=old;}
}

async function unlockLegacyPrf(slot,button,twoFactor) {
  const password=twoFactor?$('unlock-2fa-password').value:null;if(twoFactor&&!password){$('unlock-error').textContent='Digite a senha mestra.';return;}
  button.disabled=true;const old=button.textContent;button.textContent='Aguardando YubiKey...';let secret=null;
  try{secret=await evaluatePrf(slot);const u=twoFactor?await legacyUnlockPasswordPrf(record,slot,password,secret):await legacyUnlockPrf(record,slot,secret);session={kind:'legacy',vault:u.vault,vaultKey:u.vaultKey};clearSecretInputs();enterApp();}
  catch(e){$('unlock-error').textContent=e.message||String(e);}finally{secret&&wipe(secret);button.disabled=false;button.textContent=old;}
}

async function unlockWithRecoveryFile(file){
  if(!file||!isKdbxRecord(record))return;let bytes=null;try{bytes=new Uint8Array(await file.arrayBuffer());if(bytes.length!==32)throw new Error('A chave de recuperação/key file deve ter exatamente 32 bytes nesta versão.');const pass=$('unlock-recovery-password').value||null;const header=getKdbxHeaderInfo();const u=header?.publicMeta?.schema?await openStoredKdbxWithRecoveryKey(record,bytes,pass):await openStoredKdbxGeneric(record,pass,bytes);session={kind:'kdbx',vault:u.vault,components:u.components,publicMeta:u.publicMeta,kdbxInfo:u.info};clearSecretInputs();enterApp();showToast('Cofre aberto pela recuperação/key file.','success');}catch(e){$('unlock-error').textContent=e.message||String(e);}finally{bytes&&wipe(bytes);$('unlock-recovery-key-file').value='';}
}

function enterApp(){setPublicScreen('app');$('app-vault-name').textContent=session.vault.name||'Meu Cofre';$('search').value='';renderEntries();renderSecurity();renderSettings();navigate('vault');resetIdleTimer();}
function clearSessionMemory(){if(session?.vaultKey)wipe(session.vaultKey);for(const c of session?.components||[])wipe(c);session=null;editingId=null;clearTimeout(idleTimer);clearTimeout(backgroundTimer);clearTimeout(clipboardTimer);stopTotpTimer();clearSecretInputs();}
function lockVault(message){clearSessionMemory();closeEntryModal();renderUnlockMethods();setPublicScreen('unlock');if(message)showToast(message);}
function resetIdleTimer(){if(!session)return;clearTimeout(idleTimer);const m=clampInt(session.vault.settings?.idleLockMinutes,1,120,5);idleTimer=setTimeout(()=>lockVault('Bloqueado por inatividade.'),m*60000);}
function handleVisibility(){if(!session)return;clearTimeout(backgroundTimer);if(document.hidden){const s=clampInt(session.vault.settings?.backgroundLockSeconds,0,300,0);if(s===0)lockVault('Bloqueado ao sair do aplicativo.');else backgroundTimer=setTimeout(()=>lockVault('Bloqueado em segundo plano.'),s*1000);}}
function navigate(view){document.querySelectorAll('.view').forEach(el=>el.classList.toggle('active',el.dataset.view===view));document.querySelectorAll('[data-nav]').forEach(el=>el.classList.toggle('active',el.dataset.nav===view));if(view==='security')renderSecurity();if(view==='settings')renderSettings();$('app-scroll').scrollTop=0;}

function entryMatches(e,t){if(!t)return true;return[e.title,e.username,e.url,...(e.tags||[])].join(' ').toLocaleLowerCase('pt-BR').includes(t);}
function renderEntries(){if(!session)return;const list=$('entry-list');list.replaceChildren();const term=$('search').value.trim().toLocaleLowerCase('pt-BR');const entries=[...session.vault.entries].filter(e=>entryMatches(e,term)).sort((a,b)=>Number(!!b.favorite)-Number(!!a.favorite)||String(a.title).localeCompare(String(b.title),'pt-BR'));$('app-count').textContent=`${session.vault.entries.length} ${session.vault.entries.length===1?'item':'itens'}`;if(!entries.length){const d=document.createElement('div');d.className='empty';d.textContent=term?'Nenhum item encontrado.':'Seu cofre está vazio. Toque em + para adicionar a primeira senha.';list.append(d);return;}for(const e of entries){const item=document.createElement('button');item.type='button';item.className='entry';item.addEventListener('click',()=>openEntryModal(e.id));const ic=document.createElement('div');ic.className='entry-icon';ic.textContent=(e.title||'?').trim().slice(0,1).toUpperCase();const main=document.createElement('div');const title=document.createElement('div');title.className='entry-title';title.textContent=e.title||'Sem título';const meta=document.createElement('div');meta.className='entry-meta';meta.textContent=e.username||e.url||(e.tags||[]).join(', ')||'Credencial';main.append(title,meta);const fav=document.createElement('div');fav.className='favorite';fav.textContent=e.favorite?'★':'';item.append(ic,main,fav);list.append(item);}}
function openEntryModal(id=null){if(!session)return;editingId=id;const e=id?session.vault.entries.find(x=>x.id===id):null;$('entry-modal-title').textContent=e?'Editar item':'Novo item';$('entry-id').value=e?.id||'';$('entry-title').value=e?.title||'';$('entry-username').value=e?.username||'';$('entry-password').value=e?.password||'';$('entry-password').type='password';$('entry-show-password').textContent='Mostrar';$('entry-url').value=e?.url||'';$('entry-tags').value=(e?.tags||[]).join(', ');$('entry-totp').value=e?.totpSecret||'';$('entry-notes').value=e?.notes||'';$('entry-favorite').checked=!!e?.favorite;$('entry-delete').hidden=!e;$('entry-quick-actions').hidden=!e;$('entry-modal').hidden=false;updateTotpBox();setTimeout(()=>$('entry-title').focus(),80);}
function closeEntryModal(){if(!$('entry-modal'))return;$('entry-modal').hidden=true;editingId=null;stopTotpTimer();$('entry-form').reset();$('entry-totp-box').hidden=true;}
async function saveEntryFromForm(event){event.preventDefault();if(!session)return;const title=$('entry-title').value.trim();if(!title)return showToast('Informe um título.','error');const now=new Date().toISOString(),existing=editingId?session.vault.entries.find(e=>e.id===editingId):null;const e={id:existing?.id||uuid(),kdbxUuidBytes:existing?.kdbxUuidBytes,title,username:$('entry-username').value,password:$('entry-password').value,url:$('entry-url').value.trim(),tags:$('entry-tags').value.split(',').map(x=>x.trim()).filter(Boolean).slice(0,30),totpSecret:$('entry-totp').value.trim().replace(/\s+/g,''),notes:$('entry-notes').value,favorite:$('entry-favorite').checked,createdAt:existing?.createdAt||now,updatedAt:now};if(existing)Object.assign(existing,e);else session.vault.entries.push(e);try{await persistVault();closeEntryModal();renderEntries();showToast('Item salvo no cofre criptografado.','success');}catch(err){showToast(err.message||String(err),'error');}}
async function deleteCurrentEntry(){if(!session||!editingId)return;const e=session.vault.entries.find(x=>x.id===editingId);if(!confirm(`Excluir “${e?.title||'este item'}”?`))return;session.vault.entries=session.vault.entries.filter(x=>x.id!==editingId);await persistVault();closeEntryModal();renderEntries();showToast('Item excluído.');}
function toggleEntryPassword(){const i=$('entry-password');i.type=i.type==='password'?'text':'password';$('entry-show-password').textContent=i.type==='password'?'Mostrar':'Ocultar';}
function openCurrentUrl(){const url=safeHttpUrl($('entry-url').value);if(!url)return showToast('URL inválida ou não permitida.','error');window.open(url.href,'_blank','noopener,noreferrer');}

async function persistVault(){if(!session)return;session.vault.updatedAt=new Date().toISOString();if(isLegacySession())record=await legacySaveRecord(record,session.vaultKey,session.vault);else record=await saveStoredKdbx(record,session.vault,session.components,session.publicMeta,session.kdbxInfo?.rounds);await putVaultRecord(record);}

async function copyText(value,message){if(!value)return;try{await navigator.clipboard.writeText(value);showToast(message,'success');clearTimeout(clipboardTimer);const sec=clampInt(session?.vault.settings?.clipboardClearSeconds,0,300,20);if(sec>0)clipboardTimer=setTimeout(async()=>{try{const current=await navigator.clipboard.readText();if(current===value)await navigator.clipboard.writeText('');}catch{}},sec*1000);}catch{showToast('Não foi possível copiar para a área de transferência.','error');}}
function generateNewPassword(){try{$('generated-password').textContent=generatePassword({length:clampInt($('gen-length').value,8,128,24),lower:$('gen-lower').checked,upper:$('gen-upper').checked,digits:$('gen-digits').checked,symbols:$('gen-symbols').checked});}catch(e){showToast(e.message,'error');}}
function stopTotpTimer(){clearInterval(totpTimer);totpTimer=null;}
async function updateTotpBox(){stopTotpTimer();const secret=$('entry-totp').value.trim();if(!secret){$('entry-totp-box').hidden=true;return;}$('entry-totp-box').hidden=false;const refresh=async()=>{try{const r=await totp(secret);$('entry-totp-code').textContent=r.code;$('entry-totp-remaining').textContent=`${r.remaining}s`;}catch{$('entry-totp-code').textContent='inválido';$('entry-totp-remaining').textContent='';}};await refresh();totpTimer=setInterval(refresh,1000);}

async function renderSecurity(){if(!session)return;const legacy=isLegacySession();$('legacy-migration-section').hidden=!legacy;$('kdbx-summary').replaceChildren();$('auth-slots').replaceChildren();$('recovery-key-section').hidden=true;$('change-password-section').hidden=true;
  if(legacy){renderLegacyMigrationChoices();const row=document.createElement('div');row.className='security-note';row.textContent='Formato legado AES-GCM/PBKDF2. Exporte o backup antigo e migre para KDBX 4.1.';$('kdbx-summary').append(row);renderLegacySlots();}
  else {renderKdbxSummary();renderKdbxSlots();const mode=session.publicMeta.mode;$('recovery-key-section').hidden=mode===PROTECTION_MODES.PASSWORD;$('change-password-section').hidden=mode===PROTECTION_MODES.YUBIKEY;}
  await renderDiagnostics();$('backup-status').textContent=isKdbxSession()?'O arquivo .kdbx contém o cofre cifrado e autenticado. Exporte após mudanças importantes.':'Migre primeiro para KDBX 4.1.';
}
function renderKdbxSummary(){const data=[['Formato','KDBX 4.1'],['Proteção',modeLabel(session.publicMeta.mode)],['Cifrador',session.kdbxInfo?.cipher||'AES-256-CBC'],['KDF',`${session.kdbxInfo?.kdf||'AES-KDF'} · ${(session.kdbxInfo?.rounds||0).toLocaleString('pt-BR')} rodadas`],['Compressão',session.kdbxInfo?.compression||'Nenhuma']];for(const [a,b] of data){const r=document.createElement('div');r.className='row';const m=document.createElement('div');m.className='row-main';const t=document.createElement('div');t.className='row-title';t.textContent=a;const s=document.createElement('div');s.className='row-sub';s.textContent=b;m.append(t,s);r.append(m);$('kdbx-summary').append(r);}}
function renderKdbxSlots(){const slots=session.publicMeta.slots||[];if(!slots.length){const d=document.createElement('div');d.className='empty';d.textContent=session.publicMeta.mode===PROTECTION_MODES.PASSWORD?'Nenhuma YubiKey cadastrada.':'Nenhuma chave cadastrada — use a chave de recuperação antes de bloquear.';$('auth-slots').append(d);return;}for(const slot of slots){const r=document.createElement('div');r.className='row';const m=document.createElement('div');m.className='row-main';const t=document.createElement('div');t.className='row-title';t.textContent=slot.label||(slot.kind==='platform'?'Este iPhone':'YubiKey');const s=document.createElement('div');s.className='row-sub';s.textContent=`WebAuthn PRF/HKDF · ${formatDateTime(slot.createdAt)} · ${slot.role==='keyfile'?'componente de chave':'componente de senha'}`;m.append(t,s);const pill=document.createElement('span');pill.className='pill ok';pill.textContent=slot.kind==='platform'?'Passkey':'YubiKey';const remove=document.createElement('button');remove.className='btn danger small';remove.textContent='Remover';remove.addEventListener('click',()=>removeKdbxSlot(slot.id));r.append(m,pill,remove);$('auth-slots').append(r);}}
function renderLegacySlots(){for(const slot of record.slots||[]){if(slot.type==='password')continue;const r=document.createElement('div');r.className='row';const m=document.createElement('div');m.className='row-main';const t=document.createElement('div');t.className='row-title';t.textContent=slot.label||'YubiKey';const s=document.createElement('div');s.className='row-sub';s.textContent='Credencial legada; pode ser reutilizada durante a migração.';m.append(t,s);r.append(m);$('auth-slots').append(r);}}
function renderLegacyMigrationChoices(){const select=$('migration-yubikey');select.replaceChildren();const seen=new Set();for(const slot of record.slots||[]){if(slot.kind!=='security-key'||!slot.credentialId||seen.has(slot.credentialId))continue;seen.add(slot.credentialId);const o=document.createElement('option');o.value=slot.id;o.textContent=slot.label||'YubiKey';select.append(o);}if(!select.options.length){const o=document.createElement('option');o.value='';o.textContent='Nenhuma YubiKey legada disponível';select.append(o);}renderMigrationMode();}

async function renderDiagnostics(){const box=$('security-diagnostics');box.replaceChildren();let persisted=false;try{persisted=await navigator.storage?.persisted?.();}catch{}const items=[['HTTPS / contexto seguro',window.isSecureContext],['WebCrypto',!!crypto?.subtle],['WebAuthn',!!(window.PublicKeyCredential&&navigator.credentials)],['Service Worker / offline','serviceWorker'in navigator],['Armazenamento persistente concedido',!!persisted],['App instalado',matchMedia('(display-mode: standalone)').matches||navigator.standalone===true],['Autenticador do dispositivo',await platformAuthenticatorAvailable()]];for(const [label,ok] of items){const r=document.createElement('div');r.className='row';const t=document.createElement('div');t.className='row-title';t.textContent=label;const p=document.createElement('span');p.className=`pill ${ok?'ok':'bad'}`;p.textContent=ok?'OK':'Não';r.append(t,p);box.append(r);}}

async function addWebAuthnMethod(kind){if(!isKdbxSession())return showToast('Migre primeiro para KDBX 4.1.','error');const pseudo={webauthnUserId:session.publicMeta.webauthnUserId};let secret=null;try{const reg=await registerPrfCredential(pseudo,kind);secret=reg.prfSecret;const result=await addPrfSlotToKdbx(record,session,reg.registration,secret);record=result.record;session.publicMeta=result.publicMeta;await putVaultRecord(record);renderSecurity();showToast(`${reg.registration.label} adicionada.`, 'success');}catch(e){showToast(e.message||String(e),'error');}finally{secret&&wipe(secret);}}
async function removeKdbxSlot(slotId){if(!confirm('Remover este método? Confirme que você possui outra YubiKey ou a chave de recuperação quando aplicável.'))return;try{const r=await removePrfSlotFromKdbx(record,session,slotId);record=r.record;session.publicMeta=r.publicMeta;await putVaultRecord(record);renderSecurity();showToast('Método removido.');}catch(e){showToast(e.message||String(e),'error');}}
function downloadRecoveryKey(bytes){downloadBlob(new Blob([bytes],{type:'application/octet-stream'}),`MeuCofre-Recovery-${new Date().toISOString().slice(0,10)}.key`);}
function exportRecoveryKey(){if(!isKdbxSession())return;try{const b=exportRecoveryKeyBytes(session);downloadRecoveryKey(b);wipe(b);showToast('Chave de recuperação exportada. Guarde-a separadamente.','success');}catch(e){showToast(e.message||String(e),'error');}}
async function changeMaster(){if(!isKdbxSession())return;const a=$('new-master').value,b=$('new-master2').value;try{requireStrongEnough(a);if(a!==b)throw new Error('As senhas não coincidem.');const r=await changeKdbxMasterPassword(record,session,a);for(const c of session.components||[])wipe(c);record=r.record;session.components=r.components;await putVaultRecord(record);clearSecretInputs();renderSecurity();showToast('Senha mestra alterada e KDBX recriptografado. Exporte um novo backup.','success');}catch(e){showToast(e.message||String(e),'error');}}
function exportKdbx(){if(!isKdbxRecord(record))return showToast('Migre primeiro para KDBX.','error');try{const b=storedRecordBytes(record);downloadBlob(new Blob([b],{type:'application/octet-stream'}),`MeuCofre-${new Date().toISOString().slice(0,10)}.kdbx`);wipe(b);showToast('KDBX exportado.','success');}catch(e){showToast(e.message||String(e),'error');}}

async function migrateLegacyToKdbx(){if(!isLegacySession())return;const mode=$('migration-mode').value;const password=$('migration-password').value,repeat=$('migration-password2').value;if(mode!==PROTECTION_MODES.YUBIKEY){try{requireStrongEnough(password);}catch(e){return showToast(e.message,'error');}if(password!==repeat)return showToast('As senhas não coincidem.','error');}
  const btn=$('migrate-kdbx');btn.disabled=true;btn.textContent='Preparando migração...';let secret=null,recovery=null;
  try{
    // Always export the legacy envelope before replacing IndexedDB.
    downloadBlob(new Blob([JSON.stringify(record,null,2)],{type:'application/json'}),`MeuCofre-ANTES-KDBX-${new Date().toISOString().slice(0,10)}.mcvault`);
    let registration=null,webauthnUserId=record.webauthnUserId||bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));
    if(mode!==PROTECTION_MODES.PASSWORD){const slotId=$('migration-yubikey').value;const slot=(record.slots||[]).find(s=>s.id===slotId);if(!slot)throw new Error('Selecione uma YubiKey existente ou cadastre uma na versão antiga antes da migração.');btn.textContent='Toque na YubiKey...';secret=await evaluatePrf(slot);registration={kind:'security-key',label:slot.label||'YubiKey / chave FIDO2',credentialId:slot.credentialId,transports:slot.transports||[],prfSalt:slot.prfSalt};}
    const vault=migrateLegacyVaultData(session.vault);btn.textContent='Gerando KDBX 4.1...';const created=await createKdbxRecord({vault,mode,password:mode===PROTECTION_MODES.YUBIKEY?null:password,registration,prfSecret:secret,webauthnUserId});recovery=created.recoveryKey;
    if(session.vaultKey)wipe(session.vaultKey);record=created.record;session={kind:'kdbx',vault:created.vault,components:created.components,publicMeta:created.publicMeta,kdbxInfo:created.kdbxInfo};await putVaultRecord(record);clearSecretInputs();renderSecurity();renderEntries();renderUnlockMethods();
    const k=storedRecordBytes(record);downloadBlob(new Blob([k],{type:'application/octet-stream'}),`MeuCofre-MIGRADO-${new Date().toISOString().slice(0,10)}.kdbx`);wipe(k);if(recovery){downloadRecoveryKey(recovery);wipe(recovery);recovery=null;}showToast('Migração concluída. Foram baixados o backup antigo e o novo KDBX; guarde-os até validar a abertura.','success');
  }catch(e){showToast(e.message||String(e),'error');}finally{secret&&wipe(secret);recovery&&wipe(recovery);btn.disabled=false;btn.textContent='Fazer backup antigo e migrar para KDBX';}}

async function importKdbxFile(file,replaceExisting){if(!file)return;try{const bytes=new Uint8Array(await file.arrayBuffer());const info=inspectKdbx(bytes);if(!confirm(`Importar KDBX ${info.version}, ${info.kdf}? ${replaceExisting?'Isso substituirá o cofre local atual.':''}`))return;record=makeStoredRecord(bytes);wipe(bytes);await putVaultRecord(record);clearSessionMemory();renderUnlockMethods();setPublicScreen('unlock');showToast('KDBX armazenado localmente. Desbloqueie para validar a chave.','success');}catch(e){showToast(`Não foi possível importar: ${e.message||e}`,'error');}finally{for(const id of ['setup-import-kdbx-file','unlock-import-kdbx-file','restore-kdbx-file'])if($(id))$(id).value='';}}
async function importLegacyBackup(file){if(!file)return;try{const parsed=JSON.parse(await file.text());validateLegacyRecord(parsed);if(!confirm('Restaurar o backup legado neste aparelho?'))return;record=parsed;await putVaultRecord(record);renderUnlockMethods();setPublicScreen('unlock');showToast('Backup legado restaurado. Desbloqueie e migre para KDBX.','success');}catch(e){showToast(`Backup legado inválido: ${e.message||e}`,'error');}finally{$('setup-import-legacy-file').value='';}}

function renderSettings(){if(!session)return;$('setting-idle').value=clampInt(session.vault.settings?.idleLockMinutes,1,120,5);$('setting-background').value=clampInt(session.vault.settings?.backgroundLockSeconds,0,300,0);$('setting-clipboard').value=clampInt(session.vault.settings?.clipboardClearSeconds,0,300,20);updatePersistentStatus();}
async function saveSettings(){if(!session)return;session.vault.settings={...session.vault.settings,idleLockMinutes:clampInt($('setting-idle').value,1,120,5),backgroundLockSeconds:clampInt($('setting-background').value,0,300,0),clipboardClearSeconds:clampInt($('setting-clipboard').value,0,300,20)};await persistVault();showToast('Configurações salvas.','success');}
async function updatePersistentStatus(){if(!$('persistent-status'))return;if(!navigator.storage?.persisted){$('persistent-status').textContent='API de persistência não disponível neste navegador.';return;}try{$('persistent-status').textContent=(await navigator.storage.persisted())?'Armazenamento persistente: concedido. Ainda mantenha backups KDBX.':'Persistência não garantida pelo navegador. Mantenha backups KDBX.';}catch{$('persistent-status').textContent='Não foi possível consultar a persistência.';}}
async function requestPersistentStorage(){try{const ok=await navigator.storage?.persist?.();await updatePersistentStatus();showToast(ok?'Persistência solicitada/concedida.':'O iOS decidiu não conceder persistência explícita. Backups continuam obrigatórios.',ok?'success':'');}catch(e){showToast(e.message||String(e),'error');}}

async function registerServiceWorker(){if(!('serviceWorker'in navigator))return;try{const r=await navigator.serviceWorker.register(`./sw.js?v=${APP_VERSION}`,{scope:'./',updateViaCache:'none'});const inspect=()=>{if(r.waiting&&navigator.serviceWorker.controller)showUpdate(r.waiting);};inspect();r.addEventListener('updatefound',()=>{const w=r.installing;if(!w)return;w.addEventListener('statechange',()=>{if(w.state==='installed'&&navigator.serviceWorker.controller)showUpdate(w);});});navigator.serviceWorker.addEventListener('controllerchange',()=>location.reload());r.update().catch(()=>{});setTimeout(()=>r.update().catch(()=>{}),1800);const check=async()=>{try{const res=await fetch(`./version.json?t=${Date.now()}`,{cache:'no-store'});if(!res.ok)return;const v=await res.json();if(v?.version&&v.version!==APP_VERSION){await r.update().catch(()=>{});inspect();}}catch{}};check();document.addEventListener('visibilitychange',()=>{if(!document.hidden)check();});}catch(e){console.warn('Service Worker indisponível:',e);}}
function showUpdate(worker){waitingWorker=worker;$('update-banner').hidden=false;}

init().catch(error=>{console.error(error);document.body.textContent=`Falha ao iniciar Meu Cofre: ${error.message||error}`;});
