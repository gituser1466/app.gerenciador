import { deleteVeraCryptFidoProfile, getVaultRecord, getVeraCryptFidoProfile, getVeraCryptLinkedProfiles, putVaultRecord, putVeraCryptFidoProfile, putVeraCryptLinkedProfiles } from './storage.js';
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
import { openVeraCryptFile } from './veracrypt.js';
import { openSupportedFileSystem } from './filesystem.js';
import { addSlot as addVeraCryptFidoSlot, createProfile as createVeraCryptFidoProfile, openRecoveryVault as openVeraCryptRecoveryVault, rawKeyfileBlob, recoveryFromFile, recoveryToBlob, unwrapSecretFromSlot, validateProfile as validateVeraCryptFidoProfile, wrapSecretForRegistration } from './veracrypt-fido.js';
import { addLinkedProfileSlot, buildCredentialBundle, changeRecoveryPassword as changeLinkedRecoveryPassword, createLinkedProfile, decryptBundle as decryptLinkedBundle, materializeBundleCredentials, profileFromFile as linkedProfileFromFile, profileToBlob as linkedProfileToBlob, removeLinkedProfileSlot, unwrapDekFromRecovery as unwrapLinkedDekFromRecovery, unwrapDekFromSlot as unwrapLinkedDekFromSlot, validateLinkedProfile, verifyContainerAgainstProfile, wipeMaterializedCredentials } from './veracrypt-linked.js';
import { base64ToBytes, bytesToBase64, clampInt, downloadBlob, formatDateTime, safeHttpUrl, uuid, wipe } from './utils.js';

const APP_VERSION = '1.4.0';
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
let vcSelectedFile = null;
let vcKeyfiles = [];
let vcVolume = null;
let vcFs = null;
let vcPath = [];
let vcDirectoryRequest = 0;
let vcFidoProfile = null;
let vcImportedRecovery = null;
let vcLinkedProfiles = [];
let vcLinkSelectedFile = null;
let vcLinkKeyfiles = [];
let vcLinkedPendingOpen = null;

function isLegacyRecord(value) { return value?.format === LEGACY_FORMAT; }
function isLegacySession() { return session?.kind === 'legacy'; }
function isKdbxSession() { return session?.kind === 'kdbx'; }

function showToast(message, type = '') {
  const el = $('toast'); el.textContent = message; el.className = `toast ${type}`; el.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 4200);
}
function setPublicScreen(name) {
  for (const id of ['home','setup','unlock','veracrypt','app']) $(`screen-${id}`).hidden = id !== name;
  $('public-brand').hidden = name === 'app' || name === 'veracrypt';
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
  vcFidoProfile = await getVeraCryptFidoProfile();
  if (vcFidoProfile) { try { validateVeraCryptFidoProfile(vcFidoProfile); } catch (e) { console.warn('Configuração VeraCrypt FIDO2 ignorada:', e); vcFidoProfile = null; } }
  vcLinkedProfiles = await getVeraCryptLinkedProfiles();
  vcLinkedProfiles = vcLinkedProfiles.filter((profile) => { try { validateLinkedProfile(profile); return true; } catch (e) { console.warn('Perfil VeraCrypt vinculado ignorado:', e); return false; } });
  renderVcLinkedProfiles();
  renderVcFido();
  if (record && !isLegacyRecord(record) && !isKdbxRecord(record)) throw new Error('Formato local desconhecido. Restaure um backup válido.');
  renderHome();
  setPublicScreen('home');
  generateNewPassword();
  await updatePersistentStatus();
  registerServiceWorker();
}

function bindEvents() {
  $('home-open-veracrypt').addEventListener('click', openVeraCryptFromHome);
  $('home-open-kdbx').addEventListener('click', openKdbxFromHome);
  $('vc-home-btn').addEventListener('click', returnToHome);
  $('setup-home-btn').addEventListener('click', returnToHome);
  $('unlock-home-btn').addEventListener('click', returnToHome);
  $('app-home-btn').addEventListener('click', returnToHome);
  $('open-veracrypt-from-app').addEventListener('click', openVeraCryptFromApp);
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
  $('vc-choose-file').addEventListener('click', () => $('vc-file').click());
  $('vc-file').addEventListener('change', e => selectVcFile(e.target.files?.[0] || null));
  $('vc-choose-keyfiles').addEventListener('click', () => $('vc-keyfiles').click());
  $('vc-keyfiles').addEventListener('change', e => selectVcKeyfiles([...(e.target.files || [])]));
  $('vc-open').addEventListener('click', openVcContainer);
  $('vc-password').addEventListener('keydown', e => { if (e.key === 'Enter') openVcContainer(); });
  $('vc-close').addEventListener('click', () => closeVeraCryptSession(true));
  $('vc-back').addEventListener('click', vcGoBack);
  $('vc-linked-new').addEventListener('click', () => showVcLinkWizard(true));
  $('vc-link-cancel').addEventListener('click', () => showVcLinkWizard(false));
  $('vc-link-choose-file').addEventListener('click', () => $('vc-link-file').click());
  $('vc-link-file').addEventListener('change', e => selectVcLinkFile(e.target.files?.[0] || null));
  $('vc-link-choose-keyfiles').addEventListener('click', () => $('vc-link-keyfiles').click());
  $('vc-link-keyfiles').addEventListener('change', e => selectVcLinkKeyfiles([...(e.target.files || [])]));
  $('vc-link-create').addEventListener('click', createVcLinkedProfileFromExisting);
  $('vc-linked-import').addEventListener('click', () => $('vc-linked-import-file').click());
  $('vc-linked-import-file').addEventListener('change', e => importVcLinkedProfile(e.target.files?.[0]));
  $('vc-linked-container-file').addEventListener('change', e => continueVcLinkedOpen(e.target.files?.[0] || null));
  $('vc-fido-create').addEventListener('click', createVcFidoConfiguration);
  $('vc-fido-open').addEventListener('click', openVcWithFido);
  $('vc-fido-add-key').addEventListener('click', addVcFidoKey);
  $('vc-fido-export-keyfile').addEventListener('click', exportVcFidoRawKeyfile);
  $('vc-fido-export-recovery').addEventListener('click', exportVcFidoRecovery);
  $('vc-fido-open-recovery').addEventListener('click', openVcWithRecovery);
  $('vc-fido-import-recovery').addEventListener('click', () => $('vc-fido-recovery-file').click());
  $('vc-fido-recovery-file').addEventListener('change', e => importVcRecovery(e.target.files?.[0]));
  $('vc-fido-restore-profile').addEventListener('click', restoreVcFidoProfileFromRecovery);
  $('vc-fido-reset').addEventListener('click', resetVcFidoConfiguration);
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
  renderSetupMode(); renderMigrationMode(); renderVcFido();
}

function renderHome() {
  const status = $('home-kdbx-status');
  if (status) {
    if (!record) status.textContent = 'Criar ou importar um KDBX';
    else if (isLegacyRecord(record)) status.textContent = 'Cofre legado encontrado · desbloquear e migrar';
    else status.textContent = 'KDBX local encontrado · desbloquear';
  }
  const vcStatus=$('home-vc-status');
  if(vcStatus)vcStatus.textContent=vcLinkedProfiles.length?`${vcLinkedProfiles.length} vault(s) vinculado(s) · abrir com YubiKey ou recovery`:'Abrir ou vincular um container VeraCrypt';
}
function openKdbxFromHome() {
  closeVeraCryptSession(true);
  clearSecretInputs();
  if (!record) setPublicScreen('setup');
  else { renderUnlockMethods(); setPublicScreen('unlock'); }
}
function openVeraCryptFromHome() {
  if (session) clearSessionMemory();
  clearSecretInputs();
  renderVcLinkedProfiles();
  renderVcFido();
  setPublicScreen('veracrypt');
  $('vc-standalone-scroll').scrollTop = 0;
}
function openVeraCryptFromApp() {
  clearSessionMemory();
  renderHome();
  renderVcLinkedProfiles();
  renderVcFido();
  setPublicScreen('veracrypt');
  $('vc-standalone-scroll').scrollTop = 0;
  showToast('KDBX bloqueado antes de abrir o Vault VeraCrypt.');
}
function returnToHome() {
  if (session) clearSessionMemory();
  else closeVeraCryptSession(true);
  clearSecretInputs();
  renderHome();
  setPublicScreen('home');
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
function clearSessionMemory(){closeVeraCryptSession(true);if(session?.vaultKey)wipe(session.vaultKey);for(const c of session?.components||[])wipe(c);session=null;editingId=null;clearTimeout(idleTimer);clearTimeout(backgroundTimer);clearTimeout(clipboardTimer);stopTotpTimer();clearSecretInputs();}
function lockVault(message){clearSessionMemory();closeEntryModal();renderUnlockMethods();setPublicScreen('unlock');if(message)showToast(message);}
function resetIdleTimer(){if(!session)return;clearTimeout(idleTimer);const m=clampInt(session.vault.settings?.idleLockMinutes,1,120,5);idleTimer=setTimeout(()=>lockVault('Bloqueado por inatividade.'),m*60000);}
function handleVisibility(){clearTimeout(backgroundTimer);if(document.hidden&&vcVolume&&!session){closeVeraCryptSession(false);return;}if(!session)return;if(document.hidden){const s=clampInt(session.vault.settings?.backgroundLockSeconds,0,300,0);if(s===0)lockVault('Bloqueado ao sair do aplicativo.');else backgroundTimer=setTimeout(()=>lockVault('Bloqueado em segundo plano.'),s*1000);}}
function navigate(view){document.querySelectorAll('.view').forEach(el=>el.classList.toggle('active',el.dataset.view===view));document.querySelectorAll('[data-nav]').forEach(el=>el.classList.toggle('active',el.dataset.nav===view));if(view==='security')renderSecurity();if(view==='settings')renderSettings();$('app-scroll').scrollTop=0;}

function entryMatches(e,t){if(!t)return true;return[e.title,e.username,e.url,...(e.tags||[])].join(' ').toLocaleLowerCase('pt-BR').includes(t);}
function renderEntries(){if(!session)return;const list=$('entry-list');list.replaceChildren();const term=$('search').value.trim().toLocaleLowerCase('pt-BR');const entries=[...session.vault.entries].filter(e=>entryMatches(e,term)).sort((a,b)=>Number(!!b.favorite)-Number(!!a.favorite)||String(a.title).localeCompare(String(b.title),'pt-BR'));$('app-count').textContent=`${session.vault.entries.length} ${session.vault.entries.length===1?'item':'itens'}`;if(!entries.length){const d=document.createElement('div');d.className='empty';d.textContent=term?'Nenhum item encontrado.':'Seu cofre está vazio. Toque em + para adicionar a primeira senha.';list.append(d);return;}for(const e of entries){const item=document.createElement('button');item.type='button';item.className='entry';item.addEventListener('click',()=>openEntryModal(e.id));const ic=document.createElement('div');ic.className='entry-icon';ic.textContent=(e.title||'?').trim().slice(0,1).toUpperCase();const main=document.createElement('div');const title=document.createElement('div');title.className='entry-title';title.textContent=e.title||'Sem título';const meta=document.createElement('div');meta.className='entry-meta';meta.textContent=e.username||e.url||(e.tags||[]).join(', ')||'Credencial';main.append(title,meta);const fav=document.createElement('div');fav.className='favorite';fav.textContent=e.favorite?'★':'';item.append(ic,main,fav);list.append(item);}}
function openEntryModal(id=null){if(!session)return;editingId=id;const e=id?session.vault.entries.find(x=>x.id===id):null;$('entry-modal-title').textContent=e?'Editar item':'Novo item';$('entry-id').value=e?.id||'';$('entry-title').value=e?.title||'';$('entry-username').value=e?.username||'';$('entry-password').value=e?.password||'';$('entry-password').type='password';$('entry-show-password').textContent='Mostrar';$('entry-url').value=e?.url||'';$('entry-tags').value=(e?.tags||[]).join(', ');$('entry-totp').value=e?.totpSecret||'';$('entry-notes').value=e?.notes||'';$('entry-favorite').checked=!!e?.favorite;$('entry-delete').hidden=!e;$('entry-quick-actions').hidden=!e;$('entry-modal').hidden=false;updateTotpBox();setTimeout(()=>$('entry-title').focus(),80);}
function closeEntryModal(){if(!$('entry-modal'))return;$('entry-modal').hidden=true;editingId=null;stopTotpTimer();$('entry-form').reset();$('entry-totp-box').hidden=true;}
async function saveEntryFromForm(event){event.preventDefault();if(!session)return;const title=$('entry-title').value.trim();if(!title)return showToast('Informe um título.','error');const now=new Date().toISOString(),existing=editingId?session.vault.entries.find(e=>e.id===editingId):null;const e={id:existing?.id||uuid(),kdbxUuidBytes:existing?.kdbxUuidBytes,title,username:$('entry-username').value,password:$('entry-password').value,url:$('entry-url').value.trim(),tags:$('entry-tags').value.split(',').map(x=>x.trim()).filter(Boolean).slice(0,30),totpSecret:$('entry-totp').value.trim().replace(/\s+/g,''),notes:$('entry-notes').value,favorite:$('entry-favorite').checked,createdAt:existing?.createdAt||now,updatedAt:now};if(existing)Object.assign(existing,e);else session.vault.entries.push(e);try{await persistVault();closeEntryModal();renderEntries();showToast('Item salvo no cofre criptografado.','success');}catch(err){showToast(err.message||String(err),'error');}}
async function deleteCurrentEntry(){if(!session||!editingId)return;const e=session.vault.entries.find(x=>x.id===editingId);if(!confirm(`Excluir “${e?.title||'este item'}”?`))return;session.vault.entries=session.vault.entries.filter(x=>x.id!==editingId);await persistVault();closeEntryModal();renderEntries();showToast('Item excluído.');}
function toggleEntryPassword(){const i=$('entry-password');i.type=i.type==='password'?'text':'password';$('entry-show-password').textContent=i.type==='password'?'Mostrar':'Ocultar';}
function openCurrentUrl(){const url=safeHttpUrl($('entry-url').value);if(!url)return showToast('URL inválida ou não permitida.','error');window.open(url.href,'_blank','noopener,noreferrer');}

function showVcLinkWizard(show){
  $('vc-link-wizard').hidden=!show;
  if(show){$('vc-link-name').focus();$('vc-standalone-scroll').scrollTo({top:0,behavior:'smooth'});}
  else resetVcLinkWizard();
}
function resetVcLinkWizard(){
  vcLinkSelectedFile=null;vcLinkKeyfiles=[];
  for(const id of ['vc-link-name','vc-link-password','vc-link-recovery','vc-link-recovery2'])if($(id))$(id).value='';
  if($('vc-link-pim'))$('vc-link-pim').value='0';if($('vc-link-kdf'))$('vc-link-kdf').value='auto';if($('vc-link-volume-type'))$('vc-link-volume-type').value='normal';
  if($('vc-link-file'))$('vc-link-file').value='';if($('vc-link-keyfiles'))$('vc-link-keyfiles').value='';
  if($('vc-link-file-info'))$('vc-link-file-info').textContent='Nenhum container selecionado.';
  if($('vc-link-keyfile-info'))$('vc-link-keyfile-info').textContent='Sem keyfiles.';
}
function selectVcLinkFile(file){
  vcLinkSelectedFile=file;
  $('vc-link-file-info').textContent=file?`${file.name} · ${formatVcBytes(file.size)}`:'Nenhum container selecionado.';
  if(file&&!$('vc-link-name').value.trim())$('vc-link-name').value=(file.name||'Vault VeraCrypt').replace(/\.(hc|tc|vc|veracrypt)$/i,'').slice(0,100);
}
function selectVcLinkKeyfiles(files){
  vcLinkKeyfiles=files.slice(0,32);
  $('vc-link-keyfile-info').textContent=vcLinkKeyfiles.length?`${vcLinkKeyfiles.length} keyfile(s): ${vcLinkKeyfiles.map(f=>f.name).join(', ')}`:'Sem keyfiles.';
}
async function persistVcLinkedProfiles(){await putVeraCryptLinkedProfiles(vcLinkedProfiles);renderVcLinkedProfiles();}
function getVcLinkedProfile(id){return vcLinkedProfiles.find(p=>p.id===id)||null;}
function vcLinkedStatus(profile){
  if(profile.slots.length<2)return ['Cadastre YubiKey 2','warn'];
  if(profile.slots.some(slot=>!slot.lastTestedAt))return ['Teste as YubiKeys','warn'];
  if(!profile.lastRecoveryTestedAt)return ['Teste recovery','warn'];
  return ['Pronto','ok'];
}
function appendText(el,tag,text,className=''){const n=document.createElement(tag);if(className)n.className=className;n.textContent=text;el.append(n);return n;}
function renderVcLinkedProfiles(){
  const list=$('vc-linked-list');if(!list)return;list.replaceChildren();
  $('vc-linked-count').textContent=`${vcLinkedProfiles.length} ${vcLinkedProfiles.length===1?'vault vinculado':'vaults vinculados'}`;
  if(!vcLinkedProfiles.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='Nenhum vault vinculado. Você pode usar um container já criado no VeraCrypt do Mac sem alterá-lo.';list.append(empty);return;}
  for(const profile of vcLinkedProfiles){
    const card=document.createElement('div');card.className='linked-profile-card';
    const head=document.createElement('div');head.className='linked-profile-head';
    const main=document.createElement('div');main.className='row-main';appendText(main,'div',profile.name,'row-title');appendText(main,'div',`${profile.container.name} · ${formatVcBytes(profile.container.size)} · ${profile.container.hidden?'oculto':'normal'} · ${profile.slots.length} YubiKey(s)`,'row-sub');
    const [st,cls]=vcLinkedStatus(profile);const pill=document.createElement('span');pill.className=`pill ${cls}`;pill.textContent=st;head.append(main,pill);card.append(head);
    const fp=document.createElement('div');fp.className='hint';fp.textContent=`Header: ${shortFingerprint(profile.container.headerFingerprint)}${profile.lastVerifiedAt?` · validado ${formatDateTime(profile.lastVerifiedAt)}`:''}`;card.append(fp);
    const slotLabel=document.createElement('label');slotLabel.textContent='YubiKey';const select=document.createElement('select');select.id=`vc-linked-slot-${profile.id}`;for(const slot of profile.slots){const o=document.createElement('option');o.value=slot.id;o.textContent=`${slot.label||'YubiKey FIDO2'}${slot.lastTestedAt?' ✓':''}`;select.append(o);}slotLabel.append(select);card.append(slotLabel);
    const actions=document.createElement('div');actions.className='actions';
    const open=document.createElement('button');open.className='btn';open.textContent='Abrir com YubiKey';open.addEventListener('click',()=>queueVcLinkedOpen(profile.id,'fido',select.value));
    const test=document.createElement('button');test.className='btn ghost';test.textContent='Testar YubiKey';test.addEventListener('click',()=>testVcLinkedFido(profile.id,select.value,test));
    const add=document.createElement('button');add.className='btn secondary';add.textContent='Adicionar YubiKey';add.disabled=profile.slots.length>=8;add.addEventListener('click',()=>addVcLinkedKey(profile.id,select.value,add));actions.append(open,test,add);card.append(actions);
    const exportBtn=document.createElement('button');exportBtn.className='btn secondary';exportBtn.textContent='Exportar perfil .vcprofile';exportBtn.addEventListener('click',()=>exportVcLinkedProfile(profile.id));card.append(exportBtn);
    const details=document.createElement('details');details.className='recovery-details';const summary=document.createElement('summary');summary.textContent='Recuperação e manutenção';details.append(summary);const body=document.createElement('div');body.className='recovery-body stack';
    const recLabel=document.createElement('label');recLabel.textContent='Senha de recuperação';const rec=document.createElement('input');rec.type='password';rec.autocomplete='current-password';rec.id=`vc-linked-recovery-${profile.id}`;recLabel.append(rec);body.append(recLabel);
    const recActions=document.createElement('div');recActions.className='actions';const recOpen=document.createElement('button');recOpen.className='btn secondary';recOpen.textContent='Abrir com recovery';recOpen.addEventListener('click',()=>queueVcLinkedOpen(profile.id,'recovery',null,rec.id));const recTest=document.createElement('button');recTest.className='btn ghost';recTest.textContent='Testar recovery';recTest.addEventListener('click',()=>testVcLinkedRecovery(profile.id,rec.id,recTest));recActions.append(recOpen,recTest);body.append(recActions);
    const new1=document.createElement('input');new1.type='password';new1.autocomplete='new-password';new1.placeholder='Nova senha de recuperação';new1.id=`vc-linked-newrec-${profile.id}`;const new2=document.createElement('input');new2.type='password';new2.autocomplete='new-password';new2.placeholder='Repetir nova senha';new2.id=`vc-linked-newrec2-${profile.id}`;body.append(new1,new2);
    const change=document.createElement('button');change.className='btn secondary';change.textContent='Trocar senha de recuperação';change.addEventListener('click',()=>changeVcLinkedRecovery(profile.id,select.value,new1.id,new2.id,change));body.append(change);
    const remove=document.createElement('button');remove.className='btn ghost';remove.textContent='Remover YubiKey selecionada';remove.disabled=profile.slots.length<=1;remove.addEventListener('click',()=>removeVcLinkedKey(profile.id,select.value));body.append(remove);
    const del=document.createElement('button');del.className='btn danger';del.textContent='Excluir vínculo deste aparelho';del.addEventListener('click',()=>deleteVcLinkedProfile(profile.id));body.append(del);
    appendText(body,'p','O .vcprofile contém as credenciais VeraCrypt somente cifradas. Guarde uma cópia fora do iPhone; sem ele, um aparelho novo não conhece os wrappers das YubiKeys.','hint');details.append(body);card.append(details);list.append(card);
  }
}
async function createVcLinkedProfileFromExisting(){
  const name=$('vc-link-name').value.trim(),recovery=$('vc-link-recovery').value,repeat=$('vc-link-recovery2').value;
  if(!vcLinkSelectedFile)return showToast('Selecione o container VeraCrypt existente.','error');
  try{requireStrongEnough(recovery);if(recovery!==repeat)throw new Error('As senhas de recuperação não coincidem.');}
  catch(e){return showToast(e.message||String(e),'error');}
  const btn=$('vc-link-create');const old=btn.textContent;let bundle=null,volume=null,prf=null;
  try{
    btn.disabled=true;btn.textContent='Validando o container...';
    bundle=await buildCredentialBundle({password:$('vc-link-password').value,pim:$('vc-link-pim').value,hash:$('vc-link-kdf').value,hidden:$('vc-link-volume-type').value==='hidden',keyfiles:vcLinkKeyfiles});
    volume=await openVeraCryptFile(vcLinkSelectedFile,{password:bundle.password,pim:bundle.pim,hash:bundle.hash,hidden:bundle.hidden,keyfiles:vcLinkKeyfiles});volume.close();volume=null;
    btn.textContent='Cadastre a YubiKey 1...';
    const reg=await registerPrfCredential({webauthnUserId:bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))},'security-key');prf=reg.prfSecret;reg.registration.label='YubiKey 1';
    btn.textContent='Cifrando as credenciais...';
    const profile=await createLinkedProfile({name,file:vcLinkSelectedFile,bundle,registration:reg.registration,prfSecret:prf,recoveryPassword:recovery});
    profile.rpId=location.hostname;
    vcLinkedProfiles.push(profile);await persistVcLinkedProfiles();showVcLinkWizard(false);showToast('Vault vinculado. Agora cadastre a segunda YubiKey e teste o recovery.','success');
  }catch(e){try{volume?.close?.();}catch{}showToast(e.message||String(e),'error');}
  finally{if(bundle){bundle.password='';for(const k of bundle.keyfiles||[])k.data='';}prf&&wipe(prf);btn.disabled=false;btn.textContent=old;clearSecretInputs();}
}
function queueVcLinkedOpen(profileId,method,slotId=null,recoveryInputId=null){
  const profile=getVcLinkedProfile(profileId);if(!profile)return showToast('Perfil VeraCrypt não encontrado.','error');
  if(method==='recovery'&&!$(recoveryInputId)?.value)return showToast('Informe a senha de recuperação.','error');
  vcLinkedPendingOpen={profileId,method,slotId,recoveryInputId};$('vc-linked-container-file').value='';$('vc-linked-container-file').click();
}
async function linkedBundleViaFido(profile,slotId,button=null){
  const slot=profile.slots.find(s=>s.id===slotId)||profile.slots[0];if(!slot)throw new Error('YubiKey não encontrada.');
  const old=button?.textContent;if(button){button.disabled=true;button.textContent='Aguardando YubiKey...';}
  let prf=null,dek=null;
  try{prf=await evaluatePrf(slot);dek=await unwrapLinkedDekFromSlot(profile,slot,prf);return await decryptLinkedBundle(profile,dek);}
  finally{prf&&wipe(prf);dek&&wipe(dek);if(button){button.disabled=false;button.textContent=old;}}
}
async function linkedBundleViaRecovery(profile,password){let dek=null;try{dek=await unwrapLinkedDekFromRecovery(profile,password);return await decryptLinkedBundle(profile,dek);}finally{dek&&wipe(dek);}}
async function continueVcLinkedOpen(file){
  const pending=vcLinkedPendingOpen;vcLinkedPendingOpen=null;$('vc-linked-container-file').value='';if(!file||!pending)return;
  const profile=getVcLinkedProfile(pending.profileId);if(!profile)return showToast('Perfil VeraCrypt não encontrado.','error');
  let bundle=null,creds=null;
  try{
    const match=await verifyContainerAgainstProfile(profile,file);if(!match.ok&&!confirm('O header/tamanho deste arquivo não coincide com o vault vinculado. Tentar abrir mesmo assim?'))return;
    selectVcFile(file);
    if(pending.method==='fido')bundle=await linkedBundleViaFido(profile,pending.slotId);
    else bundle=await linkedBundleViaRecovery(profile,$(pending.recoveryInputId)?.value||'');
    creds=materializeBundleCredentials(bundle);
    const opened=await openVcUsing({password:creds.password,keyfiles:creds.keyfiles,pim:creds.pim,hash:creds.hash,hidden:creds.hidden,button:$('vc-open'),statusPrefix:pending.method==='fido'?'YubiKey validada. Credenciais do vault liberadas somente em memória.':'Recovery validado. Credenciais do vault liberadas somente em memória.'});
    if(!opened)return;
    profile.lastVerifiedAt=new Date().toISOString();if(pending.method==='fido'){profile.lastFidoTestedAt=profile.lastVerifiedAt;const slot=profile.slots.find(s=>s.id===pending.slotId)||profile.slots[0];if(slot)slot.lastTestedAt=profile.lastVerifiedAt;}else profile.lastRecoveryTestedAt=profile.lastVerifiedAt;await persistVcLinkedProfiles();
    if(pending.recoveryInputId)$(pending.recoveryInputId).value='';
  }catch(e){showToast(e.message||String(e),'error');}
  finally{if(creds)wipeMaterializedCredentials(creds);if(bundle){bundle.password='';for(const k of bundle.keyfiles||[])k.data='';}}
}
async function testVcLinkedFido(profileId,slotId,button){const profile=getVcLinkedProfile(profileId);if(!profile)return;let bundle=null;try{bundle=await linkedBundleViaFido(profile,slotId,button);const now=new Date().toISOString();profile.lastFidoTestedAt=now;const slot=profile.slots.find(s=>s.id===slotId)||profile.slots[0];if(slot)slot.lastTestedAt=now;await persistVcLinkedProfiles();showToast('YubiKey válida e pacote de credenciais autenticado.','success');}catch(e){showToast(e.message||String(e),'error');}finally{if(bundle){bundle.password='';for(const k of bundle.keyfiles||[])k.data='';}}}
async function addVcLinkedKey(profileId,slotId,button){
  const profile=getVcLinkedProfile(profileId);if(!profile)return;let bundle=null,prf=null,dek=null;
  const slot=profile.slots.find(s=>s.id===slotId)||profile.slots[0];const old=button.textContent;
  try{
    button.disabled=true;button.textContent='Valide uma YubiKey já cadastrada...';prf=await evaluatePrf(slot);dek=await unwrapLinkedDekFromSlot(profile,slot,prf);wipe(prf);prf=null;
    button.textContent='Cadastre a nova YubiKey...';const reg=await registerPrfCredential({webauthnUserId:bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))},'security-key');prf=reg.prfSecret;reg.registration.label=`YubiKey ${profile.slots.length+1}`;
    const next=await addLinkedProfileSlot(profile,dek,reg.registration,prf,reg.registration.label);vcLinkedProfiles=vcLinkedProfiles.map(p=>p.id===profile.id?next:p);await persistVcLinkedProfiles();showToast('Nova YubiKey adicionada ao mesmo vault.','success');
  }catch(e){showToast(e.message||String(e),'error');}
  finally{prf&&wipe(prf);dek&&wipe(dek);if(bundle)bundle.password='';button.disabled=false;button.textContent=old;}
}
function exportVcLinkedProfile(profileId){const profile=getVcLinkedProfile(profileId);if(!profile)return;const safe=profile.name.replace(/[^a-z0-9._-]+/gi,'_').slice(0,80)||'Vault';downloadBlob(linkedProfileToBlob(profile),`${safe}.vcprofile`);showToast('Perfil cifrado exportado. Guarde-o junto ao plano de recuperação.','success');}
async function importVcLinkedProfile(file){
  if(!file)return;try{const profile=await linkedProfileFromFile(file);if(profile.rpId&&profile.rpId!==location.hostname&&!confirm(`Este perfil foi criado para o domínio ${profile.rpId}. O domínio atual é ${location.hostname}; as YubiKeys FIDO2 provavelmente não funcionarão aqui. Importar mesmo assim para usar o recovery?`))return;const idx=vcLinkedProfiles.findIndex(p=>p.id===profile.id);if(idx>=0){if(!confirm('Este perfil já existe. Substituir a cópia local pelo arquivo importado?'))return;vcLinkedProfiles[idx]=profile;}else vcLinkedProfiles.push(profile);await persistVcLinkedProfiles();showToast('Perfil VeraCrypt importado.','success');}catch(e){showToast(e.message||String(e),'error');}finally{$('vc-linked-import-file').value='';}
}
async function testVcLinkedRecovery(profileId,inputId,button){const profile=getVcLinkedProfile(profileId);const password=$(inputId).value;if(!profile||!password)return showToast('Informe a senha de recuperação.','error');let dek=null,bundle=null;const old=button.textContent;try{button.disabled=true;button.textContent='Testando...';dek=await unwrapLinkedDekFromRecovery(profile,password);bundle=await decryptLinkedBundle(profile,dek);profile.lastRecoveryTestedAt=new Date().toISOString();await persistVcLinkedProfiles();showToast('Recovery válido e credenciais autenticadas.','success');$(inputId).value='';}catch(e){showToast(e.message||String(e),'error');}finally{dek&&wipe(dek);if(bundle){bundle.password='';for(const k of bundle.keyfiles||[])k.data='';}button.disabled=false;button.textContent=old;}}
async function changeVcLinkedRecovery(profileId,slotId,newId,repeatId,button){const profile=getVcLinkedProfile(profileId),a=$(newId).value,b=$(repeatId).value;if(!profile)return;try{requireStrongEnough(a);if(a!==b)throw new Error('As novas senhas não coincidem.');}catch(e){return showToast(e.message||String(e),'error');}const slot=profile.slots.find(s=>s.id===slotId)||profile.slots[0];let prf=null,dek=null;const old=button.textContent;try{button.disabled=true;button.textContent='Valide a YubiKey...';prf=await evaluatePrf(slot);dek=await unwrapLinkedDekFromSlot(profile,slot,prf);const next=await changeLinkedRecoveryPassword(profile,dek,a);next.lastRecoveryTestedAt=null;vcLinkedProfiles=vcLinkedProfiles.map(p=>p.id===profile.id?next:p);await persistVcLinkedProfiles();$(newId).value='';$(repeatId).value='';showToast('Senha de recuperação alterada. Exporte um novo .vcprofile e teste a nova senha.','success');}catch(e){showToast(e.message||String(e),'error');}finally{prf&&wipe(prf);dek&&wipe(dek);button.disabled=false;button.textContent=old;}}
async function removeVcLinkedKey(profileId,slotId){const profile=getVcLinkedProfile(profileId);if(!profile)return;if(profile.slots.length<=1)return showToast('Mantenha ao menos uma YubiKey.','error');const slot=profile.slots.find(s=>s.id===slotId);if(!slot)return;if(!confirm(`Remover “${slot.label||'YubiKey'}” deste vault? A credencial física não é apagada da YubiKey, apenas deixa de ser aceita pelo perfil.`))return;try{const next=removeLinkedProfileSlot(profile,slotId);vcLinkedProfiles=vcLinkedProfiles.map(p=>p.id===profile.id?next:p);await persistVcLinkedProfiles();showToast('YubiKey removida do perfil.','success');}catch(e){showToast(e.message||String(e),'error');}}
async function deleteVcLinkedProfile(profileId){const profile=getVcLinkedProfile(profileId);if(!profile)return;if(!confirm(`Excluir o vínculo “${profile.name}” deste aparelho? Isso não altera o container VeraCrypt. Confirme que você possui o .vcprofile de recuperação.`))return;vcLinkedProfiles=vcLinkedProfiles.filter(p=>p.id!==profileId);await persistVcLinkedProfiles();showToast('Vínculo local removido.');}

function selectedVcFidoSlot(){
  if(!vcFidoProfile)return null;
  const id=$('vc-fido-slot')?.value;
  return vcFidoProfile.slots.find(slot=>slot.id===id)||vcFidoProfile.slots[0]||null;
}
function shortFingerprint(value){return value?`${value.slice(0,12)}…${value.slice(-12)}`:'—';}
function renderVcFido(){
  if(!$('vc-fido-empty'))return;
  const configured=!!vcFidoProfile;
  $('vc-fido-empty').hidden=configured;
  $('vc-fido-configured').hidden=!configured;
  if(configured){
    const select=$('vc-fido-slot');select.replaceChildren();
    for(const slot of vcFidoProfile.slots){const o=document.createElement('option');o.value=slot.id;o.textContent=`${slot.label||'YubiKey FIDO2'}${slot.lastTestedAt?' ✓':''}`;select.append(o);}
    $('vc-fido-summary').textContent=`Chave VeraCrypt compartilhada: ${shortFingerprint(vcFidoProfile.fingerprint)} · ${vcFidoProfile.slots.length} YubiKey(s) · backup por senha ${vcFidoProfile.recovery?'configurado':'ausente'}.`;
    $('vc-fido-add-key').disabled=vcFidoProfile.slots.length>=8;
    $('vc-fido-open-recovery').disabled=!vcFidoProfile.recovery&&!vcImportedRecovery;
    $('vc-fido-export-recovery').disabled=!vcFidoProfile.recovery;
  }else{
    $('vc-fido-open-recovery').disabled=!vcImportedRecovery;
  }
  $('vc-fido-import-status').textContent=vcImportedRecovery?`Backup importado: ${shortFingerprint(vcImportedRecovery.fingerprint)}. Informe a senha para abrir ou restaurar a configuração FIDO2.`:'';
  $('vc-fido-restore-profile').hidden=!vcImportedRecovery||configured;
}
async function createVcFidoConfiguration(){
  if(vcFidoProfile)return showToast('A configuração FIDO2 já existe.','error');
  const password=$('vc-fido-new-recovery').value,repeat=$('vc-fido-new-recovery2').value;
  try{requireStrongEnough(password);if(password!==repeat)throw new Error('As senhas de recuperação não coincidem.');}
  catch(e){return showToast(e.message,'error');}
  const btn=$('vc-fido-create');const old=btn.textContent;btn.disabled=true;let prf=null,shared=null;
  try{
    btn.textContent='Cadastre a YubiKey 1...';
    const reg=await registerPrfCredential({webauthnUserId:bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))},'security-key');prf=reg.prfSecret;
    reg.registration.label='YubiKey 1';
    btn.textContent='Protegendo a chave compartilhada...';
    const created=await createVeraCryptFidoProfile(reg.registration,prf,password);shared=created.secret;vcFidoProfile=created.profile;
    await putVeraCryptFidoProfile(vcFidoProfile);clearSecretInputs();renderVcFido();
    showToast('FIDO2 configurado. Cadastre a segunda YubiKey e exporte o cofre de recuperação.','success');
  }catch(e){showToast(e.message||String(e),'error');}
  finally{prf&&wipe(prf);shared&&wipe(shared);btn.disabled=false;btn.textContent=old;}
}
async function getVcFidoSecretFromSelectedKey(button=null){
  if(!vcFidoProfile)throw new Error('Configure primeiro o módulo VeraCrypt FIDO2.');
  const slot=selectedVcFidoSlot();if(!slot)throw new Error('Nenhuma YubiKey FIDO2 cadastrada.');
  const old=button?.textContent;if(button){button.disabled=true;button.textContent='Aguardando YubiKey...';}
  let prf=null;
  try{prf=await evaluatePrf(slot);return await unwrapSecretFromSlot(vcFidoProfile,slot,prf);}
  finally{prf&&wipe(prf);if(button){button.disabled=false;button.textContent=old;}}
}
async function addVcFidoKey(){
  const btn=$('vc-fido-add-key');let secret=null,prf=null;
  try{
    secret=await getVcFidoSecretFromSelectedKey(btn);
    btn.disabled=true;btn.textContent='Cadastre a nova YubiKey...';
    const reg=await registerPrfCredential({webauthnUserId:bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))},'security-key');prf=reg.prfSecret;
    reg.registration.label=`YubiKey ${vcFidoProfile.slots.length+1}`;
    vcFidoProfile=await addVeraCryptFidoSlot(vcFidoProfile,secret,reg.registration,prf,reg.registration.label);
    await putVeraCryptFidoProfile(vcFidoProfile);renderVcFido();showToast('Nova YubiKey cadastrada para a mesma chave VeraCrypt.','success');
  }catch(e){showToast(e.message||String(e),'error');}
  finally{secret&&wipe(secret);prf&&wipe(prf);btn.disabled=false;btn.textContent='Adicionar outra YubiKey';}
}
async function exportVcFidoRawKeyfile(){
  if(!confirm('Este arquivo de 64 bytes é a chave VeraCrypt em estado bruto. Quem obtiver uma cópia poderá substituir a YubiKey. Exporte somente para configurar/recuperar o VeraCrypt e apague a cópia temporária depois.'))return;
  const btn=$('vc-fido-export-keyfile');let secret=null;
  try{secret=await getVcFidoSecretFromSelectedKey(btn);downloadBlob(rawKeyfileBlob(secret),`MeuCofre-VeraCrypt-FIDO-${new Date().toISOString().slice(0,10)}.key`);showToast('Keyfile bruto exportado. Trate-o como segredo crítico.','success');}
  catch(e){showToast(e.message||String(e),'error');}finally{secret&&wipe(secret);}
}
function exportVcFidoRecovery(){
  if(!vcFidoProfile?.recovery)return showToast('Nenhum cofre de recuperação configurado.','error');
  downloadBlob(recoveryToBlob(vcFidoProfile.recovery),`MeuCofre-VeraCrypt-Recovery-${new Date().toISOString().slice(0,10)}.vcrecovery`);
  showToast('Cofre de recuperação criptografado exportado.','success');
}
async function importVcRecovery(file){
  if(!file)return;
  try{vcImportedRecovery=await recoveryFromFile(file);renderVcFido();showToast('Cofre de recuperação importado na memória.','success');}
  catch(e){showToast(e.message||String(e),'error');}
  finally{$('vc-fido-recovery-file').value='';}
}
async function getRecoverySecret(){
  const recovery=vcImportedRecovery||vcFidoProfile?.recovery;if(!recovery)throw new Error('Importe ou configure um cofre de recuperação.');
  const password=$('vc-fido-recovery-password').value;if(!password)throw new Error('Informe a senha do cofre de recuperação.');
  return openVeraCryptRecoveryVault(recovery,password);
}
async function restoreVcFidoProfileFromRecovery(){
  if(vcFidoProfile)return showToast('Já existe uma configuração FIDO2 local.','error');
  const btn=$('vc-fido-restore-profile');let secret=null,prf=null;
  try{
    secret=await getRecoverySecret();btn.disabled=true;btn.textContent='Cadastre uma YubiKey...';
    const reg=await registerPrfCredential({webauthnUserId:bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))},'security-key');prf=reg.prfSecret;reg.registration.label='YubiKey 1';
    const profile={format:'meucofre-veracrypt-fido-v1',version:1,id:uuid(),createdAt:new Date().toISOString(),updatedAt:new Date().toISOString(),fingerprint:vcImportedRecovery.fingerprint,slots:[],recovery:structuredClone(vcImportedRecovery)};
    profile.slots.push(await wrapSecretForRegistration(profile.id,secret,reg.registration,prf,'YubiKey 1'));
    vcFidoProfile=profile;await putVeraCryptFidoProfile(profile);vcImportedRecovery=null;clearSecretInputs();renderVcFido();showToast('Configuração FIDO2 restaurada a partir do backup por senha.','success');
  }catch(e){showToast(e.message||String(e),'error');}
  finally{secret&&wipe(secret);prf&&wipe(prf);btn.disabled=false;btn.textContent='Restaurar FIDO2 a partir deste backup';}
}
async function resetVcFidoConfiguration(){
  if(!vcFidoProfile)return;
  if(!confirm('Apagar a configuração FIDO2 local? Faça antes o backup .vcrecovery e confirme que uma YubiKey ou o backup por senha realmente libera a chave. Os containers VeraCrypt não serão alterados.'))return;
  if(!confirm('Confirma a remoção dos invólucros FIDO2 deste iPhone?'))return;
  await deleteVeraCryptFidoProfile();vcFidoProfile=null;renderVcFido();showToast('Configuração FIDO2 local removida.');
}

function formatVcBytes(value){
  const n=Number(value)||0;
  if(n<1024)return `${n} B`;
  const units=['KB','MB','GB','TB'];let v=n/1024,i=0;
  while(v>=1024&&i<units.length-1){v/=1024;i++;}
  return `${v>=10?v.toFixed(1):v.toFixed(2)} ${units[i]}`;
}
function resetVcOpenedState(){
  vcDirectoryRequest++;
  try{vcFs?.close?.();}catch{}
  try{vcVolume?.close?.();}catch{}
  vcFs=null;vcVolume=null;vcPath=[];
  if($('vc-open-area'))$('vc-open-area').hidden=true;
  if($('vc-browser-section'))$('vc-browser-section').hidden=false;
  $('vc-metadata')?.replaceChildren();$('vc-files')?.replaceChildren();
  if($('vc-path'))$('vc-path').textContent='Raiz';
  if($('vc-back'))$('vc-back').hidden=true;
}
function selectVcFile(file){
  resetVcOpenedState();
  vcSelectedFile=file;
  if(!file){$('vc-file-info').textContent='Nenhum container selecionado.';return;}
  $('vc-file-info').textContent=`${file.name} · ${formatVcBytes(file.size)}`;
  $('vc-status').textContent='Container selecionado. Informe a senha e, se usados no volume, PIM/keyfiles.';
}
function selectVcKeyfiles(files){
  vcKeyfiles=files.slice(0,32);
  $('vc-keyfile-info').textContent=vcKeyfiles.length?`${vcKeyfiles.length} keyfile(s): ${vcKeyfiles.map(f=>f.name).join(', ')}`:'Sem keyfiles.';
}
function closeVeraCryptSession(resetSelection=false){
  resetVcOpenedState();
  if($('vc-password'))$('vc-password').value='';
  if($('vc-status'))$('vc-status').textContent='';
  vcKeyfiles=[];
  if($('vc-keyfiles'))$('vc-keyfiles').value='';
  if($('vc-keyfile-info'))$('vc-keyfile-info').textContent='Sem keyfiles.';
  if(resetSelection){
    vcSelectedFile=null;
    vcLinkSelectedFile=null;
    vcLinkKeyfiles=[];
    vcLinkedPendingOpen=null;
    if($('vc-file'))$('vc-file').value='';
    if($('vc-file-info'))$('vc-file-info').textContent='Nenhum container selecionado.';
    if($('vc-link-file'))$('vc-link-file').value='';
    if($('vc-link-keyfiles'))$('vc-link-keyfiles').value='';
    if($('vc-link-file-info'))$('vc-link-file-info').textContent='Nenhum container selecionado.';
    if($('vc-link-keyfile-info'))$('vc-link-keyfile-info').textContent='Sem keyfiles.';
  }
}
function addVcMeta(label,value){
  const row=document.createElement('div');row.className='row';
  const main=document.createElement('div');main.className='row-main';
  const title=document.createElement('div');title.className='row-title';title.textContent=label;
  const sub=document.createElement('div');sub.className='row-sub';sub.textContent=String(value);
  main.append(title,sub);row.append(main);$('vc-metadata').append(row);
}
function renderVcMetadata(fileSystemError=null){
  $('vc-metadata').replaceChildren();
  const i=vcVolume?.info||{};
  addVcMeta('Container',vcSelectedFile?.name||'—');
  addVcMeta('Criptografia','AES-256-XTS');
  addVcMeta('KDF',`${i.hash||'—'} · ${Number(i.iterations||0).toLocaleString('pt-BR')} iterações${i.pim?` · PIM ${i.pim}`:''}`);
  addVcMeta('Cabeçalho',`${i.hidden?'oculto':'normal'} · versão ${i.headerVersion??'—'} · ${i.headerSource||'primário'}`);
  addVcMeta('Volume',formatVcBytes(i.volumeSize||0));
  addVcMeta('Área criptografada',`${formatVcBytes(i.encryptedAreaLength||0)} a partir de ${formatVcBytes(i.encryptedAreaStart||0)}`);
  addVcMeta('Setor',`${i.sectorSize||512} bytes`);
  addVcMeta('Sistema de arquivos',vcFs?.info?.type||(fileSystemError?`não suportado (${fileSystemError.message||fileSystemError})`:'não identificado'));
}
async function openVcUsing({password='',keyfiles=[],pim=null,hash=null,hidden=null,button,statusPrefix='Lendo cabeçalho e derivando a chave localmente.'}={}){
  if(!vcSelectedFile)return showToast('Selecione um container VeraCrypt.','error');
  const btn=button||$('vc-open');const old=btn.textContent;btn.disabled=true;btn.textContent='Derivando chave...';
  resetVcOpenedState();
  let volume=null;
  try{
    $('vc-status').textContent=`${statusPrefix} Arquivos grandes não são enviados para nenhum servidor.`;
    volume=await openVeraCryptFile(vcSelectedFile,{password,pim:pim??$('vc-pim').value,keyfiles,hash:hash??$('vc-kdf').value,hidden:hidden??($('vc-volume-type').value==='hidden')});
    vcVolume=volume;volume=null;
    let fsError=null;
    try{vcFs=await openSupportedFileSystem(vcVolume);}catch(e){fsError=e;vcFs=null;}
    $('vc-open-area').hidden=false;
    $('vc-browser-section').hidden=!vcFs;
    renderVcMetadata(fsError);
    $('vc-password').value='';
    vcKeyfiles=[];$('vc-keyfiles').value='';$('vc-keyfile-info').textContent='Sem keyfiles (descartados após a abertura).';
    if(vcFs){
      vcPath=[{name:'Raiz',locator:null}];
      await renderVcDirectory();
      $('vc-status').textContent=`Volume aberto em modo somente leitura · ${vcFs.info.type}.`;
    }else{
      $('vc-status').textContent='Cabeçalho VeraCrypt aberto, mas o sistema de arquivos interno ainda não é suportado nesta versão.';
    }
    return true;
  }catch(e){
    try{volume?.close?.();}catch{}
    resetVcOpenedState();
    $('vc-status').textContent=e.message||String(e);
    showToast(`Não foi possível abrir o container: ${e.message||e}`,'error');
    return false;
  }finally{btn.disabled=false;btn.textContent=old;}
}
async function openVcContainer(){
  return openVcUsing({password:$('vc-password').value,keyfiles:vcKeyfiles,button:$('vc-open')});
}
async function openVcWithFido(){
  const btn=$('vc-fido-open');let secret=null;
  try{
    if(!vcSelectedFile)throw new Error('Selecione primeiro o container VeraCrypt.');
    secret=await getVcFidoSecretFromSelectedKey(btn);
    await openVcUsing({password:'',keyfiles:[secret],button:btn,statusPrefix:'YubiKey validada. Usando a chave VeraCrypt compartilhada somente em memória.'});
  }catch(e){showToast(e.message||String(e),'error');}
  finally{secret&&wipe(secret);}
}
async function openVcWithRecovery(){
  const btn=$('vc-fido-open-recovery');let secret=null;
  try{
    if(!vcSelectedFile)throw new Error('Selecione primeiro o container VeraCrypt.');
    secret=await getRecoverySecret();
    await openVcUsing({password:'',keyfiles:[secret],button:btn,statusPrefix:'Backup por senha validado. Usando a chave VeraCrypt recuperada somente em memória.'});
    $('vc-fido-recovery-password').value='';
  }catch(e){showToast(e.message||String(e),'error');}
  finally{secret&&wipe(secret);}
}
async function renderVcDirectory(){
  if(!vcFs||!vcPath.length)return;
  const request=++vcDirectoryRequest;
  const current=vcPath[vcPath.length-1];
  $('vc-path').textContent=vcPath.map(x=>x.name).join(' / ');
  $('vc-back').hidden=vcPath.length<=1;
  $('vc-files').replaceChildren();
  const wait=document.createElement('div');wait.className='hint';wait.textContent='Lendo diretório...';$('vc-files').append(wait);
  try{
    const entries=await vcFs.readDirectory(current.locator);
    if(request!==vcDirectoryRequest)return;
    $('vc-files').replaceChildren();
    if(!entries.length){const empty=document.createElement('div');empty.className='empty';empty.textContent='Pasta vazia.';$('vc-files').append(empty);return;}
    entries.sort((a,b)=>Number(b.isDirectory)-Number(a.isDirectory)||a.name.localeCompare(b.name,'pt-BR')).forEach(entry=>{
      const row=document.createElement('button');row.type='button';row.className='vc-file-row';
      const icon=document.createElement('span');icon.className='vc-file-icon';icon.textContent=entry.isDirectory?'▣':'▤';
      const main=document.createElement('span');
      const name=document.createElement('span');name.className='vc-file-name';name.textContent=entry.name;
      const meta=document.createElement('span');meta.className='vc-file-meta';meta.textContent=entry.isDirectory?'Pasta':`${formatVcBytes(entry.size)}${entry.modified?` · ${new Date(entry.modified).toLocaleString('pt-BR')}`:''}`;
      main.append(name,meta);
      const action=document.createElement('span');action.className='vc-file-action';action.textContent=entry.isDirectory?'Abrir':'Exportar';
      row.append(icon,main,action);
      row.addEventListener('click',()=>entry.isDirectory?vcEnterDirectory(entry):vcExportFile(entry));
      $('vc-files').append(row);
    });
  }catch(e){if(request!==vcDirectoryRequest)return;$('vc-files').replaceChildren();const err=document.createElement('div');err.className='error';err.textContent=e.message||String(e);$('vc-files').append(err);}
}
function vcEnterDirectory(entry){if(!vcFs||!entry.isDirectory)return;vcPath.push({name:entry.name,locator:entry});renderVcDirectory();}
function vcGoBack(){if(vcPath.length<=1)return;vcPath.pop();renderVcDirectory();}
async function vcExportFile(entry){
  if(!vcFs||entry.isDirectory)return;
  const safe=(entry.name||'arquivo').replace(/[\\/:*?"<>|\u0000-\u001f]/g,'_').slice(0,220)||'arquivo';
  $('vc-status').textContent=`Descriptografando ${entry.name}...`;
  let bytes=null;
  try{
    bytes=await vcFs.readFile(entry);
    const blob=new Blob([bytes],{type:'application/octet-stream'});
    downloadBlob(blob,safe);
    $('vc-status').textContent=`${entry.name} exportado. A cópia baixada está em texto claro fora do container.`;
    showToast('Arquivo exportado do container.','success');
  }catch(e){showToast(e.message||String(e),'error');$('vc-status').textContent=e.message||String(e);}
  finally{bytes&&wipe(bytes);}
}

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
