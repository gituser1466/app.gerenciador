const DB_NAME = 'meucofre-local';
const DB_VERSION = 1;
const STORE = 'state';
const VAULT_KEY = 'vault-record';
const VC_FIDO_KEY = 'veracrypt-fido-profile';
const VC_LINKED_PROFILES_KEY = 'veracrypt-linked-profiles-v1';
const VC_MAC_HELPER_PAIR_KEY = 'veracrypt-macos-helper-pair-v1';

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    request.onerror = () => reject(request.error || new Error('Falha ao abrir o armazenamento local.'));
    request.onsuccess = () => resolve(request.result);
  });
}

async function run(mode, callback) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const store = tx.objectStore(STORE);
      let result;
      try {
        result = callback(store);
      } catch (error) {
        reject(error);
        return;
      }
      tx.oncomplete = () => resolve(result);
      tx.onerror = () => reject(tx.error || new Error('Falha no armazenamento local.'));
      tx.onabort = () => reject(tx.error || new Error('Operação de armazenamento cancelada.'));
    });
  } finally {
    db.close();
  }
}

export async function getVaultRecord() {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(VAULT_KEY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error('Falha ao ler o cofre.'));
    });
  } finally {
    db.close();
  }
}

export async function putVaultRecord(record) {
  return run('readwrite', (store) => store.put(structuredClone(record), VAULT_KEY));
}

export async function deleteVaultRecord() {
  return run('readwrite', (store) => store.delete(VAULT_KEY));
}

export async function getVeraCryptFidoProfile() {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(VC_FIDO_KEY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error('Falha ao ler a configuração VeraCrypt FIDO2.'));
    });
  } finally { db.close(); }
}

export async function putVeraCryptFidoProfile(profile) {
  return run('readwrite', (store) => store.put(structuredClone(profile), VC_FIDO_KEY));
}

export async function deleteVeraCryptFidoProfile() {
  return run('readwrite', (store) => store.delete(VC_FIDO_KEY));
}


export async function getVeraCryptLinkedProfiles() {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(VC_LINKED_PROFILES_KEY);
      req.onsuccess = () => resolve(Array.isArray(req.result) ? req.result : []);
      req.onerror = () => reject(req.error || new Error('Falha ao ler os vaults VeraCrypt vinculados.'));
    });
  } finally { db.close(); }
}

export async function putVeraCryptLinkedProfiles(profiles) {
  if (!Array.isArray(profiles)) throw new Error('Lista de vaults VeraCrypt inválida.');
  return run('readwrite', (store) => store.put(structuredClone(profiles), VC_LINKED_PROFILES_KEY));
}

export async function deleteVeraCryptLinkedProfiles() {
  return run('readwrite', (store) => store.delete(VC_LINKED_PROFILES_KEY));
}


export async function getVeraCryptMacHelperPair() {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(VC_MAC_HELPER_PAIR_KEY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error || new Error('Falha ao ler o pareamento do helper macOS.'));
    });
  } finally { db.close(); }
}

export async function putVeraCryptMacHelperPair(pairing) {
  return run('readwrite', (store) => store.put(structuredClone(pairing), VC_MAC_HELPER_PAIR_KEY));
}

export async function deleteVeraCryptMacHelperPair() {
  return run('readwrite', (store) => store.delete(VC_MAC_HELPER_PAIR_KEY));
}
