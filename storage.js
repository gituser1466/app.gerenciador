const DB_NAME = 'meucofre-local';
const DB_VERSION = 1;
const STORE = 'state';
const VAULT_KEY = 'vault-record';

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
