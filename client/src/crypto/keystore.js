// client/src/crypto/keystore.js

const DB_NAME = 'messenger-keystore';
const STORE_NAME = 'records';
const IDENTITY_KEY = 'identity';
const PREKEYS_KEY = 'prekeys';
const PBKDF2_ITERATIONS = 210_000;
const AES_GCM_IV_BYTES = 12;
const PBKDF2_SALT_BYTES = 16;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const memoryFallback = new Map();

function toUint8(view) {
  if (view instanceof Uint8Array) {
    return new Uint8Array(view);
  }
  if (view instanceof ArrayBuffer) {
    return new Uint8Array(view);
  }
  if (ArrayBuffer.isView(view)) {
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  throw new TypeError('Unsupported binary type');
}

function hasIndexedDb() {
  return typeof indexedDB !== 'undefined';
}

function bytesToBase64(bytes) {
  if (bytes instanceof ArrayBuffer) {
    bytes = new Uint8Array(bytes);
  }
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('Expected Uint8Array or ArrayBuffer');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  if (typeof btoa === 'function') {
    return btoa(binary);
  }
  return Buffer.from(binary, 'binary').toString('base64');
}

function base64ToBytes(base64) {
  let binary;
  if (typeof atob === 'function') {
    binary = atob(base64);
  } else {
    binary = Buffer.from(base64, 'base64').toString('binary');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function getCrypto() {
  const crypto = globalThis.crypto || (typeof window !== 'undefined' ? window.crypto : undefined);
  if (!crypto?.subtle) {
    throw new Error('WebCrypto not available');
  }
  return crypto;
}

async function openDb() {
  if (!hasIndexedDb()) {
    return null;
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

async function writeRecord(key, value) {
  const db = await openDb();
  if (!db) {
    memoryFallback.set(key, value);
    return;
  }
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    store.put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function readRecord(key) {
  const db = await openDb();
  if (!db) {
    return memoryFallback.get(key) ?? null;
  }
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

function normaliseKeyPair(keyPair) {
  if (!keyPair || !keyPair.pubKey || !keyPair.privKey) {
    throw new TypeError('Invalid identity key pair');
  }
  return {
    pubKey: toUint8(keyPair.pubKey),
    privKey: toUint8(keyPair.privKey),
  };
}

function serialiseIdentity(identity) {
  const keyPair = normaliseKeyPair(identity.identityKeyPair);
  return {
    registrationId: identity.registrationId,
    identityKeyPair: {
      pubKey: bytesToBase64(keyPair.pubKey),
      privKey: bytesToBase64(keyPair.privKey),
    },
  };
}

function deserialiseIdentity(record) {
  if (!record) return null;
  return {
    registrationId: record.registrationId,
    identityKeyPair: {
      pubKey: base64ToBytes(record.identityKeyPair.pubKey),
      privKey: base64ToBytes(record.identityKeyPair.privKey),
    },
  };
}

function serialisePreKeys(preKeys) {
  if (!preKeys || !preKeys.signedPreKey) {
    throw new TypeError('Signed pre-key is required');
  }
  const result = {
    signedPreKey: {
      keyId: preKeys.signedPreKey.keyId,
      publicKey: bytesToBase64(toUint8(preKeys.signedPreKey.keyPair.pubKey)),
      privateKey: bytesToBase64(toUint8(preKeys.signedPreKey.keyPair.privKey)),
      signature: bytesToBase64(toUint8(preKeys.signedPreKey.signature)),
    },
    oneTimePreKeys: [],
  };
  if (Array.isArray(preKeys.oneTimePreKeys)) {
    for (const item of preKeys.oneTimePreKeys) {
      result.oneTimePreKeys.push({
        keyId: item.keyId,
        publicKey: bytesToBase64(toUint8(item.keyPair.pubKey)),
        privateKey: bytesToBase64(toUint8(item.keyPair.privKey)),
      });
    }
  }
  return result;
}

function deserialisePreKeys(record) {
  if (!record) return null;
  return {
    signedPreKey: {
      keyId: record.signedPreKey.keyId,
      keyPair: {
        pubKey: base64ToBytes(record.signedPreKey.publicKey),
        privKey: base64ToBytes(record.signedPreKey.privateKey),
      },
      signature: base64ToBytes(record.signedPreKey.signature),
    },
    oneTimePreKeys: Array.isArray(record.oneTimePreKeys)
      ? record.oneTimePreKeys.map((item) => ({
          keyId: item.keyId,
          keyPair: {
            pubKey: base64ToBytes(item.publicKey),
            privKey: base64ToBytes(item.privateKey),
          },
        }))
      : [],
  };
}

async function deriveAesKey(passphrase, saltBytes) {
  const crypto = await getCrypto();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function saveIdentityEncrypted(passphrase, identity) {
  if (!passphrase) {
    throw new Error('Passphrase is required to encrypt identity material');
  }
  const crypto = await getCrypto();
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const payload = textEncoder.encode(JSON.stringify(serialiseIdentity(identity)));
  const aesKey = await deriveAesKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, payload);

  await writeRecord(IDENTITY_KEY, {
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
  });
}

export async function loadIdentity(passphrase) {
  const record = await readRecord(IDENTITY_KEY);
  if (!record) {
    return null;
  }
  if (!passphrase) {
    throw new Error('Passphrase is required to decrypt identity material');
  }

  const crypto = await getCrypto();
  const salt = base64ToBytes(record.salt);
  const iv = base64ToBytes(record.iv);
  const aesKey = await deriveAesKey(passphrase, new Uint8Array(salt));

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      aesKey,
      base64ToBytes(record.ciphertext)
    );
    const json = JSON.parse(textDecoder.decode(new Uint8Array(decrypted)));
    return deserialiseIdentity(json);
  } catch {
    throw new Error('Failed to decrypt identity material');
  }
}

export async function savePreKeys(preKeys) {
  await writeRecord(PREKEYS_KEY, serialisePreKeys(preKeys));
}

export async function loadPreKeys() {
  const record = await readRecord(PREKEYS_KEY);
  return deserialisePreKeys(record);
}
