const IDENTITY_DB = 'sentineldrop-client-identities'
const IDENTITY_STORE = 'identities'
const TEXT_ENCODER = new TextEncoder()

function webCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error('This browser does not support the secure cryptography required by SentinelDrop.')
  }
  return globalThis.crypto
}

function assertSecureBrowserContext() {
  if (typeof window !== 'undefined' && !globalThis.isSecureContext) {
    throw new Error('Secure device pairing requires HTTPS or localhost. Open the secure site and try again.')
  }
  if (typeof indexedDB === 'undefined') {
    throw new Error('This browser cannot securely store the device identity. Enable site storage and try again.')
  }
}

function toBase64(bytes) {
  let binary = ''
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function fromBase64(value) {
  try {
    const binary = atob(value)
    return Uint8Array.from(binary, (character) => character.charCodeAt(0))
  } catch {
    throw new Error('The peer public key is not valid base64.')
  }
}

function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function fromHex(value) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) {
    throw new Error('Encrypted transfer contains invalid hexadecimal data.')
  }
  return Uint8Array.from(value.match(/.{2}/g) || [], (byte) => Number.parseInt(byte, 16))
}

function canonicalMetadata(metadata) {
  const normalized = Object.fromEntries(Object.entries(metadata).sort(([left], [right]) => left.localeCompare(right)))
  return TEXT_ENCODER.encode(JSON.stringify(normalized))
}

export async function generateClientKeyPair() {
  const pair = await webCrypto().subtle.generateKey(
    { name: 'X25519' },
    false,
    ['deriveBits'],
  )
  return { privateKey: pair.privateKey, publicKey: pair.publicKey }
}

export async function exportRawPublicKey(publicKey) {
  return new Uint8Array(await webCrypto().subtle.exportKey('raw', publicKey))
}

export async function exportPublicKeyBase64(publicKey) {
  return toBase64(await exportRawPublicKey(publicKey))
}

function openIdentityDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(IDENTITY_DB, 1)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(IDENTITY_STORE)) {
        request.result.createObjectStore(IDENTITY_STORE, { keyPath: 'username' })
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error || new Error('Unable to open secure browser storage.'))
    request.onblocked = () => reject(new Error('Close other SentinelDrop tabs to finish updating secure browser storage.'))
  })
}

async function identityTransaction(mode, operation) {
  const database = await openIdentityDatabase()
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(IDENTITY_STORE, mode)
    const store = transaction.objectStore(IDENTITY_STORE)
    let result
    try {
      result = operation(store)
    } catch (error) {
      database.close()
      reject(error)
      return
    }
    transaction.oncomplete = () => {
      database.close()
      resolve(result?.result)
    }
    transaction.onerror = () => {
      database.close()
      reject(transaction.error || new Error('Secure browser storage failed.'))
    }
    transaction.onabort = () => {
      database.close()
      reject(transaction.error || new Error('Secure browser storage was interrupted.'))
    }
  })
}

async function fingerprintFor(publicKey) {
  const digest = new Uint8Array(await webCrypto().subtle.digest('SHA-256', publicKey))
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(':')
}

export async function getOrCreateClientIdentity(username) {
  assertSecureBrowserContext()
  const normalizedUsername = String(username || '').trim().toLowerCase()
  if (!normalizedUsername) throw new Error('Sign in before creating a device identity.')

  const database = await openIdentityDatabase()
  const existing = await new Promise((resolve, reject) => {
    const request = database.transaction(IDENTITY_STORE, 'readonly')
      .objectStore(IDENTITY_STORE).get(normalizedUsername)
    request.onsuccess = () => resolve(request.result || null)
    request.onerror = () => reject(request.error || new Error('Unable to read the stored device identity.'))
  })
  database.close()
  if (existing) {
    return {
      username: normalizedUsername,
      privateKey: existing.privateKey,
      publicKey: existing.publicKey,
      fingerprint: existing.fingerprint,
    }
  }

  let pair
  try {
    pair = await generateClientKeyPair()
  } catch (error) {
    if (error?.name === 'NotSupportedError') {
      throw new Error('This browser does not support X25519. Update it to a current version to pair devices securely.', { cause: error })
    }
    throw error
  }
  const publicKey = await exportRawPublicKey(pair.publicKey)
  const record = {
    username: normalizedUsername,
    privateKey: pair.privateKey,
    publicKey: toBase64(publicKey),
    fingerprint: await fingerprintFor(publicKey),
  }
  await identityTransaction('readwrite', (store) => store.add(record))
  return record
}

export async function loadClientIdentity(username) {
  assertSecureBrowserContext()
  const normalizedUsername = String(username || '').trim().toLowerCase()
  const database = await openIdentityDatabase()
  const result = await new Promise((resolve, reject) => {
    const request = database.transaction(IDENTITY_STORE, 'readonly')
      .objectStore(IDENTITY_STORE).get(normalizedUsername)
    request.onsuccess = () => resolve(request.result || null)
    request.onerror = () => reject(request.error || new Error('Unable to read the stored device identity.'))
  })
  database.close()
  if (!result) throw new Error('This browser has no saved private identity for this account. Re-pairing with a new identity is required.')
  return result
}

export async function deriveSessionCryptoKey(privateKey, peerPublicKeyBase64, sessionId, senderUserId, recipientUserId) {
  if (!sessionId) throw new Error('A valid session is required before deriving an encryption key.')
  if (!Number.isSafeInteger(senderUserId) || !Number.isSafeInteger(recipientUserId) || senderUserId === recipientUserId) {
    throw new Error('Valid sender and recipient accounts are required to derive a directional key.')
  }
  const subtle = webCrypto().subtle
  const peerBytes = fromBase64(peerPublicKeyBase64)
  if (peerBytes.byteLength !== 32) throw new Error('The peer public key has an invalid length.')
  const peerPublicKey = await subtle.importKey('raw', peerBytes, { name: 'X25519' }, false, [])
  const sharedSecret = new Uint8Array(await subtle.deriveBits(
    { name: 'X25519', public: peerPublicKey },
    privateKey,
    256,
  ))
  if (sharedSecret.every((byte) => byte === 0)) {
    throw new Error('The peer public key produced an invalid shared secret. Pair the device again.')
  }
  const material = await subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey'])
  sharedSecret.fill(0)
  const salt = await subtle.digest('SHA-256', TEXT_ENCODER.encode(sessionId))
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: TEXT_ENCODER.encode(`SentinelDrop end-to-end AES-256-GCM v2|${sessionId}|${senderUserId}|${recipientUserId}`),
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

export async function encryptBytes(key, plaintext, metadata) {
  const nonce = webCrypto().getRandomValues(new Uint8Array(12))
  const ciphertext = await webCrypto().subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: canonicalMetadata(metadata), tagLength: 128 },
    key,
    plaintext,
  )
  return { nonce: toHex(nonce), ciphertext: toHex(ciphertext) }
}

export async function decryptBytes(key, encrypted, metadata) {
  const nonce = fromHex(encrypted.nonce)
  const ciphertext = fromHex(encrypted.ciphertext)
  if (nonce.byteLength !== 12 || ciphertext.byteLength < 16) {
    throw new Error('Encrypted transfer is incomplete or malformed.')
  }
  const plaintext = await webCrypto().subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: canonicalMetadata(metadata), tagLength: 128 },
    key,
    ciphertext,
  )
  return new Uint8Array(plaintext)
}
