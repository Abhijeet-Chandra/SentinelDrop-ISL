import { createVoskClient } from '@lichess-org/vosk-browser'
import workerUrl from '@lichess-org/vosk-browser/dist/vosk.worker.js?url'
import wasmUrl from '@lichess-org/vosk-browser/dist/vosk.wasm?url'

import { getStoredToken, localApiUrl } from './api'
import { transcribeWithVoskClient } from './offlineVoiceRecognition'

const DATABASE_NAME = 'sentineldrop-offline-models'
const DATABASE_VERSION = 1
const MODEL_STORE = 'models'
const MODEL_KEY = 'vosk-small-en-us-0.15'
let clientPromise

function openModelDatabase() {
  if (!globalThis.indexedDB) {
    return Promise.reject(new Error('This browser cannot save the offline speech model. Use a current browser with site storage enabled.'))
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(MODEL_STORE)) {
        request.result.createObjectStore(MODEL_STORE)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new Error('The browser could not open offline speech storage.'))
  })
}

async function readCachedModel() {
  const database = await openModelDatabase()
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(MODEL_STORE, 'readonly')
      const request = transaction.objectStore(MODEL_STORE).get(MODEL_KEY)
      request.onsuccess = () => resolve(request.result || null)
      request.onerror = () => reject(new Error('The saved offline speech model could not be read.'))
    })
  } finally {
    database.close()
  }
}

async function saveCachedModel(modelBlob) {
  const database = await openModelDatabase()
  try {
    await new Promise((resolve, reject) => {
      const transaction = database.transaction(MODEL_STORE, 'readwrite')
      transaction.objectStore(MODEL_STORE).put(modelBlob, MODEL_KEY)
      transaction.oncomplete = resolve
      transaction.onerror = () => reject(new Error('The offline speech model could not be saved. Check available browser storage.'))
      transaction.onabort = () => reject(new Error('The offline speech model could not be saved. Check available browser storage.'))
    })
    void navigator.storage?.persist?.().catch(() => {})
  } finally {
    database.close()
  }
}

async function fetchModelBlob(onStatus) {
  const cached = await readCachedModel()
  if (cached instanceof Blob && cached.size > 0) return cached

  const token = getStoredToken()
  if (!token) throw new Error('Sign in before loading offline speech recognition.')
  onStatus?.('Downloading the offline speech model for first use…')
  const response = await fetch(`${localApiUrl()}/voice/model`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) {
    const error = await response.json().catch(() => ({}))
    throw new Error(error.detail || 'The offline speech model could not be downloaded.')
  }

  const modelBlob = await response.blob()
  if (!modelBlob.size) throw new Error('The downloaded offline speech model was empty.')
  await saveCachedModel(modelBlob)
  return modelBlob
}

async function getOfflineVoskClient(onStatus) {
  if (!clientPromise) {
    clientPromise = (async () => {
      const modelBlob = await fetchModelBlob(onStatus)
      const modelUrl = URL.createObjectURL(modelBlob)
      try {
        onStatus?.('Loading offline speech recognition…')
        return await createVoskClient({ modelUrl, workerUrl, wasmUrl, logLevel: -1 })
      } finally {
        URL.revokeObjectURL(modelUrl)
      }
    })().catch((error) => {
      clientPromise = undefined
      throw error
    })
  }
  return clientPromise
}

export async function transcribeVoiceOffline(samples, sampleRate, onStatus) {
  const client = await getOfflineVoskClient(onStatus)
  const startedAt = performance.now()
  const text = await transcribeWithVoskClient(client, samples, sampleRate)
  return { text, transcriptionTimeMs: performance.now() - startedAt }
}
