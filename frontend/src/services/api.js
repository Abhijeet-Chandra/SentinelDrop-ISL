import {
  decryptBytes,
  deriveSessionCryptoKey,
  encryptBytes,
  loadClientIdentity,
  getOrCreateClientIdentity,
  incomingTransferMetadata,
} from './e2ee'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const TOKEN_KEY = 'sentineldrop_token'
const USERNAME_KEY = 'sentineldrop_username'
const ADMIN_KEY = 'sentineldrop_is_admin'
const SESSION_KEY = 'sentineldrop_session_id'
const PEER_KEY = 'sentineldrop_peer_public_key'
const PAIRED_FINGERPRINT_KEY = 'sentineldrop_paired_fingerprint'

async function parseResponse(response) {
  const data = await response.json().catch(() => ({}))

  if (!response.ok) {
    const detail = data.detail
    throw new Error(
      typeof detail === 'string'
        ? detail
        : 'Something went wrong.'
    )
  }

  return data
}

function jsonHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    ...extra,
  }
}

export function localApiUrl() {
  return API_BASE_URL
}

export async function registerUser(username, password) {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ username, password }),
  })
  return parseResponse(response)
}

export async function loginUser(username, password) {
  return storeLoginResponse('/auth/login', username, password)
}

export async function adminLoginUser(username, password) {
  return storeLoginResponse('/auth/admin/login', username, password)
}

async function storeLoginResponse(path, username, password) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ username, password }),
  })

  const data = await parseResponse(response)
  const token = data.access_token || data.token

  if (!token) {
    throw new Error(
      'Login succeeded, but the server did not return an authentication token.'
    )
  }

  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USERNAME_KEY, data.username || username)
  localStorage.setItem(ADMIN_KEY, data.is_admin ? 'true' : 'false')
  return data
}

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getStoredUsername() {
  return localStorage.getItem(USERNAME_KEY)
}

export function getStoredIsAdmin() {
  return localStorage.getItem(ADMIN_KEY) === 'true'
}

export function getStoredSessionId() {
  return localStorage.getItem(SESSION_KEY)
}

export function getStoredPeerPublicKey() {
  return localStorage.getItem(PEER_KEY)
}

export function storePeerPublicKey(publicKey) {
  if (publicKey) {
    localStorage.setItem(PEER_KEY, publicKey)
  }
}

export function getPairedFingerprintKey() {
  return PAIRED_FINGERPRINT_KEY
}

export async function logoutUser() {
  const token = getStoredToken()
  if (token) {
    await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    }).catch(() => {})
  }
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USERNAME_KEY)
  localStorage.removeItem(ADMIN_KEY)
  localStorage.removeItem(SESSION_KEY)
  localStorage.removeItem(PEER_KEY)
}

export async function authenticatedFetch(path, options = {}) {
  const token = getStoredToken()
  if (!token) {
    throw new Error('You are not signed in.')
  }

  const headers = new Headers(options.headers || {})
  headers.set('Authorization', `Bearer ${token}`)

  if (
    options.body &&
    typeof options.body === 'object' &&
    !(options.body instanceof FormData) &&
    !headers.has('Content-Type')
  ) {
    headers.set('Content-Type', 'application/json')
    options.body = JSON.stringify(options.body)
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  })

  if (response.status === 401 && getStoredToken() === token) {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(SESSION_KEY)
    localStorage.removeItem(ADMIN_KEY)
    window.dispatchEvent(new Event('sentineldrop-session-expired'))
  }

  return parseResponse(response)
}

export async function getLocalPairingInfo() {
  const identity = await getOrCreateClientIdentity(getStoredUsername())
  await authenticatedFetch('/devices/me/identity', {
    method: 'PUT',
    body: { public_key: identity.publicKey, fingerprint: identity.fingerprint },
  })
  return authenticatedFetch('/devices/me/pairing')
}

export async function getMyPairingQrObjectUrl() {
  const token = getStoredToken()
  const response = await fetch(`${API_BASE_URL}/devices/me/pairing/qr`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  if (!response.ok) {
    throw new Error('Unable to load pairing QR.')
  }
  const blob = await response.blob()
  return URL.createObjectURL(blob)
}

export async function preparePairing(payload) {
  return authenticatedFetch('/devices/pairing/prepare', {
    method: 'POST',
    body: { payload },
  })
}

export async function confirmPairing(payload, fingerprint) {
  const data = await authenticatedFetch('/devices/pairing/confirm', {
    method: 'POST',
    body: { payload, fingerprint },
  })
  storePeerPublicKey(data.public_key)
  if (data.fingerprint) {
    localStorage.setItem(PAIRED_FINGERPRINT_KEY, data.fingerprint)
  }
  return data
}

export async function getSecurityDashboard() {
  return authenticatedFetch('/security/dashboard')
}

export async function getAuditEvents() {
  return authenticatedFetch('/audit/events')
}

export async function verifyAudit() {
  return authenticatedFetch('/audit/verify')
}

export async function getAdminMessageLogs() {
  return authenticatedFetch('/admin/message-logs')
}

export async function getAdminMessageLog(messageId) {
  return authenticatedFetch(`/admin/message-logs/${messageId}`)
}

export async function getAdminMonitorStatus() {
  return authenticatedFetch('/admin/monitor/status')
}

export async function getAdminReadiness() {
  return authenticatedFetch('/admin/readiness')
}

export async function getAdminLiveCaptureInterfaces() {
  return authenticatedFetch('/admin/monitor/live/interfaces')
}

export async function getAdminLiveCaptureStatus() {
  return authenticatedFetch('/admin/monitor/live/status')
}

export async function startAdminLiveCapture(settings) {
  return authenticatedFetch('/admin/monitor/live/start', { method: 'POST', body: settings })
}

export async function stopAdminLiveCapture() {
  return authenticatedFetch('/admin/monitor/live/stop', { method: 'POST' })
}

export async function getAdminHttpMonitorStatus() {
  return authenticatedFetch('/admin/monitor/http/status')
}

export async function startAdminHttpMonitor() {
  return authenticatedFetch('/admin/monitor/http/start', {
    method: 'POST',
    body: { duration_seconds: 30, request_limit: 1000 },
  })
}

export async function stopAdminHttpMonitor() {
  return authenticatedFetch('/admin/monitor/http/stop', { method: 'POST' })
}

export async function runAdminImageMetrics(file) {
  const body = new FormData()
  body.append('image', file)
  return authenticatedFetch('/admin/evaluation/image-metrics', {
    method: 'POST',
    body,
  })
}

export async function runAdminImageBenchmark(file, rounds = 3) {
  const body = new FormData()
  body.append('image', file)
  return authenticatedFetch(`/admin/evaluation/image-benchmark?rounds=${rounds}`, {
    method: 'POST',
    body,
  })
}

export async function runAdminPerformanceBenchmark() {
  return authenticatedFetch('/admin/evaluation/benchmark', {
    method: 'POST',
  })
}

export async function downloadAdminBenchmarkCsv() {
  const response = await fetch(`${API_BASE_URL}/admin/evaluation/benchmark.csv`, {
    headers: { Authorization: `Bearer ${getStoredToken()}` },
  })
  if (!response.ok) {
    const data = await response.json().catch(() => ({}))
    throw new Error(typeof data.detail === 'string' ? data.detail : 'Unable to export benchmark data.')
  }
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'sentineldrop-aes-benchmark.csv'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export async function runAdminTextAnalysis(text) {
  return authenticatedFetch('/admin/evaluation/text-analysis', {
    method: 'POST',
    body: { text },
  })
}

export async function runAdminHashAnalysis(text) {
  return authenticatedFetch('/admin/evaluation/hash-analysis', {
    method: 'POST',
    body: { text },
  })
}

export async function runAdminSignatureDemo(text) {
  return authenticatedFetch('/admin/evaluation/signature-demo', {
    method: 'POST',
    body: { text },
  })
}

export async function runAdminSecurityDemos() {
  return authenticatedFetch('/admin/evaluation/security-demos', { method: 'POST' })
}

export async function runAdminVoiceBenchmark(file, rounds = 3) {
  const body = new FormData()
  body.append('audio', file)
  return authenticatedFetch(`/admin/evaluation/voice-benchmark?rounds=${rounds}`, {
    method: 'POST',
    body,
  })
}

export async function runAdminPcapAnalysis(file) {
  const body = new FormData()
  body.append('capture', file)
  return authenticatedFetch('/admin/evaluation/pcap-analysis', {
    method: 'POST',
    body,
  })
}

export async function establishSecureSession(peerPublicKey = getStoredPeerPublicKey()) {
  if (!peerPublicKey) {
    throw new Error('Pair and trust the other device before opening a session.')
  }

  const opened = await authenticatedFetch('/sessions/open', {
    method: 'POST',
    body: { device_public_key: peerPublicKey },
  })
  localStorage.setItem(SESSION_KEY, opened.session_id)
  return opened
}

function createTransferMetadata(session, sequenceNumber, messageType, extra = {}) {
  return {
    session_id: session.session_id,
    sequence_number: sequenceNumber,
    message_type: messageType,
    sender_user_id: session.local_user_id,
    recipient_user_id: session.peer_user_id,
    ...extra,
  }
}

function newSequenceNumber() {
  return globalThis.crypto.getRandomValues(new Uint32Array(1))[0]
}

export async function sendMessage(session, message, messageType = 'text') {
  const identity = await loadClientIdentity(getStoredUsername())
  const sequenceNumber = newSequenceNumber()
  const metadata = createTransferMetadata(session, sequenceNumber, messageType)
  const key = await deriveSessionCryptoKey(
    identity.privateKey,
    getStoredPeerPublicKey(),
    session.session_id,
    metadata.sender_user_id,
    metadata.recipient_user_id,
  )
  const encrypted = await encryptBytes(key, new TextEncoder().encode(message), metadata)
  return authenticatedFetch('/messages/send', {
    method: 'POST',
    body: { ...metadata, ...encrypted },
  })
}

export async function listPendingMessages() {
  return authenticatedFetch('/messages/pending')
}

export async function receiveMessage(encryptedMessage) {
  const identity = await loadClientIdentity(getStoredUsername())
  const key = await deriveSessionCryptoKey(
    identity.privateKey,
    getStoredPeerPublicKey(),
    encryptedMessage.session_id,
    encryptedMessage.sender_user_id,
    encryptedMessage.recipient_user_id,
  )
  const metadata = incomingTransferMetadata(encryptedMessage)
  const plaintext = await decryptBytes(key, encryptedMessage, metadata)
  await authenticatedFetch('/messages/receive', {
    method: 'POST',
    body: {
      session_id: encryptedMessage.session_id,
      sequence_number: encryptedMessage.sequence_number,
      ciphertext: encryptedMessage.ciphertext,
    },
  })
  return { ...encryptedMessage, message: new TextDecoder().decode(plaintext) }
}

export async function receiveFile(encryptedFile) {
  const identity = await loadClientIdentity(getStoredUsername())
  const key = await deriveSessionCryptoKey(
    identity.privateKey,
    getStoredPeerPublicKey(),
    encryptedFile.session_id,
    encryptedFile.sender_user_id,
    encryptedFile.recipient_user_id,
  )
  const metadata = incomingTransferMetadata(encryptedFile)
  const plaintext = await decryptBytes(key, encryptedFile, metadata)
  await authenticatedFetch('/files/receive-encrypted', {
    method: 'POST',
    body: {
      session_id: encryptedFile.session_id,
      sequence_number: encryptedFile.sequence_number,
      ciphertext: encryptedFile.ciphertext,
    },
  })
  return {
    ...encryptedFile,
    size: plaintext.byteLength,
    object_url: URL.createObjectURL(new Blob([plaintext], { type: encryptedFile.mime_type || 'application/octet-stream' })),
  }
}

export async function listReceivedFiles() {
  return authenticatedFetch('/files/received')
}

export function receivedFileUrl(filename) {
  return `${API_BASE_URL}/files/received/${encodeURIComponent(filename)}`
}

export async function downloadReceivedFile(file) {
  const temporaryUrl = file?.blob instanceof Blob ? URL.createObjectURL(file.blob) : null
  const downloadUrl = file?.object_url || temporaryUrl
  if (!downloadUrl) {
    throw new Error('This file is no longer available in this browser tab.')
  }
  const anchor = document.createElement('a')
  anchor.href = downloadUrl
  anchor.download = file.filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  if (temporaryUrl) window.setTimeout(() => URL.revokeObjectURL(temporaryUrl), 60_000)
}

export async function prepareFile(session, file, messageType = 'image') {
  const identity = await loadClientIdentity(getStoredUsername())
  const sequenceNumber = newSequenceNumber()
  const metadata = createTransferMetadata(session, sequenceNumber, messageType, {
    filename: file.name,
    mime_type: file.type || 'application/octet-stream',
    file_size: file.size,
  })
  const key = await deriveSessionCryptoKey(
    identity.privateKey,
    getStoredPeerPublicKey(),
    session.session_id,
    metadata.sender_user_id,
    metadata.recipient_user_id,
  )
  const encrypted = await encryptBytes(key, new Uint8Array(await file.arrayBuffer()), metadata)
  return authenticatedFetch('/files/inbox', {
    method: 'POST',
    body: { ...metadata, ...encrypted },
  })
}

export async function reportVoiceTranscriptionMetric(audioBytes, transcriptionTimeMs) {
  return authenticatedFetch('/voice/transcription-metric', {
    method: 'POST',
    body: { audio_bytes: audioBytes, transcription_time_ms: transcriptionTimeMs },
  })
}
