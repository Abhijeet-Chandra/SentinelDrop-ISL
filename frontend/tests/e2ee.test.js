import assert from 'node:assert/strict'
import test from 'node:test'

import {
  decryptBytes,
  deriveSessionCryptoKey,
  encryptBytes,
  exportPublicKeyBase64,
  exportRawPublicKey,
  generateClientKeyPair,
  incomingTransferMetadata,
} from '../src/services/e2ee.js'

test('two clients derive a matching key and AES-GCM authenticates transfer metadata', async () => {
  const alice = await generateClientKeyPair()
  const bob = await generateClientKeyPair()
  const alicePublic = await exportPublicKeyBase64(alice.publicKey)
  const bobPublic = await exportPublicKeyBase64(bob.publicKey)
  const aliceKey = await deriveSessionCryptoKey(alice.privateKey, bobPublic, 'session-123', 10, 11)
  const bobKey = await deriveSessionCryptoKey(bob.privateKey, alicePublic, 'session-123', 10, 11)
  const metadata = {
    session_id: 'session-123',
    sequence_number: 1,
    message_type: 'text',
    sender_user_id: 10,
    recipient_user_id: 11,
  }
  const plaintext = new TextEncoder().encode('hello from the browser')
  const encrypted = await encryptBytes(aliceKey, plaintext, metadata)

  assert.notDeepEqual(encrypted.ciphertext, plaintext)
  assert.deepEqual(await decryptBytes(bobKey, encrypted, metadata), plaintext)
  const reverseDirectionKey = await deriveSessionCryptoKey(alice.privateKey, bobPublic, 'session-123', 11, 10)
  await assert.rejects(decryptBytes(reverseDirectionKey, encrypted, metadata))
  await assert.rejects(
    decryptBytes(bobKey, encrypted, { ...metadata, recipient_user_id: 12 }),
  )
})

test('receiver authenticates the original sender and recipient for text and files', async () => {
  const sender = await generateClientKeyPair()
  const receiver = await generateClientKeyPair()
  const senderPublic = await exportPublicKeyBase64(sender.publicKey)
  const receiverPublic = await exportPublicKeyBase64(receiver.publicKey)
  const senderKey = await deriveSessionCryptoKey(sender.privateKey, receiverPublic, 'session-456', 10, 11)
  const receiverKey = await deriveSessionCryptoKey(receiver.privateKey, senderPublic, 'session-456', 10, 11)
  for (const extra of [{}, { filename: 'report.txt', mime_type: 'text/plain', file_size: 5 }]) {
    const metadata = {
      session_id: 'session-456', sequence_number: 2, message_type: 'text',
      sender_user_id: 10, recipient_user_id: 11, ...extra,
    }
    const encrypted = await encryptBytes(senderKey, new TextEncoder().encode('hello'), metadata)
    const received = { ...metadata, ...encrypted }
    assert.deepEqual(incomingTransferMetadata(received), metadata)
    assert.equal(new TextDecoder().decode(await decryptBytes(receiverKey, received, incomingTransferMetadata(received))), 'hello')
  }
})

test('browser identity private keys are non-extractable and public keys remain exportable', async () => {
  const pair = await generateClientKeyPair()
  assert.equal(pair.privateKey.extractable, false)
  assert.equal((await exportRawPublicKey(pair.publicKey)).byteLength, 32)
})
