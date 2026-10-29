import assert from 'node:assert/strict'
import test from 'node:test'

import { transcribeWithVoskClient } from '../src/services/offlineVoiceRecognition.js'

function fakeClient({ result = 'recognized words', error = null } = {}) {
  const calls = []
  const recognizer = {
    on(eventName, listener) {
      calls.push(['on', eventName])
      if (eventName === 'result') this.resultListener = listener
      if (eventName === 'error') this.errorListener = listener
    },
    acceptWaveformFloat(samples, sampleRate) {
      calls.push(['audio', samples, sampleRate])
    },
    retrieveFinalResult() {
      calls.push(['final'])
      queueMicrotask(() => error
        ? this.errorListener({ error })
        : this.resultListener({ result: { text: result } }))
    },
    remove() { calls.push(['remove']) },
  }
  return { calls, KaldiRecognizer: function KaldiRecognizer() { return recognizer } }
}

test('offline voice recognition sends local samples to Vosk and returns its transcript', async () => {
  const client = fakeClient()
  const samples = new Float32Array([0.1, -0.2, 0.3])
  const transcript = await transcribeWithVoskClient(client, samples, 16000)

  assert.equal(transcript, 'recognized words')
  assert.deepEqual(client.calls.find(([kind]) => kind === 'audio'), ['audio', samples, 16000])
  assert.ok(client.calls.some(([kind]) => kind === 'final'))
  assert.ok(client.calls.some(([kind]) => kind === 'remove'))
})

test('offline voice recognition rejects Vosk errors and releases its recognizer', async () => {
  const client = fakeClient({ error: 'recognition failed' })
  await assert.rejects(transcribeWithVoskClient(client, new Float32Array([0.1]), 16000), /recognition failed/)
  assert.ok(client.calls.some(([kind]) => kind === 'remove'))
})
