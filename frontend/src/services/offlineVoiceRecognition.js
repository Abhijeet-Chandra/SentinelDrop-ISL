export function transcribeWithVoskClient(client, samples, sampleRate) {
  return new Promise((resolve, reject) => {
    const recognizer = new client.KaldiRecognizer(sampleRate)
    let settled = false
    const timeout = setTimeout(() => finish(new Error('Speech recognition took too long. Try a shorter recording.')), 30_000)

    function finish(error, text = '') {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      try {
        recognizer.remove()
      } catch (cleanupError) {
        if (!error) error = cleanupError
      }
      if (error) reject(error)
      else resolve(text.trim())
    }

    recognizer.on('result', (message) => finish(null, message.result?.text || ''))
    recognizer.on('error', (message) => finish(new Error(message.error || 'Offline speech recognition failed.')))

    try {
      recognizer.acceptWaveformFloat(samples, sampleRate)
      recognizer.retrieveFinalResult()
    } catch (error) {
      finish(error)
    }
  })
}
