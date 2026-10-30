import { useCallback, useEffect, useRef, useState } from 'react'
import { BrowserQRCodeReader } from '@zxing/browser'
import { DecodeHintType } from '@zxing/library'
import {
  confirmPairing,
  adminLoginUser,
  downloadAdminBenchmarkCsv,
  downloadReceivedFile,
  establishSecureSession,
  getAuditEvents,
  getAdminMessageLog,
  getAdminMessageLogs,
  getAdminMonitorStatus,
  getAdminReadiness,
  getAdminLiveCaptureInterfaces,
  getAdminLiveCaptureStatus,
  getAdminHttpMonitorStatus,
  getLocalPairingInfo,
  getMyPairingQrObjectUrl,
  getPairedFingerprintKey,
  getSecurityDashboard,
  getStoredPeerPublicKey,
  getStoredToken,
  getStoredIsAdmin,
  getStoredUsername,
  listPendingMessages,
  loginUser,
  logoutUser,
  prepareFile,
  preparePairing,
  reportVoiceTranscriptionMetric,
  receiveFile,
  receiveMessage,
  registerUser,
  runAdminImageMetrics,
  runAdminImageBenchmark,
  runAdminHashAnalysis,
  runAdminPerformanceBenchmark,
  runAdminPcapAnalysis,
  runAdminSignatureDemo,
  runAdminSecurityDemos,
  runAdminVoiceBenchmark,
  startAdminLiveCapture,
  startAdminHttpMonitor,
  stopAdminLiveCapture,
  stopAdminHttpMonitor,
  runAdminTextAnalysis,
  sendMessage,
  verifyAudit,
} from './services/api'
import './App.css'

const PAIRED_FINGERPRINT_KEY = getPairedFingerprintKey()

const THEMES = [
  { id: 'midnight', name: 'Midnight' },
  { id: 'ocean', name: 'Ocean' },
  { id: 'forest', name: 'Forest' },
  { id: 'ember', name: 'Ember' },
  { id: 'rose', name: 'Rose' },
  { id: 'paper', name: 'Paper' },
]

function ThemePicker({ theme, onChange }) {
  return (
    <label className="theme-picker">
      <span>Theme</span>
      <select value={theme} onChange={(event) => onChange(event.target.value)} aria-label="Choose color theme">
        {THEMES.map((option) => <option key={option.id} value={option.id}>{option.name}</option>)}
      </select>
    </label>
  )
}

function MetricBarChart({ title, rows, unit = '%' }) {
  const finite = rows.map((row) => Math.abs(Number(row.value) || 0))
  const maximum = Math.max(...finite, 0.01)
  return (
    <div className="analysis-chart" role="img" aria-label={title}>
      <strong>{title}</strong>
      {rows.map((row) => {
        const value = Number(row.value) || 0
        const width = Math.max(2, (Math.abs(value) / maximum) * 100)
        return (
          <div className="analysis-chart-row" key={row.label}>
            <span>{row.label}</span>
            <div className="analysis-chart-track"><i style={{ width: `${width}%` }} /></div>
            <b>{Number.isFinite(value) ? `${value.toFixed(2)}${unit}` : '—'}</b>
          </div>
        )
      })}
    </div>
  )
}

function MetricTrendChart({ title, rows, unit = '' }) {
  const samples = rows.filter((row) => Number.isFinite(Number(row.value)))
  if (!samples.length) return null
  const values = samples.map((row) => Number(row.value))
  const low = Math.min(0, ...values)
  const high = Math.max(1, ...values)
  const spread = high - low || 1
  const points = samples.map((row, index) => ({
    x: 42 + (index / Math.max(1, samples.length - 1)) * 528,
    y: 142 - ((Number(row.value) - low) / spread) * 112,
  }))
  const line = points.map(({ x, y }) => `${x},${y}`).join(' ')
  const area = `42,142 ${line} ${points.at(-1).x},142`
  return (
    <div className="analysis-chart analysis-trend" role="img" aria-label={`${title}. ${samples.map((row) => `${row.label}: ${row.value}${unit}`).join(', ')}`}>
      <strong>{title}</strong>
      <svg viewBox="0 0 600 170" preserveAspectRatio="xMidYMid meet" aria-hidden="true">
        <line className="trend-grid" x1="42" y1="30" x2="570" y2="30" />
        <line className="trend-grid" x1="42" y1="86" x2="570" y2="86" />
        <line className="trend-grid" x1="42" y1="142" x2="570" y2="142" />
        <polygon className="trend-fill" points={area} />
        <polyline className="trend-line" points={line} />
        {points.map((point, index) => <circle className="trend-point" key={index} cx={point.x} cy={point.y} r="3.5" />)}
        <text x="0" y="34">{high.toFixed(high < 10 ? 1 : 0)}</text>
        <text x="15" y="146">{low.toFixed(low < 10 ? 1 : 0)}</text>
      </svg>
      <div className="trend-labels"><span>{samples[0].label}</span><span>{samples.length > 1 ? samples.at(-1).label : `${values[0].toFixed(2)}${unit}`}</span></div>
    </div>
  )
}

function resampleVoice(samples, sourceRate, targetRate = 16000) {
  if (sourceRate === targetRate) return samples
  const outputLength = Math.floor((samples.length * targetRate) / sourceRate)
  const output = new Float32Array(outputLength)
  const ratio = sourceRate / targetRate
  for (let index = 0; index < outputLength; index += 1) {
    const sourceIndex = index * ratio
    const left = Math.floor(sourceIndex)
    const right = Math.min(left + 1, samples.length - 1)
    const fraction = sourceIndex - left
    output[index] = samples[left] * (1 - fraction) + samples[right] * fraction
  }
  return output
}

function normalizeVoice(samples) {
  let peak = 0
  let mean = 0
  for (const sample of samples) {
    peak = Math.max(peak, Math.abs(sample))
    mean += sample
  }
  if (samples.length) mean /= samples.length
  if (peak < 0.008) {
    throw new Error('No clear speech was captured. Move closer to the microphone and try again.')
  }
  const gain = Math.min(6, 0.85 / peak)
  return Float32Array.from(samples, (sample) => Math.max(-1, Math.min(1, (sample - mean) * gain)))
}

function releaseVoiceCapture(capture) {
  capture.processor.disconnect()
  capture.source.disconnect()
  capture.silentOutput.disconnect()
  capture.stream.getTracks().forEach((track) => track.stop())
  if (capture.context.state !== 'closed') {
    void capture.context.close().catch(() => {})
  }
}

function AdminConsole({ username, onSignOut, theme, onThemeChange }) {
  const [auditEvents, setAuditEvents] = useState([])
  const [messageLogs, setMessageLogs] = useState([])
  const [auditValid, setAuditValid] = useState(null)
  const [signaturePublicKey, setSignaturePublicKey] = useState('')
  const [signatureNote, setSignatureNote] = useState('')
  const [expandedId, setExpandedId] = useState(null)
  const [messageDetails, setMessageDetails] = useState({})
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [monitorStatus, setMonitorStatus] = useState(null)
  const [readiness, setReadiness] = useState(null)
  const [liveInterfaces, setLiveInterfaces] = useState([])
  const [liveCapture, setLiveCapture] = useState(null)
  const [captureInterface, setCaptureInterface] = useState('')
  const [captureError, setCaptureError] = useState('')
  const [packetCaptureNotice, setPacketCaptureNotice] = useState('')
  const [httpMonitor, setHttpMonitor] = useState(null)
  const [httpMonitorError, setHttpMonitorError] = useState('')
  const [monitorError, setMonitorError] = useState('')
  const [analysisError, setAnalysisError] = useState('')
  const [imageMetrics, setImageMetrics] = useState(null)
  const [imageBenchmark, setImageBenchmark] = useState(null)
  const [selectedAnalysisImage, setSelectedAnalysisImage] = useState(null)
  const [imageMetricsLoading, setImageMetricsLoading] = useState(false)
  const [imageBenchmarkLoading, setImageBenchmarkLoading] = useState(false)
  const [benchmark, setBenchmark] = useState(null)
  const [benchmarkLoading, setBenchmarkLoading] = useState(false)
  const [textAnalysisSample, setTextAnalysisSample] = useState('SentinelDrop protects messages with AES-256-GCM.')
  const [textAnalysis, setTextAnalysis] = useState(null)
  const [textAnalysisLoading, setTextAnalysisLoading] = useState(false)
  const [hashAnalysis, setHashAnalysis] = useState(null)
  const [hashAnalysisLoading, setHashAnalysisLoading] = useState(false)
  const [signatureDemo, setSignatureDemo] = useState(null)
  const [signatureDemoLoading, setSignatureDemoLoading] = useState(false)
  const [pcapFile, setPcapFile] = useState(null)
  const [pcapResult, setPcapResult] = useState(null)
  const [pcapLoading, setPcapLoading] = useState(false)
  const [securityDemos, setSecurityDemos] = useState(null)
  const [securityDemosLoading, setSecurityDemosLoading] = useState(false)
  const [voiceBenchmarkFile, setVoiceBenchmarkFile] = useState(null)
  const [voiceBenchmark, setVoiceBenchmark] = useState(null)
  const [voiceBenchmarkLoading, setVoiceBenchmarkLoading] = useState(false)

  const refreshLogs = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [events, verification, messages] = await Promise.all([
        getAuditEvents(),
        verifyAudit(),
        getAdminMessageLogs(),
      ])
      setAuditEvents(events.events || [])
      setAuditValid(verification.valid)
      setMessageLogs(messages.messages || [])
      setSignaturePublicKey(messages.signature_public_key || '')
      setSignatureNote(messages.signature_note || '')
    } catch (err) {
      setError(err.message || 'Unable to load administrator logs.')
    } finally {
      setLoading(false)
    }
  }, [])

  const refreshMonitor = useCallback(async () => {
    setMonitorError('')
    try {
      setMonitorStatus(await getAdminMonitorStatus())
    } catch (err) {
      setMonitorError(err.message || 'Unable to load monitor status.')
    }
  }, [])

  const refreshReadiness = useCallback(async () => {
    try {
      setReadiness(await getAdminReadiness())
    } catch (err) {
      setCaptureError(err.message || 'Unable to load deployment readiness.')
    }
  }, [])

  const refreshLiveCapture = useCallback(async () => {
    try {
      setLiveCapture(await getAdminLiveCaptureStatus())
    } catch (err) {
      setCaptureError(err.message || 'Unable to load live capture status.')
    }
  }, [])

  const refreshHttpMonitor = useCallback(async () => {
    try {
      setHttpMonitor(await getAdminHttpMonitorStatus())
    } catch (err) {
      setHttpMonitorError(err.message || 'Unable to load HTTP monitor status.')
    }
  }, [])

  const loadLiveInterfaces = useCallback(async () => {
    try {
      const result = await getAdminLiveCaptureInterfaces()
      setLiveInterfaces(result.interfaces || [])
      setCaptureInterface((current) => current || result.interfaces?.[0] || '')
      setPacketCaptureNotice('')
    } catch (err) {
      setLiveInterfaces([])
      setCaptureInterface('')
      setPacketCaptureNotice(err.message || 'TShark interfaces are unavailable on this backend host.')
    }
  }, [])

  useEffect(() => {
    const refreshTimer = window.setTimeout(() => {
      void refreshLogs()
      void refreshMonitor()
      void refreshReadiness()
      void loadLiveInterfaces()
      void refreshLiveCapture()
      void refreshHttpMonitor()
    }, 0)
    return () => window.clearTimeout(refreshTimer)
  }, [refreshLogs, refreshMonitor, refreshReadiness, loadLiveInterfaces, refreshLiveCapture, refreshHttpMonitor])

  useEffect(() => {
    if (!['running', 'stopping'].includes(liveCapture?.status)) return undefined
    const timer = window.setInterval(() => { void refreshLiveCapture() }, 1000)
    return () => window.clearInterval(timer)
  }, [liveCapture?.status, refreshLiveCapture])

  useEffect(() => {
    if (httpMonitor?.status !== 'running') return undefined
    const timer = window.setInterval(() => { void refreshHttpMonitor() }, 1000)
    return () => window.clearInterval(timer)
  }, [httpMonitor?.status, refreshHttpMonitor])

  async function handleRunImageMetrics() {
    if (!selectedAnalysisImage) {
      setAnalysisError('Choose an image before running the analysis.')
      return
    }
    setImageMetricsLoading(true)
    setAnalysisError('')
    try {
      setImageMetrics(await runAdminImageMetrics(selectedAnalysisImage))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to analyze this image.')
    } finally {
      setImageMetricsLoading(false)
    }
  }

  async function handleRunImageBenchmark() {
    if (!selectedAnalysisImage) {
      setAnalysisError('Choose an image before running the benchmark.')
      return
    }
    setImageBenchmarkLoading(true)
    setAnalysisError('')
    try {
      setImageBenchmark(await runAdminImageBenchmark(selectedAnalysisImage, 3))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to benchmark this image.')
    } finally {
      setImageBenchmarkLoading(false)
    }
  }

  async function handleRunBenchmark() {
    setBenchmarkLoading(true)
    setAnalysisError('')
    try {
      setBenchmark(await runAdminPerformanceBenchmark())
    } catch (err) {
      setAnalysisError(err.message || 'Unable to run the performance benchmark.')
    } finally {
      setBenchmarkLoading(false)
    }
  }

  async function handleExportBenchmarkCsv() {
    setAnalysisError('')
    try {
      await downloadAdminBenchmarkCsv()
    } catch (err) {
      setAnalysisError(err.message || 'Unable to export benchmark data.')
    }
  }

  async function handleRunTextAnalysis() {
    setTextAnalysisLoading(true)
    setAnalysisError('')
    try {
      setTextAnalysis(await runAdminTextAnalysis(textAnalysisSample))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to analyze this text sample.')
    } finally {
      setTextAnalysisLoading(false)
    }
  }

  async function handleRunHashAnalysis() {
    setHashAnalysisLoading(true)
    setAnalysisError('')
    try {
      setHashAnalysis(await runAdminHashAnalysis(textAnalysisSample))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to run hash analysis.')
    } finally {
      setHashAnalysisLoading(false)
    }
  }

  async function handleRunSignatureDemo() {
    setSignatureDemoLoading(true)
    setAnalysisError('')
    try {
      setSignatureDemo(await runAdminSignatureDemo(textAnalysisSample))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to run the signature demo.')
    } finally {
      setSignatureDemoLoading(false)
    }
  }

  async function handleRunPcapAnalysis() {
    if (!pcapFile) {
      setAnalysisError('Choose a PCAP or PCAPNG capture first.')
      return
    }
    setPcapLoading(true)
    setAnalysisError('')
    try {
      setPcapResult(await runAdminPcapAnalysis(pcapFile))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to analyze this capture.')
    } finally {
      setPcapLoading(false)
    }
  }

  async function handleStartLiveCapture() {
    if (!captureInterface) {
      setCaptureError('Choose an available capture interface first.')
      return
    }
    setCaptureError('')
    try {
      setLiveCapture(await startAdminLiveCapture({ interface: captureInterface, duration_seconds: 10, packet_limit: 1000 }))
    } catch (err) {
      setCaptureError(err.message || 'Unable to start live capture.')
    }
  }

  async function handleStopLiveCapture() {
    setCaptureError('')
    try {
      setLiveCapture(await stopAdminLiveCapture())
    } catch (err) {
      setCaptureError(err.message || 'Unable to stop live capture.')
    }
  }

  async function handleStartHttpMonitor() {
    setHttpMonitorError('')
    try {
      setHttpMonitor(await startAdminHttpMonitor())
    } catch (err) {
      setHttpMonitorError(err.message || 'Unable to start HTTP request monitor.')
    }
  }

  async function handleStopHttpMonitor() {
    setHttpMonitorError('')
    try {
      setHttpMonitor(await stopAdminHttpMonitor())
    } catch (err) {
      setHttpMonitorError(err.message || 'Unable to stop HTTP request monitor.')
    }
  }

  async function handleRunSecurityDemos() {
    setSecurityDemosLoading(true)
    setAnalysisError('')
    try {
      setSecurityDemos(await runAdminSecurityDemos())
    } catch (err) {
      setAnalysisError(err.message || 'Unable to run the isolated security demonstrations.')
    } finally {
      setSecurityDemosLoading(false)
    }
  }

  async function handleRunVoiceBenchmark() {
    if (!voiceBenchmarkFile) {
      setAnalysisError('Choose a WAV recording before running the voice benchmark.')
      return
    }
    setVoiceBenchmarkLoading(true)
    setAnalysisError('')
    try {
      setVoiceBenchmark(await runAdminVoiceBenchmark(voiceBenchmarkFile, 3))
    } catch (err) {
      setAnalysisError(err.message || 'Unable to run the voice benchmark.')
    } finally {
      setVoiceBenchmarkLoading(false)
    }
  }

  function exportAnalysisResults() {
    const exportedImageMetrics = imageMetrics && Object.fromEntries(
      Object.entries(imageMetrics).filter(([key]) => !key.endsWith('_data_url')),
    )
    const payload = {
      exported_at: new Date().toISOString(),
      text_aes_analysis: textAnalysis,
      image_metrics: exportedImageMetrics,
      image_benchmark: imageBenchmark,
      aes_performance_benchmark: benchmark,
      sha256_analysis: hashAnalysis,
      ed25519_signature_demo: signatureDemo,
      pcap_summary: pcapResult,
      live_capture_summary: liveCapture,
      application_http_summary: httpMonitor,
      deployment_readiness: readiness,
      controlled_security_demonstrations: securityDemos,
      offline_voice_benchmark: voiceBenchmark,
      note: 'Input plaintext, uploaded image previews, and uploaded PCAP bytes are not included.',
    }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'sentineldrop-admin-analysis.json'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  const formatMetric = (value, suffix = '') => {
    if (value === null || value === undefined) return '—'
    return `${typeof value === 'number' ? value.toFixed(4) : value}${suffix}`
  }

  async function toggleMessage(messageId) {
    if (expandedId === messageId) {
      setExpandedId(null)
      return
    }
    setExpandedId(messageId)
    if (messageDetails[messageId]) return
    try {
      const details = await getAdminMessageLog(messageId)
      setMessageDetails((current) => ({ ...current, [messageId]: details }))
    } catch (err) {
      setError(err.message || 'Unable to load ciphertext details.')
    }
  }

  return (
    <main className="dashboard-shell">
      <header className="dashboard-header">
        <div className="brand">
          <span className="brand-mark">S</span>
          <div>
            <h1>SentinelDrop Admin</h1>
            <p>Restricted audit console</p>
          </div>
        </div>
        <div className="header-actions">
          <span className="user-label">{username}</span>
          <ThemePicker theme={theme} onChange={onThemeChange} />
          <button className="secondary-button" type="button" onClick={refreshLogs} disabled={loading}>
            {loading ? 'Refreshing…' : 'Refresh logs'}
          </button>
          <button className="secondary-button" type="button" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </header>

      <section className="dashboard-content">
        {error && <div className="alert error">{error}</div>}
        <section className="workspace-panel security-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">ADMIN ONLY</span>
              <h2>Security audit trail</h2>
              <p>Hash-chained login, pairing, and security events. Chain status: {auditValid === null ? 'loading' : auditValid ? 'intact' : 'failed'}.</p>
            </div>
          </div>
          {auditEvents.length === 0 ? (
            <p className="empty-state">No audit events are recorded yet.</p>
          ) : (
            <>
            <MetricBarChart title="Audit events by type" unit=" events" rows={Object.entries(auditEvents.reduce((counts, event) => {
              counts[event.event_type] = (counts[event.event_type] || 0) + 1
              return counts
            }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([label, value]) => ({ label: label.replaceAll('_', ' '), value }))} />
            <div className="message-list admin-record-list">
              {auditEvents.map((event) => (
                <article className="message-item" key={event.id}>
                  <div>
                    <strong>{event.event_type}</strong>
                    <span>{event.created_at ? new Date(event.created_at).toLocaleString() : 'Time unavailable'}</span>
                  </div>
                  <p>{event.details}</p>
                  <p>Actor: {event.actor_id || 'system'} · Status: {event.status || 'recorded'}</p>
                  <code>{event.entry_hash}</code>
                </article>
              ))}
            </div>
            </>
          )}
        </section>

        <section className="workspace-panel security-panel admin-analysis-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">ADMIN ONLY · EVALUATION</span>
              <h2>Security and performance analysis</h2>
              <p>Run bounded image and AES-GCM evaluations, and inspect application security signals for this backend instance.</p>
            </div>
          </div>
          {analysisError && <div className="alert error">{analysisError}</div>}
          <button className="secondary-button" type="button" onClick={exportAnalysisResults} disabled={!textAnalysis && !imageMetrics && !imageBenchmark && !benchmark && !hashAnalysis && !signatureDemo && !pcapResult && !securityDemos && !voiceBenchmark}>Export current results as JSON</button>
          <div className="admin-analysis-grid">
            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">DEPLOYMENT CHECK</span><h3>Configuration readiness</h3></div><button className="secondary-button" type="button" onClick={refreshReadiness}>Refresh</button></div>
              {readiness ? <>
                <div className={`monitor-indicator ${readiness.ready ? 'available' : 'unavailable'}`}>{readiness.ready ? 'Checks ready' : 'Review items below'}</div>
                <div className="admin-monitor-events">
                  {Object.entries(readiness.checks).map(([name, check]) => <div className="admin-monitor-event" key={name}>
                    <strong>{check.advisory ? 'ADVISORY' : check.ready ? 'READY' : 'CHECK'} · {name.replaceAll('_', ' ')}</strong>
                    <p>{check.detail}</p>
                  </div>)}
                </div>
                <p className="admin-analysis-note">{readiness.note}</p>
              </> : <p className="empty-state">Loading deployment checks…</p>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">SENTINEL MONITOR · HOST CAPTURE</span><h3>TShark packet capture</h3></div><button className="secondary-button" type="button" onClick={loadLiveInterfaces}>Refresh interfaces</button></div>
              <p>Captures on the backend host for at most 10 seconds or 1,000 packets. Only aggregate counts are shown; packet contents and endpoint addresses are not retained. Use only on an interface you are authorized to monitor.</p>
              {liveInterfaces.length ? <label className="admin-file-picker">Capture interface<select value={captureInterface} onChange={(event) => setCaptureInterface(event.target.value)}>{liveInterfaces.map((name) => <option key={name} value={name}>{name}</option>)}</select></label> : <p className="admin-analysis-note">{packetCaptureNotice || 'No TShark interfaces are available on this backend host.'} The live API request monitor below works on the deployed service without TShark.</p>}
              {captureError && <div className="alert error">{captureError}</div>}
              <div className="admin-action-row">
                <button className="secondary-button" type="button" onClick={handleStartLiveCapture} disabled={!captureInterface || ['running', 'stopping'].includes(liveCapture?.status)}>Start 10-second capture</button>
                <button className="secondary-button" type="button" onClick={handleStopLiveCapture} disabled={!['running', 'stopping'].includes(liveCapture?.status)}>Stop capture</button>
              </div>
              {liveCapture && <>
                <div className="admin-metric-grid">
                  <div><span>Status</span><strong>{liveCapture.status}</strong></div>
                  <div><span>Packets</span><strong>{liveCapture.packet_count}</strong></div>
                  <div><span>Bytes</span><strong>{liveCapture.bytes_total}</strong></div>
                  <div><span>Peak rate</span><strong>{liveCapture.peak_packets_per_second} pkt/s</strong></div>
                </div>
                {Object.keys(liveCapture.protocol_counts || {}).length > 0 && <MetricBarChart title="Captured packets by protocol" unit=" packets" rows={Object.entries(liveCapture.protocol_counts).map(([label, value]) => ({ label, value }))} />}
                {liveCapture.error && <div className="alert error">{liveCapture.error}</div>}
                <p className="admin-analysis-note">{liveCapture.note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">SENTINEL MONITOR · HOSTED</span><h3>Live API request monitor</h3></div><button className="secondary-button" type="button" onClick={refreshHttpMonitor}>Refresh</button></div>
              <p>Measures requests handled by this backend for up to 30 seconds or 1,000 requests. Open the app on another device and send a message while it runs. This is application traffic, not a packet capture.</p>
              {httpMonitorError && <div className="alert error">{httpMonitorError}</div>}
              <div className="admin-action-row">
                <button className="secondary-button" type="button" onClick={handleStartHttpMonitor} disabled={httpMonitor?.status === 'running'}>Start 30-second monitor</button>
                <button className="secondary-button" type="button" onClick={handleStopHttpMonitor} disabled={httpMonitor?.status !== 'running'}>Stop monitor</button>
              </div>
              {httpMonitor && <>
                <div className="admin-metric-grid">
                  <div><span>Status</span><strong>{httpMonitor.status}</strong></div>
                  <div><span>Requests</span><strong>{httpMonitor.request_count}</strong></div>
                  <div><span>Request body bytes</span><strong>{httpMonitor.request_bytes.toLocaleString()}</strong></div>
                  <div><span>Response body bytes</span><strong>{httpMonitor.response_bytes.toLocaleString()}</strong></div>
                  <div><span>Peak rate</span><strong>{httpMonitor.peak_requests_per_second} req/s</strong></div>
                </div>
                {Object.keys(httpMonitor.status_counts || {}).length > 0 && <MetricBarChart title="API responses by status" unit=" requests" rows={Object.entries(httpMonitor.status_counts).map(([label, value]) => ({ label, value }))} />}
                {httpMonitor.requests_per_second?.length > 0 && <MetricTrendChart title="API requests over time" unit=" req/s" rows={httpMonitor.requests_per_second.map((value, index) => ({ label: `${index}s`, value }))} />}
                <p className="admin-analysis-note">{httpMonitor.note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">TRAFFIC ANALYSIS</span><h3>Offline PCAP review</h3></div></div>
              <p>Upload a capture up to 20 MB. Analysis is administrator-only, limited to 50,000 packets, and the uploaded file is deleted after processing. Requires PyShark and TShark on the backend.</p>
              <label className="admin-file-picker">Choose packet capture<input type="file" accept=".pcap,.pcapng,.cap" onChange={(event) => { setPcapFile(event.target.files?.[0] || null); setPcapResult(null) }} /></label>
              {pcapFile && <p className="admin-result-caption">{pcapFile.name} · {pcapFile.size.toLocaleString()} bytes</p>}
              <button className="secondary-button" type="button" onClick={handleRunPcapAnalysis} disabled={!pcapFile || pcapLoading}>{pcapLoading ? 'Analyzing capture…' : 'Analyze capture'}</button>
              {pcapResult && <>
                <div className="admin-metric-grid">
                  <div><span>Packets analyzed</span><strong>{pcapResult.packet_count}</strong></div>
                  <div><span>Capture bytes</span><strong>{pcapResult.bytes_total}</strong></div>
                  <div><span>Duration</span><strong>{pcapResult.duration_seconds} s</strong></div>
                  <div><span>Average rate</span><strong>{pcapResult.packets_per_second} pkt/s</strong></div>
                  <div><span>Peak 1-second rate</span><strong>{pcapResult.peak_packets_per_second} pkt/s</strong></div>
                  <div><span>Endpoint pairs</span><strong>{pcapResult.unique_connections}</strong></div>
                </div>
                <MetricBarChart title="Packets by protocol" unit=" packets" rows={Object.entries(pcapResult.protocol_counts).map(([label, value]) => ({ label, value }))} />
                <div className="admin-monitor-alert">{pcapResult.suspicious_flood_signal ? 'Traffic rate exceeds the simple demo threshold; inspect this capture.' : 'No packet-rate threshold alert in this capture.'}</div>
                <p className="admin-analysis-note">{pcapResult.note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">AUDIO PROCESSING</span><h3>Offline voice benchmark</h3></div></div>
              <p>Runs up to three local Vosk transcriptions and transient transcript AES-GCM timing. Transcript text is discarded; no audio or transcript is retained.</p>
              <label className="admin-file-picker">Choose WAV recording<input type="file" accept="audio/wav,.wav" onChange={(event) => { setVoiceBenchmarkFile(event.target.files?.[0] || null); setVoiceBenchmark(null) }} /></label>
              {voiceBenchmarkFile && <p className="admin-result-caption">{voiceBenchmarkFile.name} · {voiceBenchmarkFile.size.toLocaleString()} bytes</p>}
              <button className="secondary-button" type="button" onClick={handleRunVoiceBenchmark} disabled={!voiceBenchmarkFile || voiceBenchmarkLoading}>
                {voiceBenchmarkLoading ? 'Measuring voice processing…' : 'Run 3-pass voice benchmark'}
              </button>
              {voiceBenchmark && <>
                <div className="admin-metric-grid">
                  <div><span>Model</span><strong>{voiceBenchmark.model}</strong></div>
                  <div><span>Audio size</span><strong>{voiceBenchmark.audio_bytes.toLocaleString()} bytes</strong></div>
                  <div><span>Transcription mean / median</span><strong>{voiceBenchmark.transcription.mean_ms} / {voiceBenchmark.transcription.median_ms} ms</strong></div>
                  <div><span>Transcript encryption mean</span><strong>{voiceBenchmark.transcript_encryption.mean_ms} ms</strong></div>
                  <div><span>Transcript decryption mean</span><strong>{voiceBenchmark.transcript_decryption.mean_ms} ms</strong></div>
                  <div><span>Round trip</span><strong>{voiceBenchmark.crypto_roundtrip_verified ? 'Verified' : 'Failed'}</strong></div>
                </div>
                <MetricBarChart title="Voice processing mean time" unit=" ms" rows={[{ label: 'Vosk transcription', value: voiceBenchmark.transcription.mean_ms }, { label: 'Transcript encryption', value: voiceBenchmark.transcript_encryption.mean_ms }, { label: 'Transcript decryption', value: voiceBenchmark.transcript_decryption.mean_ms }]} />
                <p className="admin-analysis-note">{voiceBenchmark.measurement_scope}. {voiceBenchmark.note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">CONTROLLED SECURITY LAB</span><h3>Run isolated demonstrations</h3></div></div>
              <p>Seven bounded, in-memory examples. They do not change accounts, messages, audit rows, or send traffic.</p>
              <button className="secondary-button" type="button" onClick={handleRunSecurityDemos} disabled={securityDemosLoading}>
                {securityDemosLoading ? 'Running demonstrations…' : 'Run all seven demonstrations'}
              </button>
              {securityDemos && <>
                <div className="admin-metric-grid">
                  <div><span>Scenarios passed</span><strong>{securityDemos.scenarios.filter((scenario) => scenario.passed).length} / {securityDemos.scenarios.length}</strong></div>
                  <div><span>Scope</span><strong>{securityDemos.scope}</strong></div>
                </div>
                {securityDemos.scenarios.map((scenario) => <article className="message-item" key={scenario.name}>
                  <strong>{scenario.passed ? 'PASS' : 'FAIL'} · {scenario.name}</strong>
                  <p><b>Setup:</b> {scenario.setup}</p>
                  <p><b>Expected:</b> {scenario.expected}</p>
                  <p><b>Observed:</b> {scenario.observed}</p>
                  <p className="admin-analysis-note"><b>Limit:</b> {scenario.limitations}</p>
                </article>)}
                <p className="admin-analysis-note">{securityDemos.note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">HASHING</span><h3>SHA-256 properties and timing</h3></div></div>
              <p>Uses the sample text entered in the text-analysis section. Reduced-digest searches are bounded teaching examples, never attacks on full SHA-256.</p>
              <button className="secondary-button" type="button" onClick={handleRunHashAnalysis} disabled={hashAnalysisLoading || !textAnalysisSample.trim()}>
                {hashAnalysisLoading ? 'Calculating…' : 'Run hash analysis'}
              </button>
              {hashAnalysis && <>
                <div className="admin-metric-grid">
                  <div><span>Digest</span><strong>SHA-256</strong></div>
                  <div><span>Input size</span><strong>{hashAnalysis.input_bytes} bytes</strong></div>
                  <div><span>Generation time</span><strong>{hashAnalysis.generation_time_ms} ms</strong></div>
                  <div><span>Changed digest bits</span><strong>{hashAnalysis.digest_changed_bits} / {hashAnalysis.digest_output_bits}</strong></div>
                </div>
                <code className="analysis-hash-value">{hashAnalysis.digest_hex}</code>
                <div className="admin-table-wrap"><table className="admin-analysis-table"><thead><tr><th>Input size</th><th>Mean SHA-256 time</th></tr></thead><tbody>{hashAnalysis.size_benchmarks.map((row) => <tr key={row.bytes}><td>{row.bytes} bytes</td><td>{row.mean_generation_time_ms} ms</td></tr>)}</tbody></table></div>
                <MetricBarChart title="SHA-256 time by input size" unit=" ms" rows={hashAnalysis.size_benchmarks.map((row) => ({ label: `${row.bytes} B`, value: row.mean_generation_time_ms }))} />
                <div className="admin-table-wrap"><table className="admin-analysis-table"><thead><tr><th>Concept</th><th>Attempts</th><th>Time</th><th>Limit</th></tr></thead><tbody>
                  <tr><td>Pre-image</td><td>{hashAnalysis.toy_demonstration.preimage_attempts ?? 'Not found'}</td><td>{hashAnalysis.toy_demonstration.preimage_time_ms} ms</td><td>{hashAnalysis.toy_demonstration.attempt_limit}</td></tr>
                  <tr><td>Second pre-image</td><td>{hashAnalysis.toy_demonstration.second_preimage_attempts ?? 'Not found'}</td><td>{hashAnalysis.toy_demonstration.second_preimage_time_ms} ms</td><td>{hashAnalysis.toy_demonstration.attempt_limit}</td></tr>
                  <tr><td>Collision</td><td>{hashAnalysis.toy_demonstration.collision_attempts ?? 'Not found'}</td><td>{hashAnalysis.toy_demonstration.collision_time_ms} ms</td><td>{hashAnalysis.toy_demonstration.attempt_limit}</td></tr>
                </tbody></table></div>
                <p className="admin-analysis-note">{hashAnalysis.toy_demonstration.note} {hashAnalysis.security_note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">DIGITAL SIGNATURE</span><h3>Ed25519 signing and verification</h3></div></div>
              <p>Creates an ephemeral key for the sample text. The private key is discarded and never displayed or stored.</p>
              <button className="secondary-button" type="button" onClick={handleRunSignatureDemo} disabled={signatureDemoLoading || !textAnalysisSample.trim()}>
                {signatureDemoLoading ? 'Signing…' : 'Run signature demonstration'}
              </button>
              {signatureDemo && <>
                <div className="admin-metric-grid">
                  <div><span>Algorithm</span><strong>{signatureDemo.algorithm}</strong></div>
                  <div><span>Signature time</span><strong>{signatureDemo.signature_generation_time_ms} ms</strong></div>
                  <div><span>Verification time</span><strong>{signatureDemo.verification_time_ms} ms</strong></div>
                  <div><span>Valid signature</span><strong>{signatureDemo.valid_signature_verified ? 'Accepted' : 'Rejected'}</strong></div>
                  <div><span>Edited message</span><strong>{signatureDemo.modified_message_verified ? 'Accepted' : 'Rejected'}</strong></div>
                </div>
                <MetricBarChart title="Ed25519 signing and verification time" unit=" ms" rows={[{ label: 'Sign', value: signatureDemo.signature_generation_time_ms }, { label: 'Verify', value: signatureDemo.verification_time_ms }]} />
                <p className="analysis-hash-label">Public key</p><code className="analysis-hash-value">{signatureDemo.public_key_base64}</code>
                <p className="analysis-hash-label">Signature</p><code className="analysis-hash-value">{signatureDemo.signature_base64}</code>
                <p className="admin-analysis-note">{signatureDemo.note}</p>
              </>}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading">
                <div>
                  <span className="eyebrow">IMAGE SECURITY</span>
                  <h3>Image metrics</h3>
                </div>
              </div>
              <p>Calculate the synopsis metrics and timing for a temporary AES-GCM image analysis. The selected file is analyzed in memory and is not saved.</p>
              <label className="admin-file-picker">
                <span>{selectedAnalysisImage?.name || 'Choose an image (up to 8 MB)'}</span>
                <input
                  type="file"
                  accept="image/*"
                  onChange={(event) => {
                    setSelectedAnalysisImage(event.target.files?.[0] || null)
                    setImageMetrics(null)
                    setImageBenchmark(null)
                    setAnalysisError('')
                  }}
                />
              </label>
              <button className="secondary-button" type="button" onClick={handleRunImageMetrics} disabled={imageMetricsLoading || !selectedAnalysisImage}>
                {imageMetricsLoading ? 'Analyzing image…' : 'Run image analysis'}
              </button>
              <button className="secondary-button" type="button" onClick={handleRunImageBenchmark} disabled={imageBenchmarkLoading || !selectedAnalysisImage}>
                {imageBenchmarkLoading ? 'Running image benchmark…' : 'Run 3-pass image benchmark'}
              </button>
              {imageBenchmark && <>
                <p className="admin-result-caption">{imageBenchmark.summary.image} · {imageBenchmark.measurements} passes · analyzed {imageBenchmark.summary.shape?.join(' × ')} px</p>
                <div className="admin-table-wrap">
                  <table className="admin-analysis-table"><thead><tr><th>Pass</th><th>Encrypt</th><th>Decrypt</th><th>Total crypto</th><th>Full analysis</th><th>Cipher entropy</th><th>NPCR</th><th>UACI</th></tr></thead>
                    <tbody>{imageBenchmark.runs.map((run) => <tr key={run.run}><td>{run.run}</td><td>{run.encryption_ms} ms</td><td>{run.decryption_ms} ms</td><td>{run.total_crypto_ms} ms</td><td>{run.end_to_end_analysis_ms} ms</td><td>{run.entropy_cipher}</td><td>{run.npcr_percent}%</td><td>{run.uaci_percent}%</td></tr>)}</tbody>
                  </table>
                </div>
                <div className="admin-metric-grid">
                  <div><span>Mean encryption</span><strong>{imageBenchmark.summary.mean_encryption_ms} ms</strong></div>
                  <div><span>Median encryption</span><strong>{imageBenchmark.summary.median_encryption_ms} ms</strong></div>
                  <div><span>Mean decryption</span><strong>{imageBenchmark.summary.mean_decryption_ms} ms</strong></div>
                  <div><span>Mean total crypto</span><strong>{imageBenchmark.summary.mean_total_crypto_ms} ms</strong></div>
                  <div><span>Mean full analysis</span><strong>{imageBenchmark.summary.mean_end_to_end_analysis_ms} ms</strong></div>
                </div>
                <MetricBarChart title="Image encryption time per pass" unit=" ms" rows={imageBenchmark.runs.map((run) => ({ label: `Pass ${run.run}`, value: run.encryption_ms }))} />
                <MetricBarChart title="Image decryption time per pass" unit=" ms" rows={imageBenchmark.runs.map((run) => ({ label: `Pass ${run.run}`, value: run.decryption_ms }))} />
                <div className="admin-table-wrap">
                  <table className="admin-analysis-table"><thead><tr><th>Scaled image size</th><th>Encryption mean / median</th><th>Decryption mean / median</th><th>Encryption / decryption speed</th><th>Entropy</th><th>NPCR / UACI</th><th>Correlation H / V / D</th><th>Decrypted MSE / PSNR</th></tr></thead>
                    <tbody>{imageBenchmark.size_sweep.map((row) => <tr key={row.target_long_side}><td>{row.shape.join(' × ')} px · {row.pixels.toLocaleString()} pixels</td><td>{row.encryption_ms_mean} / {row.encryption_ms_median} ms</td><td>{row.decryption_ms_mean} / {row.decryption_ms_median} ms</td><td>{row.encryption_mib_per_second} / {row.decryption_mib_per_second} MiB/s</td><td>{row.entropy_plain} / {row.entropy_cipher}</td><td>{row.npcr_percent}% / {row.uaci_percent}%</td><td>{row.correlation_cipher_h} / {row.correlation_cipher_v} / {row.correlation_cipher_d}</td><td>{row.mse_decrypted} / {row.psnr_decrypted_db} dB</td></tr>)}</tbody>
                  </table>
                </div>
                <MetricBarChart title="Image encryption time by pixel count" unit=" ms" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.encryption_ms_mean }))} />
                <MetricBarChart title="Image decryption time by pixel count" unit=" ms" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.decryption_ms_mean }))} />
                <MetricBarChart title="Image throughput by pixel count (encryption)" unit=" MiB/s" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.encryption_mib_per_second }))} />
                <MetricBarChart title="Image entropy by pixel count" unit=" bits" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.entropy_cipher }))} />
                <MetricBarChart title="Image NPCR by pixel count" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.npcr_percent }))} />
                <MetricBarChart title="Image UACI by pixel count" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.uaci_percent }))} />
                <MetricBarChart title="Cipher correlation by pixel count (horizontal)" unit="" rows={imageBenchmark.size_sweep.map((row) => ({ label: `${row.pixels.toLocaleString()} px`, value: row.correlation_cipher_h }))} />
                <p className="admin-analysis-note">Decrypted MSE is expected to remain 0 and decrypted PSNR to be infinite because AES-GCM recovery is exact. The other figures are evaluations of the ciphertext-byte visualization, not proof of image-cipher strength.</p>
                <p className="admin-analysis-note">{imageBenchmark.note}</p>
              </>}
              {imageMetrics && (
                <>
                  <p className="admin-result-caption">{imageMetrics.image} · source {imageMetrics.source_shape?.join(' × ')} px · analyzed {imageMetrics.shape?.join(' × ')} px{imageMetrics.downsampled_for_analysis ? ' (downsampled to keep analysis memory bounded)' : ''}</p>
                  <div className="analysis-image-previews">
                    {imageMetrics.source_image_data_url && <figure><img src={imageMetrics.source_image_data_url} alt="Selected source image" /><figcaption>Source image</figcaption></figure>}
                    {imageMetrics.ciphertext_image_data_url && <figure><img src={imageMetrics.ciphertext_image_data_url} alt="Ciphertext bytes rendered as a noisy grayscale image" /><figcaption>Encrypted byte visualization</figcaption></figure>}
                  </div>
                  <p className="admin-analysis-note">{imageMetrics.ciphertext_visualization_note}</p>
                  <div className="admin-metric-grid">
                    <div><span>Plain entropy</span><strong>{formatMetric(imageMetrics.entropy_plain)} bits</strong></div>
                    <div><span>Cipher entropy</span><strong>{formatMetric(imageMetrics.entropy_cipher)} bits</strong></div>
                    <div><span>NPCR</span><strong>{formatMetric(imageMetrics.npcr_percent, '%')}</strong></div>
                    <div><span>UACI</span><strong>{formatMetric(imageMetrics.uaci_percent, '%')}</strong></div>
                    <div><span>Plain correlation H / V / D</span><strong>{formatMetric(imageMetrics.correlation_plain_h)} / {formatMetric(imageMetrics.correlation_plain_v)} / {formatMetric(imageMetrics.correlation_plain_d)}</strong></div>
                    <div><span>Cipher correlation H / V / D</span><strong>{formatMetric(imageMetrics.correlation_cipher_h)} / {formatMetric(imageMetrics.correlation_cipher_v)} / {formatMetric(imageMetrics.correlation_cipher_d)}</strong></div>
                    <div><span>Decrypted image MSE</span><strong>{formatMetric(imageMetrics.mse_decrypted)}</strong></div>
                    <div><span>Decrypted image PSNR</span><strong>{formatMetric(imageMetrics.psnr_decrypted_db, ' dB')}</strong></div>
                    <div><span>Ciphertext MSE / PSNR</span><strong>Not applicable</strong></div>
                    <div><span>Encryption time</span><strong>{formatMetric(imageMetrics.encryption_time_ms, ' ms')}</strong></div>
                    <div><span>Decryption time</span><strong>{formatMetric(imageMetrics.decryption_time_ms, ' ms')}</strong></div>
                    <div><span>Total crypto time</span><strong>{formatMetric(imageMetrics.total_crypto_time_ms, ' ms')}</strong></div>
                    <div><span>Ciphertext size</span><strong>{imageMetrics.ciphertext_bytes} bytes</strong></div>
                  </div>
                  <MetricBarChart title="Image entropy (bits per pixel)" unit=" bits" rows={[{ label: 'Plain', value: imageMetrics.entropy_plain }, { label: 'Cipher view', value: imageMetrics.entropy_cipher }]} />
                  <MetricBarChart title="Ciphertext pixel-change metrics" rows={[{ label: 'NPCR', value: imageMetrics.npcr_percent }, { label: 'UACI', value: imageMetrics.uaci_percent }]} />
                  <MetricBarChart title="Adjacent pixel correlation (cipher view)" unit="" rows={[{ label: 'Horizontal', value: imageMetrics.correlation_cipher_h }, { label: 'Vertical', value: imageMetrics.correlation_cipher_v }, { label: 'Diagonal', value: imageMetrics.correlation_cipher_d }]} />
                  <p className="admin-analysis-note">Ciphertext-vs-plaintext MSE and PSNR are not meaningful because encrypted bytes are not a distorted version of the source image. Ciphertext entropy should approach 8 bits per byte and adjacent ciphertext-byte correlation should be near zero. Under this controlled AES-GCM counter-mode experiment, a one-bit plaintext change alters the corresponding ciphertext bit, so classic image-cipher reference values near 100% NPCR and 33% UACI do not apply. Exact decryption gives MSE 0 and infinite PSNR.</p>
                  <p className="admin-analysis-note">{imageMetrics.metric_note} These statistical results are evaluation aids, not a substitute for cryptographic review.</p>
                </>
              )}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading">
                <div><span className="eyebrow">TEXT SECURITY</span><h3>Text, AES and hash analysis</h3></div>
              </div>
              <p>Enter a sample. It is processed in memory for this run and is not saved to the database.</p>
              <textarea className="analysis-text-input" value={textAnalysisSample} onChange={(event) => setTextAnalysisSample(event.target.value)} maxLength={1000000} aria-label="Sample text to analyze" />
              <button className="secondary-button" type="button" onClick={handleRunTextAnalysis} disabled={textAnalysisLoading || !textAnalysisSample.trim()}>
                {textAnalysisLoading ? 'Analyzing text…' : 'Run text analysis'}
              </button>
              {textAnalysis && (
                <>
                  <div className="admin-metric-grid">
                    <div><span>Input size</span><strong>{textAnalysis.input_bytes} bytes</strong></div>
                    <div><span>Ciphertext size</span><strong>{textAnalysis.ciphertext_bytes} bytes</strong></div>
                    <div><span>Encryption</span><strong>{formatMetric(textAnalysis.encryption_time_ms, ' ms')}</strong></div>
                    <div><span>Decryption</span><strong>{formatMetric(textAnalysis.decryption_time_ms, ' ms')}</strong></div>
                    <div><span>Total crypto time</span><strong>{formatMetric(textAnalysis.total_crypto_time_ms, ' ms')}</strong></div>
                    <div><span>Recovery check</span><strong>{textAnalysis.recovery_matches ? 'Passed' : 'Failed'}</strong></div>
                  </div>
                  <div className="admin-table-wrap">
                    <table className="admin-analysis-table">
                      <thead><tr><th>Evaluation</th><th>Changed output bits</th><th>Changed</th><th>Interpretation</th></tr></thead>
                      <tbody>
                        <tr><td>AES diffusion</td><td>{textAnalysis.diffusion_average_changed_bits} avg / {textAnalysis.aes_block_bits} (range {textAnalysis.diffusion_min_changed_bits}–{textAnalysis.diffusion_max_changed_bits})</td><td>{textAnalysis.diffusion_percent}%</td><td>Mean across all 128 input-bit flips</td></tr>
                        <tr><td>AES avalanche</td><td>{textAnalysis.avalanche_changed_bits} / {textAnalysis.aes_block_bits}</td><td>{textAnalysis.avalanche_percent}%</td><td>One plaintext bit flip</td></tr>
                        <tr><td>AES avalanche · hex characters</td><td>{textAnalysis.avalanche_mean_changed_hex_characters} / {textAnalysis.aes_block_hex_characters} mean</td><td>{textAnalysis.avalanche_mean_hex_character_change_percent}%</td><td>{textAnalysis.avalanche_rounds} samples · lab reference 100%</td></tr>
                        <tr><td>AES confusion</td><td>{textAnalysis.confusion_changed_bits} / {textAnalysis.aes_block_bits}</td><td>{textAnalysis.confusion_percent}%</td><td>Flip one key bit</td></tr>
                        <tr><td>SHA-256 avalanche</td><td>{textAnalysis.hash_avalanche_changed_bits} / {textAnalysis.hash_output_bits}</td><td>{textAnalysis.hash_avalanche_percent}%</td><td>Flip one input bit</td></tr>
                      </tbody>
                    </table>
                  </div>
                  <div className="admin-table-wrap">
                    <table className="admin-analysis-table">
                      <thead><tr><th>Sample bytes</th><th>Ciphertext bytes</th><th>Encryption</th><th>Decryption</th><th>Total</th><th>Throughput</th></tr></thead>
                      <tbody><tr>
                        <td>{textAnalysis.input_bytes}</td><td>{textAnalysis.ciphertext_bytes}</td>
                        <td>{formatMetric(textAnalysis.encryption_time_ms, ' ms')}</td>
                        <td>{formatMetric(textAnalysis.decryption_time_ms, ' ms')}</td>
                        <td>{formatMetric(textAnalysis.total_crypto_time_ms, ' ms')}</td>
                        <td>{textAnalysis.total_crypto_time_ms > 0 ? `${(textAnalysis.input_bytes / (textAnalysis.total_crypto_time_ms / 1000) / 1048576).toFixed(3)} MiB/s` : '—'}</td>
                      </tr></tbody>
                    </table>
                  </div>
                  <MetricBarChart title="Output changes in controlled samples" rows={[{ label: 'AES diffusion (bits)', value: textAnalysis.diffusion_percent }, { label: 'AES avalanche (bits)', value: textAnalysis.avalanche_mean_percent }, { label: 'AES avalanche (hex chars)', value: textAnalysis.avalanche_mean_hex_character_change_percent }, { label: 'AES confusion (bits)', value: textAnalysis.confusion_percent }, { label: 'SHA-256 avalanche (bits)', value: textAnalysis.hash_avalanche_percent }]} />
                  <MetricBarChart title="Avalanche percent per sample (output bits)" rows={textAnalysis.avalanche_samples.map((sample) => ({ label: `Sample ${sample.sample}`, value: sample.bit_change_percent }))} />
                  <p className="analysis-hash-label">SHA-256 of sample text</p><code className="analysis-hash-value">{textAnalysis.sample_text_sha256}</code>
                  <p className="analysis-hash-label">SHA-256 of ciphertext</p><code className="analysis-hash-value">{textAnalysis.ciphertext_sha256}</code>
                  <p className="admin-analysis-note">{textAnalysis.analysis_note}</p>
                  <p className="admin-analysis-note">{textAnalysis.hash_security_note}</p>
                  <p className="admin-analysis-note"><strong>Preimage resistance:</strong> finding any input for a chosen digest. <strong>Collision resistance:</strong> finding any two different inputs with the same digest. SHA-256's generic estimates are theoretical, not a result of this sample run.</p>
                </>
              )}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">VOICE PERFORMANCE</span><h3>Offline transcription time</h3></div><button className="secondary-button" type="button" onClick={refreshLogs}>Refresh timings</button></div>
              {(() => {
                const voiceRuns = auditEvents
                  .filter((event) => event.event_type === 'VOICE_CLIENT_TRANSCRIPTION_COMPLETED')
                  .slice(0, 8)
                  .map((event) => {
                    const match = event.details.match(/transcription_time_ms=([0-9.]+)/)
                    return { event, value: match ? Number(match[1]) : null }
                  })
                  .filter((run) => run.value !== null)
                return voiceRuns.length ? (
                  <>
                    <MetricTrendChart title="Recent on-device transcription time" unit=" ms" rows={voiceRuns.slice().reverse().map((run, index) => ({ label: `Run ${index + 1}`, value: run.value }))} />
                    <div className="admin-table-wrap">
                      <table className="admin-analysis-table"><thead><tr><th>When</th><th>User</th><th>Audio size</th><th>Transcription time</th></tr></thead>
                        <tbody>{voiceRuns.map(({ event, value }) => {
                          const size = event.details.match(/audio_bytes=(\d+)/)?.[1]
                          return <tr key={event.id}><td>{event.created_at ? new Date(event.created_at).toLocaleString() : '—'}</td><td>{event.actor_id || '—'}</td><td>{size ? `${size} B` : '—'}</td><td>{value.toFixed(3)} ms</td></tr>
                        })}</tbody>
                      </table>
                    </div>
                    <p className="admin-analysis-note">Only audio size and elapsed transcription time are logged; audio and transcript content remain on the sender device. Times exclude recording and network transfer.</p>
                  </>
                ) : <p className="empty-state">No voice transcription timings have been recorded yet.</p>
              })()}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading"><div><span className="eyebrow">TRANSFER PERFORMANCE</span><h3>End-to-end delivery latency</h3></div></div>
              {(() => {
                const delivered = messageLogs.filter((message) => Number.isFinite(message.transfer_latency_ms))
                return delivered.length ? (
                  <>
                    <MetricTrendChart title="Recent send-to-receive times" unit=" ms" rows={delivered.slice(0, 8).reverse().map((message, index) => ({ label: `${message.message_type} ${index + 1}`, value: message.transfer_latency_ms }))} />
                    <p className="admin-analysis-note">Measured from the server's stored send time until the receiver successfully decrypts and acknowledges the message. Includes waiting and network delay; it is not just AES processing time.</p>
                  </>
                ) : <p className="empty-state">No completed message transfers have a receive time yet.</p>
              })()}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading">
                <div>
                  <span className="eyebrow">PROCESSING PERFORMANCE</span>
                  <h3>AES-GCM benchmark</h3>
                </div>
              </div>
              <p>Measures backend encryption, decryption and total crypto time at several payload sizes, with overhead and throughput.</p>
              <button className="secondary-button" type="button" onClick={handleRunBenchmark} disabled={benchmarkLoading}>
                {benchmarkLoading ? 'Running benchmark…' : 'Run performance benchmark'}
              </button>
              <button className="secondary-button" type="button" onClick={handleExportBenchmarkCsv}>
                Run and download CSV
              </button>
              {benchmark && (
                <>
                  <p className="admin-result-caption">Measured {benchmark.measured_at_utc || 'just now'} · {benchmark.rounds} rounds per size</p>
                  <div className="admin-table-wrap">
                    <table className="admin-analysis-table">
                      <thead><tr><th>Payload</th><th>Copy baseline</th><th>Encrypt mean / median</th><th>Decrypt mean / median</th><th>Total mean / median</th><th>Overhead</th><th>Encrypt / decrypt speed</th></tr></thead>
                      <tbody>
                        {benchmark.results.map((row) => (
                          <tr key={row.bytes}>
                            <td>{row.bytes >= 1048576 ? `${(row.bytes / 1048576).toFixed(0)} MiB` : row.bytes >= 1024 ? `${(row.bytes / 1024).toFixed(0)} KiB` : `${row.bytes} B`}</td>
                            <td>{row.baseline_copy_ms} ms</td>
                            <td>{row.encryption_ms} / {row.encryption_ms_median} ms</td>
                            <td>{row.decryption_ms} / {row.decryption_ms_median} ms</td>
                            <td>{row.total_crypto_ms} / {row.total_crypto_ms_median} ms</td>
                            <td>{row.crypto_overhead_bytes} B · {row.crypto_overhead_percent}%</td>
                            <td>{row.encryption_mib_per_second} / {row.decryption_mib_per_second} MiB/s</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <MetricBarChart title="Total AES-GCM crypto time by payload size" unit=" ms" rows={benchmark.results.map((row) => ({ label: row.bytes >= 1048576 ? `${(row.bytes / 1048576).toFixed(0)} MiB` : `${Math.round(row.bytes / 1024)} KiB`, value: row.total_crypto_ms }))} />
                  <MetricTrendChart title="AES-GCM throughput by payload size" unit=" MiB/s" rows={benchmark.results.map((row) => ({ label: row.bytes >= 1048576 ? `${(row.bytes / 1048576).toFixed(0)} MiB` : `${Math.round(row.bytes / 1024)} KiB`, value: row.encryption_mib_per_second }))} />
                  <p className="admin-analysis-note">{benchmark.note}</p>
                </>
              )}
            </article>

            <article className="admin-analysis-card">
              <div className="admin-analysis-heading">
                <div>
                  <span className="eyebrow">SENTINEL MONITOR</span>
                  <h3>Runtime signals</h3>
                </div>
                <button className="secondary-button" type="button" onClick={refreshMonitor}>Refresh</button>
              </div>
              {monitorError ? (
                <p className="monitor-unavailable">{monitorError}</p>
              ) : monitorStatus ? (
                <>
                  <span className={`monitor-indicator ${monitorStatus.pyshark_available ? 'available' : 'unavailable'}`}>
                    PyShark {monitorStatus.pyshark_available ? 'available' : 'not detected'}
                  </span>
                  <p className="admin-monitor-alert">{monitorStatus.alert}</p>
                  <p className="admin-analysis-note">{monitorStatus.note} Application event count: {monitorStatus.suspicious_count} suspicious signal(s).</p>
                  {monitorStatus.recent_events?.length ? (
                    <div className="admin-monitor-events">
                      {[...monitorStatus.recent_events].reverse().slice(0, 8).map((event, index) => (
                        <div className="admin-monitor-event" key={`${event.created_at}-${index}`}>
                          <strong>{event.kind}</strong>
                          <span>{event.created_at ? new Date(event.created_at).toLocaleString() : 'Time unavailable'}</span>
                          <p>{event.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : <p className="empty-state">No runtime security signals recorded by this process.</p>}
                </>
              ) : <p className="empty-state">Loading monitor status…</p>}
            </article>
          </div>
        </section>

        <section className="workspace-panel security-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">ADMIN ONLY</span>
              <h2>Message transfer records</h2>
              <p>Sender, recipient, send/receive times, ciphertext digest, nonce, authentication tag, and audit signature. Plaintext is not stored in these records.</p>
            </div>
          </div>
          {messageLogs.length === 0 ? (
            <p className="empty-state">No message transfers are recorded yet.</p>
          ) : (
            <>
            <MetricBarChart title="Message delivery status" unit=" transfers" rows={[{ label: 'Received', value: messageLogs.filter((message) => Boolean(message.received_at)).length }, { label: 'Awaiting receipt', value: messageLogs.filter((message) => !message.received_at).length }]} />
            <MetricBarChart title="Transfers by content type" unit=" transfers" rows={Object.entries(messageLogs.reduce((counts, message) => {
              const type = message.message_type || 'other'
              counts[type] = (counts[type] || 0) + 1
              return counts
            }, {})).map(([label, value]) => ({ label, value }))} />
            <div className="message-list admin-record-list">
              {messageLogs.map((message) => {
                const details = messageDetails[message.id]
                return (
                  <article className="message-item" key={message.id}>
                    <div>
                      <strong>{message.message_type} · #{message.sequence_number}</strong>
                      <span>{message.sender || 'Unknown sender'} → {message.recipient || 'Unknown recipient'}</span>
                    </div>
                    <p>Sent: {message.sent_at ? new Date(message.sent_at).toLocaleString() : 'Unknown'} · Received: {message.received_at ? new Date(message.received_at).toLocaleString() : 'Not yet received'}</p>
                    {Number.isFinite(message.transfer_latency_ms) && <p>End-to-end delivery: {message.transfer_latency_ms.toFixed(3)} ms</p>}
                    {message.filename && <p>File: {message.filename}</p>}
                    <p>SHA-256: <code>{message.ciphertext_sha256 || 'Unavailable'}</code></p>
                    <button className="secondary-button" type="button" onClick={() => toggleMessage(message.id)}>
                      {expandedId === message.id ? 'Hide encrypted details' : 'View encrypted details'}
                    </button>
                    {expandedId === message.id && (
                      <div className="pairing-verification transfer-details">
                        {details ? (
                          <>
                            <h3>Transfer details</h3>
                            <p className="transfer-details-intro">These values describe the encrypted file transfer. The original file contents are not shown here.</p>

                            <div className="transfer-summary-grid">
                              <div className="transfer-summary-item">
                                <span>Sender</span>
                                <strong>{details.sender || 'Unknown'}</strong>
                              </div>
                              <div className="transfer-summary-item">
                                <span>Recipient</span>
                                <strong>{details.recipient || 'Unknown'}</strong>
                              </div>
                              <div className="transfer-summary-item">
                                <span>Sequence</span>
                                <strong>#{details.sequence_number}</strong>
                              </div>
                              <div className="transfer-summary-item">
                                <span>Received</span>
                                <strong>{details.received_at ? new Date(details.received_at).toLocaleString() : 'Not yet received'}</strong>
                              </div>
                              <div className="transfer-summary-item">
                                <span>Encrypted size</span>
                                <strong>{details.ciphertext_bytes ?? 'Unknown'} bytes</strong>
                              </div>
                            </div>

                            <div className="transfer-field">
                              <div className="transfer-field-heading">
                                <strong>SHA-256 of ciphertext</strong>
                                <span>Fingerprint used to detect changes to the encrypted data.</span>
                              </div>
                              <code className="transfer-code">{details.ciphertext_sha256 || 'Unavailable'}</code>
                            </div>

                            <div className="transfer-summary-grid transfer-crypto-grid">
                              <div className="transfer-field">
                                <div className="transfer-field-heading">
                                  <strong>Nonce</strong>
                                  <span>A unique value used by AES-GCM for this encryption.</span>
                                </div>
                                <code className="transfer-code">{details.nonce || 'Unavailable'}</code>
                              </div>
                              <div className="transfer-field">
                                <div className="transfer-field-heading">
                                  <strong>AES-GCM authentication tag</strong>
                                  <span>Lets the receiver detect altered ciphertext.</span>
                                </div>
                                <code className="transfer-code">{details.authentication_tag || 'Unavailable'}</code>
                              </div>
                            </div>

                            <section className="transfer-field signature-field">
                              <div className="transfer-field-heading">
                                <strong>Server audit signature</strong>
                                <span>{details.signature_algorithm || 'Ed25519'} — signs the audit metadata, not the sender’s device.</span>
                              </div>
                              <span className={details.signature_valid ? 'signature-status valid' : 'signature-status invalid'}>
                                {details.signature_valid ? 'Signature verifies' : 'Signature missing or invalid'}
                              </span>
                              <textarea className="audit-value" readOnly rows={3} value={details.signature || 'No signature recorded'} aria-label="Server audit signature" />
                              <div className="signature-key">
                                <strong>Server public key</strong>
                                <span>{signatureNote}</span>
                                <code className="transfer-code">{signaturePublicKey || 'Unavailable'}</code>
                              </div>
                            </section>

                            <details className="transfer-technical-details">
                              <summary>Show signed metadata</summary>
                              <p>The signature covers these fields. Use them with the server’s public signing key to check what was signed.</p>
                              <pre className="transfer-code transfer-json">{JSON.stringify(details.signature_payload, null, 2) || 'Unavailable'}</pre>
                            </details>

                            {details.ciphertext_image_preview && (
                              <section className="transfer-field">
                                <div className="transfer-field-heading">
                                  <strong>Encrypted image visualization</strong>
                                  <span>{details.ciphertext_image_preview_note}</span>
                                </div>
                                <div className="actual-cipher-preview"><img src={details.ciphertext_image_preview} alt="Actual image-transfer ciphertext rendered as noisy pixels" /></div>
                              </section>
                            )}

                            <section className="transfer-field ciphertext-field">
                              <div className="transfer-field-heading">
                                <strong>Encrypted data (ciphertext)</strong>
                                <span>Hexadecimal representation of the encrypted file. This is not the original image.</span>
                              </div>
                              <textarea className="audit-value" readOnly rows={8} value={details.ciphertext || 'No ciphertext recorded'} aria-label="Encrypted ciphertext" />
                            </section>
                          </>
                        ) : <p>Loading encrypted details…</p>}
                      </div>
                    )}
                  </article>
                )
              })}
            </div>
            </>
          )}
        </section>
      </section>
    </main>
  )
}

function App() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('sentineldrop_theme')
    return THEMES.some((option) => option.id === saved) ? saved : 'midnight'
  })
  const [authenticated, setAuthenticated] = useState(Boolean(getStoredToken()))
  const [isAdmin, setIsAdmin] = useState(getStoredIsAdmin())
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState(getStoredUsername() || '')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [showMessages, setShowMessages] = useState(true)
  const [messageText, setMessageText] = useState('')
  const [pendingMessageType, setPendingMessageType] = useState('text')
  const [messages, setMessages] = useState([])
  const [files, setFiles] = useState([])
  const [messageLoading, setMessageLoading] = useState(false)
  const [transferError, setTransferError] = useState('')
  const [inboxError, setInboxError] = useState('')
  const [transferStatus, setTransferStatus] = useState('')
  const [localPayload, setLocalPayload] = useState('')
  const [localFingerprint, setLocalFingerprint] = useState('')
  const [localQrUrl, setLocalQrUrl] = useState('')
  const [pairingInput, setPairingInput] = useState('')
  const [pairingVerification, setPairingVerification] = useState(null)
  const [pairingLoading, setPairingLoading] = useState(false)
  const [pairingConfirmed, setPairingConfirmed] = useState(
    Boolean(localStorage.getItem(PAIRED_FINGERPRINT_KEY) && getStoredPeerPublicKey())
  )
  const [dashboard, setDashboard] = useState(null)
  const [fileName, setFileName] = useState('')
  const [selectedFile, setSelectedFile] = useState(null)
  const [recording, setRecording] = useState(false)
  const [voiceProcessing, setVoiceProcessing] = useState(false)
  const [scanning, setScanning] = useState(false)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('sentineldrop_theme', theme)
  }, [theme])
  const inboxBusy = useRef(false)
  const videoRef = useRef(null)
  const scanControlsRef = useRef(null)
  const scanHandledRef = useRef(false)
  const voiceCaptureRef = useRef(null)

  useEffect(() => {
    const expireSession = () => {
      setAuthenticated(false)
      setIsAdmin(false)
      setMode('login')
      setPairingConfirmed(false)
      setTransferStatus('')
      setTransferError('')
      setInboxError('')
      setMessages([])
      files.forEach((file) => {
        if (file.object_url) URL.revokeObjectURL(file.object_url)
      })
      setFiles([])
      setPassword('')
      setSuccess('')
      setError('Your server session expired or was reset. Sign in again to continue. If your account no longer exists, register it again.')
    }
    window.addEventListener('sentineldrop-session-expired', expireSession)
    return () => window.removeEventListener('sentineldrop-session-expired', expireSession)
  }, [files])

  useEffect(() => () => {
    if (voiceCaptureRef.current) {
      releaseVoiceCapture(voiceCaptureRef.current)
      voiceCaptureRef.current = null
    }
  }, [])

  const isLogin = mode !== 'register'
  const isAdminLogin = mode === 'admin-login'

  const refreshSecurity = useCallback(async () => {
    try {
      const dash = await getSecurityDashboard()
      setDashboard(dash)
      const trusted = dash.trusted_devices?.some((device) => device.public_key === getStoredPeerPublicKey())
      setPairingConfirmed(trusted && Boolean(getStoredPeerPublicKey()))
    } catch (err) {
      setDashboard(null)
      if (/token|authenticated user not found/i.test(err.message || '')) {
        setPairingConfirmed(false)
        setError('This server session is no longer valid. Sign out, sign in again, then pair both devices again.')
      }
    }
  }, [])

  const pullInbox = useCallback(async ({ showError = false } = {}) => {
    if (!getStoredPeerPublicKey() || inboxBusy.current) {
      return
    }
    inboxBusy.current = true
    let hadPending = false
    try {
      const pending = await listPendingMessages()
      const failures = []
      const queued = [...(pending.messages || [])].sort((left, right) => {
        const sessionOrder = String(left.session_id).localeCompare(String(right.session_id))
        return sessionOrder || left.sequence_number - right.sequence_number
      })
      hadPending = queued.length > 0
      for (const item of queued) {
        try {
        if (item.transfer_kind === 'file') {
          const received = await receiveFile(item)
          setFiles((current) => [{
            filename: received.filename,
            size: received.size,
            object_url: received.object_url,
            message_type: received.message_type,
            sequence_number: received.sequence_number,
            direction: 'received',
          }, ...current])
          setMessages((current) => [
            ...current,
            {
              text: `Received encrypted ${received.message_type}: ${received.filename}`,
              sequence: received.sequence_number,
              sent: false,
              type: received.message_type,
            },
          ])
        } else {
          const decrypted = await receiveMessage(item)
          setMessages((current) => [
            ...current,
            {
              text: decrypted.message,
              sequence: decrypted.sequence_number,
              sent: false,
              type: decrypted.message_type,
            },
          ])
        }
        } catch (err) {
          failures.push(`Transfer #${item.sequence_number}: ${err.message || 'decryption failed'}`)
        }
      }
      setInboxError(failures.length ? `${failures.length} incoming transfer(s) could not be opened. Other transfers continue. ${failures[0]}` : '')
      await refreshSecurity()
    } catch (err) {
      if (showError || hadPending) {
        setInboxError(err.message || 'Unable to refresh inbox.')
        setError(hadPending
          ? `Incoming transfer could not be opened: ${err.message || 'decryption failed'}. Check that both devices are paired with their current identities.`
          : err.message || 'Unable to refresh inbox.')
      }
    } finally {
      inboxBusy.current = false
    }
  }, [refreshSecurity])

  useEffect(() => {
    if (!authenticated) {
      return undefined
    }
    let qrUrl = ''
    getLocalPairingInfo()
      .then((data) => {
        setLocalPayload(data.payload || '')
        setLocalFingerprint(data.fingerprint || '')
        return getMyPairingQrObjectUrl()
      })
      .then((url) => {
        qrUrl = url
        setLocalQrUrl(url)
      })
      .catch(() => {})
    const refreshTimer = window.setTimeout(() => {
      void refreshSecurity()
    }, 0)
    const timer = setInterval(() => {
      refreshSecurity()
      pullInbox()
    }, 5000)
    return () => {
      window.clearTimeout(refreshTimer)
      clearInterval(timer)
      if (qrUrl) {
        URL.revokeObjectURL(qrUrl)
      }
    }
  }, [authenticated, pairingConfirmed, pullInbox, refreshSecurity])

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)
    try {
      if (isLogin) {
        const data = isAdminLogin
          ? await adminLoginUser(username.trim(), password)
          : await loginUser(username.trim(), password)
        setUsername(data.username || username.trim())
        setIsAdmin(Boolean(data.is_admin))
        setPassword('')
        setAuthenticated(true)
        try {
          if (data.is_admin) return
          const dash = await getSecurityDashboard()
          setDashboard(dash)
          const trusted = dash.trusted_devices?.some((device) => device.public_key === getStoredPeerPublicKey())
          setPairingConfirmed(trusted && Boolean(getStoredPeerPublicKey()))
        } catch {
          setPairingConfirmed(
            Boolean(localStorage.getItem(PAIRED_FINGERPRINT_KEY) && getStoredPeerPublicKey())
          )
        }
      } else {
        const data = await registerUser(username.trim(), password)
        setIsAdmin(false)
        setSuccess(data.message || 'User registered successfully.')
        setMode('login')
        setPassword('')
      }
    } catch (err) {
      setError(err.message || 'Unable to connect to SentinelDrop.')
    } finally {
      setLoading(false)
    }
  }

  async function verifyPairingPayload(payload, scanned = false) {
    const cleanPayload = payload.trim()
    if (!cleanPayload) {
      setError('Paste the other device pairing payload first.')
      return
    }
    setPairingLoading(true)
    setError('')
    setSuccess('')
    try {
      const data = await preparePairing(cleanPayload)
      setPairingVerification(data)
      setSuccess(
        scanned
          ? 'QR scanned and fingerprint verified. Compare it with the other device, then confirm trust.'
          : 'Pairing payload verified. Check the fingerprint before trusting.'
      )
    } catch (err) {
      setError(err.message || 'Unable to verify the pairing payload.')
    } finally {
      setPairingLoading(false)
    }
  }

  async function handlePreparePairing(event) {
    event.preventDefault()
    await verifyPairingPayload(pairingInput)
  }

  async function handleConfirmPairing() {
    if (!pairingVerification) {
      setError('Verify the pairing payload before confirming the device.')
      return
    }
    setPairingLoading(true)
    setError('')
    setSuccess('')
    try {
      const fingerprint =
        pairingVerification.fingerprint || pairingVerification.data?.fingerprint
      await confirmPairing(pairingInput.trim(), fingerprint)
      setPairingConfirmed(true)
      setSuccess(
        'Peer trusted on this device. The other device must also confirm your fingerprint before you can exchange data.'
      )
      await refreshSecurity()
    } catch (err) {
      setError(err.message || 'Unable to confirm and trust the device.')
    } finally {
      setPairingLoading(false)
    }
  }

  async function handleScanQr() {
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('Camera access is unavailable. Open this page over HTTPS and allow camera access in your browser settings.')
      return
    }
    setError('')
    setSuccess('')
    setPairingVerification(null)
    scanHandledRef.current = false
    setScanning(true)
    try {
      const video = videoRef.current
      if (!video) {
        throw new Error('Camera preview is not ready. Please try again.')
      }
      const reader = new BrowserQRCodeReader(
        new Map([[DecodeHintType.TRY_HARDER, true]]),
        { delayBetweenScanAttempts: 250, delayBetweenScanSuccess: 500 }
      )
      const controls = await reader.decodeFromConstraints(
        {
          audio: false,
          video: {
            facingMode: { ideal: 'environment' },
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          },
        },
        video,
        (result, _error, scanControls) => {
          if (result && !scanHandledRef.current) {
            scanHandledRef.current = true
            const payload = result.getText()
            setPairingInput(payload)
            stopScan(scanControls)
            void verifyPairingPayload(payload, true)
          }
        }
      )
      scanControlsRef.current = controls
    } catch (err) {
      scanControlsRef.current?.stop()
      scanControlsRef.current = null
      setScanning(false)
      const cameraErrors = {
        NotAllowedError: 'Camera permission was denied. Allow camera access for this site in your browser settings, then try again.',
        NotFoundError: 'No camera was found on this device.',
        NotReadableError: 'The camera is already in use by another app. Close it and try again.',
      }
      setError(cameraErrors[err.name] || err.message || 'Unable to start the camera. Check browser camera permissions and try again.')
    }
  }

  function stopScan(activeControls = scanControlsRef.current) {
    setScanning(false)
    activeControls?.stop()
    if (scanControlsRef.current === activeControls) {
      scanControlsRef.current = null
    }
    const video = videoRef.current
    const stream = video?.srcObject
    if (stream) {
      stream.getTracks().forEach((track) => track.stop())
      video.srcObject = null
    }
  }

  async function ensureSession() {
    return establishSecureSession()
  }

  async function handleSendMessage(event) {
    event.preventDefault()
    if (!messageText.trim() || !pairingConfirmed) {
      return
    }
    setMessageLoading(true)
    setError('')
    setTransferError('')
    setTransferStatus('Opening a secure session…')
    try {
      const sessionId = await ensureSession()
      setTransferStatus('Encrypting and sending…')
      const messageType = pendingMessageType
      const data = await sendMessage(sessionId, messageText.trim(), messageType)
      setMessages((current) => [
        ...current,
        { text: messageText.trim(), sequence: data.sequence_number, sent: true, type: messageType },
      ])
      setMessageText('')
      setPendingMessageType('text')
      setTransferStatus('Encrypted message queued. Waiting for the other device to receive it.')
      await refreshSecurity()
    } catch (err) {
      localStorage.removeItem('sentineldrop_session_id')
      setTransferStatus('')
      setTransferError(err.message || 'Unable to establish a secure session or send the message.')
      setError(err.message || 'Unable to establish a secure session or send the message.')
    } finally {
      setMessageLoading(false)
    }
  }

  function handleSelectFile(event) {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (file) {
      setSelectedFile(file)
      setError('')
      setSuccess('')
    }
  }

  async function handleSendFile() {
    if (!selectedFile || !pairingConfirmed) {
      return
    }
    const file = selectedFile
    setMessageLoading(true)
    setError('')
    setTransferError('')
    setTransferStatus(`Encrypting and sending ${file.name}…`)
    setSuccess(`Encrypting and sending ${file.name}...`)
    try {
      const sessionId = await ensureSession()
      const kind = file.type.startsWith('image/')
        ? 'image'
        : file.type.startsWith('audio/')
          ? 'audio'
          : 'document'
      const encrypted = await prepareFile(sessionId, file, kind)
      setFileName(encrypted.filename || file.name)
      setSelectedFile(null)
      setFiles((current) => [{
        filename: file.name,
        size: file.size,
        blob: file,
        direction: 'sent',
        message_type: kind,
        sequence_number: encrypted.sequence_number,
      }, ...current])
      setTransferStatus(`Encrypted ${kind} queued. Waiting for the other device to receive it.`)
      setMessages((current) => [
        ...current,
        {
          text: `Encrypted ${kind} sent: ${file.name}`,
          sequence: encrypted.sequence_number,
          sent: true,
          type: kind,
        },
      ])
      setSuccess(`Encrypted ${kind} sent.`)
    } catch (err) {
      localStorage.removeItem('sentineldrop_session_id')
      setTransferStatus('')
      setTransferError(err.message || 'Unable to transfer the file.')
      setError(err.message || 'Unable to transfer the file.')
    } finally {
      setMessageLoading(false)
    }
  }

  async function startVoiceRecording() {
    setError('')
    setSuccess('')
    setVoiceProcessing(true)
    let stream
    let context
    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error('Microphone access requires a secure HTTPS connection or localhost.')
      }
      const AudioContextClass = window.AudioContext || window.webkitAudioContext
      if (!AudioContextClass) {
        throw new Error('Audio recording is not supported by this browser.')
      }
      stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: 1,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        },
      })
      context = new AudioContextClass()
      await context.resume()
      const source = context.createMediaStreamSource(stream)
      const processor = context.createScriptProcessor(4096, 1, 1)
      const silentOutput = context.createGain()
      silentOutput.gain.value = 0
      const chunks = []
      processor.onaudioprocess = (event) => {
        chunks.push(new Float32Array(event.inputBuffer.getChannelData(0)))
      }
      source.connect(processor)
      processor.connect(silentOutput)
      silentOutput.connect(context.destination)
      voiceCaptureRef.current = { stream, context, source, processor, silentOutput, chunks }
      setRecording(true)
      setSuccess('Recording… select “Stop & transcribe” when you are finished speaking.')
    } catch (err) {
      stream?.getTracks().forEach((track) => track.stop())
      if (context && context.state !== 'closed') {
        await context.close().catch(() => {})
      }
      const microphoneErrors = {
        NotAllowedError: 'Microphone permission was denied. Allow microphone access for this site, then try again.',
        NotFoundError: 'No microphone was found on this device.',
        NotReadableError: 'The microphone is already in use by another app.',
      }
      setError(microphoneErrors[err.name] || err.message || 'Unable to start voice recording.')
    } finally {
      setVoiceProcessing(false)
    }
  }

  async function stopVoiceRecording() {
    const capture = voiceCaptureRef.current
    if (!capture) return

    voiceCaptureRef.current = null
    setRecording(false)
    setVoiceProcessing(true)
    setError('')
    setSuccess('Preparing your recording for on-device transcription…')
    try {
      const sourceRate = capture.context.sampleRate
      const length = capture.chunks.reduce((sum, part) => sum + part.length, 0)
      const samples = new Float32Array(length)
      let offset = 0
      capture.chunks.forEach((part) => {
        samples.set(part, offset)
        offset += part.length
      })
      releaseVoiceCapture(capture)
      if (length < sourceRate / 2) {
        throw new Error('The recording was too short. Hold the microphone on, speak, then turn it off.')
      }
      const speechSamples = normalizeVoice(resampleVoice(samples, sourceRate))
      const { transcribeVoiceOffline } = await import('./services/offlineVoice')
      const transcription = await transcribeVoiceOffline(speechSamples, 16000, setSuccess)
      void reportVoiceTranscriptionMetric(speechSamples.byteLength, transcription.transcriptionTimeMs).catch(() => {})
      if (!transcription.text) {
        throw new Error('No words were recognized. Try speaking clearly in English in a quieter place.')
      }
      setMessageText(transcription.text)
      setPendingMessageType('audio_transcript')
      setSuccess('Transcript ready on this device. Audio was not uploaded. Review it, then select “Send transcript”.')
    } catch (err) {
      setSuccess('')
      setError(err.message || 'Voice transcription failed. Please try again.')
    } finally {
      setVoiceProcessing(false)
    }
  }

  async function handleRecordVoice() {
    if (recording) {
      await stopVoiceRecording()
    } else {
      await startVoiceRecording()
    }
  }

  function switchMode() {
    setMode(mode === 'register' ? 'login' : 'register')
    setError('')
    setSuccess('')
    setPassword('')
  }

  function switchAdminLogin() {
    setMode(isAdminLogin ? 'login' : 'admin-login')
    setError('')
    setSuccess('')
    setPassword('')
  }

  async function handleLogout() {
    stopScan()
    if (voiceCaptureRef.current) {
      releaseVoiceCapture(voiceCaptureRef.current)
      voiceCaptureRef.current = null
      setRecording(false)
      setVoiceProcessing(false)
    }
    await logoutUser()
    setAuthenticated(false)
    setIsAdmin(false)
    setMode('login')
    setPassword('')
    setMessages([])
    files.forEach((file) => {
      if (file.object_url) URL.revokeObjectURL(file.object_url)
    })
    setFiles([])
    setMessageText('')
    setPairingInput('')
    setPairingVerification(null)
    setPairingConfirmed(false)
    setDashboard(null)
    localStorage.removeItem(PAIRED_FINGERPRINT_KEY)
  }

  if (authenticated && isAdmin) {
    return <AdminConsole username={username} onSignOut={handleLogout} theme={theme} onThemeChange={setTheme} />
  }

  if (!authenticated) {
    return (
      <main className="app-shell">
        <section className="auth-card">
          <div className="brand">
            <span className="brand-mark">S</span>
            <div>
              <h1>SentinelDrop</h1>
              <p>Secure local transfer</p>
            </div>
          </div>
          <div className="auth-theme-row"><ThemePicker theme={theme} onChange={setTheme} /></div>
          <div className="auth-heading">
            <h2>{isAdminLogin ? 'Administrator sign in' : isLogin ? 'Welcome back' : 'Create your account'}</h2>
            <p>
              {isAdminLogin
                ? 'Sign in with the administrator account configured by the service owner.'
                : isLogin
                ? 'Sign in to pair another device and exchange encrypted evidence.'
                : 'Create an account on this local SentinelDrop server.'}
            </p>
          </div>
          {error && <div className="alert error">{error}</div>}
          {success && <div className="alert success">{success}</div>}
          <form onSubmit={handleSubmit}>
            <label>
              Username
              <input
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Enter username"
                autoComplete="username"
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter password"
                autoComplete={isLogin ? 'current-password' : 'new-password'}
                required
              />
            </label>
            <button className="primary-button" type="submit" disabled={loading}>
              {loading ? 'Please wait...' : isLogin ? 'Sign in' : 'Create account'}
            </button>
          </form>
          <button className="link-button" type="button" onClick={isAdminLogin ? switchAdminLogin : switchMode}>
            {isAdminLogin ? 'Return to user sign in' : isLogin ? 'Need an account? Register' : 'Already have an account? Sign in'}
          </button>
          {mode === 'login' && (
            <button className="link-button" type="button" onClick={switchAdminLogin}>
              Administrator sign in
            </button>
          )}
        </section>
      </main>
    )
  }

  return (
    <main className="dashboard-shell">
      <header className="dashboard-header">
        <div className="brand">
          <span className="brand-mark">S</span>
          <div>
            <h1>SentinelDrop</h1>
            <p>Encrypted send and receive</p>
          </div>
        </div>
        <div className="header-actions">
          <span className="user-label">{username}</span>
          <ThemePicker theme={theme} onChange={setTheme} />
          <button className="secondary-button" type="button" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </header>

      <section className="dashboard-content">
        {error && <div className="alert error">{error}</div>}
        {success && <div className="alert success">{success}</div>}

        <section className="pairing-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">DEVICE SECURITY</span>
              <h2>Pair another device</h2>
              <p>
                Show this QR on one device. On the other, paste or scan the payload,
                compare fingerprints, then confirm. Repeat in the opposite direction.
              </p>
            </div>
            <span className={pairingConfirmed ? 'status-badge secure' : 'status-badge pending'}>
              {pairingConfirmed ? 'Peer trusted here' : 'Pairing required'}
            </span>
          </div>

          <div className="pairing-grid pairing-grid-three">
            <article className="pairing-card">
              <div className="pairing-label">This device</div>
              {localQrUrl ? (
                <img className="qr-image pairing-qr" src={localQrUrl} alt="This device pairing QR" />
              ) : (
                <p className="empty-state">Loading QR...</p>
              )}
              <div className="fingerprint-box">{localFingerprint || 'Loading fingerprint...'}</div>
              <textarea className="pairing-payload" value={localPayload} readOnly rows={4} />
            </article>

            <article className="pairing-card">
              <div className="pairing-label">Scan or paste peer payload</div>
              <h3>Other device</h3>
              <button
                className="pairing-action-button"
                type="button"
                onClick={scanning ? stopScan : handleScanQr}
                disabled={pairingLoading}
              >
                {scanning ? 'Stop camera' : 'Scan QR with camera'}
              </button>
              <video
                ref={videoRef}
                className="scanner-video"
                muted
                playsInline
                style={{ display: scanning ? 'block' : 'none' }}
              />
              <p className="scanner-help" aria-live="polite">
                {scanning
                  ? 'Camera is scanning continuously. Center the other device’s QR in the frame, move it closer until it looks sharp, and hold it steady. The fingerprint will verify automatically when recognized.'
                  : 'If camera access is blocked on HTTP LAN, copy the payload from the other device and paste it here.'}
              </p>
            </article>

            <article className="pairing-card">
              <div className="pairing-label">Verify fingerprint</div>
              <h3>Trust peer</h3>
              <form onSubmit={handlePreparePairing}>
                <textarea
                  className="pairing-payload"
                  value={pairingInput}
                  onChange={(event) => {
                    setPairingInput(event.target.value)
                    setPairingVerification(null)
                  }}
                  placeholder="Paste pairing payload from the other device"
                  rows={5}
                  required
                />
                <button className="pairing-action-button" type="submit" disabled={pairingLoading}>
                  {pairingLoading ? 'Verifying...' : 'Verify device'}
                </button>
              </form>
              {pairingVerification && (
                <div className="pairing-verification">
                  <div className="fingerprint-box">
                    {pairingVerification.fingerprint}
                  </div>
                  <button
                    className="pairing-confirm-button"
                    type="button"
                    onClick={handleConfirmPairing}
                    disabled={pairingLoading}
                  >
                    Confirm and trust this device
                  </button>
                </div>
              )}
            </article>
          </div>
        </section>

        <section className="workspace-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">SECURE TRANSFER</span>
              <h2>Send and receive encrypted data</h2>
              <p>AES-256-GCM after an X25519 session. Both paired devices can send and receive.</p>
            </div>
            <div className="header-actions">
              <button
                className="secondary-button"
                type="button"
                onClick={() => pullInbox({ showError: true })}
                disabled={!pairingConfirmed}
              >
                Refresh inbox
              </button>
              <button className="secondary-button" type="button" onClick={() => setShowMessages((v) => !v)}>
                {showMessages ? 'Hide log' : 'Show log'}
              </button>
            </div>
          </div>

          <form className="message-form" onSubmit={handleSendMessage}>
            {transferError && <div className="alert error" role="alert">Transfer issue: {transferError}</div>}
            {inboxError && <div className="alert error" role="alert">Inbox: {inboxError}</div>}
            {transferStatus && <div className="alert success" role="status">{transferStatus}</div>}
            <textarea
              value={messageText}
              onChange={(event) => {
                setMessageText(event.target.value)
                if (pendingMessageType !== 'text') {
                  setPendingMessageType('text')
                }
              }}
              placeholder={
                pairingConfirmed
                  ? 'Write a secure message or transcribe a voice note...'
                  : 'Pair the other device before sending...'
              }
              rows={4}
              disabled={!pairingConfirmed}
            />
            <div className="transfer-actions">
              <button
                className="primary-button"
                type="submit"
                disabled={messageLoading || voiceProcessing || recording || !pairingConfirmed || !messageText.trim()}
              >
                {messageLoading ? 'Sending...' : pendingMessageType === 'audio_transcript' ? 'Send transcript' : 'Send text'}
              </button>
              <label className={`file-button ${!pairingConfirmed || messageLoading ? 'disabled' : ''}`}>
                {pairingConfirmed ? 'Choose image / audio / file' : 'Trust a peer to send files'}
                <input type="file" onChange={handleSelectFile} disabled={!pairingConfirmed || messageLoading} />
              </label>
              {selectedFile && (
                <button
                  className="primary-button"
                  type="button"
                  onClick={handleSendFile}
                  disabled={messageLoading || !pairingConfirmed}
                >
                  {messageLoading ? 'Sending file...' : `Send ${selectedFile.name}`}
                </button>
              )}
              <button
                className="secondary-button"
                type="button"
                onClick={handleRecordVoice}
                disabled={voiceProcessing || !pairingConfirmed || messageLoading}
                aria-pressed={recording}
              >
                {voiceProcessing
                  ? recording ? 'Starting microphone…' : 'Transcribing on device…'
                  : recording ? 'Stop & transcribe' : 'Start voice recording'}
              </button>
            </div>
            {recording && (
              <p className="voice-recording-status" role="status">
                <span aria-hidden="true" /> Microphone is on. Speak clearly in English, then select “Stop & transcribe”.
              </p>
            )}
            <p className="empty-state">
              {!pairingConfirmed
                ? 'Both devices must confirm each other\'s fingerprint. Then either device can send.'
                : 'Incoming messages appear below automatically. Use Refresh inbox if needed.'}
            </p>
          </form>
          {fileName && <p className="empty-state">Last file sent: {fileName}</p>}
          {showMessages && (
            <div className="message-list">
              {messages.length === 0 ? (
                <p className="empty-state">No transfers yet.</p>
              ) : (
                messages.map((message, index) => (
                  <article className="message-item" key={`${message.sequence}-${index}`}>
                    <div>
                      <strong>{message.sent ? 'sent' : 'received'} · {message.type || 'text'}</strong>
                      <span>Sequence #{message.sequence}</span>
                    </div>
                    <p>{message.text}</p>
                  </article>
                ))
              )}
            </div>
          )}
          {files.length > 0 && (
            <div className="message-list">
              <h3>Files available to download in this tab</h3>
              {files.map((file, index) => (
                <article className="message-item" key={`${file.direction}-${file.sequence_number}-${index}`}>
                  <div>
                    <strong>{file.direction} · {file.message_type || 'file'}</strong>
                    <span>{file.size} bytes</span>
                  </div>
                  <p>
                    <span>{file.filename}</span>{' '}
                    <button
                      className="secondary-button"
                      type="button"
                      onClick={() =>
                        downloadReceivedFile(file).catch((err) =>
                          setError(err.message || 'Unable to download the file.')
                        )
                      }
                    >
                      Download
                    </button>
                  </p>
                </article>
              ))}
            </div>
          )}
        </section>

        <section className="workspace-panel security-panel">
          <div className="section-heading">
            <div>
              <span className="eyebrow">ACCOUNTABILITY</span>
              <h2>Security dashboard</h2>
              <p>Your device identity, trusted peers, and local connection status.</p>
            </div>
          </div>
          {dashboard ? (
            <div className="metrics-grid">
              <article className="pairing-card">
                <div className="pairing-label">This client fingerprint</div>
                <div className="fingerprint-box">{dashboard.device.fingerprint}</div>
                <p>Security audit events are available only through administrator sign in.</p>
              </article>
              <article className="pairing-card">
                <div className="pairing-label">Trusted devices</div>
                {dashboard.trusted_devices.length === 0 ? (
                  <p>None yet.</p>
                ) : (
                  dashboard.trusted_devices.map((device) => (
                    <div key={device.fingerprint} className="fingerprint-box">
                      {device.device_name}: {device.fingerprint}
                    </div>
                  ))
                )}
              </article>
              <article className="pairing-card">
                <div className="pairing-label">Sentinel Monitor</div>
                <p>System monitoring details are available only to administrators.</p>
              </article>
            </div>
          ) : (
            <p className="empty-state">Dashboard loading...</p>
          )}
        </section>
      </section>
    </main>
  )
}

export default App
