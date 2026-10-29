# SentinelDrop

For cloud deployment setup, see [DEPLOYMENT.md](DEPLOYMENT.md).

Local transfer of text, image evidence, and voice transcripts. Pairing uses QR payloads and public-key fingerprint confirmation. The application uses X25519/HKDF session material and AES-256-GCM, with hash-chained audit events.

Text and file payloads are encrypted in the browser with AES-256-GCM. Browsers derive directional keys from X25519 and HKDF after users verify each other's device fingerprints. The API relays ciphertext and metadata; it does not receive those payloads' plaintext or session keys. Use HTTPS for deployed sites and local TLS for LAN camera/microphone access. The API still receives account, pairing, routing, and transfer metadata, and this student project has not had an independent security review.

Two physical devices use the **same** backend and the **same** web UI. Each signed-in user has a distinct X25519 identity. Neither client is permanently a sender or receiver.

## Ports (this folder)

| Service | Bind | URL |
| --- | --- | --- |
| FastAPI | `0.0.0.0:8000` | `http://<LAN-IP>:8000` |
| Vite UI | `0.0.0.0:5173` | `http://<LAN-IP>:5173` |

The Vite dev server proxies API routes to `127.0.0.1:8000`, so other laptops only need the UI origin.

## Setup

Use the same Python version that creates the venv. Do not mix 3.14 wheels into a 3.13 venv.

```bash
cd SentinelDrop-Fresh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cd frontend && npm install
```

macOS/Linux PowerShell equivalent on Windows:

```powershell
cd SentinelDrop-Fresh
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd frontend
npm install
```

Voice notes are transcribed on the sender device by Vosk WebAssembly in a browser worker. On first use, the backend downloads the small English Vosk model (about 43 MB compressed) from the official Vosk host, creates an authenticated model archive, and serves it to the signed-in browser. The browser keeps that archive in IndexedDB. Later transcription runs locally without sending audio to the API; only the transcript is placed in the existing encrypted text-transfer flow. The Admin audit log records audio size and transcription time only. Clearing browser storage means the model must be downloaded again. The Render persistent disk can retain the backend model/archive between restarts; a backend without outbound internet access must have `vosk-model-small-en-us-0.15` installed under `SENTINEL_DATA_DIR/models/vosk/` before the browser can download it. An Admin may separately upload a WAV to the explicit benchmark tool; that tool is for measurements and is not used by ordinary voice messages.

## Run on one laptop (also used as the LAN host)

Terminal 1 — API (reachable on the LAN):

```bash
cd SentinelDrop-Fresh
source .venv/bin/activate
export SENTINEL_RATE_LIMIT_DISABLED=1   # optional, for demos
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Terminal 2 — UI:

```bash
cd SentinelDrop-Fresh/frontend
npm run dev
```

Find this laptop's LAN IP:

```bash
ipconfig getifaddr en0    # macOS Wi-Fi
hostname -I               # Linux
ipconfig                  # Windows, look for IPv4
```

## Two physical devices (same Wi-Fi / hotspot)

1. Connect both laptops to the same Wi-Fi, LAN, or phone hotspot.
2. Start the backend and UI on **Laptop 1** as above (`--host 0.0.0.0`).
3. On Laptop 1 open `http://<LAPTOP1-IP>:5173` (or `http://127.0.0.1:5173`).
4. On Laptop 2 open `http://<LAPTOP1-IP>:5173`.
5. Register or login as **different users** on each laptop. Tokens stay in that browser only.
6. Pair (both directions), then send from either side.

### Pairing

1. On device 1, leave **This device** QR / payload visible.
2. On device 2, paste that payload (or use **Scan QR with camera** if the browser allows it), verify the fingerprint, then **Confirm and trust this device**.
3. Reverse the process so device 1 also trusts device 2.
4. Either device can then send text, images, or audio transcripts. Incoming items appear in the same UI (polling).

Camera and microphone on a **second laptop** often require a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). `http://127.0.0.1` is treated as secure; `http://192.168.x.x` usually is not. Pairing still works by pasting the payload. For camera/mic on the second device, the smallest option is local HTTPS (for example [mkcert](https://github.com/FiloSottile/mkcert) certificates) without turning off browser security. Do not use a public URL unless you need one.

### Two browser tabs on one machine

Open two tabs at `http://127.0.0.1:5173`, log in as two users, pair both ways, and transfer. This is the original two-tab workflow against a single backend.

## Admin Dashboard and ISL analysis

Sign in through the separate administrator login using credentials provisioned by the service owner (`SENTINEL_ADMIN_USERNAME` and `SENTINEL_ADMIN_PASSWORD`). Audit events, message metadata, audit verification, analysis, and monitoring endpoints require administrator authorization on the backend.

The Admin Dashboard includes AES text analysis and graphs, SHA-256 timing and bounded reduced-digest teaching searches, an ephemeral Ed25519 signature demonstration, image metrics and ciphertext visualization, repeatable text/image/audio processing benchmarks, transfer latency, seven isolated security demonstrations, deployment-readiness signals, application-security events, bounded offline PCAP analysis, and bounded live-capture controls. Offline PCAP uploads are limited to 20 MB and 50,000 packets. TShark packet capture is limited to 10 seconds or 1,000 packets from a listed interface; it reports aggregates and does not retain packet payloads or endpoint addresses. Offline PCAP analysis and packet capture need PyShark/TShark; packet capture also needs OS capture permissions (Npcap on Windows). On hosts without TShark interfaces, the Admin dashboard has a separate 30-second, 1,000-request application HTTP monitor. It reports status classes, request rates, and bounded Content-Length totals without retaining payloads, addresses, credentials, or paths; these are API requests, not network packets. The packet-rate alert is a simple threshold signal, not an attack verdict. Current analysis results can be exported as JSON; AES processing benchmark rows can be exported as CSV.

Image NPCR/UACI compare AES-GCM ciphertext body visualizations under an isolated one-bit-change experiment. AES-GCM counter mode changes the corresponding ciphertext bit under this controlled setup, so classic image-cipher reference values near 100% NPCR and 33% UACI do not apply. Ciphertext-vs-plaintext MSE/PSNR are not meaningful; exact decryption reports MSE zero and infinite PSNR.

## Security audit log

Only an administrator can view or verify hash-chained events. The normal user dashboard does not expose the audit trail. Use the admin login, or call:

```bash
curl -H "Authorization: Bearer <admin-token>" http://127.0.0.1:8000/audit/events
curl -H "Authorization: Bearer <admin-token>" http://127.0.0.1:8000/audit/verify
```

`/audit/verify` returns whether the chain is intact. Changing an `audit_logs` row in SQLite makes verification fail.

## Encryption demonstration log

Disabled by default. Do not enable plaintext logging for normal use. In particular, leave `ENCRYPTION_DEMO_INCLUDE_PLAINTEXT` unset or false; the communication APIs are ciphertext-only and do not need this option.

```bash
export ENABLE_ENCRYPTION_DEMO_LOG=true
export ENCRYPTION_DEMO_INCLUDE_PLAINTEXT=false
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Writes only metadata for legacy isolated demonstrations to `logs/encryption_demo.log`. Never enable plaintext logging for real users or transfers. Session keys, passwords, and tokens must never be written. `logs/` is gitignored.

## Tests

```bash
cd SentinelDrop-Fresh
source .venv/bin/activate
export SENTINEL_RATE_LIMIT_DISABLED=1
python -m pytest tests -q
```

## Security controls implemented

- bcrypt password hashing; hashed bearer tokens; logout revocation
- Per-user QR pairing payload + fingerprint confirmation
- Browser-owned X25519 identities, authenticated fingerprint confirmation, and directional HKDF-derived AES-256-GCM keys
- Browser-side AES-256-GCM for text and files; authenticated metadata, account/session checks, nonce-reuse rejection, and persistent ciphertext inboxes
- Seven-day bearer tokens and per-IP rate limiting
- Hash-chained audit log with `/audit/verify`
- Per-IP rate limiting (login is stricter)
- Sentinel Monitor application events, offline PCAP analysis, and bounded Admin live capture
- Image encryption metrics: entropy, NPCR, UACI, correlation, PSNR, MSE

See [the requirements audit](docs/ISL_REQUIREMENTS_AUDIT.md), [open-items checklist](docs/ISL_MISSING_FEATURES_CHECKLIST.md), and [final compliance report](docs/ISL_FINAL_COMPLIANCE_REPORT.md) for exact status and limitations.
