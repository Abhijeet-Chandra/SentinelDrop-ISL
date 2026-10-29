# ISL Completion and Acceptance Checklist

This checklist is for the current isolated implementation. **Code complete** means the code path and automated tests are present. **External acceptance** requires the real provider, TShark/Npcap, Vosk model, or two physical devices and cannot be inferred from unit tests.

## Implemented in code and locally testable

- [x] Browser-generated X25519 identity and IndexedDB private-key storage; QR/public-key fingerprint pairing with reciprocal account approval.
- [x] Direction-specific HKDF-derived AES-256-GCM keys for browser text and image/document payloads; authenticated metadata; the API stores and routes ciphertext only.
- [x] Durable database-backed session authorization and ciphertext inbox; nonce reuse registry, per-recipient queue cap, account-scoped retrieval, and seven-day bearer-token expiry.
- [x] Admin-only audit/event verification and message-transfer records with send/receive times, ciphertext digest, nonce, GCM tag, and server Ed25519 attestation; plaintext is omitted.
- [x] Text analysis with AES timing, confusion/diffusion/avalanche sample graphs, and SHA-256 timing plus bounded reduced-digest teaching demonstrations.
- [x] Image analysis and five-size repeated benchmark with entropy, correlation, NPCR/UACI experiment, encryption/decryption times, throughput, and exact-recovery MSE/PSNR. The UI explains which classic image-cipher expectations do not apply to AES-GCM.
- [x] Dated local evaluation tables and raw JSON results for image metrics, a five-size image sweep, text confusion/diffusion/avalanche, and four AES payload sizes; results are explicitly labeled as local and illustrative.
- [x] Repeatable backend AES benchmark with copy baseline, payload sizes, mean/median/spread, throughput, overhead, and CSV output. This is a processing microbenchmark, not a network baseline comparison.
- [x] Sender-side offline voice transcription with Vosk WebAssembly in a browser worker; the authenticated model is cached in IndexedDB, and only the recognized transcript enters the existing encrypted text flow. Admin timing logs contain size/time metadata only.
- [x] Seven bounded, isolated Admin security demonstrations with expected/observed outcomes and limitations.
- [x] Admin-only uploaded-PCAP analysis and bounded live-capture API/dashboard (max 10 seconds/1,000 dashboard packets); live results aggregate protocol/byte/rate counts without retaining packet content or endpoint addresses.
- [x] Admin-only deployment-readiness card reports configuration booleans and advisory items without returning secret values.
- [x] Backup-copy schema-migration regression test; repeatable migration preserves user/token/message records and is idempotent.
- [x] Itemized implementation audit, deployment guide, and these acceptance items updated to reflect the code.

## External checks still required before claiming full synopsis validation

- [ ] **Two physical devices:** complete reciprocal QR approval, text, image and document delivery, receipt acknowledgement, logout/login, browser-storage loss, and backend restart/reconnect against the same LAN backend. Automated browser crypto and API integration tests are not a substitute.
- [ ] **Browser permissions:** verify QR auto-decoding and microphone access in current Android/iOS browsers using HTTPS; record device/browser versions. HTTP LAN addresses generally are not secure contexts.
- [ ] **Voice device acceptance:** verify first model download, then disable the network and test cached transcription; test representative speech, transcript review, and encrypted delivery on supported Android/iOS browsers. Record model version, browser/device, and recognition results. The Admin benchmark is a separate explicit WAV upload.
- [ ] **TShark integration:** analyze sanitized PCAP and PCAPNG fixtures on a machine with TShark; exercise live capture on a designated owned interface and confirm start, natural timeout, stop, OS permissions, and teardown. This environment has not run an actual capture.
- [ ] **Deployment persistence:** verify the Render service is on a plan with a persistent disk, confirm database path and disk mount, then backup and test restart/redeploy. `render.yaml` requests a persistent disk, but provider settings and billing cannot be validated from this checkout.
- [ ] **TLS/CORS:** verify the deployed Admin readiness output and browser network requests use the intended HTTPS origins; test actual Vercel-to-Render preflight and API access. A code-level readiness flag cannot confirm provider routing or browser behavior.
- [ ] **Traffic demonstrations:** use Wireshark on the owned test network to verify that text/file request bodies contain ciphertext; run only bounded, isolated replay/tamper/failed-login/flood lab scenarios. The seven UI demos are intentionally simulations, not live attacks or proof of resistance to all attacks.
- [ ] **Audit anchoring:** the chain detects in-chain changes but has no external append-only checkpoint. Preserve an independent signed backup/checkpoint if resistance to full database rewrite or tail deletion is required.
- [ ] **Baseline comparison:** current AES comparison baseline is an in-memory byte copy and excludes HTTP/network. Collect same-host, same-size end-to-end measurements for a clearly defined unsecured baseline and secured workflow if the synopsis table requires transfer-overhead comparison.
- [ ] **Representative presentation evidence:** rerun Admin analyses with representative project photos and on the final demo host, then save its host/model/round details. The current [local results sheet](local_evaluation_results_2026-10-29.md) uses the repository's transparent logo illustration and a copy microbenchmark; do not present those as a natural-image dataset or unsecured network baseline, and do not present toy-digest search as full SHA-256 breaking.

## Environment-dependent notes

- A standard external audit/security review has not been performed.
- The Render blueprint is single-instance SQLite; scaling horizontally requires a shared database/store and coordination design.
- The readiness card cannot validate plan billing, disk retention after a future redeploy, Vercel environment variables, secret rotation history, two-device pairing, or TLS beyond the scheme observed by the API request.
- No code in this worktree has been pushed or deployed by this task.
