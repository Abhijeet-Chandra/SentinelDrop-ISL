# SentinelDrop ISL Implementation and Verification Report

## Scope

This report describes the implementation in the isolated `codex/sentineldrop-isl` worktree as of 2026-10-29. It is reconciled with the submitted synopsis. “Implemented” means the code and local automated checks support the named behavior; it does not mean production, two-device, or independent security acceptance is complete.

## Implemented

- Browser-owned X25519 identity keys in IndexedDB, reciprocal QR/fingerprint trust, directional HKDF-SHA-256 key derivation, and client AES-256-GCM for text and files.
- Authenticated metadata, account-bound durable session authorization, persistent ciphertext inboxes, unique session/sender nonce registry, bounded recipient queue, and expiring bearer tokens.
- Admin-only hash-chained audit verification, ciphertext transfer records, receiver timestamps, SHA-256 digests, GCM nonce/tag, and server-generated Ed25519 attestations.
- Admin text analysis with timing, confusion, diffusion, avalanche graphs; SHA-256 concepts plus bounded toy-digest demonstrations; ephemeral Ed25519 sign/verify demonstration.
- Admin image visualization/metrics and a repeated, five-size image benchmark with encryption/decryption timing, entropy, correlation, scoped NPCR/UACI, throughput, and recovery MSE/PSNR. Transparent PNGs are composited onto white before grayscale evaluation.
- Repeatable AES processing benchmark and CSV export; voice benchmark with transcript omitted; transfer latency records.
- Seven bounded in-memory security demonstrations, admin-only offline PCAP upload analysis, and admin-only live capture with strict time/packet bounds and aggregate-only output.
- Admin deployment-readiness checks report configuration state without returning environment secret values.
- Dated local result tables and raw JSON for the repository image asset, text metrics, and four AES payload sizes are in `docs/local_evaluation_results_2026-10-29.md` and `.json`. The icon is illustrative, not a representative photo dataset; the copy baseline excludes network.
- Sender-side offline voice transcription runs Vosk WebAssembly in a browser worker; its authenticated model archive is downloaded on first use and cached in IndexedDB. Ordinary voice notes do not upload audio or transcript text; only the transcript enters the existing encrypted text flow. Admin records size/time metadata only, while the WAV benchmark remains a separate explicit operation.
- Additive database migration passes twice against a test-created copy of an older SQLite schema while preserving its user, token, ciphertext message, and nonce records.
- README, deployment guide, synopsis audit, and acceptance checklist describe the implemented architecture and its limits.

## Verification performed

- Backend: `pytest tests -q --basetemp .pytest-final-tmp` — **117 passed, 1 skipped**. One third-party Starlette/httpx deprecation warning remains.
- One test is skipped because the model is not installed in this isolated worktree; tests deliberately do not download large models. Separately, the existing local Vosk model loaded successfully, transcribed a one-second silent WAV, and produced a valid 42.5 MB browser model archive.
- Python `compileall` for `app/` — passed.
- Frontend ESLint — passed. Node frontend tests — **4 passed**.
- Image transparency regression test — passed; the dated evaluation sheet and raw JSON were regenerated after the fix.
- Frontend Vite production build — passed. Voice code is split into a lazy chunk; Vite still warns that the main JavaScript bundle is about 783 kB and exceeds its 500 kB advisory threshold.
- Migration test uses only a temporary copy created by the test. No real deployed database was accessed.
- Live-capture lifecycle tests use a fake capture adapter. No real TShark capture was started in this environment.

## Remaining before claiming full synopsis validation

1. **Representative results:** rerun image analysis with representative project photos and capture the secured-vs-defined-baseline network comparison on the final demo host. The current local artifact uses a small logo illustration and a byte-copy baseline.
2. **Real device acceptance:** verify QR auto-scan, microphone permissions, text/image/document exchange, disconnect/reconnect, identity-loss recovery, and cached offline voice recognition on two physical devices with HTTPS.
3. **Network evidence:** inspect a capture from the owned LAN in Wireshark to show that browser-to-API payloads contain ciphertext. The seven Admin lab demos are safe simulations, not packet-level attack tests.
4. **Traffic integration:** validate sanitized PCAP/PCAPNG parsing and run/stop the bounded capture on a TShark/Npcap-enabled host with authorized interface permissions.
5. **Performance comparison:** run and record same-host end-to-end timings for a defined unsecured baseline versus the secured workflow. The existing copy baseline is an in-memory microbenchmark and excludes HTTP/network.
6. **Hosted persistence/TLS:** confirm the deployed Render plan has a persistent disk, back up and test the actual database copy before any production migration, and check Vercel-to-Render HTTPS/CORS from the browser. The readiness endpoint cannot verify provider billing or future retention behavior.
7. **Audit anchoring:** hash-chain verification detects edits to existing rows but does not stop full database rewrite or tail removal without an external checkpoint/backup.
8. **Security review:** this educational project has not received an independent security audit.

See [the line-item synopsis audit](ISL_REQUIREMENTS_AUDIT.md) and [the remaining acceptance checklist](ISL_MISSING_FEATURES_CHECKLIST.md) for destinations and detailed evidence.

## Deployment boundary

Changes remain local to the isolated worktree. This task did not push, commit, deploy, change hosting secrets, or modify the original `main` checkout.
